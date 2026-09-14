"""Sandbox cleanup Lambda.

Iterates over all enabled regions in the account and deletes billable
resources. Runs in DRY RUN mode by default: resources are only listed, not
deleted.

Deletion only happens when the DRY_RUN environment variable is explicitly set
to "false" (case-insensitive).
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _is_dry_run() -> bool:
    # Safe default: any value other than "false" means dry run.
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


# Tag keys that, when present, cause the resource to be left untouched.
PROTECT_TAG_KEYS = {
    k.strip()
    for k in os.environ.get("PROTECT_TAG_KEYS", "keep,protected,do-not-delete").split(",")
    if k.strip()
}


DRY_RUN = _is_dry_run()

# When true, running/stopped EC2 instances are stopped instead of terminated.
STOP_EC2 = os.environ.get("STOP_EC2", "false").strip().lower() == "true"

# SNS topic that receives the cleanup report. Empty means notifications are off.
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "").strip()

# Summary of actions for reporting.
_actions: list[str] = []

# Present-participle form used when an action is actually performed.
_VERB_GERUND = {
    "delete": "Deleting",
    "stop": "Stopping",
    "terminate": "Terminating",
    "release": "Releasing",
}


def _record(action: str, resource: str, region: str, extra: str = "", verb: str = "delete") -> None:
    if DRY_RUN:
        prefix = f"[DRY-RUN] Would {verb}"
    else:
        prefix = _VERB_GERUND.get(verb, f"{verb.capitalize()}ing")
    msg = f"{prefix} {action} '{resource}' in region {region}"
    if extra:
        msg += f" ({extra})"
    logger.info(msg)
    _actions.append(msg)


def _tags_protect(tags: list[dict] | None) -> bool:
    if not tags:
        return False
    keys = {t.get("Key", "") for t in tags}
    return bool(keys & PROTECT_TAG_KEYS)


def _enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2")
    resp = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in resp["Regions"]]


# --------------------------------------------------------------------------- #
# Per-resource cleaners. Each takes a boto3 session and a region.
# --------------------------------------------------------------------------- #


def clean_ec2_instances(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")
    # When STOP_EC2 is set, only running instances are worth stopping.
    states = ["running"] if STOP_EC2 else ["pending", "running", "stopping", "stopped"]
    action = "stop" if STOP_EC2 else "terminate"
    targets: list[str] = []
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": states}]
    ):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if _tags_protect(inst.get("Tags")):
                    continue
                iid = inst["InstanceId"]
                _record("EC2 instance", iid, region, inst.get("InstanceType", ""), verb=action)
                targets.append(iid)
    if targets and not DRY_RUN:
        if STOP_EC2:
            resp = ec2.stop_instances(InstanceIds=targets)
        else:
            resp = ec2.terminate_instances(InstanceIds=targets)
        # stop/terminate report per-instance failures without raising.
        for failure in resp.get("Unsuccessful", []):
            err = failure.get("Error", {})
            logger.warning(
                "Failed to %s EC2 instance %s: %s - %s",
                action,
                failure.get("InstanceId", "?"),
                err.get("Code", ""),
                err.get("Message", ""),
            )


def clean_ebs_volumes(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page["Volumes"]:
            # Never delete a volume still attached to an instance (e.g. a stopped one).
            if vol.get("Attachments"):
                continue
            if _tags_protect(vol.get("Tags")):
                continue
            vid = vol["VolumeId"]
            _record("unattached EBS volume", vid, region, f"{vol.get('Size')} GiB")
            if not DRY_RUN:
                try:
                    ec2.delete_volume(VolumeId=vid)
                except ClientError as e:
                    logger.warning("Failed to delete EBS volume %s: %s", vid, e)


def clean_elastic_ips(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    # describe_addresses has no boto3 paginator; page manually via NextToken.
    next_token = None
    while True:
        resp = ec2.describe_addresses(**({"NextToken": next_token} if next_token else {}))
        for addr in resp["Addresses"]:
            if _tags_protect(addr.get("Tags")):
                continue
            alloc = addr.get("AllocationId")
            # Only VPC EIPs (AllocationId) can be released; skip anything else.
            if not alloc:
                continue
            assoc = addr.get("AssociationId")
            public_ip = addr.get("PublicIp", "")
            # AWS bills every allocated public IPv4 address, even while associated,
            # so associated EIPs are disassociated and released too.
            label = "Elastic IP" if assoc else "unassociated Elastic IP"
            _record(label, public_ip, region, verb="release")
            if not DRY_RUN:
                try:
                    if assoc:
                        ec2.disassociate_address(AssociationId=assoc)
                    ec2.release_address(AllocationId=alloc)
                except ClientError as e:
                    logger.warning("Failed to release Elastic IP %s: %s", public_ip, e)
        next_token = resp.get("NextToken")
        if not next_token:
            break


def clean_nat_gateways(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_nat_gateways")
    for page in paginator.paginate(Filter=[{"Name": "state", "Values": ["available", "pending"]}]):
        for nat in page["NatGateways"]:
            if _tags_protect(nat.get("Tags")):
                continue
            nid = nat["NatGatewayId"]
            _record("NAT gateway", nid, region)
            if not DRY_RUN:
                try:
                    ec2.delete_nat_gateway(NatGatewayId=nid)
                except ClientError as e:
                    logger.warning("Failed to delete NAT gateway %s: %s", nid, e)


def clean_load_balancers(session: boto3.Session, region: str) -> None:
    # ALB / NLB (ELBv2)
    elbv2 = session.client("elbv2", region_name=region)
    for lb in elbv2.get_paginator("describe_load_balancers").paginate():
        for entry in lb["LoadBalancers"]:
            arn = entry["LoadBalancerArn"]
            tags = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]["Tags"]
            if _tags_protect(tags):
                continue
            _record("load balancer", entry["LoadBalancerName"], region, entry.get("Type", ""))
            if not DRY_RUN:
                try:
                    elbv2.delete_load_balancer(LoadBalancerArn=arn)
                except ClientError as e:
                    logger.warning("Failed to delete load balancer %s: %s", arn, e)

    # Classic ELB
    elb = session.client("elb", region_name=region)
    for lb in elb.get_paginator("describe_load_balancers").paginate():
        for entry in lb["LoadBalancerDescriptions"]:
            name = entry["LoadBalancerName"]
            _record("classic load balancer", name, region)
            if not DRY_RUN:
                try:
                    elb.delete_load_balancer(LoadBalancerName=name)
                except ClientError as e:
                    logger.warning("Failed to delete classic load balancer %s: %s", name, e)


def clean_rds(session: boto3.Session, region: str) -> None:
    rds = session.client("rds", region_name=region)

    # Standalone DB instances. Aurora members (those with a DBClusterIdentifier)
    # are owned by a cluster and handled in the cluster loop below, so that a
    # protected cluster is not emptied out here before its tags are checked.
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            if db.get("DBClusterIdentifier"):
                continue
            if _tags_protect(db.get("TagList")):
                continue
            dbid = db["DBInstanceIdentifier"]
            _record("RDS instance", dbid, region, db.get("DBInstanceClass", ""))
            if not DRY_RUN:
                _delete_db_instance(rds, dbid, db.get("DeletionProtection", False))

    # Aurora clusters
    for page in rds.get_paginator("describe_db_clusters").paginate():
        for cluster in page["DBClusters"]:
            if _tags_protect(cluster.get("TagList")):
                continue
            cid = cluster["DBClusterIdentifier"]
            _record("RDS cluster", cid, region, cluster.get("Engine", ""))
            if not DRY_RUN:
                _delete_db_cluster(rds, cluster, region)


def _delete_db_instance(rds, dbid: str, deletion_protection: bool) -> None:
    """Delete a DB instance, waiting for any deletion-protection change first."""
    try:
        if deletion_protection:
            rds.modify_db_instance(
                DBInstanceIdentifier=dbid, DeletionProtection=False, ApplyImmediately=True
            )
            # delete_db_instance is rejected while the modification is pending.
            rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=dbid)
        rds.delete_db_instance(
            DBInstanceIdentifier=dbid, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    except ClientError as e:
        logger.warning("Failed to delete RDS instance %s: %s", dbid, e)


def _delete_db_cluster(rds, cluster: dict, region: str) -> None:
    """Delete a cluster after its member instances have finished deleting."""
    cid = cluster["DBClusterIdentifier"]
    try:
        # Members must be gone before delete_db_cluster is accepted.
        members = [m["DBInstanceIdentifier"] for m in cluster.get("DBClusterMembers", [])]
        for member in members:
            desc = rds.describe_db_instances(DBInstanceIdentifier=member)["DBInstances"][0]
            _record("RDS cluster member", member, region)
            _delete_db_instance(rds, member, desc.get("DeletionProtection", False))
        for member in members:
            rds.get_waiter("db_instance_deleted").wait(DBInstanceIdentifier=member)

        if cluster.get("DeletionProtection"):
            rds.modify_db_cluster(
                DBClusterIdentifier=cid, DeletionProtection=False, ApplyImmediately=True
            )
            rds.get_waiter("db_cluster_available").wait(DBClusterIdentifier=cid)
        rds.delete_db_cluster(DBClusterIdentifier=cid, SkipFinalSnapshot=True)
    except ClientError as e:
        logger.warning("Failed to delete RDS cluster %s: %s", cid, e)


def clean_ecs(session: boto3.Session, region: str) -> None:
    ecs = session.client("ecs", region_name=region)
    for page in ecs.get_paginator("list_clusters").paginate():
        for cluster_arn in page["clusterArns"]:
            # A protected cluster (and everything inside it) is left untouched.
            cluster_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn).get("tags", [])
            if _tags_protect(_norm_ecs_tags(cluster_tags)):
                continue

            deleted_services: list[str] = []
            # Scale services to zero and delete them, then delete the cluster.
            for svc_page in ecs.get_paginator("list_services").paginate(cluster=cluster_arn):
                for svc_arn in svc_page["serviceArns"]:
                    svc_tags = ecs.list_tags_for_resource(resourceArn=svc_arn).get("tags", [])
                    if _tags_protect(_norm_ecs_tags(svc_tags)):
                        continue
                    _record("ECS service", svc_arn, region)
                    if not DRY_RUN:
                        try:
                            ecs.delete_service(cluster=cluster_arn, service=svc_arn, force=True)
                            deleted_services.append(svc_arn)
                        except ClientError as e:
                            logger.warning("Failed to delete ECS service %s: %s", svc_arn, e)

            # Stop standalone tasks that are not owned by a service.
            for task_page in ecs.get_paginator("list_tasks").paginate(cluster=cluster_arn):
                for task_arn in task_page["taskArns"]:
                    _record("ECS task", task_arn, region, verb="stop")
                    if not DRY_RUN:
                        try:
                            ecs.stop_task(cluster=cluster_arn, task=task_arn)
                        except ClientError as e:
                            logger.warning("Failed to stop ECS task %s: %s", task_arn, e)

            _record("ECS cluster", cluster_arn, region)
            if not DRY_RUN:
                try:
                    # delete_service is async; wait for services to drain first.
                    if deleted_services:
                        ecs.get_waiter("services_inactive").wait(
                            cluster=cluster_arn, services=deleted_services
                        )
                    ecs.delete_cluster(cluster=cluster_arn)
                except ClientError as e:
                    logger.warning("Failed to delete ECS cluster %s: %s", cluster_arn, e)


def _norm_ecs_tags(tags: list[dict] | None) -> list[dict]:
    """ECS/EKS tags use lowercase keys; normalize to the {'Key': ...} form."""
    if not tags:
        return []
    return [{"Key": t.get("key", t.get("Key", ""))} for t in tags]


def clean_eks(session: boto3.Session, region: str) -> None:
    eks = session.client("eks", region_name=region)
    for page in eks.get_paginator("list_clusters").paginate():
        for name in page["clusters"]:
            cluster = eks.describe_cluster(name=name)["cluster"]
            # A protected cluster and all of its node groups are left untouched.
            if _dict_tags_protect(cluster.get("tags")):
                continue

            deleted_nodegroups: list[str] = []
            # Node groups must be deleted before the cluster.
            for ng_page in eks.get_paginator("list_nodegroups").paginate(clusterName=name):
                for ng in ng_page["nodegroups"]:
                    ng_desc = eks.describe_nodegroup(clusterName=name, nodegroupName=ng)["nodegroup"]
                    if _dict_tags_protect(ng_desc.get("tags")):
                        continue
                    _record("EKS node group", f"{name}/{ng}", region)
                    if not DRY_RUN:
                        try:
                            eks.delete_nodegroup(clusterName=name, nodegroupName=ng)
                            deleted_nodegroups.append(ng)
                        except ClientError as e:
                            logger.warning("Failed to delete EKS node group %s: %s", ng, e)

            # Fargate profiles must also be removed before the cluster.
            deleted_profiles: list[str] = []
            for fp_page in eks.get_paginator("list_fargate_profiles").paginate(clusterName=name):
                for fp in fp_page["fargateProfileNames"]:
                    _record("EKS Fargate profile", f"{name}/{fp}", region)
                    if not DRY_RUN:
                        try:
                            eks.delete_fargate_profile(clusterName=name, fargateProfileName=fp)
                            deleted_profiles.append(fp)
                        except ClientError as e:
                            logger.warning("Failed to delete EKS Fargate profile %s: %s", fp, e)

            _record("EKS cluster", name, region)
            if not DRY_RUN:
                try:
                    # Deletions above are async; the cluster cannot go until they finish.
                    for ng in deleted_nodegroups:
                        eks.get_waiter("nodegroup_deleted").wait(clusterName=name, nodegroupName=ng)
                    for fp in deleted_profiles:
                        eks.get_waiter("fargate_profile_deleted").wait(
                            clusterName=name, fargateProfileName=fp
                        )
                    eks.delete_cluster(name=name)
                except ClientError as e:
                    logger.warning("Failed to delete EKS cluster %s: %s", name, e)


def _dict_tags_protect(tags: dict | None) -> bool:
    """EKS tags are returned as a plain {key: value} mapping."""
    return bool(tags) and bool(set(tags) & PROTECT_TAG_KEYS)


def clean_elasticache(session: boto3.Session, region: str) -> None:
    ec = session.client("elasticache", region_name=region)

    # Redis/Valkey replication groups must be deleted as a whole; their member
    # clusters cannot be deleted individually with delete_cache_cluster.
    for page in ec.get_paginator("describe_replication_groups").paginate():
        for rg in page["ReplicationGroups"]:
            rgid = rg["ReplicationGroupId"]
            _record("ElastiCache replication group", rgid, region)
            if not DRY_RUN:
                try:
                    ec.delete_replication_group(
                        ReplicationGroupId=rgid, RetainPrimaryCluster=False
                    )
                except ClientError as e:
                    logger.warning(
                        "Failed to delete ElastiCache replication group %s: %s", rgid, e
                    )

    # Standalone cache clusters. Members of a replication group are skipped
    # because they are removed together with the group above.
    for page in ec.get_paginator("describe_cache_clusters").paginate():
        for cluster in page["CacheClusters"]:
            if cluster.get("ReplicationGroupId"):
                continue
            cid = cluster["CacheClusterId"]
            _record("ElastiCache cluster", cid, region, cluster.get("Engine", ""))
            if not DRY_RUN:
                try:
                    ec.delete_cache_cluster(CacheClusterId=cid)
                except ClientError as e:
                    logger.warning("Failed to delete ElastiCache cluster %s: %s", cid, e)


def clean_amis(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    # Only AMIs owned by this account; deregister the image and delete its
    # backing EBS snapshots so they stop incurring storage charges.
    images = ec2.describe_images(Owners=["self"])["Images"]
    for image in images:
        if _tags_protect(image.get("Tags")):
            continue
        image_id = image["ImageId"]
        snapshot_ids = [
            bdm["Ebs"]["SnapshotId"]
            for bdm in image.get("BlockDeviceMappings", [])
            if bdm.get("Ebs", {}).get("SnapshotId")
        ]
        _record("AMI", image_id, region, image.get("Name", ""))
        if not DRY_RUN:
            try:
                ec2.deregister_image(ImageId=image_id)
            except ClientError as e:
                logger.warning("Failed to deregister AMI %s: %s", image_id, e)
                continue
            for snap_id in snapshot_ids:
                _record("AMI snapshot", snap_id, region, f"from {image_id}")
                try:
                    ec2.delete_snapshot(SnapshotId=snap_id)
                except ClientError as e:
                    logger.warning("Failed to delete snapshot %s: %s", snap_id, e)
        else:
            for snap_id in snapshot_ids:
                _record("AMI snapshot", snap_id, region, f"from {image_id}")


# Cleaners that run per region.
REGIONAL_CLEANERS = [
    clean_ec2_instances,
    clean_nat_gateways,
    clean_load_balancers,
    clean_rds,
    clean_ecs,
    clean_eks,
    clean_elasticache,
    clean_amis,
    clean_ebs_volumes,
    clean_elastic_ips,
]


def handler(event, context):  # noqa: ARG001 - Lambda signature
    _actions.clear()
    session = boto3.Session()

    mode = "DRY RUN" if DRY_RUN else "DELETE"
    logger.info("Sandbox cleanup starting in mode: %s", mode)

    regions = _enabled_regions(session)
    logger.info("Scanning %d regions", len(regions))

    for region in regions:
        for cleaner in REGIONAL_CLEANERS:
            try:
                cleaner(session, region)
            except ClientError as e:
                logger.warning(
                    "Cleaner %s failed in region %s: %s", cleaner.__name__, region, e
                )

    logger.info("Done. %d resources %s.", len(_actions), "listed" if DRY_RUN else "processed")

    _log_summary()
    _publish_report(session)

    return {
        "dry_run": DRY_RUN,
        "count": len(_actions),
        "actions": _actions,
    }


def _log_summary() -> None:
    """Log a final summary of everything the script would delete."""
    header = (
        "SUMMARY - resources that WOULD be processed (dry run):"
        if DRY_RUN
        else "SUMMARY - resources that were processed:"
    )
    logger.info("=" * 72)
    logger.info(header)
    logger.info("=" * 72)
    if not _actions:
        logger.info("Nothing to process - no billable resources found.")
        return
    for i, action in enumerate(_actions, start=1):
        logger.info("%3d. %s", i, action)
    logger.info("-" * 72)
    logger.info("Total: %d resource(s).", len(_actions))


def _build_report() -> tuple[str, str]:
    """Return the (subject, body) of the cleanup report email."""
    if DRY_RUN:
        subject = f"[DRY RUN] Sandbox cleanup - {len(_actions)} resource(s) would be processed"
        header = "The following resources WOULD be processed (dry run):"
    else:
        subject = f"Sandbox cleanup - {len(_actions)} resource(s) processed"
        header = "The following resources were processed:"

    if _actions:
        lines = [f"{i:3d}. {action}" for i, action in enumerate(_actions, start=1)]
        body = "\n".join([header, "", *lines, "", f"Total: {len(_actions)} resource(s)."])
    else:
        body = "Nothing to process - no billable resources found."

    # SNS subjects are limited to 100 characters.
    return subject[:100], body


def _publish_report(session: boto3.Session) -> None:
    """Send the cleanup report to SNS, if a topic is configured."""
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set - skipping notification.")
        return
    subject, body = _build_report()
    try:
        region = SNS_TOPIC_ARN.split(":")[3]
        sns = session.client("sns", region_name=region)
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)
        logger.info("Published cleanup report to %s", SNS_TOPIC_ARN)
    except (ClientError, IndexError) as e:
        logger.warning("Failed to publish cleanup report to SNS: %s", e)
