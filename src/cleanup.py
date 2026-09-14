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


def _record(action: str, resource: str, region: str, extra: str = "") -> None:
    prefix = "[DRY-RUN] Would delete" if DRY_RUN else "Deleting"
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
                _record(f"EC2 instance ({action})", iid, region, inst.get("InstanceType", ""))
                targets.append(iid)
    if targets and not DRY_RUN:
        if STOP_EC2:
            ec2.stop_instances(InstanceIds=targets)
        else:
            ec2.terminate_instances(InstanceIds=targets)


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
    addresses = ec2.describe_addresses()["Addresses"]
    for addr in addresses:
        # An EIP in use (attached to an instance) does not incur a separate charge.
        if addr.get("AssociationId"):
            continue
        if _tags_protect(addr.get("Tags")):
            continue
        alloc = addr.get("AllocationId")
        public_ip = addr.get("PublicIp", "")
        _record("unassociated Elastic IP", public_ip, region)
        if not DRY_RUN and alloc:
            try:
                ec2.release_address(AllocationId=alloc)
            except ClientError as e:
                logger.warning("Failed to release Elastic IP %s: %s", public_ip, e)


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

    # Standalone DB instances
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            if _tags_protect(db.get("TagList")):
                continue
            dbid = db["DBInstanceIdentifier"]
            _record("RDS instance", dbid, region, db.get("DBInstanceClass", ""))
            if not DRY_RUN:
                try:
                    if db.get("DeletionProtection"):
                        rds.modify_db_instance(
                            DBInstanceIdentifier=dbid, DeletionProtection=False, ApplyImmediately=True
                        )
                    rds.delete_db_instance(
                        DBInstanceIdentifier=dbid, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
                    )
                except ClientError as e:
                    logger.warning("Failed to delete RDS instance %s: %s", dbid, e)

    # Aurora clusters
    for page in rds.get_paginator("describe_db_clusters").paginate():
        for cluster in page["DBClusters"]:
            if _tags_protect(cluster.get("TagList")):
                continue
            cid = cluster["DBClusterIdentifier"]
            _record("RDS cluster", cid, region, cluster.get("Engine", ""))
            if not DRY_RUN:
                try:
                    if cluster.get("DeletionProtection"):
                        rds.modify_db_cluster(
                            DBClusterIdentifier=cid, DeletionProtection=False, ApplyImmediately=True
                        )
                    rds.delete_db_cluster(DBClusterIdentifier=cid, SkipFinalSnapshot=True)
                except ClientError as e:
                    logger.warning("Failed to delete RDS cluster %s: %s", cid, e)


def clean_ecs(session: boto3.Session, region: str) -> None:
    ecs = session.client("ecs", region_name=region)
    for page in ecs.get_paginator("list_clusters").paginate():
        for cluster_arn in page["clusterArns"]:
            # Scale services to zero and delete them, then delete the cluster.
            for svc_page in ecs.get_paginator("list_services").paginate(cluster=cluster_arn):
                for svc_arn in svc_page["serviceArns"]:
                    _record("ECS service", svc_arn, region)
                    if not DRY_RUN:
                        try:
                            ecs.delete_service(cluster=cluster_arn, service=svc_arn, force=True)
                        except ClientError as e:
                            logger.warning("Failed to delete ECS service %s: %s", svc_arn, e)
            _record("ECS cluster", cluster_arn, region)
            if not DRY_RUN:
                try:
                    ecs.delete_cluster(cluster=cluster_arn)
                except ClientError as e:
                    logger.warning("Failed to delete ECS cluster %s: %s", cluster_arn, e)


def clean_eks(session: boto3.Session, region: str) -> None:
    eks = session.client("eks", region_name=region)
    for page in eks.get_paginator("list_clusters").paginate():
        for name in page["clusters"]:
            # Node groups must be deleted before the cluster.
            for ng_page in eks.get_paginator("list_nodegroups").paginate(clusterName=name):
                for ng in ng_page["nodegroups"]:
                    _record("EKS node group", f"{name}/{ng}", region)
                    if not DRY_RUN:
                        try:
                            eks.delete_nodegroup(clusterName=name, nodegroupName=ng)
                        except ClientError as e:
                            logger.warning("Failed to delete EKS node group %s: %s", ng, e)
            _record("EKS cluster", name, region)
            if not DRY_RUN:
                try:
                    eks.delete_cluster(name=name)
                except ClientError as e:
                    logger.warning("Failed to delete EKS cluster %s: %s", name, e)


def clean_elasticache(session: boto3.Session, region: str) -> None:
    ec = session.client("elasticache", region_name=region)
    for page in ec.get_paginator("describe_cache_clusters").paginate():
        for cluster in page["CacheClusters"]:
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
        "SUMMARY - resources that WOULD be deleted (dry run):"
        if DRY_RUN
        else "SUMMARY - resources that were deleted:"
    )
    logger.info("=" * 72)
    logger.info(header)
    logger.info("=" * 72)
    if not _actions:
        logger.info("Nothing to delete - no billable resources found.")
        return
    for i, action in enumerate(_actions, start=1):
        logger.info("%3d. %s", i, action)
    logger.info("-" * 72)
    logger.info("Total: %d resource(s).", len(_actions))


def _build_report() -> tuple[str, str]:
    """Return the (subject, body) of the cleanup report email."""
    if DRY_RUN:
        subject = f"[DRY RUN] Sandbox cleanup - {len(_actions)} resource(s) would be deleted"
        header = "The following resources WOULD be deleted (dry run):"
    else:
        subject = f"Sandbox cleanup - {len(_actions)} resource(s) deleted"
        header = "The following resources were deleted:"

    if _actions:
        lines = [f"{i:3d}. {action}" for i, action in enumerate(_actions, start=1)]
        body = "\n".join([header, "", *lines, "", f"Total: {len(_actions)} resource(s)."])
    else:
        body = "Nothing to delete - no billable resources found."

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
