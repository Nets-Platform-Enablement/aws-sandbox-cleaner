"""Sandbox cleanup Lambda.

Scans supported resource types in enabled regions. This is not a complete
account wipe; protected, managed and unsupported resources can retain charges.
Runs in DRY RUN mode by default: resources are only listed, not deleted.
STOP_EC2 defaults to true and also retains EKS clusters with EC2 capacity.

Deletion only happens when the DRY_RUN environment variable is explicitly set
to "false" (case-insensitive).
"""

import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _is_dry_run() -> bool:
    # Safe default: any value other than "false" means dry run.
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


# Tag keys that, when present, cause the resource to be left untouched.
PROTECT_TAG_KEYS = {
    k.strip()
    for k in os.environ.get("PROTECT_TAG_KEYS", "keep,protected,do-not-delete").split(
        ","
    )
    if k.strip()
}


DRY_RUN = _is_dry_run()

# When true, eligible running standalone EC2 instances are stopped rather than terminated.
STOP_EC2 = os.environ.get("STOP_EC2", "true").strip().lower() != "false"

# SNS topic that receives the cleanup report. Empty means notifications are off.
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "").strip()
SNS_MESSAGE_MAX_BYTES = 262144
SNS_PUBLISH_OVERHEAD_BYTES = 1024

# Summary of actions for reporting.
_actions: list[str] = []

# Failures encountered during the run. A non-empty list means the run is
# incomplete and some resources may still exist.
_failures: list[str] = []

# Check before API calls and paginator pages, leaving time for the SNS report.
_TIME_BUDGET_MS = 45_000


def _record(
    action: str, resource: str, region: str, extra: str = "", verb: str = "delete"
) -> None:
    if DRY_RUN:
        prefix = f"[DRY-RUN] Would {verb}"
    else:
        prefix = f"Accepted {verb} request for"
    msg = f"{prefix} {action} '{resource}' in region {region}"
    if extra:
        msg += f" ({extra})"
    logger.info(msg)
    _actions.append(msg)


def _record_failure(detail: str, *args) -> None:
    """Log and track every failure, including failures handled by a cleaner."""
    if args:
        detail = detail % args
    logger.warning(detail)
    _failures.append(detail)


def _tags_protect(tags: list[dict] | None) -> bool:
    if not tags:
        return False
    keys = {t.get("Key", "") for t in tags}
    return bool(keys & PROTECT_TAG_KEYS)


def _chunked(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2")
    resp = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in resp["Regions"]]


# --------------------------------------------------------------------------- #
# Per-resource cleaners. Each takes a boto3 session and a region.
# --------------------------------------------------------------------------- #


# Invocation-local caches are cleared at the start of handler().
_protection = {}
_pending: list[str] = []
_retained: list[str] = []
_context = None
_SNAPSHOT_MARKER = "sandbox-cleanup:pending-ami-delete"
_SDK_CONFIG = Config(
    connect_timeout=3,
    read_timeout=5,
    retries={"mode": "standard", "total_max_attempts": 2},
)


class TimeBudgetExceeded(RuntimeError):
    pass


def _check_time():
    if _time_is_up(_context):
        raise TimeBudgetExceeded("Lambda reporting reserve reached")


def _defer(message):
    logger.info("PENDING: %s", message)
    _pending.append(message)


def _retain(message):
    logger.info("RETAINED: %s", message)
    _retained.append(message)


class _GuardedPaginator:
    def __init__(self, paginator):
        self.paginator = paginator

    def paginate(self, **kwargs):
        pages = iter(self.paginator.paginate(**kwargs))
        while True:
            _check_time()
            try:
                page = next(pages)
            except StopIteration:
                return
            yield page


class _GuardedClient:
    def __init__(self, client):
        self.client = client

    def get_paginator(self, name):
        return _GuardedPaginator(self.client.get_paginator(name))

    def __getattr__(self, name):
        method = getattr(self.client, name)
        if not callable(method):
            return method

        def call(**kwargs):
            _check_time()
            if DRY_RUN and name.startswith(
                (
                    "delete_",
                    "stop_",
                    "terminate_",
                    "release_",
                    "disassociate_",
                    "deregister_",
                    "modify_",
                    "create_",
                )
            ):
                raise RuntimeError(f"Blocked mutation {name} during DRY_RUN")
            return method(**kwargs)

        return call


class _GuardedSession:
    def __init__(self, session):
        self.session = session
        self.clients = {}

    def client(self, service, region_name=None):
        _check_time()
        key = (service, region_name)
        if key not in self.clients:
            self.clients[key] = _GuardedClient(
                self.session.client(
                    service, region_name=region_name, config=_SDK_CONFIG
                )
            )
        return self.clients[key]


def _items(client, operation, key, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        for item in page[key]:
            _check_time()
            yield item


def _tag_map(tags):
    if isinstance(tags, dict):
        return tags
    return {
        t.get("Key", t.get("key", "")): t.get("Value", t.get("value", ""))
        for t in tags or []
    }


def _ecs_objects(ecs, operation, key, requested, **kwargs):
    response = getattr(ecs, operation)(**kwargs)
    if response.get("failures"):
        raise ValueError(f"{operation}: {response['failures']}")
    objects = response[key]
    arn_key = {"tasks": "taskArn", "containerInstances": "containerInstanceArn"}[key]
    if {o[arn_key] for o in objects} != set(requested):
        raise ValueError(
            f"{operation} omitted requested resources; protection is unknown"
        )
    return objects


class _Protection:
    """Read dependencies before any regional mutation; failures abort the region."""

    def __init__(self, session, region):
        self.region = region
        ec2 = session.client("ec2", region_name=region)
        self.instances = {
            i["InstanceId"]: i
            for reservation in _items(ec2, "describe_instances", "Reservations")
            for i in reservation["Instances"]
            if i["State"]["Name"] != "terminated"
        }
        self.volumes = {
            v["VolumeId"]: v for v in _items(ec2, "describe_volumes", "Volumes")
        }
        self.addresses = ec2.describe_addresses()["Addresses"]
        self.spot_requests = {
            request["SpotInstanceRequestId"]: request
            for request in _items(
                ec2, "describe_spot_instance_requests", "SpotInstanceRequests"
            )
            if request.get("SpotInstanceRequestId")
        }
        asg = session.client("autoscaling", region_name=region)
        self.groups = {
            g["AutoScalingGroupName"]: g
            for g in _items(asg, "describe_auto_scaling_groups", "AutoScalingGroups")
        }
        self.managed_ids = {
            i["InstanceId"]
            for g in self.groups.values()
            for i in g.get("Instances", [])
        }
        self.ecs = self._ecs(session, region)
        self.eks = self._eks(session, region)

    def instance_protected(self, instance):
        if _tags_protect(instance.get("Tags")):
            return True
        for mapping in instance.get("BlockDeviceMappings", []):
            vid = mapping.get("Ebs", {}).get("VolumeId")
            if vid and vid not in self.volumes:
                _defer(
                    f"EC2 {instance['InstanceId']} in {self.region}: volume {vid} protection is unknown"
                )
                return True
            if vid and _tags_protect(self.volumes[vid].get("Tags")):
                return True
        enis = {n["NetworkInterfaceId"] for n in instance.get("NetworkInterfaces", [])}
        return any(
            _tags_protect(a.get("Tags"))
            and (
                a.get("InstanceId") == instance["InstanceId"]
                or a.get("NetworkInterfaceId") in enis
            )
            for a in self.addresses
        )

    def _ecs(self, session, region):
        ecs = session.client("ecs", region_name=region)
        clusters = []
        for arn in _items(ecs, "list_clusters", "clusterArns"):
            tags = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
            protected = _tags_protect(_norm_ecs_tags(tags))
            services = list(_items(ecs, "list_services", "serviceArns", cluster=arn))
            for service in services:
                tags = ecs.list_tags_for_resource(resourceArn=service)["tags"]
                protected |= _tags_protect(_norm_ecs_tags(tags))
            tasks = []
            task_arns = list(_items(ecs, "list_tasks", "taskArns", cluster=arn))
            for batch in _chunked(task_arns, 100):
                tasks.extend(
                    _ecs_objects(
                        ecs,
                        "describe_tasks",
                        "tasks",
                        batch,
                        cluster=arn,
                        tasks=batch,
                        include=["TAGS"],
                    )
                )
            # Inspect service tasks BEFORE deleting their parent service.
            protected |= any(
                _tags_protect(_norm_ecs_tags(t.get("tags"))) for t in tasks
            )
            containers = []
            arns = list(
                _items(
                    ecs,
                    "list_container_instances",
                    "containerInstanceArns",
                    cluster=arn,
                )
            )
            for batch in _chunked(arns, 100):
                containers.extend(
                    _ecs_objects(
                        ecs,
                        "describe_container_instances",
                        "containerInstances",
                        batch,
                        cluster=arn,
                        containerInstances=batch,
                        include=["TAGS"],
                    )
                )
            for container in containers:
                protected |= _tags_protect(_norm_ecs_tags(container.get("tags")))
                iid = container.get("ec2InstanceId")
                if iid:
                    self.managed_ids.add(iid)
                    instance = self.instances.get(iid)
                    if instance is None:
                        _defer(
                            f"ECS cluster {arn} in {region}: backing instance {iid} unavailable"
                        )
                    protected |= instance is None or self.instance_protected(instance)
            clusters.append(
                {
                    "arn": arn,
                    "protected": protected,
                    "services": services,
                    "tasks": tasks,
                    "containers": containers,
                }
            )
        return clusters

    def _eks(self, session, region):
        eks = session.client("eks", region_name=region)
        clusters = []
        for name in _items(eks, "list_clusters", "clusters"):
            cluster = eks.describe_cluster(name=name)["cluster"]
            groups = [
                eks.describe_nodegroup(clusterName=name, nodegroupName=ng)["nodegroup"]
                for ng in _items(eks, "list_nodegroups", "nodegroups", clusterName=name)
            ]
            profiles = [
                eks.describe_fargate_profile(clusterName=name, fargateProfileName=fp)[
                    "fargateProfile"
                ]
                for fp in _items(
                    eks,
                    "list_fargate_profiles",
                    "fargateProfileNames",
                    clusterName=name,
                )
            ]
            protected = _dict_tags_protect(cluster.get("tags"))
            protected |= any(_dict_tags_protect(g.get("tags")) for g in groups)
            protected |= any(_dict_tags_protect(p.get("tags")) for p in profiles)
            ids = set()
            for ng in groups:
                for reference in ng.get("resources", {}).get("autoScalingGroups", []):
                    group = self.groups.get(reference["name"])
                    if group is None:
                        protected = True
                        _defer(
                            f"EKS {name} in {region}: backing ASG {reference['name']} unavailable"
                        )
                        continue
                    protected |= _tags_protect(group.get("Tags"))
                    ids.update(i["InstanceId"] for i in group.get("Instances", []))
            for iid, instance in self.instances.items():
                tags = _tag_map(instance.get("Tags"))
                if (
                    tags.get("eks:cluster-name") == name
                    or tags.get("aws:eks:cluster-name") == name
                    or f"kubernetes.io/cluster/{name}" in tags
                ):
                    ids.add(iid)
            self.managed_ids.update(ids)
            for iid in ids:
                instance = self.instances.get(iid)
                if instance is None:
                    _defer(
                        f"EKS cluster {name} in {region}: backing instance {iid} unavailable"
                    )
                protected |= instance is None or self.instance_protected(instance)
            if STOP_EC2 and (
                groups or ids or cluster.get("computeConfig", {}).get("enabled")
            ):
                protected = True
                _retain(f"EKS {name} in {region}: STOP_EC2 preserves its EC2 capacity")
            clusters.append(
                {
                    "cluster": cluster,
                    "protected": protected,
                    "groups": groups,
                    "profiles": profiles,
                }
            )
        return clusters

    def owned_by_retained_cluster(self, tags):
        tags = _tag_map(tags)
        eks_names = {c["cluster"]["name"] for c in self.eks if c["protected"]}
        ecs_names = {c["arn"].rsplit("/", 1)[-1] for c in self.ecs if c["protected"]}
        return (
            tags.get("aws:ecs:cluster-name") in ecs_names
            or any(
                tags.get(k) in eks_names
                for k in (
                    "eks:cluster-name",
                    "aws:eks:cluster-name",
                    "elbv2.k8s.aws/cluster",
                )
            )
            or any(f"kubernetes.io/cluster/{name}" in tags for name in eks_names)
        )

    def persistent_spot_request_id(self, instance):
        request_id = instance.get("SpotInstanceRequestId")
        request = self.spot_requests.get(request_id) if request_id else None
        if request and request.get("Type") == "persistent" and request.get(
            "State"
        ) in {"open", "active"}:
            return request_id
        return None


def _cancel_persistent_spot_request(ec2, protection, instance, region):
    request_id = protection.persistent_spot_request_id(instance)
    if not request_id:
        return True
    try:
        response = ec2.cancel_spot_instance_requests(
            SpotInstanceRequestIds=[request_id]
        )
    except (ClientError, BotoCoreError) as exc:
        _record_failure(
            f"cancel_spot_instance_requests failed for {request_id} in {region}: {exc}"
        )
        return False
    if not any(
        request.get("SpotInstanceRequestId") == request_id
        and request.get("State") in {"cancelled", "closed"}
        for request in response.get("CancelledSpotInstanceRequests", [])
    ):
        _record_failure(
            f"cancel_spot_instance_requests did not confirm {request_id} in {region}"
        )
        return False
    _record("Spot instance request", request_id, region, verb="cancel")
    return True


def clean_ec2_instances(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    protection = _protection[region]
    for iid, inst in protection.instances.items():
        _check_time()
        if protection.instance_protected(inst):
            _retain(f"EC2 {iid} in {region}: resource or attached child is protected")
            continue
        tags = _tag_map(inst.get("Tags"))
        if (
            iid in protection.managed_ids
            or any(
                k in tags
                for k in (
                    "aws:autoscaling:groupName",
                    "aws:ecs:cluster-name",
                    "eks:cluster-name",
                    "aws:eks:cluster-name",
                )
            )
            or any(k.startswith("kubernetes.io/cluster/") for k in tags)
        ):
            _retain(
                f"EC2 {iid} in {region}: managed capacity is retained by the EC2 pass"
            )
            continue
        state = inst["State"]["Name"]
        if STOP_EC2:
            if state != "running":
                continue
            if inst.get("RootDeviceType") != "ebs":
                _retain(f"EC2 {iid} in {region}: instance-store root cannot be stopped")
                continue
            operation, result_key, action = (
                "stop_instances",
                "StoppingInstances",
                "stop",
            )
            accepted_states = {"stopping", "stopped"}
        else:
            if state not in {"pending", "running", "stopping", "stopped"}:
                continue
            operation, result_key, action = (
                "terminate_instances",
                "TerminatingInstances",
                "terminate",
            )
            accepted_states = {"shutting-down", "terminated"}
        if DRY_RUN:
            _record("EC2 instance", iid, region, verb=action)
            continue
        # Isolate instances so a protected/stale instance cannot fail the whole batch.
        try:
            if action == "terminate" and not _cancel_persistent_spot_request(
                ec2, protection, inst, region
            ):
                continue
            response = getattr(ec2, operation)(InstanceIds=[iid])
            if not any(
                i.get("InstanceId") == iid
                and i.get("CurrentState", {}).get("Name") in accepted_states
                for i in response.get(result_key, [])
            ):
                _record_failure(f"{operation} did not confirm {iid} in {region}")
                continue
            _record("EC2 instance", iid, region, verb=action)
        except (ClientError, BotoCoreError) as exc:
            _record_failure(f"{operation} failed for {iid} in {region}: {exc}")


def clean_ebs_volumes(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": "status", "Values": ["available"]}]
    ):
        for vol in page["Volumes"]:
            # Never delete a volume still attached to an instance (e.g. a stopped one).
            if vol.get("Attachments"):
                continue
            if _tags_protect(vol.get("Tags")) or _protection[
                region
            ].owned_by_retained_cluster(vol.get("Tags")):
                continue
            vid = vol["VolumeId"]
            extra = f"{vol.get('Size')} GiB"
            if DRY_RUN:
                _record("unattached EBS volume", vid, region, extra)
            else:
                try:
                    ec2.delete_volume(VolumeId=vid)
                    _record("unattached EBS volume", vid, region, extra)
                except (ClientError, BotoCoreError) as e:
                    _record_failure("Failed to delete EBS volume %s: %s", vid, e)


def clean_elastic_ips(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    for addr in ec2.describe_addresses()["Addresses"]:
        _check_time()
        alloc = addr.get("AllocationId")
        if not alloc or _tags_protect(addr.get("Tags")):
            continue
        if (
            addr.get("AssociationId")
            or addr.get("NetworkInterfaceId")
            or addr.get("InstanceId")
            or addr.get("ServiceManaged")
        ):
            _retain(f"Elastic IP {alloc} in {region}: associated or service-managed")
            continue
        if DRY_RUN:
            _record("unassociated Elastic IP", alloc, region, verb="release")
        else:
            try:
                ec2.release_address(AllocationId=alloc)
                _record("unassociated Elastic IP", alloc, region, verb="release")
            except (ClientError, BotoCoreError) as exc:
                _record_failure(
                    f"Failed to release Elastic IP {alloc} in {region}: {exc}"
                )


def clean_nat_gateways(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    protected_ips = {
        a["AllocationId"]
        for a in _protection[region].addresses
        if a.get("AllocationId") and _tags_protect(a.get("Tags"))
    }
    for nat in _items(ec2, "describe_nat_gateways", "NatGateways"):
        if _tags_protect(nat.get("Tags")) or any(
            a.get("AllocationId") in protected_ips
            for a in nat.get("NatGatewayAddresses", [])
        ):
            continue
        nid = nat["NatGatewayId"]
        if nat["State"] == "deleting":
            _defer(f"NAT gateway {nid} in {region} is still deleting")
            continue
        if nat["State"] not in {"available", "pending", "failed"}:
            continue
        if DRY_RUN:
            _record("NAT gateway", nid, region)
        else:
            try:
                ec2.delete_nat_gateway(NatGatewayId=nid)
                _record("NAT gateway", nid, region)
                _defer(
                    f"NAT {nid} in {region}: release its EIP after asynchronous deletion completes"
                )
            except (ClientError, BotoCoreError) as exc:
                _record_failure(
                    f"Failed to delete NAT gateway {nid} in {region}: {exc}"
                )


def clean_load_balancers(session: boto3.Session, region: str) -> None:
    # ALB / NLB (ELBv2)
    elbv2 = session.client("elbv2", region_name=region)
    for lb in elbv2.get_paginator("describe_load_balancers").paginate():
        for entry in lb["LoadBalancers"]:
            arn = entry["LoadBalancerArn"]
            allocations = {
                a.get("AllocationId")
                for z in entry.get("AvailabilityZones", [])
                for a in z.get("LoadBalancerAddresses", [])
            }
            if any(
                a.get("AllocationId") in allocations and _tags_protect(a.get("Tags"))
                for a in _protection[region].addresses
            ):
                continue
            tags = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]["Tags"]
            if _tags_protect(tags) or _protection[region].owned_by_retained_cluster(
                tags
            ):
                continue
            if DRY_RUN:
                _record(
                    "load balancer",
                    entry["LoadBalancerName"],
                    region,
                    entry.get("Type", ""),
                )
            else:
                try:
                    elbv2.delete_load_balancer(LoadBalancerArn=arn)
                    _record(
                        "load balancer",
                        entry["LoadBalancerName"],
                        region,
                        entry.get("Type", ""),
                    )
                except (ClientError, BotoCoreError) as e:
                    _record_failure("Failed to delete load balancer %s: %s", arn, e)

    # Classic ELB
    elb = session.client("elb", region_name=region)
    for lb in elb.get_paginator("describe_load_balancers").paginate():
        for entry in lb["LoadBalancerDescriptions"]:
            name = entry["LoadBalancerName"]
            tags = elb.describe_tags(LoadBalancerNames=[name])["TagDescriptions"][0][
                "Tags"
            ]
            if _tags_protect(tags) or _protection[region].owned_by_retained_cluster(
                tags
            ):
                continue
            if DRY_RUN:
                _record("classic load balancer", name, region)
            else:
                try:
                    elb.delete_load_balancer(LoadBalancerName=name)
                    _record("classic load balancer", name, region)
                except (ClientError, BotoCoreError) as e:
                    _record_failure(
                        "Failed to delete classic load balancer %s: %s", name, e
                    )


def clean_rds(session: boto3.Session, region: str) -> None:
    rds = session.client("rds", region_name=region)

    # Standalone DB instances. Aurora members (those with a DBClusterIdentifier)
    # are owned by a cluster and handled in the cluster loop below, so that a
    # protected cluster is not emptied out here before its tags are checked.
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            if db.get("DBClusterIdentifier"):
                continue
            # Fetch tags explicitly so the protection check is independent of Describe output.
            tags = _rds_tags(rds, db["DBInstanceArn"])
            if tags is None or _tags_protect(tags):
                continue
            dbid = db["DBInstanceIdentifier"]
            if db.get("DBInstanceStatus") == "deleting":
                _defer(f"RDS instance {dbid} in {region} is deleting")
                continue
            if DRY_RUN or _delete_db_instance(
                rds, dbid, db.get("DeletionProtection", False)
            ):
                _record("RDS instance", dbid, region, db.get("DBInstanceClass", ""))

    # Aurora and Multi-AZ DB clusters
    for page in rds.get_paginator("describe_db_clusters").paginate():
        for cluster in page["DBClusters"]:
            tags = _rds_tags(rds, cluster["DBClusterArn"])
            if tags is None or _tags_protect(tags):
                continue
            _clean_db_cluster(rds, cluster, region)


def _rds_tags(rds, arn: str) -> list[dict] | None:
    """Read authoritative tag data explicitly for each resource."""
    try:
        return rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    except (ClientError, BotoCoreError) as e:
        _record_failure("Failed to read RDS tags for %s: %s", arn, e)
        return None


def _delete_db_instance(rds, dbid: str, deletion_protection: bool) -> bool:
    """Request deletion; defer protection changes instead of waiting in Lambda."""
    try:
        if deletion_protection:
            rds.modify_db_instance(
                DBInstanceIdentifier=dbid,
                DeletionProtection=False,
                ApplyImmediately=True,
            )
            _defer(
                f"RDS instance {dbid}: deletion protection change requested; recheck next run"
            )
            return False
        rds.delete_db_instance(
            DBInstanceIdentifier=dbid,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
        return True
    except (ClientError, BotoCoreError) as exc:
        _record_failure(f"Failed to delete RDS instance {dbid}: {exc}")
        return False


def _clean_db_cluster(rds, cluster: dict, region: str) -> None:
    cid = cluster["DBClusterIdentifier"]
    members = []
    for member in cluster.get("DBClusterMembers", []):
        mid = member["DBInstanceIdentifier"]
        response = rds.describe_db_instances(DBInstanceIdentifier=mid)["DBInstances"]
        if len(response) != 1 or response[0]["DBInstanceIdentifier"] != mid:
            raise ValueError(f"RDS member {mid}: protection cannot be verified")
        desc = response[0]
        tags = _rds_tags(rds, desc["DBInstanceArn"])
        if tags is None or _tags_protect(tags):
            _retain(
                f"RDS cluster {cid} in {region}: a member is protected or tags unavailable"
            )
            return
        members.append(desc)
    if cluster.get("Status") == "deleting":
        _defer(f"RDS cluster {cid} in {region} is deleting")
        return
    if DRY_RUN:
        if str(cluster.get("Engine", "")).startswith("aurora"):
            for member in members:
                _record("RDS cluster member", member["DBInstanceIdentifier"], region)
        _record("RDS cluster", cid, region, cluster.get("Engine", ""))
        return
    try:
        # Disable protection on the cluster BEFORE touching its Aurora members.
        if cluster.get("DeletionProtection"):
            rds.modify_db_cluster(
                DBClusterIdentifier=cid, DeletionProtection=False, ApplyImmediately=True
            )
            _defer(
                f"RDS cluster {cid} in {region}: recheck deletion protection next run"
            )
            return
        if str(cluster.get("Engine", "")).startswith("aurora") and members:
            for member in members:
                mid = member["DBInstanceIdentifier"]
                if member.get("DBInstanceStatus") == "deleting":
                    continue
                if _delete_db_instance(
                    rds, mid, member.get("DeletionProtection", False)
                ):
                    _record("RDS cluster member", mid, region)
            _defer(
                f"RDS cluster {cid} in {region}: waiting for Aurora members to disappear"
            )
            return
        # Multi-AZ DB cluster members must be deleted through DeleteDBCluster.
        rds.delete_db_cluster(
            DBClusterIdentifier=cid, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
        _record("RDS cluster", cid, region, cluster.get("Engine", ""))
    except (ClientError, BotoCoreError) as exc:
        _record_failure(f"Failed to delete RDS cluster {cid} in {region}: {exc}")


def _request(client, operation, kind, identity, region, verb="delete", **kwargs):
    """One mutation with uniform dry-run and error handling."""
    _check_time()
    if DRY_RUN:
        _record(kind, identity, region, verb=verb)
        return True
    try:
        response = getattr(client, operation)(**kwargs)
        if response.get("Return") is False or response.get("failures"):
            _record_failure(
                f"{operation} failed for {identity} in {region}: {response}"
            )
            return False
        _record(kind, identity, region, verb=verb)
        return True
    except (ClientError, BotoCoreError) as exc:
        _record_failure(f"{operation} failed for {identity} in {region}: {exc}")
        return False


def clean_ecs(session: boto3.Session, region: str) -> None:
    ecs = session.client("ecs", region_name=region)
    for cluster in _protection[region].ecs:
        arn = cluster["arn"]
        if cluster["protected"]:
            _retain(f"ECS cluster {arn} in {region}: cluster or child is protected")
            continue
        for service in cluster["services"]:
            _request(
                ecs,
                "delete_service",
                "ECS service",
                service,
                region,
                cluster=arn,
                service=service,
                force=True,
            )
        active_tasks = [t for t in cluster["tasks"] if t.get("lastStatus") != "STOPPED"]
        for task in active_tasks:
            if str(task.get("group", "")).startswith("service:"):
                continue
            _request(
                ecs,
                "stop_task",
                "ECS task",
                task["taskArn"],
                region,
                verb="stop",
                cluster=arn,
                task=task["taskArn"],
            )
        if not DRY_RUN and (cluster["services"] or active_tasks):
            _defer(
                f"ECS cluster {arn} in {region}: recheck services and tasks next run"
            )
            continue
        deregistered = True
        for container in cluster["containers"]:
            ci = container["containerInstanceArn"]
            deregistered &= _request(
                ecs,
                "deregister_container_instance",
                "ECS container instance",
                ci,
                region,
                verb="deregister",
                cluster=arn,
                containerInstance=ci,
                force=False,
            )
        if deregistered:
            _request(ecs, "delete_cluster", "ECS cluster", arn, region, cluster=arn)


def _norm_ecs_tags(tags: list[dict] | None) -> list[dict]:
    """ECS/EKS tags use lowercase keys; normalize to the {'Key': ...} form."""
    if not tags:
        return []
    return [{"Key": t.get("key", t.get("Key", ""))} for t in tags]


def clean_eks(session: boto3.Session, region: str) -> None:
    eks = session.client("eks", region_name=region)
    for entry in _protection[region].eks:
        cluster = entry["cluster"]
        name = cluster["name"]
        if entry["protected"]:
            _retain(
                f"EKS cluster {name} in {region}: cluster, child or EC2 capacity is retained"
            )
            continue
        if cluster.get("status") == "DELETING":
            _defer(f"EKS cluster {name} in {region} is deleting")
            continue
        for ng in entry["groups"]:
            ng_name = ng["nodegroupName"]
            if ng.get("status") == "DELETING":
                continue
            _request(
                eks,
                "delete_nodegroup",
                "EKS node group",
                f"{name}/{ng_name}",
                region,
                clusterName=name,
                nodegroupName=ng_name,
            )
        # AWS permits only one DELETING Fargate profile per cluster at a time.
        deleting = any(p.get("status") == "DELETING" for p in entry["profiles"])
        for profile in entry["profiles"]:
            if deleting and not DRY_RUN:
                break
            if profile.get("status") == "DELETING":
                continue
            fp = profile["fargateProfileName"]
            accepted = _request(
                eks,
                "delete_fargate_profile",
                "EKS Fargate profile",
                f"{name}/{fp}",
                region,
                clusterName=name,
                fargateProfileName=fp,
            )
            if accepted and not DRY_RUN:
                break
        if not DRY_RUN and (entry["groups"] or entry["profiles"]):
            _defer(
                f"EKS cluster {name} in {region}: waiting for node groups and profiles to disappear"
            )
            continue
        _request(eks, "delete_cluster", "EKS cluster", name, region, name=name)


def _dict_tags_protect(tags: dict | None) -> bool:
    """EKS tags are returned as a plain {key: value} mapping."""
    return bool(tags) and bool(set(tags) & PROTECT_TAG_KEYS)


def clean_elasticache(session: boto3.Session, region: str) -> None:
    ec = session.client("elasticache", region_name=region)

    # Redis/Valkey replication groups must be deleted as a whole; their member
    # clusters cannot be deleted individually with delete_cache_cluster.
    for page in ec.get_paginator("describe_replication_groups").paginate():
        for rg in page["ReplicationGroups"]:
            tags = _elasticache_tags(ec, rg.get("ARN"))
            if tags is None or _tags_protect(tags):
                continue
            rgid = rg["ReplicationGroupId"]
            if rg.get("Status") == "deleting":
                _defer(f"ElastiCache group {rgid} in {region} is deleting")
                continue
            # RetainPrimaryCluster=false also deletes member clusters, so a
            # protected member must preserve the whole group.
            if _replication_group_has_protected_member(ec, rg):
                logger.info(
                    "Skipping ElastiCache replication group %s: a member is protected",
                    rgid,
                )
                continue
            if DRY_RUN:
                _record("ElastiCache replication group", rgid, region)
            else:
                try:
                    ec.delete_replication_group(
                        ReplicationGroupId=rgid, RetainPrimaryCluster=False
                    )
                    _record("ElastiCache replication group", rgid, region)
                except (ClientError, BotoCoreError) as e:
                    _record_failure(
                        "Failed to delete ElastiCache replication group %s: %s", rgid, e
                    )

    # Standalone cache clusters. Members of a replication group are skipped
    # because they are removed together with the group above.
    for page in ec.get_paginator("describe_cache_clusters").paginate():
        for cluster in page["CacheClusters"]:
            if cluster.get("ReplicationGroupId"):
                continue
            tags = _elasticache_tags(ec, cluster.get("ARN"))
            if tags is None or _tags_protect(tags):
                continue
            cid = cluster["CacheClusterId"]
            if cluster.get("CacheClusterStatus") == "deleting":
                _defer(f"ElastiCache cluster {cid} in {region} is deleting")
                continue
            if DRY_RUN:
                _record("ElastiCache cluster", cid, region, cluster.get("Engine", ""))
            else:
                try:
                    ec.delete_cache_cluster(CacheClusterId=cid)
                    _record(
                        "ElastiCache cluster", cid, region, cluster.get("Engine", "")
                    )
                except (ClientError, BotoCoreError) as e:
                    _record_failure(
                        "Failed to delete ElastiCache cluster %s: %s", cid, e
                    )


def _elasticache_tags(ec, arn: str | None) -> list[dict] | None:
    """describe_* omits tags for ElastiCache; fetch them by ARN."""
    if not arn:
        _record_failure("Missing resource ARN; cannot verify protection tags")
        return None
    try:
        return ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    except (ClientError, BotoCoreError) as e:
        _record_failure("Failed to read ElastiCache tags for %s: %s", arn, e)
        return None


def _replication_group_has_protected_member(ec, rg: dict) -> bool:
    """True if any member cache cluster is protected. Fails closed when a
    member's tags cannot be read."""
    for mid in rg.get("MemberClusters", []):
        try:
            desc = ec.describe_cache_clusters(CacheClusterId=mid)["CacheClusters"][0]
        except (ClientError, BotoCoreError, IndexError) as e:
            _record_failure("Failed to describe ElastiCache member %s: %s", mid, e)
            return True
        tags = _elasticache_tags(ec, desc.get("ARN"))
        if tags is None or _tags_protect(tags):
            return True
    return False


def _image_snapshots(image):
    return {
        bdm["Ebs"]["SnapshotId"]
        for bdm in image.get("BlockDeviceMappings", [])
        if bdm.get("Ebs", {}).get("SnapshotId")
    }


def clean_amis(session: boto3.Session, region: str) -> None:
    ec2 = session.client("ec2", region_name=region)
    images = list(
        _items(
            ec2,
            "describe_images",
            "Images",
            Owners=["self"],
            IncludeDeprecated=True,
            IncludeDisabled=True,
        )
    )
    used_images = {i.get("ImageId") for i in _protection[region].instances.values()}
    # Preserve boot assets referenced by existing launch definitions, including
    # non-default versions. Missing tag/reference information fails closed.
    for template in _items(ec2, "describe_launch_templates", "LaunchTemplates"):
        for version in _items(
            ec2,
            "describe_launch_template_versions",
            "LaunchTemplateVersions",
            LaunchTemplateId=template["LaunchTemplateId"],
        ):
            iid = version.get("LaunchTemplateData", {}).get("ImageId")
            if iid and iid.startswith("resolve:ssm:"):
                _defer(
                    f"AMI cleanup in {region}: launch template has an unresolved SSM AMI reference"
                )
                return
            used_images.add(iid)
    asg = session.client("autoscaling", region_name=region)
    for config in _items(asg, "describe_launch_configurations", "LaunchConfigurations"):
        used_images.add(config.get("ImageId"))
    snapshots = {}
    required = sorted(set().union(*(_image_snapshots(i) for i in images)))
    for batch in _chunked(required, 1000):
        described = list(
            _items(ec2, "describe_snapshots", "Snapshots", SnapshotIds=batch)
        )
        if {s["SnapshotId"] for s in described} != set(batch):
            raise ValueError("Snapshot lookup omitted resources; protection is unknown")
        snapshots.update({s["SnapshotId"]: s for s in described})
    pending = list(
        _items(
            ec2,
            "describe_snapshots",
            "Snapshots",
            OwnerIds=["self"],
            Filters=[{"Name": f"tag:{_SNAPSHOT_MARKER}", "Values": ["true"]}],
        )
    )
    snapshots.update({s["SnapshotId"]: s for s in pending})
    candidates = {s["SnapshotId"] for s in pending}
    retained_ids = {
        i["ImageId"]
        for i in images
        if _tags_protect(i.get("Tags"))
        or i["ImageId"] in used_images
        or any(_tags_protect(snapshots[s].get("Tags")) for s in _image_snapshots(i))
    }
    retained_snapshots = set().union(
        *(_image_snapshots(i) for i in images if i["ImageId"] in retained_ids)
    )
    for image in images:
        iid = image["ImageId"]
        if iid in retained_ids:
            _retain(
                f"AMI {iid} in {region}: protected or referenced by compute/launch definitions"
            )
            continue
        own_snapshots = sorted(
            s
            for s in _image_snapshots(image)
            if snapshots[s].get("OwnerId") == image["OwnerId"]
            and s not in retained_snapshots
        )
        if not DRY_RUN and own_snapshots:
            # Mark BEFORE deregistration. Failed deletes can then be discovered on
            # later invocations even though the original AMI no longer exists.
            try:
                for batch in _chunked(own_snapshots, 1000):
                    ec2.create_tags(
                        Resources=batch,
                        Tags=[{"Key": _SNAPSHOT_MARKER, "Value": "true"}],
                    )
            except (ClientError, BotoCoreError) as exc:
                _record_failure(
                    f"Failed to mark snapshots for AMI {iid} in {region}: {exc}"
                )
                continue
        if _request(
            ec2, "deregister_image", "AMI", iid, region, verb="deregister", ImageId=iid
        ):
            candidates.update(own_snapshots)
    # A protected/failed AMI retains its snapshots. Rechecking references also
    # handles eventual consistency; later invocations retry marked snapshots.
    references = (
        retained_snapshots
        if DRY_RUN
        else set().union(
            *(
                _image_snapshots(i)
                for i in _items(
                    ec2,
                    "describe_images",
                    "Images",
                    Owners=["self"],
                    IncludeDeprecated=True,
                    IncludeDisabled=True,
                )
            )
        )
    )
    for sid in sorted(candidates):
        if _tags_protect(snapshots[sid].get("Tags")):
            continue
        if sid in references:
            if sid not in retained_snapshots:
                _defer(
                    f"Snapshot {sid} in {region}: still referenced by a registered AMI"
                )
            continue
        if DRY_RUN:
            _record("AMI snapshot", sid, region)
            continue
        try:
            ec2.delete_snapshot(SnapshotId=sid)
            _record("AMI snapshot", sid, region)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidSnapshot.NotFound":
                continue
            if code == "InvalidSnapshot.InUse":
                _defer(f"Snapshot {sid} in {region}: in use; marked for later retry")
            else:
                _record_failure(f"Snapshot {sid} deletion failed in {region}: {exc}")
        except BotoCoreError as exc:
            _record_failure(f"Snapshot {sid} deletion failed in {region}: {exc}")


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


def handler(event, context):
    global DRY_RUN, STOP_EC2, SNS_TOPIC_ARN, PROTECT_TAG_KEYS, _context
    # Refresh configuration and all state on every warm invocation.
    DRY_RUN = _is_dry_run()
    STOP_EC2 = os.environ.get("STOP_EC2", "true").strip().lower() != "false"
    SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "").strip()
    PROTECT_TAG_KEYS = {
        k.strip()
        for k in os.environ.get(
            "PROTECT_TAG_KEYS", "keep,protected,do-not-delete"
        ).split(",")
        if k.strip()
    }
    for values in (_actions, _failures, _pending, _retained, _protection):
        values.clear()
    _context = context
    raw_session = boto3.Session()
    session = _GuardedSession(raw_session)
    next_region = None
    try:
        regions = sorted(_enabled_regions(session))
        if regions:
            # Rotate daily to reduce starvation; this is not a durable checkpoint.
            start = datetime.now(timezone.utc).date().toordinal() % len(regions)
            requested = event.get("start_region") if isinstance(event, dict) else None
            if requested is not None:
                if requested not in regions:
                    raise ValueError(f"start_region {requested!r} is not enabled")
                start = regions.index(requested)
            regions = regions[start:] + regions[:start]
        for region in regions:
            next_region = region
            _check_time()
            try:
                _protection.clear()
                _protection[region] = _Protection(session, region)
            except (ClientError, BotoCoreError, ValueError, KeyError) as exc:
                _record_failure(
                    f"Skipped region {region}: protection preflight failed: {exc}"
                )
                continue
            for cleaner in REGIONAL_CLEANERS:
                _check_time()
                try:
                    cleaner(session, region)
                except TimeBudgetExceeded:
                    raise
                except Exception as exc:
                    logger.exception(
                        "Cleaner %s failed in %s", cleaner.__name__, region
                    )
                    _record_failure(
                        f"Cleaner {cleaner.__name__} failed in {region}: {exc}"
                    )
        next_region = None
    except TimeBudgetExceeded:
        _record_failure(
            f"Time budget exhausted at {next_region or 'region discovery'}; invoke again "
            "to revisit remaining work. No durable checkpoint is stored."
        )
    except Exception as exc:
        logger.exception("Cleanup failed")
        _record_failure(f"Cleanup failed: {exc}")
    finally:
        _context = None
    # The raw session can use the reserved reporting time without the work guard.
    _publish_report(raw_session)
    logger.info(
        "Done: %d accepted/planned actions, %d failures, %d pending, %d retained",
        len(_actions),
        len(_failures),
        len(_pending),
        len(_retained),
    )
    # Bound the synchronous response; full entries are logged as they occur.
    result = {
        "dry_run": DRY_RUN,
        "complete": not _failures and not _pending,
        "count": len(_actions),
        "failure_count": len(_failures),
        "pending_count": len(_pending),
        "retained_count": len(_retained),
        "next_region": next_region,
        "complete_meaning": "Supported scans finished without errors or deferred work, not an empty account.",
    }
    details = {
        "actions": _actions,
        "failures": _failures,
        "pending": _pending,
        "retained": _retained,
    }
    for key, values in details.items():
        result[key] = [v[:1000] for v in values[:100]]
    result["details_truncated"] = any(
        len(v) > 100 or any(len(s) > 1000 for s in v) for v in details.values()
    )
    return result


def _time_is_up(context) -> bool:
    """True when too little Lambda execution time remains to start more work."""
    try:
        return context.get_remaining_time_in_millis() < _TIME_BUDGET_MS
    except AttributeError:
        return False


def _build_report() -> tuple[str, str]:
    mode = "DRY RUN" if DRY_RUN else "LIVE"
    state = "INCOMPLETE" if _failures or _pending else "SCAN COMPLETE"
    subject = f"[{mode}] [{state}] Sandbox cleanup - {len(_actions)} action(s)"
    lines = [
        subject,
        "",
        "Live actions mean AWS accepted requests; deletion may still be in progress.",
        "Only supported resource types are scanned; retained resources may still incur charges.",
    ]
    if not _actions:
        lines.append("No eligible actions were recorded.")
    # Put failures first so a truncated SNS report cannot hide them behind actions.
    for label, values in (
        ("Failures", _failures),
        ("Pending / revisit", _pending),
        ("Actions", _actions),
        ("Retained", _retained),
    ):
        if values:
            lines.extend(["", f"{label} ({len(values)}):", *values])
    return subject[:99], "\n".join(lines)


def _publish_report(session: boto3.Session) -> None:
    """Send the cleanup report to SNS, if a topic is configured."""
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set - skipping notification.")
        return
    subject, body = _build_report()
    subject_bytes = len(subject.encode("utf-8"))
    max_body_bytes = max(
        SNS_MESSAGE_MAX_BYTES - subject_bytes - SNS_PUBLISH_OVERHEAD_BYTES,
        0,
    )
    body_bytes = body.encode("utf-8")
    if len(body_bytes) > max_body_bytes:
        suffix = "\n\n[truncated; full entries are in CloudWatch logs]"
        suffix_bytes = suffix.encode("utf-8")
        max_bytes = max(max_body_bytes - len(suffix_bytes), 0)
        if max_body_bytes > len(suffix_bytes):
            body = body_bytes[:max_bytes].decode("utf-8", errors="ignore") + suffix
        else:
            body = body_bytes[:max_body_bytes].decode("utf-8", errors="ignore")
    try:
        parts = SNS_TOPIC_ARN.split(":", 5)
        if (
            len(parts) != 6
            or parts[0] != "arn"
            or parts[2] != "sns"
            or not parts[3]
            or not parts[5]
        ):
            raise ValueError("SNS_TOPIC_ARN is not a valid SNS topic ARN")
        region = parts[3]
        sns = session.client("sns", region_name=region, config=_SDK_CONFIG)
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)
        logger.info("Published cleanup report to %s", SNS_TOPIC_ARN)
    except (ClientError, BotoCoreError, ValueError) as e:
        _record_failure("Failed to publish cleanup report to SNS: %s", e)
