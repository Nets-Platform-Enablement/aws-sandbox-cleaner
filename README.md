This Lambda, nicknamed Vorlon Planet Killer, deletes billable resources of the
supported types below from every enabled region of an account. It is intended
exclusively for sandbox use and is not suitable for production environments.

It does not remove every billable service in the account—only the resource
types listed here. Any other billable service will remain and must be cleaned
up separately.

## Supported resource types

- EC2 instances (terminated, or stopped when `STOP_EC2=true`)
- Unattached EBS volumes
- Elastic IPs
- NAT gateways
- Load balancers (ALB, NLB, and Classic ELB)
- RDS instances and Aurora clusters
- ECS services, tasks, and clusters
- EKS clusters, node groups, and Fargate profiles
- ElastiCache clusters and replication groups
- AMIs owned by the account and their backing EBS snapshots

Resources carrying any of the protection tag keys (`keep`, `protected`,
`do-not-delete` by default) are left untouched.
