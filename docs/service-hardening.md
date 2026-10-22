# Conditional Service and Container Hardening Review

**Checked against linked primary sources:** 2026-10-22. Apply this module only
when a service, container, task definition, or workload configuration is in
scope. It is a read-only review; vendor-managed settings that cannot be
observed are `unknown` or vendor-owned limitations.

## Evidence to collect

Review the actual deployed configuration, rather than only a source manifest.
For each in-scope workload, collect redacted evidence for the effective UID,
privileged mode, Linux capabilities, host mounts, writable filesystem locations,
container-engine socket exposure, and effective cloud or task IAM permissions.
Compare the deployed revision or image digest with the reviewed configuration.

| Control | Evidence from deployed configuration | Result | Constraint, owner, and recheck trigger |
| --- | --- | --- | --- |
| Service/container UID | Effective runtime UID and configured user | `pass / finding / unknown` | `compatibility or vendor limit; role; event` |
| Privileged mode | Effective task/container privilege setting | `pass / finding / unknown` | `reason and owner` |
| Capabilities | Effective capability add/drop set | `pass / finding / unknown` | `required capability and review date` |
| Host mounts and engine socket | Mount source/type and socket exposure | `pass / finding / unknown` | `required path and owner` |
| Root filesystem | Read-only compatibility and explicit writable paths | `pass / finding / unknown` | `runtime paths and rollout plan` |
| Cloud/task IAM | Effective role and permissions boundary | `pass / finding / unknown` | `least-privilege review owner` |

AWS recommends non-root containers, no privileged mode, minimal capabilities,
and read-only root filesystems where compatible. Use the governing platform's
equivalent controls and confirm their effective deployed values. [Amazon ECS
security tasks for containers](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-tasks-containers.html)
For ECS, task-role permissions are delivered to the task's containers; distinguish
them from execution-role permissions and collect effective-policy evidence.
[Amazon ECS task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)

## Interpretation and approved changes

Record a finding when evidence proves that the actual configuration exceeds the
documented need. Record `unknown` when evidence is unavailable or inconclusive;
do not relabel it as excess privilege. A read-only root filesystem may require explicit writable
locations for temporary files, caches, sockets, uploads, or runtime state;
test those paths in an owner-authorized environment before an approved rollout.
Do not infer IAM permissions from a role name, source declaration, or intended
policy. Capture effective permissions and any platform-managed unknowns.

For an approved change, retain the authorizing record, compatibility and health
evidence, rollback method, deployed revision or digest, and a recheck trigger.
Use controlled tests only in environments authorized by the owner. Do not
publish mount paths, role identifiers, account identifiers, or configuration
exports that are not public-safe.
