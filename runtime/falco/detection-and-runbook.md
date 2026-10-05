# Runtime detection: accounts-api credential theft

Threats: **T3** (attacker with code execution moving to credentials), **T4** (insider with `kubectl exec`). Source: `runtime/falco/accounts-api-rules.yaml`.

## The rule

Fires when any process **other than the service itself** reads the database credential file (`/var/run/secrets/db/`) inside an `accounts-api` pod.

```yaml
- list: accounts_api_expected_readers
  items: [accounts-api]            # REPLACE with the service's real process name

- rule: accounts-api DB credential read by unexpected process
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_read=true and fd.typechar='f'
    and container.id != host
    and k8s.ns.name = "accounts" and k8s.pod.label.app in (accounts-api, quarantine)
    and fd.name startswith /var/run/secrets/db/
    and not proc.name in (accounts_api_expected_readers)
  output: >
    accounts-api DB credential read by unexpected process
    (proc=%proc.name cmdline="%proc.cmdline" parent=%proc.pname user=%user.name file=%fd.name
    pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository:%container.image.tag container=%container.id)
  priority: CRITICAL
```

**Why this one:** it is specific to this workload (one known file, one known reader), so it should have almost no false positives, unlike a generic "shell in container" rule. It also lands on the crown jewel: the credential that unlocks customer data.

## Alert payload

Process name, full command line, parent process, user, file path, pod, namespace, image and tag, container ID. Enough to answer "what ran, from what, in which pod" without opening the cluster.

## Routing and owner

| Priority | Goes to | Who is woken |
|---|---|---|
| CRITICAL (this rule) | PagerDuty service `security-oncall` via falcosidekick | **Security on-call** (primary), platform on-call (secondary after 10 min without acknowledgement) |
| WARNING and below | Slack `#security-alerts` | Nobody paged |

Target: acknowledged within 5 minutes. An alert with no owner is telemetry, not a control.

## Responder runbook: first three steps

1. **Contain without destroying evidence.** Relabel the pod so it leaves the Service and the ReplicaSet starts a replacement, while the `quarantine-deny-all` NetworkPolicy cuts it off:
   `kubectl -n accounts label pod <pod> app=quarantine --overwrite`
   Do **not** delete the pod.
2. **Preserve evidence.** Save the Falco alert JSON, then:
   `kubectl -n accounts get pod <pod> -o yaml > pod.yaml`
   `kubectl -n accounts logs <pod> --all-containers > pod.log`
   Record the image digest. Take a node disk snapshot only if node-level compromise is suspected.
3. **Scope and rotate.** In CloudTrail, list `GetSecretValue` calls on the DB secret in the last 24 hours and check the database for sessions from the pod's IP. Treat the credential as stolen and run the emergency rotation (`docs/section6`, target under 10 minutes). If there is any sign of reaching the node, cordon it and escalate.

## Limits (honest)

- Detects reads of the credential file, not theft by a process the service itself is tricked into running (an attacker inside the service's own process looks like the expected reader).
- The secret is also in memory; this rule does not see memory reads.
- Not executed here: the rule and routing have not been run against a live Falco.
