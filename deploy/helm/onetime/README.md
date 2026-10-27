# onetime

One-time secret and file sharing — single-use links, encrypted at rest, self-destructing.

```
helm install onetime oci://ghcr.io/fortionnet/charts/onetime \
  --namespace onetime --create-namespace \
  --set config.baseURL=https://onetime.fortion.cloud \
  --set ingress.host=onetime.fortion.cloud \
  --set masterKey.existingSecret=onetime-master-key
```

---

## Before you install

### 1. Create the master keyring

The keyring encrypts every stored secret. **Lose it and every stored secret is
gone — there is no recovery path.** Create it yourself and manage it like any
other production credential:

```bash
kubectl -n onetime create secret generic onetime-master-key \
  --from-literal=master.keys="v1:$(head -c 32 /dev/urandom | base64)"
```

Format is `v2:<base64 of 32 raw bytes>,v1:<base64 of 32 raw bytes>` — newest
first. The first entry encrypts new secrets; the rest exist only to decrypt old
ones. **Rotate by prepending, never by replacing.**

Then `--set masterKey.existingSecret=onetime-master-key`.

The chart also accepts `masterKey.value` (it creates the Secret for you — fine
for dev, CI and `helm test`, but the keyring then lives in your values file and
in Helm's release Secret in plaintext) and `masterKey.autoGenerate`
(**do not use under ArgoCD** — see the warning below).

### 2. Check your ingress controller allows snippets

The Ingress uses `nginx.ingress.kubernetes.io/configuration-snippet` to set
`Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex`. ingress-nginx 1.9+
rejects that annotation unless the controller runs with
`allow-snippet-annotations: true`. Without it the Ingress is still admitted and
the headers are **silently missing** — and since the one-time link travels in
the URL path, `Referrer-Policy` is doing real work. Set
`ingress.overrideAnnotations` if you need a different controller.

### 3. Set `config.trustedProxies`

Leave it empty and every request is attributed to the ingress controller's pod
IP, so the per-IP daily quota and the passphrase throttle are shared by all
your users at once. Set it to your ingress controller's pod CIDR.

---

## Design decisions that are not negotiable

These are the ones that cost real downtime or real data when they are wrong.

| Decision | Why |
| --- | --- |
| **`replicaCount` is fixed at 1** (enforced by `values.schema.json`) | The blob store is a ReadWriteOnce volume and the GC/reconcile loops assume a single writer. A second replica gives you a Multi-Attach error plus two GC loops racing over the same blobs — not HA. |
| **`strategy` is derived from `persistence.enabled`**, not a knob | RollingUpdate against an RWO volume deadlocks: the new pod cannot attach a volume still held by the old pod's node, and the rollout wedges until someone deletes a pod by hand. With persistence on you get `Recreate` (a few seconds of downtime); with it off, `RollingUpdate`. |
| **`podDisruptionBudget.enabled: false`** | At one replica, `minAvailable: 1` permanently blocks `kubectl drain` — node maintenance hangs until someone deletes the PDB. The only consistent alternative, `maxUnavailable: 1`, always allows the eviction, i.e. it is a no-op that only looks like protection. The template is kept for a future HA mode. |
| **Redis `maxmemory-policy noeviction`** | Every key is a live secret's metadata. Any `*-lru` policy would let memory pressure silently delete secrets whose links are still in someone's inbox — data loss with no error and no way to say which ones went. `noeviction` fails the write loudly instead, and the app returns 503. |
| **`velero.io/exclude-from-backup: "true"` on the PVC** | Backing up a one-time secret store is an anti-feature. A restore resurrects secrets users were told are gone, including ones already read. The durable thing here is the promise of deletion, not the bytes. |
| **`proxy-request-buffering: "off"`** | A security control, not a performance tweak. With buffering on, nginx spools the whole request body — up to 50 MiB of user plaintext — to disk on the ingress pod, on a filesystem the app does not control and never cleans up. |
| **`/tmp` is `emptyDir{medium: Memory}`** | `readOnlyRootFilesystem` needs a writable `/tmp`, and whatever transiently lands there is plaintext. Plaintext must not survive a power cut. Note this is **not** `ONETIME_TMP_DIR` (`/data/tmp`), which must be on the PVC because blob writes `rename()` from it into `/data/blobs`, and `rename()` cannot cross filesystems. |
| **`fsGroup: 65532` matches the image UID** | 65532 is `nonroot` in `gcr.io/distroless/static-debian12`. If they drift apart, the deploy looks fine and then the first upload fails with a bare "permission denied". |
| **An `init-fs` init container** | Two kubelet behaviours the distroless image cannot work around: `subPath` directories are created as `root:root 0755` *after* `fsGroup` is applied (so a non-root app cannot write into them), and Secret volumes get group-read ORed into their mode whenever `fsGroup` is set (so `defaultMode: 0400` lands as `0440`, which the app rejects at startup). The init container creates the directories and re-copies the keyring as uid 65532 with mode 0400. |
| **Liveness points at `/healthz`, never `/readyz`** | `/healthz` has no dependencies. Pointing liveness at a dependency check turns a 30-second Redis blip into a pod restart, which does not fix Redis and does kill every in-flight upload. |
| **`terminationGracePeriodSeconds: 90`** | Must outlast an in-flight 50 MiB transfer to a slow client, and must exceed `config.shutdownTimeout` (60s). Otherwise every deploy hands somebody a truncated file with no error. |
| **NetworkPolicy default-deny egress** | The app makes no outbound calls but DNS. A deny-all egress rule therefore costs nothing operationally and removes the exfiltration path after an RCE or a supply-chain compromise. |
| **Metrics on 9090, off the Ingress** | `/metrics` leaks secret counts, upload volumes and failure rates — a usage oracle over a privacy product. The Service exposes it for in-cluster scraping; the Ingress routes only 8080. |

### `masterKey.autoGenerate` and GitOps

`autoGenerate` preserves the key across upgrades with a `lookup` against the
live cluster. **`lookup` returns nothing during `helm template`, during
`--dry-run`, and therefore under ArgoCD and Flux**, which render manifests with
`helm template` and apply the result.

In those pipelines the chart does not find the existing Secret, generates a new
keyring, and the apply replaces the old one. The sync goes green, the pods
restart cleanly, nothing logs an error — and every secret stored before that
sync is permanently undecryptable. You find out hours later when a user reports
"unknown key id". Use `masterKey.existingSecret` under GitOps.

---

## Values

### Core

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `replicaCount` | int | `1` | Fixed at 1; schema enforces `maximum: 1`. |
| `image.registry` | string | `ghcr.io` | |
| `image.repository` | string | `fortionnet/onetime` | |
| `image.tag` | string | `""` | Defaults to `.Chart.AppVersion`. |
| `image.digest` | string | `""` | `sha256:...`. Wins over `tag`; the only reference that cannot be repointed under a running release. |
| `image.pullPolicy` | string | `IfNotPresent` | |
| `imagePullSecrets` | list | `[]` | |
| `nameOverride` / `fullnameOverride` | string | `""` | |
| `initImage.repository` | string | `busybox` | Shell + coreutils for the `init-fs` container. |
| `initImage.tag` | string | `1.37.0-musl` | |
| `serviceAccount.create` | bool | `true` | |
| `serviceAccount.automountServiceAccountToken` | bool | `false` | The app never calls the Kubernetes API. |
| `podAnnotations` / `podLabels` | object | `{}` | |

### Application config (`ONETIME_*`)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `config.baseURL` | string | `https://onetime.fortion.cloud` | **Required.** Origin used to build one-time links. Use `https://` — the secret id is in the URL path. |
| `config.listenPort` | int | `8080` | |
| `config.metricsPort` | int | `9090` | Never routed by the Ingress. |
| `config.defaultLang` | string | `cs` | `cs` or `en`. |
| `config.logLevel` | string | `info` | |
| `config.logFormat` | string | `json` | |
| `config.strictStartup` | bool | `true` | Refuse to start if the keyring file is group/world-readable. Requires `masterKey.hardenPermissions`. |
| `config.shutdownTimeout` | string | `60s` | Must stay below `terminationGracePeriodSeconds`. |
| `config.enableFiles` | bool | `true` | |
| `config.readOnly` | bool | `false` | Emergency brake: serve existing secrets, refuse new writes. |
| `config.rateLimitEnabled` | bool | `true` | |
| `config.trustedProxies` | list | `[]` | CIDRs whose `X-Forwarded-For` is trusted. Empty means all per-IP limits are charged to the ingress pod. |
| `config.limits.maxFileBytes` | int | `52428800` | 50 MiB. Keep in sync with `ingress.proxyBodySize`. |
| `config.limits.maxTextInlineBytes` | int | `102400` | Stored inline in Redis. |
| `config.limits.maxTextBytes` | int | `1048576` | |
| `config.limits.dailyBytesPerIP` | int | `524288000` | |
| `config.limits.totalStorageBytes` | int | `21474836480` | Keep `<= persistence.size`. |
| `config.limits.diskHighWatermarkPct` | int | `85` | Refuse uploads above this fill level. |
| `config.ttl.minDays` / `maxDays` / `defaultDays` | int | `1` / `30` / `14` | |
| `config.ttl.receiptExtra` | string | `168h` | How long the "it was opened" receipt outlives the secret. |
| `config.ttl.tombstone` | string | `24h` | Makes a second visit say "already opened" instead of "never existed". |
| `config.ttl.downloadTicket` | string | `5m` | |
| `config.ttl.downloadAttempts` | int | `3` | |
| `config.argon2.memoryKiB` | int | `19456` | OWASP floor. Schema refuses lower. |
| `config.argon2.time` | int | `2` | |
| `config.argon2.parallelism` | int | `1` | |
| `config.argon2.concurrency` | int | `4` | Worst-case memory is `memoryKiB * concurrency` (~76 MiB). |
| `config.passphrase.windowFails` | int | `5` | |
| `config.passphrase.window` | string | `20m` | |
| `config.passphrase.totalFails` | int | `20` | |
| `config.jobs.gcInterval` | string | `1m` | |
| `config.jobs.reconcileInterval` | string | `6h` | |
| `config.jobs.orphanGrace` | string | `1h` | |
| `config.extraEnv` | object | `{}` | Raw `ONETIME_*` passthrough. |

`ONETIME_DATA_DIR` (`/data/blobs`) and `ONETIME_TMP_DIR` (`/data/tmp`) are
**deliberately not exposed**. They must sit on the same filesystem, and making
them configurable is an invitation to split them across two volumes and find
out in production.

### Master key

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `masterKey.existingSecret` | string | `""` | **Recommended.** Secret you manage yourself. |
| `masterKey.existingSecretKey` | string | `master.keys` | |
| `masterKey.value` | string | `""` | Inline keyring; chart creates the Secret. Dev/CI only. |
| `masterKey.autoGenerate` | bool | `false` | **Never under ArgoCD.** See above. |
| `masterKey.hardenPermissions` | bool | `true` | Init container re-copies the keyring at mode 0400. Required when `config.strictStartup` is true. |
| `masterKey.mountPath` | string | `/run/secrets/onetime` | |
| `masterKey.fileName` | string | `master.keys` | |

### Redis

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `redis.mode` | string | `sidecar` | `sidecar` \| `external` \| `none`. |
| `redis.image.repository` | string | `valkey/valkey` | |
| `redis.image.tag` | string | `8-alpine` | |
| `redis.maxmemory` | string | `192mb` | Keep below `resources.redis.limits.memory`. |
| `redis.extraConfig` | list | `[]` | Appended to `redis.conf`. Cannot override `maxmemory-policy`. |
| `redis.command` | list | `[redis-server, /etc/redis/redis.conf]` | |
| `redis.livenessProbeCommand` | list | `[redis-cli, -h, 127.0.0.1, -p, "6379", ping]` | |
| `redis.external.url` | string | `""` | Required when `mode=external`. Do **not** embed the password here — use `existingPasswordSecret`. |
| `redis.external.db` | int | `0` | |
| `redis.external.existingPasswordSecret` | string | `""` | Mounted as a file, never an env var. |
| `redis.external.passwordKey` | string | `password` | |

With `mode=external` you must also add the endpoint to
`networkPolicy.extraEgress`; the chart fails the render if you do not, because
default-deny egress would otherwise leave the app permanently not-ready.

### Storage, networking, scheduling

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `persistence.enabled` | bool | `true` | Off = emptyDir, everything lost on restart. Also flips the strategy to RollingUpdate. |
| `persistence.existingClaim` | string | `""` | |
| `persistence.storageClass` | string | `""` | `-` means "no class". |
| `persistence.accessMode` | string | `ReadWriteOnce` | Single-writer only. |
| `persistence.size` | string | `20Gi` | |
| `persistence.annotations` | object | `{velero.io/exclude-from-backup: "true"}` | |
| `persistence.retain` | bool | `false` | Adds `helm.sh/resource-policy: keep` to the PVC. |
| `service.type` | string | `ClusterIP` | |
| `service.port` | int | `8080` | |
| `service.metricsPort` | int | `9090` | |
| `ingress.enabled` | bool | `true` | |
| `ingress.className` | string | `nginx` | |
| `ingress.host` | string | `onetime.fortion.cloud` | |
| `ingress.extraHosts` | list | `[]` | |
| `ingress.tls.enabled` | bool | `true` | |
| `ingress.tls.clusterIssuer` | string | `letsencrypt-prod` | cert-manager. `""` to skip. |
| `ingress.tls.secretName` | string | `""` | Defaults to `<fullname>-tls`. |
| `ingress.proxyBodySize` | string | `52m` | Must exceed `maxFileBytes` plus multipart overhead. |
| `ingress.proxyReadTimeout` / `proxySendTimeout` | int | `300` | |
| `ingress.annotations` | object | `{}` | Merged over the generated set. |
| `ingress.overrideAnnotations` | object | `{}` | Replaces the generated set entirely. |
| `resources.app` / `resources.redis` / `resources.init` | object | see `values.yaml` | No CPU limit on the app: Argon2 is a deliberate burn, and throttling it stretches latency past the ingress timeout. |
| `terminationGracePeriodSeconds` | int | `90` | |
| `nodeSelector` / `tolerations` / `affinity` / `topologySpreadConstraints` | | `{}` / `[]` | |
| `priorityClassName` | string | `""` | |
| `podDisruptionBudget.enabled` | bool | `false` | See the table above. |
| `networkPolicy.enabled` | bool | `true` | Default-deny both directions. |
| `networkPolicy.ingressControllerNamespaceSelector` | object | `ingress-nginx` | |
| `networkPolicy.monitoringNamespaceSelector` | object | `monitoring` | |
| `networkPolicy.dnsNamespaceSelector` | object | `kube-system` | |
| `networkPolicy.extraEgress` / `extraIngress` | list | `[]` | |

### Probes, security, observability

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `probes.startup.periodSeconds` / `failureThreshold` | int | `2` / `30` | Up to 60s to come up. |
| `probes.liveness.periodSeconds` | int | `10` | Targets `/healthz`. |
| `probes.readiness.periodSeconds` | int | `5` | Targets `/readyz` (Redis + volume). |
| `podSecurityContext` | object | `runAsUser/Group/fsGroup: 65532`, `fsGroupChangePolicy: OnRootMismatch`, `seccompProfile: RuntimeDefault` | |
| `containerSecurityContext` | object | `readOnlyRootFilesystem: true`, `drop: [ALL]`, `allowPrivilegeEscalation: false` | |
| `tmpDir.sizeLimit` | string | `64Mi` | Memory-backed `/tmp`. |
| `serviceMonitor.enabled` | bool | `false` | Needs Prometheus Operator CRDs. |
| `prometheusRule.enabled` | bool | `false` | |
| `prometheusRule.rules.*.enabled` / `.severity` | | | Per-alert toggles. |
| `extraVolumes` / `extraVolumeMounts` / `extraContainers` | list | `[]` | |
| `extraObjects` | list | `[]` | Extra manifests (e.g. an ExternalSecret for `masterKey.existingSecret`). Maps are rendered verbatim, strings go through `tpl`. |
| `tests.enabled` | bool | `true` | `helm test` pod. |

---

## Alerts

Enable with `prometheusRule.enabled=true`.

| Alert | Expression (shape) | Why it matters |
| --- | --- | --- |
| `OnetimeUnknownKeyID` | `increase(onetime_decrypt_failures_total{reason="unknown_key_id"}[5m]) > 0` | The loudest one. Live secrets are encrypted under a key id no longer in the keyring — usually a rotation that dropped an id, or `autoGenerate` under a `helm template` pipeline. Every occurrence is a permanently unreadable secret. Threshold is `> 0` because there is no acceptable rate. |
| `OnetimePassphraseBruteForce` | `sum(rate(onetime_lookup_total{result="bad_key"}[5m])) * 60 > 5` | Argon2 makes each guess expensive, so a sustained rate is an attack or a broken retry loop — and both burn the CPU budget every user shares. |
| `OnetimeVolumeAlmostFull` | PVC free `< 15 %` | The app refuses uploads at the 85 % watermark. There is no eviction to fall back on; blobs stay until their TTL. |
| `OnetimeRedisDown` | `onetime_redis_up == 0` for `2m` | No metadata store means no link can be created, resolved or burned. |
| `OnetimeSecretsDropped` | `onetime_secrets_active` falls below 50 % of its value 5 minutes ago | Expiry is gradual; a cliff means bulk deletion — a GC bug, a wiped volume, a `FLUSHDB`, or a restore from a stale snapshot. |

---

## Upgrading and rotating

```bash
# Rotate: prepend the new key, keep every old one.
NEW=$(head -c 32 /dev/urandom | base64)
OLD=$(kubectl -n onetime get secret onetime-master-key \
  -o jsonpath='{.data.master\.keys}' | base64 -d)
kubectl -n onetime create secret generic onetime-master-key \
  --from-literal=master.keys="v2:${NEW},${OLD}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n onetime rollout restart deploy/onetime
```

Then watch `onetime_decrypt_failures_total{reason="unknown_key_id"}`. Any
non-zero value means a key that still had live secrets was dropped.

Note that with `persistence.enabled=true` the strategy is `Recreate`, so every
upgrade is a brief full outage. That is intentional — see the table above.

## Uninstalling

```bash
helm uninstall onetime -n onetime
```

The PVC goes with it unless `persistence.retain=true`. A Secret created by
`masterKey.autoGenerate` is kept (`helm.sh/resource-policy: keep`), because it
is the only copy of the key that can read whatever data you kept.
