# Provozní runbook

## Zálohování: záměrně ne

Redis AOF ani PVC se **nezálohují**. Není to opomenutí — záloha úložiště
jednorázových secretů je anti-featura:

- Obnova ze zálohy **vzkřísí už spálené secrety**. Uživatel, kterému služba
  slíbila „po přečtení se to smaže", má najednou obsah zpátky v oběhu.
- Dopad případného úniku se rozšíří z dnů (TTL, max 30) na týdny (retence záloh).

Na PVC je proto anotace `velero.io/exclude-from-backup: "true"`.

**Zálohuje se pouze:**

1. `values.production.yaml` → git (infra repo)
2. **master keyring** → password manager nebo SealedSecret v gitu
3. chart a image → ghcr.io (immutable tagy a digesty)

Master keyring je jediná nenahraditelná věc. Ztráta Redisu znamená ztrátu živých
secretů a je to přijaté SLO — uživatelům to UI říká otevřeně.

## Rotace master klíče

Díky keyringu je nedestruktivní. Nová položka jde **před** stávající:

```bash
NEW=$(kubectl -n onetime exec deploy/onetime -- onetime keygen v2 | head -1)
OLD=$(kubectl -n onetime get secret onetime-master-key \
        -o jsonpath='{.data.ONETIME_MASTER_KEYS}' | base64 -d)

kubectl -n onetime create secret generic onetime-master-key \
  --from-literal=ONETIME_MASTER_KEYS="${NEW},${OLD}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n onetime rollout restart deploy/onetime
```

Nové secrety se šifrují pod `v2`, staré se dál čtou pod `v1`.

**Kdy smět odstranit starou položku:** až po uplynutí `TTL_MAX` (30 dní)
plus rezerva, a jen když `onetime_decrypt_failures_total{reason="unknown_key_id"}`
je 24 hodin na nule.

**Co se stane při rotaci naslepo** (nahrazení celého keyringu místo připojení):
všechny živé secrety se stanou nedešifrovatelnými. Aplikace to zvládne bez pádu —
vrátí `410 Gone` a zaloguje `unknown_key_id`, uživatel dostane „odkaz už není
platný" místo stacktrace — ale data jsou nenávratně pryč. Aplikace na to při
startu upozorní hlasitým `ERROR`, pokud předtím aktivní klíč v keyringu chybí.

**Ztráta master klíče úplně:** data jsou pryč. Obnova trvá pět minut a spočívá
v tom, že se vygeneruje nový keyring, vyprázdní Redis a smažou bloby:

```bash
kubectl -n onetime exec deploy/onetime -c redis -- redis-cli FLUSHDB
kubectl -n onetime exec deploy/onetime -- rm -rf /data/blobs/
kubectl -n onetime rollout restart deploy/onetime
```

Právě proto je záloha klíče to jediné, co je kritické.

## Alerty a co s nimi

| Alert | Co se děje | Co udělat |
|---|---|---|
| `onetime_decrypt_failures_total{reason="unknown_key_id"} > 0` | **Rotace klíče proběhla špatně a právě přicházíte o data.** | Okamžitě vrátit chybějící položku do keyringu, pokud ji ještě někde máte. Každý další záznam pod ní je nečitelný natrvalo. |
| `rate(onetime_lookup_total{result="bad_key"}) > 5/min` | Někdo zkouší hádat odkazy. | Neškodné (256 bitů entropie), ale zkontrolovat zdroj a případně zúžit rate limit nebo blokovat na ingressu. |
| `onetime_redis_up == 0` po 2 min | Redis nedostupný. | Pod je unready a nedostává provoz. Zkontrolovat sidecar: `kubectl logs deploy/onetime -c redis`. |
| `onetime_secrets_active` propad > 50 % za 5 min | Pravděpodobná ztráta Redisu nebo AOF. | Zkontrolovat, jestli neproběhl neplánovaný restart nebo `FLUSHDB`. Data jsou pryč, obnova neexistuje. |
| volné místo na PVC < 15 % | Svazek se plní. | `onetime gc --force`, pak zvětšit PVC nebo snížit `maxTTL`. Nad 85 % se odmítají nové soubory (`507`), texty jdou dál. |
| `onetime_reaper_orphans_deleted_total` trvale roste | Bloby ztrácejí své záznamy. | Zkontrolovat, jestli Redis nerestartuje nebo neevictuje (`maxmemory-policy` musí být `noeviction`). |

## Havarijní scénáře

| Scénář | Dopad | Postup |
|---|---|---|
| Pod OOMKilled | výpadek ~20 s, AOF data zachová | Zvýšit `resources.limits.memory`. Zkontrolovat `onetime_payload_bytes` p99 — pokud roste, něco bufferuje místo streamování. Argon2id drží `ONETIME_ARGON2_CONCURRENCY × 19 MiB`. |
| PVC plné | `507` na upload | `kubectl exec deploy/onetime -- onetime gc --force`; zvětšit PVC, pokud to storageClass umí; snížit `maxTTL`. |
| Redis AOF poškozený | Redis nenastartuje, CrashLoop | `redis-check-aof --fix /data/redis/onetime.aof`. Když nepomůže, AOF smazat a restartovat — ztráta živých secretů je akceptovaná. |
| Ztráta node nebo PVC | totální ztráta živých secretů | `helm upgrade --install` jinam, PVC se vytvoří prázdné. Žádná obnova ze zálohy neexistuje ani se nemá dělat. |
| Regrese po deployi | | `helm rollback onetime`. Pozor: se `strategy: Recreate` to znamená druhý výpadek. PVC a Redis data zůstávají. |
| Podezření na kompromitaci | | 1. `helm upgrade --set app.readOnly=true` (zastaví nové) 2. `kubectl scale deploy/onetime --replicas=0` 3. triage z logů (`secret.revealed` + `client_ip`) 4. `FLUSHALL` + smazat bloby 5. **rotovat keyring kompletně**, bez starých položek 6. scale up |

## Ladění rate limitů

Limity se počítají **per klientská adresa**, a celá kancelář za jednou NAT bránou
je jedna adresa. Výchozí hodnoty (30 vytvoření za hodinu) sedí na veřejné
nasazení, kde každý návštěvník přichází ze své adresy — u firemního zákazníka
mohou být těsné.

Přenastavit jde bez rekompilace, formát je `"<za hodinu>/<burst>"`:

```yaml
config:
  rateLimits:
    createText: "500/50"
    reveal: "1000/100"
```

Prázdná hodnota znamená vestavěný default. Chybný zápis chart odmítne už při
renderu; kdyby se přesto dostal do env, aplikace ho zaloguje jako `ERROR`
a spadne zpět na default — jeden překlep nemá shodit službu.

Odpovídající proměnné: `ONETIME_RATELIMIT_CREATE_TEXT`, `_CREATE_FILE`,
`_GENERATE`, `_PEEK`, `_REVEAL`, `_DOWNLOAD`, `_RECEIPT`, `_BURN`, `_PAGE`.
Efektivní hodnoty se při startu vypisují do logu.

Ještě lepší než zvyšovat limity je nastavit `config.trustedProxies` na pod CIDR
ingress controlleru. Bez toho se totiž **všechny** požadavky připíšou adrese
ingress podu a jeden zákazník vyčerpá kvótu všem.

## Kill switch

`ONETIME_READ_ONLY=true` (nebo `--set app.readOnly=true`) odmítne vytváření
nových secretů a nechá čtení fungovat. Uživatel dostane stránku „Právě probíhá
údržba", ne chybu. Existující odkazy jdou dál otevřít.

`ONETIME_ENABLE_FILES=false` vypne jen soubory; texty fungují.

## Úklid osiřelých souborů

Osiřelý blob vznikne, když soubor na svazku existuje, ale jeho záznam v Redisu
ne. Příčiny: `FLUSHALL`, ztráta AOF, pád mezi zápisem souboru a zápisem do Redisu.

**Pořadí zápisu je záměrné:** nejdřív soubor (staging → `fsync` → atomický
`rename`), teprve pak Redis. Opačné pořadí by vytvořilo záznam ukazující na
neexistující soubor, což selže až ve chvíli, kdy si příjemce jde pro obsah.
Takhle je nejhorším výsledkem neškodný sirotek.

Collector běží ve dvou smyčkách:

- **sweep** (každou minutu) pracuje z plánu v Redisu → expirovaný nebo spálený
  soubor zmizí do minuty,
- **reconcile** (každých 6 h a při startu) prochází svazek a je autoritativní.
  Je to jediná věc, která umí uklidit po ztrátě Redisu, kdy je plán prázdný
  a všechno na disku je odpad. Grace perioda (1 h) brání smazání souboru, který
  se právě nahrává.

Ručně:

```bash
kubectl -n onetime exec deploy/onetime -- onetime gc
```

## Upgrade

1. Zkontrolovat `onetime_secrets_active` — ideálně upgradovat mimo špičku,
   protože `Recreate` znamená 10–20 s výpadku.
2. `helm upgrade --install onetime oci://ghcr.io/digitooai/charts/onetime \
   --version X.Y.Z -n onetime -f values.production.yaml --atomic --timeout 5m`
3. Ověřit: `curl -fsS https://onetime.digitoo.ai/readyz`, `/version` hlásí
   novou verzi, `onetime_secrets_active` se nepropadl.

AOF živé secrety přes restart zachová.

## Proč jeden pod

Architektura počítá s **jednou replikou**. PVC je `ReadWriteOnce` a Redis běží
jako sidecar na `127.0.0.1`, takže dva pody by se o svazek přetahovaly.
`values.schema.json` proto `replicaCount` omezuje na 1 a `strategy` se odvozuje
z `persistence.enabled`, aby to nikdo omylem nepřepnul na `RollingUpdate`
(což by skončilo `Multi-Attach error` a zaseknutým deployem).

Pro HA by bylo potřeba vytáhnout Redis ven (`redis.mode: external`) a přejít
z PVC na objektové úložiště. Chart pro to má připravené hodnoty, kód by
potřeboval jinou implementaci `blob.Store`.
