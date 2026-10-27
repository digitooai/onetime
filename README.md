# onetime

Jednorázové sdílení hesel a souborů. Odkaz jde otevřít jen jednou — po přečtení
se obsah smaže. Bez registrace, bez účtu.

Běží na **[onetime.digitoo.ai](https://onetime.digitoo.ai)**.

---

## Jak to funguje

Odkaz má tvar `https://onetime.digitoo.ai/s/<id>#<klíč>`. Část za `#` je
**fragment**, který prohlížeč nikdy neposílá na server. Z toho plyne celá
bezpečnostní vlastnost služby:

- **Dump databáze sám o sobě nestačí.** Šifrovací klíč se odvozuje z fragmentu,
  master klíče serveru a případného hesla navíc. Fragment se nikde neukládá,
  takže kdo má databázi i master klíč, pořád nemá čím dešifrovat.
- **Náhledoví roboti nemají co spálit.** Slack, Teams a Outlook si odkazy
  otevírají samy, aby ukázaly náhled — ale bez fragmentu nemají co odeslat.
  `GET /s/<id>` vrátí jen prázdnou stránku; obsah se zpřístupní až po
  explicitním potvrzení.
- **Heslo navíc se nikde neukládá, ani jako hash.** Ověřuje se tím, že s ním
  sedí autentizační tag na zabaleném datovém klíči. V databázi tedy není nic,
  co by šlo offline lámat.

Podrobněji: [`docs/CRYPTO.md`](docs/CRYPTO.md) · [`docs/RUNBOOK.md`](docs/RUNBOOK.md)

## Pro AI agenty

Kompletní návod pro agenty je na **`/llms.txt`** — jeden plain-text soubor
s hotovými příkazy. Nasměrujte na něj agenta a nic dalšího nepotřebuje.

Doporučený vzor: **server heslo vygeneruje a agent ho nikdy neuvidí.**

```bash
curl -fsS -X POST https://onetime.digitoo.ai/api/v1/generate \
  -H 'Accept: text/plain' -d length=24 -d ttl=14d
# https://onetime.digitoo.ai/s/Ky3fRp8mQz2wLd7vXn4bTa#8Qd2...
```

Na terminál se vypíše jen odkaz. Heslo neexistuje na stroji agenta, není
v argv, není v shell history a hlavně **není v transkriptu agenta** — což je
u AI nástrojů ta skutečná trvalá kopie, na kterou se často zapomíná. Agenti
běží v neinteraktivním shellu, kde se `~/.bash_history` ani nepíše; každý
příkaz i jeho výstup se ale ukládá do transkriptu a posílá poskytovateli
modelu. Vypnutí historie proti tomu nepomůže. Jediná spolehlivá obrana je
hodnotu vůbec nedostat do kontextu.

Když hodnota vzniká jinde, pošlete ji přes rouru — nikdy v argumentu:

```bash
terraform output -raw db_password | curl -fsS --data-binary @- \
  -H 'Content-Type: text/plain' -H 'Accept: text/plain' \
  https://onetime.digitoo.ai/api/v1/secret
```

Soubor streamujte přes `-T` (nikoliv `--data-binary @soubor`, který ho celý
načte do paměti curlu):

```bash
curl -fsS -T ./kubeconfig.yaml -H 'Accept: text/plain' \
  'https://onetime.digitoo.ai/api/v1/secret/file?filename=kubeconfig.yaml'
```

Strojově čitelná specifikace: `/api/v1/openapi.json`

## Vývoj

```bash
make run            # spustí Redis v Dockeru a server na :8080
make test           # unit a integrační testy
make test-race      # totéž s detektorem souběhu
make lint           # golangci-lint
make image          # sestaví kontejnerový obraz
scripts/doctest.sh  # protáhne příkazy z llms.txt proti běžící instanci
```

Potřebujete Go 1.24+ a Docker. Master klíč pro lokální vývoj vygenerujete
příkazem `make keygen`.

Frontend nemá build krok — jsou to Go šablony a statické CSS/JS vložené do
binárky přes `go:embed`. Za tři roky se `npm ci` nerozbije, protože tu žádné
`npm` není.

## Architektura

```
cmd/onetime/            serve, healthcheck, gc, keygen
internal/
  crypto/               formát úložiště: keyring, HKDF/Argon2id, AES-256-GCM STREAM
  store/                Redis; lua/claim_secret.lua je jediné místo, kde se spaluje
  blob/                 šifrované soubory na svazku + garbage collector
  secret/               doménová logika: co a kdy se smí odhalit
  ratelimit/            GCRA nad Redisem, identita klienta jako HMAC z IP
  httpx/                middleware, bezpečnostní hlavičky, anti-prefetch, RFC 9457
  api/                  REST rozhraní
  web/                  serverem renderované stránky
  i18n/                 katalog CS/EN
web/                    šablony a statické soubory (embedované)
deploy/helm/onetime/    Helm chart
```

Data se ukládají do Redisu (metadata a krátké texty) a na svazek (soubory).
Pořadí zápisu je záměrné: **nejdřív soubor, pak Redis.** Opačné pořadí by
vytvořilo záznam ukazující na neexistující soubor, což selže v nejhorší možný
okamžik — když si příjemce jde pro obsah. Takhle je nejhorším výsledkem
osiřelý soubor, který garbage collector tiše uklidí.

## Provoz

```bash
helm install onetime oci://ghcr.io/digitooai/charts/onetime \
  --namespace onetime --create-namespace \
  --set masterKey.existingSecret=onetime-master-key \
  --set ingress.host=onetime.digitoo.ai
```

Jeden pod, jedno PVC, Redis jako sidecar na `127.0.0.1`. Master klíč se
konfiguruje jako **keyring**, aby rotace nebyla destruktivní:

```
ONETIME_MASTER_KEYS="v2:<nový>,v1:<starý>"
```

První položka se používá pro zápis, ostatní pro čtení starších záznamů. Starou
položku odstraňte teprve až vyprší všechny secrety pod ní zapsané — jinak se
stanou nečitelnými. Metrika `onetime_decrypt_failures_total{reason="unknown_key_id"}`
je na to alert.

**Zálohy se záměrně nedělají.** Obnova ze zálohy by vzkřísila už spálené
secrety a rozšířila dopad případného úniku z dnů (TTL) na týdny (retence
záloh). Jediná nenahraditelná věc je master keyring — ten patří do password
manageru.

## Licence

Apache-2.0
