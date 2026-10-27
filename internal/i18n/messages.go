// Package i18n holds the message catalog for the onetime web frontend.
//
// The catalog is a plain map of key to string, one map per language. Keys are
// hierarchical and dot-separated (create.h1, gate.cta, status.expired.title).
// Keys prefixed with "js." are the subset shipped to the browser by JSONFor.
//
// Czech is the default language and the source of truth: every key present in
// the Czech catalog must also exist in every other one, which is enforced by
// the package tests rather than by the type system.
package i18n

import (
	"encoding/json"
	"strings"

	"golang.org/x/text/language"
)

// DefaultLang is the language served when nothing better can be negotiated.
const DefaultLang = "cs"

// jsPrefix marks the catalog keys that are exported to the browser.
const jsPrefix = "js."

var supportedLangs = []string{"cs", "en"}

// matcher is only consulted after an exact base-language scan has failed, so
// its job is limited to salvaging regional or macrolanguage tags.
var matcher = language.NewMatcher([]language.Tag{
	language.Czech,   // index 0 — also the fallback for "no match"
	language.English, // index 1
})

var catalog = map[string]map[string]string{
	"cs": cs,
	"en": en,
}

// Supported returns the language codes the frontend can render, in a stable
// order with DefaultLang first.
func Supported() []string {
	out := make([]string, len(supportedLangs))
	copy(out, supportedLangs)
	return out
}

// IsSupported reports whether lang is one of the languages the frontend can
// render. Comparison is case-insensitive and tolerates surrounding space.
func IsSupported(lang string) bool {
	_, ok := Canonical(lang)
	return ok
}

// Canonical resolves lang to the exact code this package uses for it, or
// reports that it names no supported language.
//
// The returned string is one of this package's own constants rather than a
// reshaped copy of the argument. That distinction matters to callers that put
// the result into a URL: "EN" and "en" both name English, but only one of them
// is a path this service actually serves, and a caller that echoes back what it
// was given is building the URL out of request data instead of out of a fixed
// set.
func Canonical(lang string) (string, bool) {
	lang = normalize(lang)
	for _, l := range supportedLangs {
		if l == lang {
			return l, true
		}
	}
	return "", false
}

// T translates key into lang. An unknown language falls back to DefaultLang,
// an unknown key falls back to the Czech string and finally to the key itself,
// which makes a missing translation loud in the page instead of silent.
func T(lang, key string) string {
	if m, ok := catalog[normalize(lang)]; ok {
		if s, ok := m[key]; ok {
			return s
		}
	}
	if s, ok := catalog[DefaultLang][key]; ok {
		return s
	}
	return key
}

// Translator returns a lookup function bound to lang, suitable for handing to
// html/template as the .T value.
func Translator(lang string) func(string) string {
	l := normalize(lang)
	if !IsSupported(l) {
		l = DefaultLang
	}
	return func(key string) string { return T(l, key) }
}

// Match negotiates the language for a request. An explicit cookie wins, then
// the Accept-Language header (honouring q-values), then DefaultLang.
func Match(acceptLanguage, cookie string) string {
	if IsSupported(cookie) {
		return normalize(cookie)
	}

	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return DefaultLang
	}

	// ParseAcceptLanguage returns tags sorted by descending quality, so the
	// first supported base language is the caller's best supported choice.
	for _, tag := range tags {
		base, conf := tag.Base()
		if conf == language.No {
			continue
		}
		if IsSupported(base.String()) {
			return base.String()
		}
	}

	// Nothing matched outright; let x/text try harder (sr-Latn, zh-Hant, …).
	if _, idx, conf := matcher.Match(tags...); conf > language.No && idx < len(supportedLangs) {
		return supportedLangs[idx]
	}
	return DefaultLang
}

// JSONFor returns a JSON object with every catalog key prefixed by "js.", for
// embedding into the page as <script type="application/json" id="i18n">. Keys
// keep their prefix so that a JS lookup mirrors a Go one.
func JSONFor(lang string) string {
	l := normalize(lang)
	if !IsSupported(l) {
		l = DefaultLang
	}

	out := make(map[string]string, 128)
	for key := range catalog[DefaultLang] {
		if strings.HasPrefix(key, jsPrefix) {
			out[key] = T(l, key)
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func normalize(lang string) string {
	return strings.ToLower(strings.TrimSpace(lang))
}

// ---------------------------------------------------------------------------
// Czech — the source catalog.
// ---------------------------------------------------------------------------

// Two conventions this catalogue keeps to, because both are invisible in a
// diff and expensive to rediscover:
//
//   - Nothing is written in capitals. .kicker, .label-mono, .dl dt, .toc__title
//     and .table th are uppercased by CSS, so a value shouted here is shouted
//     twice — and a screen reader may spell it out letter by letter.
//   - The dash is the Czech one: an en dash with spaces around it. The English
//     catalogue below uses the em dash, which is that language's own habit.
//
// The catalogues also trip gosec's hardcoded-credential heuristic, which sees
// keys like "create.pass.label" or "gate.pass.placeholder" next to string
// literals and infers a password. They are user-interface copy: the words for
// "password" in two languages, on the labels of the fields a passphrase is
// typed into. No credential is stored anywhere in this package.
//
//nolint:gosec // G101: UI copy about passphrases, not a passphrase
var cs = map[string]string{
	// -- chrome ------------------------------------------------------------
	"site.name":        "onetime",
	"site.title":       "onetime – jednorázové odkazy na hesla a soubory",
	"site.description": "Pošlete heslo nebo soubor odkazem, který jde otevřít jen jednou. Po přečtení se obsah smaže. Bez registrace.",
	"site.brand_aria":  "Digitoo – digitoo.ai (otevře se v novém okně)",
	"site.home_aria":   "onetime – úvodní stránka",
	"a11y.skip":        "Přejít na obsah",
	"nav.aria":         "Hlavní navigace",
	"nav.how":          "Jak to funguje",
	"nav.api":          "API",
	"lang.switch_aria": "Přepnout na angličtinu",
	"lang.cs":          "CS",
	"lang.en":          "EN",
	"footer.privacy":   "Soukromí",
	"footer.nav_aria":  "Odkazy v patičce",
	"footer.operator":  "Provozuje Digitoo a.s., Pernerova 697/35, Karlín, 186 00 Praha",
	"footer.api":       "API",
	"footer.tagline":   "Jednorázové odkazy na hesla a soubory.",

	// -- create ------------------------------------------------------------
	"create.title":                "onetime – pošlete heslo, které se po přečtení smaže",
	"create.h1.pre":               "Pošlete heslo, které se po přečtení ",
	"create.h1.mark":              "smaže",
	"create.h1.post":              ".",
	"create.lead":                 "Heslo nemusí zůstat viset v chatu. Vložte ho sem a pošlete odkaz – po prvním otevření se obsah smaže. Bez registrace.",
	"create.form_aria":            "Vytvoření jednorázového odkazu",
	"create.tablist_aria":         "Typ obsahu",
	"create.tab.text":             "Text",
	"create.tab.file":             "Soubor",
	"create.textarea.label":       "Obsah, který chcete poslat",
	"create.textarea.placeholder": "Heslo, klíč nebo krátká zpráva",
	"create.textarea.hint":        "Zašifrujeme to u nás. Dešifrovací klíč skončí jen ve vašem odkazu, ne v databázi.",
	"create.file.drop":            "Přetáhněte soubor sem",
	"create.file.or":              "nebo",
	"create.file.pick":            "Vybrat soubor",
	"create.file.max":             "Maximálně",
	"create.file.remove":          "Odebrat soubor",
	"create.file.disabled":        "Posílání souborů je teď vypnuté. Text funguje dál.",
	"create.options.summary":      "Další možnosti",
	"create.ttl.label":            "Platnost odkazu",
	"create.ttl.d1":               "1 den",
	"create.ttl.d7":               "7 dní",
	"create.ttl.d14":              "14 dní",
	"create.ttl.d30":              "30 dní",
	"create.ttl.custom":           "Jiná…",
	"create.ttl.custom_label":     "Počet dní, %d až %d",
	"create.ttl.back":             "Zpět na výběr",
	"create.pass.label":           "Heslo navíc (nepovinné)",
	"create.pass.placeholder":     "Nepovinné",
	"create.pass.show":            "Zobrazit heslo",
	"create.pass.generate":        "Vygenerovat",
	"create.pass.hint":            "Pošlete ho příjemci jinou cestou – SMS nebo telefonem. Bez něj obsah neotevře a my mu ho nepřipomeneme. Po odeslání už heslo neuvidíte.",
	"create.submit":               "Vytvořit odkaz",
	"create.upload.aria":          "Průběh nahrávání souboru",
	"create.readonly":             "Právě probíhá údržba. Nové odkazy teď nejdou vytvořit.",
	"create.how.kicker":           "Jak to funguje",
	"create.how.h2.pre":           "Tři kroky. Žádná ",
	"create.how.h2.mark":          "registrace",
	"create.how.h2.post":          ".",
	"create.how.1.title":          "Vložíte obsah",
	"create.how.1.body":           "Heslo, klíč nebo soubor. Zašifrujeme ho a šifrovací klíč vložíme do odkazu – ne do databáze.",
	"create.how.2.title":          "Pošlete odkaz",
	"create.how.2.body":           "Chatem, e-mailem, jak chcete. Náhledy v Teams a Slacku obsah nesmažou – čekáme na kliknutí od člověka.",
	"create.how.3.title":          "Příjemce odkaz otevře",
	"create.how.3.body":           "Obsah se ukáže jednou a tím se z našeho serveru smaže. Podruhé už ho nikdo neotevře.",
	"create.result.title":         "Odkaz je připravený",
	"create.result.label":         "Jednorázový odkaz",
	"create.result.copy":          "Kopírovat odkaz",
	"create.result.pass.label":    "Heslo navíc – pošlete zvlášť",
	"create.result.pass.hint":     "Pošlete ho jinou cestou než odkaz. Znovu vám ho neukážeme.",
	"create.result.warn":          "Zkopírujte si odkaz teď. Znovu ho nezobrazíme – u sebe ho celý uložený nemáme.",

	// -- gate --------------------------------------------------------------
	"gate.title":             "Jednorázový odkaz · onetime",
	"gate.loading":           "Načítám…",
	"gate.h2.text":           "Někdo vám poslal heslo",
	"gate.h2.file":           "Někdo vám poslal soubor",
	"gate.lead":              "Obsah uvidíte jen jednou. Jakmile kliknete, z našeho serveru se smaže.",
	"gate.cta":               "Zobrazit obsah",
	"gate.cta_pass":          "Pokračovat",
	"gate.cta_hint":          "Klikněte, až si budete moct obsah rovnou uložit.",
	"gate.chip.text":         "Text",
	"gate.chip.file":         "Soubor",
	"gate.chip.protected":    "Chráněno heslem",
	"gate.why.summary":       "Proč musím klikat?",
	"gate.why.body":          "Teams, Slack, Outlook i WhatsApp si odkazy otevírají samy, aby k nim ukázaly náhled. Kdybychom obsah zobrazili rovnou, jejich robot by ho přečetl dřív než vy. Proto čekáme na kliknutí od skutečného člověka.",
	"gate.pass.h2":           "Odkaz je chráněný heslem",
	"gate.pass.lead":         "Odesílatel vám ho posílal jinou cestou – nejspíš SMS nebo telefonem.",
	"gate.pass.label":        "Heslo od odesílatele",
	"gate.pass.placeholder":  "Heslo od odesílatele",
	"gate.pass.cta":          "Zobrazit obsah",
	"gate.revealed.aria":     "Zobrazený obsah",
	"gate.revealed.copy":     "Kopírovat",
	"gate.revealed.warn":     "Uložte si obsah teď. Jakmile stránku zavřete, je pryč – jinde už nikde není.",
	"gate.revealed.loop":     "Potřebujete poslat něco zpátky?",
	"gate.revealed.loop_cta": "Vytvořit odkaz",
	"gate.file.download":     "Stáhnout soubor",
	"gate.file.downloaded":   "Staženo",
	"gate.file.inapp":        "V téhle aplikaci stahování často nefunguje. Když se soubor nestáhne, zkuste tlačítko znovu – stránku ale nezavírejte, soubor jinde není.",
	"gate.text.inapp":        "Jste v prohlížeči uvnitř aplikace – kopírování v něm často nefunguje. Když tlačítko nezabere, označte text prstem a zkopírujte ho ručně. Stránku nezavírejte, obsah jinde není.",
	"gate.noscript":          "Bez JavaScriptu obsah nezobrazíme. Zapněte ho a načtěte stránku znovu.",

	// -- receipt -----------------------------------------------------------
	"receipt.title":                 "Stav odkazu · onetime",
	"receipt.kicker":                "Stav odkazu",
	"receipt.loading":               "Načítám…",
	"receipt.state.new.title":       "Čeká na přečtení",
	"receipt.state.new.sub":         "Obsah si zatím nikdo nezobrazil.",
	"receipt.state.consumed.title":  "Přečteno",
	"receipt.state.consumed.sub":    "Obsah je smazaný. Odkaz už nikdo neotevře.",
	"receipt.state.burned.title":    "Smazáno vámi",
	"receipt.state.burned.sub":      "Obsah je pryč a nejde vrátit.",
	"receipt.state.destroyed.title": "Smazáno po špatných heslech",
	"receipt.state.destroyed.sub":   "Někdo zadal špatné heslo příliš mnohokrát, tak jsme obsah smazali.",
	"receipt.state.expired.title":   "Platnost vypršela",
	"receipt.state.expired.sub":     "Odkaz nikdo neotevřel včas. Obsah je smazaný.",
	"receipt.dl.created":            "Vytvořeno",
	"receipt.dl.expires":            "Platnost do",
	"receipt.dl.content":            "Obsah",
	"receipt.dl.peeked":             "Odkaz otevřen",
	"receipt.dl.consumed":           "Obsah zobrazen",
	"receipt.dl.aria":               "Podrobnosti o odkazu",
	"receipt.burn.h3":               "Poslali jste odkaz omylem?",
	"receipt.burn.cta":              "Smazat odkaz teď",
	"receipt.burn.hint":             "Obsah zmizí okamžitě a odkaz už nikdo neotevře.",
	"receipt.burn.confirm.h3":       "Opravdu smazat?",
	"receipt.burn.confirm.body":     "Obsah se smaže hned a nejde vrátit. Kdo odkaz otevře, uvidí, že jste ho zrušili.",
	"receipt.burn.confirm.yes":      "Ano, smazat",
	"receipt.burn.confirm.no":       "Zpět",
	"receipt.bookmark":              "Uložte si tuto stránku do záložek – jinak se k ní nedostanete.",
	"receipt.privacy":               "O příjemci si neukládáme nic – jen časy.",

	// -- status ------------------------------------------------------------
	"status.title":                   "Jednorázový odkaz · onetime",
	"status.cta":                     "Vytvořit vlastní odkaz",
	"status.already_read.title":      "Odkaz už byl použitý",
	"status.already_read.body":       "Obsah si už někdo zobrazil a tím se smazal. Každý odkaz tady funguje jen jednou – požádejte odesílatele o nový.",
	"status.already_read.why":        "Co když to otevřel někdo jiný?",
	"status.already_read.why_body":   "Mohl to být robot vašeho e-mailu nebo chatu, který si odkazy otevírá sám – hlídáme to, ale zaručit se za to nemůžeme. U citlivých věcí radši předpokládejte, že obsah viděl někdo další, a řekněte odesílateli, ať heslo změní.",
	"status.expired.title":           "Platnost odkazu vypršela",
	"status.expired.body":            "Nikdo ho nestihl otevřít včas. Požádejte odesílatele o nový.",
	"status.not_found.title":         "Takový odkaz neznáme",
	"status.not_found.body":          "Nejspíš se odkaz nezkopíroval celý. Zkontrolujte ho, nebo požádejte odesílatele o nový.",
	"status.burned.title":            "Odesílatel odkaz zrušil",
	"status.burned.body":             "Smazal obsah dřív, než ho někdo otevřel. Požádejte ho o nový odkaz.",
	"status.destroyed.title":         "Obsah byl smazaný",
	"status.destroyed.body":          "Někdo zadal špatné heslo příliš mnohokrát, tak jsme obsah pro jistotu smazali. Požádejte odesílatele o nový odkaz.",
	"status.too_many_attempts.title": "Moc pokusů za sebou",
	"status.too_many_attempts.body":  "Heslo jste zkusili příliš často. Obsah jsme nesmazali – vraťte se na stejný odkaz za dvacet minut.",
	"status.missing_key.title":       "Odkazu chybí konec",
	"status.missing_key.body":        "Zkopírovala se jen část. To, co je za znakem #, je klíč k obsahu – bez něj ho nedešifrujeme. Poproste odesílatele, ať vám odkaz pošle znovu.",
	"status.server_error.title":      "Něco se nám rozbilo",
	"status.server_error.body":       "Zkuste to prosím za chvíli znovu. Váš obsah je v pořádku.",
	"status.rate_limited.title":      "Moment, prosím",
	"status.rate_limited.body":       "Z vaší sítě chodí hodně požadavků. Zkuste to prosím za minutu znovu.",
	"status.read_only.title":         "Právě probíhá údržba",
	"status.read_only.body":          "Nové odkazy teď nejdou vytvořit. Čtení funguje dál.",
	"status.preview.title":           "Někdo vám poslal jednorázový odkaz",
	"status.preview.page_title":      "Někdo vám poslal jednorázový odkaz · onetime",
	"status.preview.body":            "Obsah uvidí jen ten, kdo odkaz otevře jako první. Pak se smaže.",

	// -- api docs ----------------------------------------------------------
	"api.title":              "API · onetime",
	"api.kicker":             "HTTP API",
	"api.h1.pre":             "Jednorázové odkazy ",
	"api.h1.mark":            "z příkazové řádky",
	"api.h1.post":            ".",
	"api.lead":               "Osm endpointů, JSON dovnitř i ven, žádné API klíče a žádná registrace. Stejné limity jako ve webu.",
	"api.btn.llms":           "llms.txt",
	"api.btn.openapi":        "OpenAPI",
	"api.toc.title":          "Obsah",
	"api.toc_aria":           "Obsah stránky",
	"api.note.title":         "Poctivá poznámka",
	"api.note.body":          "Šifrování probíhá na serveru. Klíč je součástí odkazu a hned ho zahazujeme – v databázi je obsah bez odkazu nečitelný.",
	"api.s.quickstart.title": "Rychlý start",
	"api.s.quickstart.body":  "Pošlete text, dostanete zpět dva odkazy: jeden pro příjemce a jeden pro sebe. Base URL je onetime.digitoo.ai, všechny endpointy jsou pod /api/v1.",
	"api.s.quickstart.note":  "Odpověď obsahuje klíč jen jednou – v secret_url za znakem #. Nikde ho neukládáme, takže si ho uložte vy.",
	"api.s.create.title":     "Vytvoření odkazu",
	"api.s.create.body":      "Tělo je JSON. Povinný je jen secret; ttl_days je 1 až 30 (výchozí 14) a passphrase je volitelné heslo navíc.",
	"api.s.file.title":       "Soubor",
	"api.s.file.body":        "Soubor se posílá jako multipart/form-data. Pole file musí být poslední – server čte metadata dřív, než začne streamovat obsah na disk, a nechce kvůli tomu držet celý soubor v paměti.",
	"api.s.generate.title":   "Generování hesla",
	"api.s.generate.body":    "Server heslo vyrobí sám a rovnou z něj udělá odkaz. Parametr alphabet je alnum, symbols nebo hex, length 8 až 128. S return_value: false se heslo do odpovědi vůbec nedostane.",
	"api.s.reveal.title":     "Přečtení",
	"api.s.reveal.body":      "Nejdřív peek: zjistí typ, velikost a jestli je potřeba heslo, a obsah přitom nesmaže. Teprve reveal s confirm: true obsah vydá a smaže. U souboru vrací ticket, se kterým se dá obsah do pěti minut stáhnout z /api/v1/download – potom je pryč.",
	"api.s.receipt.title":    "Stav",
	"api.s.receipt.body":     "Účtenka řekne, v jakém stavu odkaz je a kdy se s ním co stalo. O příjemci nevrací nic než časy.",
	"api.s.burn.title":       "Smazání",
	"api.s.burn.body":        "Dokud odkaz nikdo nepřečetl, můžete obsah smazat. Zpátky to nejde.",
	"api.s.errors.title":     "Chyby",
	"api.s.errors.body":      "Chyby jsou application/problem+json podle RFC 9457. Rozhodujte se podle pole code, ne podle textu – ten se mění a je přeložený.",
	"api.s.errors.col_code":  "code",
	"api.s.errors.col_http":  "HTTP",
	"api.s.errors.col_desc":  "Kdy nastane",
	"api.s.limits.title":     "Limity",
	"api.s.limits.body":      "Ve výchozím nastavení text do 1 MB, soubor do 50 MB a platnost 1 až 30 dní; přesné hodnoty ukazuje formulář. Pět špatných hesel za sebou odkaz na dvacet minut zamkne, dvacet špatných pokusů celkem obsah smaže. Rate limit je na IP a vrací 429 s hlavičkou Retry-After.",
	"api.s.agents.title":     "Pro AI agenty",
	"api.s.agents.body":      "Když má agent předat heslo člověku, doporučujeme POST /api/v1/generate s return_value: false. Heslo vyrobí server, agent dostane jen odkaz – heslo se tedy nikdy nedostane do jeho kontextu, do logu ani do historie konverzace.",
	"api.s.agents.llms":      "Strojově čitelný popis služby je na /llms.txt.",

	// -- api error table ---------------------------------------------------
	// Deliberately not the js.err.* strings: those are instructions for a
	// person standing at a form ("Zadejte heslo."), and a column headed
	// "Kdy nastane" needs the condition instead.
	"api.err.not_found":             "Odkaz s tímto klíčem neexistuje, nebo už byl smazaný.",
	"api.err.already_revealed":      "Obsah už byl vydaný a tím smazaný.",
	"api.err.burned":                "Odesílatel obsah smazal dřív, než ho někdo přečetl.",
	"api.err.destroyed":             "Obsah byl smazaný po dvaceti špatných pokusech o heslo.",
	"api.err.passphrase_required":   "Odkaz je chráněný heslem navíc, ale v requestu žádné nepřišlo.",
	"api.err.bad_passphrase":        "Heslo navíc nesedí.",
	"api.err.too_many_attempts":     "Pět špatných hesel za sebou. Retry-After říká, za jak dlouho to zkusit znovu.",
	"api.err.confirmation_required": "V těle requestu chybí confirm: true.",
	"api.err.payload_too_large":     "Obsah přesahuje povolený limit.",
	"api.err.empty":                 "Tělo requestu neobsahuje žádný obsah k uložení.",
	"api.err.storage_full":          "Serveru došlo místo pro soubory.",
	"api.err.files_disabled":        "Nahrávání souborů je na této instanci vypnuté.",
	"api.err.read_only":             "Instance je v režimu údržby a nepřijímá nové odkazy.",
	"api.err.quota_exceeded":        "Vyčerpaná hodinová kvóta pro tuto IP.",
	"api.err.ticket_expired":        "Ticket na stažení je starší než pět minut, nebo už byl použitý.",
	"api.err.invalid_ttl":           "ttl_days je mimo povolený rozsah.",
	"api.err.rate_limited":          "Překročený rate limit pro tuto IP. Retry-After říká, za jak dlouho to zkusit znovu.",
	"api.err.internal":              "Neočekávaná chyba na straně serveru.",

	// -- privacy -----------------------------------------------------------
	"privacy.title":          "Soukromí · onetime",
	"privacy.kicker":         "Soukromí",
	"privacy.h1":             "Jak to funguje a co si ukládáme",
	"privacy.lead":           "Krátce: obsah držíme zašifrovaný jen do prvního přečtení nebo do vypršení platnosti. Klíč k němu si neukládáme – je jen ve vašem odkazu.",
	"privacy.not.title":      "Co si NEUKLÁDÁME",
	"privacy.not.1":          "Obsah v čitelné podobě",
	"privacy.not.2":          "Dešifrovací klíč – je jen ve vašem odkazu",
	"privacy.not.3":          "Celou IP adresu příjemce",
	"privacy.not.4":          "Analytiku ani trackery",
	"privacy.yes.title":      "Co si ukládáme",
	"privacy.yes.1":          "Zašifrovaný obsah do přečtení nebo do vypršení platnosti",
	"privacy.yes.2":          "Čas vytvoření a čas přečtení",
	"privacy.yes.3":          "Volbu jazyka v cookie",
	"privacy.yes.4":          "Provozní logy po dobu 7 dní – v nich jen zkrácenou síť, ne celou IP adresu",
	"privacy.tech.summary":   "Technické detaily",
	"privacy.tech.1":         "Obsah šifrujeme AES-256-GCM. Klíč pro každý odkaz je náhodný a odvozujeme z něj přes HKDF zvlášť klíč pro data a pro metadata.",
	"privacy.tech.2":         "Klíč je jen ve fragmentu odkazu, tedy za znakem #. Ten prohlížeč sám od sebe na server nikdy neposílá, takže se nedostane ani do našich logů, ani do logů proxy po cestě. Na server ho pošle až naše stránka, v těle požadavku, který spustíte kliknutím – a my ho po dešifrování zahodíme.",
	"privacy.tech.3":         "Heslo navíc protahujeme přes Argon2id a neukládáme ho nikde, ani jako hash. Pět špatných pokusů za sebou odkaz na dvacet minut zamkne; po dvaceti pokusech obsah smažeme.",
	"privacy.tech.4":         "Celý provoz jde přes TLS. Smazání znamená smazání záznamu i zašifrovaného souboru, ne jen příznak v databázi.",
	"privacy.operator.title": "Provozovatel",
	"privacy.operator.body":  "Službu provozuje Digitoo a.s., Pernerova 697/35, Karlín, 186 00 Praha.",
	"privacy.operator.addr":  "Pernerova 697/35, Karlín, 186 00 Praha",
	"privacy.operator.ico":   "IČO: 08494584 · DIČ: CZ08494584",
	"privacy.updated":        "Naposledy upraveno: 27. 8. 2026",

	// -- strings shipped to the browser ------------------------------------
	"js.lang":                      "cs",
	"js.locale":                    "cs-CZ",
	"js.copy":                      "Kopírovat",
	"js.copied":                    "Zkopírováno",
	"js.copy_failed_label":         "Nešlo zkopírovat",
	"js.copy_failed":               "Zkopírovat se nepodařilo. Označte text a zkopírujte ho ručně.",
	"js.creating":                  "Vytvářím…",
	"js.uploading":                 "Nahrávám",
	"js.upload_cancel":             "Zrušit",
	"js.upload_canceled":           "Nahrávání zrušeno.",
	"js.upload_remaining":          "zbývá ~{t}",
	"js.unit.of":                   "z",
	"js.unit.sec":                  "s",
	"js.unit.min":                  "min",
	"js.days.one":                  "den",
	"js.days.few":                  "dny",
	"js.days.many":                 "dní",
	"js.attempts.one":              "pokus",
	"js.attempts.few":              "pokusy",
	"js.attempts.many":             "pokusů",
	"js.summary.expires":           "Vyprší za {n} {unit}",
	"js.summary.pass":              "s heslem navíc",
	"js.summary.nopass":            "bez hesla navíc",
	"js.expires_on":                "Vyprší {date}",
	"js.kind.text":                 "Text",
	"js.kind.file":                 "Soubor",
	"js.none":                      "—",
	"js.gate.wrong":                "Heslo nesedí.",
	"js.gate.attempts_left":        "Máte ještě {n} {unit}. Pak se odkaz na dvacet minut zamkne.",
	"js.gate.last_attempt":         "Máte poslední pokus. Pak se odkaz na dvacet minut zamkne.",
	"js.gate.pass_required":        "Zadejte heslo.",
	"js.gate.revealing":            "Zobrazuji…",
	"js.gate.revealed_live":        "Obsah je zobrazený níže. Zkopírujte si ho – znovu se nenačte.",
	"js.gate.downloading":          "Stahuji…",
	"js.gate.download_again":       "Stáhnout znovu",
	"js.receipt.h2":                "Odkaz z {date}",
	"js.receipt.burning":           "Mažu…",
	"js.receipt.burned_live":       "Odkaz je smazaný.",
	"js.leave_warning":             "Odkaz jste si ještě nezkopírovali.",
	"js.err.generic":               "Něco se nepovedlo. Zkuste to prosím znovu.",
	"js.err.network":               "Nepodařilo se spojit se serverem. Zkontrolujte připojení.",
	"js.err.not_found":             "Takový odkaz neznáme.",
	"js.err.already_revealed":      "Obsah už byl přečtený a tím se smazal.",
	"js.err.burned":                "Odesílatel odkaz zrušil.",
	"js.err.destroyed":             "Obsah je smazaný – někdo zadal špatné heslo příliš mnohokrát.",
	"js.err.passphrase_required":   "Odkaz je chráněný heslem.",
	"js.err.bad_passphrase":        "Heslo nesedí.",
	"js.err.too_many_attempts":     "Moc pokusů za sebou. Zkuste to za dvacet minut – obsah je pořád tady.",
	"js.err.confirmation_required": "Potvrďte zobrazení obsahu.",
	"js.err.payload_too_large":     "Obsah je moc velký.",
	"js.err.max_size":              "Maximum je {size}.",
	"js.err.empty":                 "Vložte obsah, který chcete poslat.",
	"js.err.no_file":               "Vyberte soubor, který chcete poslat.",
	"js.err.storage_full":          "Došlo nám místo. Zkuste to za chvíli.",
	"js.err.files_disabled":        "Posílání souborů je teď vypnuté.",
	"js.err.read_only":             "Právě probíhá údržba. Nové odkazy teď nejdou vytvořit.",
	"js.err.quota_exceeded":        "Z vaší sítě vzniklo moc odkazů. Zkuste to za chvíli znovu.",
	"js.err.ticket_expired":        "Odkaz na stažení platil pět minut a vypršel. Soubor už nestáhnete – požádejte odesílatele o nový.",
	"js.err.invalid_ttl":           "Platnost musí být {min} až {max} dní.",
	"js.err.rate_limited":          "Moment – z vaší sítě chodí hodně požadavků. Zkuste to za minutu.",
	"js.err.internal":              "Něco se nám rozbilo. Zkuste to prosím za chvíli znovu.",
}

// ---------------------------------------------------------------------------
// English.
// ---------------------------------------------------------------------------

//nolint:gosec // G101: UI copy about passphrases, not a passphrase; see the note on cs
var en = map[string]string{
	// -- chrome ------------------------------------------------------------
	"site.name":        "onetime",
	"site.title":       "onetime — one-time links for passwords and files",
	"site.description": "Send a password or a file as a link that opens exactly once. After it is read, the content is deleted. No sign-up.",
	"site.brand_aria":  "Digitoo — digitoo.ai (opens in a new window)",
	"site.home_aria":   "onetime — home page",
	"a11y.skip":        "Skip to content",
	"nav.aria":         "Main navigation",
	"nav.how":          "How it works",
	"nav.api":          "API",
	"lang.switch_aria": "Switch to Czech",
	"lang.cs":          "CS",
	"lang.en":          "EN",
	"footer.privacy":   "Privacy",
	"footer.nav_aria":  "Footer links",
	"footer.operator":  "Operated by Digitoo a.s., Pernerova 697/35, Karlín, 186 00 Prague, Czech Republic",
	"footer.api":       "API",
	"footer.tagline":   "One-time links for passwords and files.",

	// -- create ------------------------------------------------------------
	"create.title":                "onetime — send a password that deletes itself once read",
	"create.h1.pre":               "Send a password that deletes itself once it is ",
	"create.h1.mark":              "read",
	"create.h1.post":              ".",
	"create.lead":                 "A password doesn't have to sit around in your chat. Paste it here and send a link — the content is deleted the first time it is opened. No sign-up.",
	"create.form_aria":            "Create a one-time link",
	"create.tablist_aria":         "Content type",
	"create.tab.text":             "Text",
	"create.tab.file":             "File",
	"create.textarea.label":       "What you want to send",
	"create.textarea.placeholder": "A password, a key or a short message",
	"create.textarea.hint":        "We encrypt it on our side. The decryption key ends up only in your link, never in the database.",
	"create.file.drop":            "Drop a file here",
	"create.file.or":              "or",
	"create.file.pick":            "Choose a file",
	"create.file.max":             "Up to",
	"create.file.remove":          "Remove file",
	"create.file.disabled":        "File sending is switched off right now. Text still works.",
	"create.options.summary":      "More options",
	"create.ttl.label":            "Link validity",
	"create.ttl.d1":               "1 day",
	"create.ttl.d7":               "7 days",
	"create.ttl.d14":              "14 days",
	"create.ttl.d30":              "30 days",
	"create.ttl.custom":           "Custom…",
	"create.ttl.custom_label":     "Number of days, %d to %d",
	"create.ttl.back":             "Back to presets",
	"create.pass.label":           "Extra password (optional)",
	"create.pass.placeholder":     "Optional",
	"create.pass.show":            "Show password",
	"create.pass.generate":        "Generate",
	"create.pass.hint":            "Send it to the recipient another way — by text message or over the phone. Without it they cannot open the content, and we cannot remind them of it. Once you submit, you will not see the password again.",
	"create.submit":               "Create link",
	"create.upload.aria":          "File upload progress",
	"create.readonly":             "Maintenance is in progress. New links cannot be created right now.",
	"create.how.kicker":           "How it works",
	"create.how.h2.pre":           "Three steps. No ",
	"create.how.h2.mark":          "sign-up",
	"create.how.h2.post":          ".",
	"create.how.1.title":          "You paste the content",
	"create.how.1.body":           "A password, a key or a file. We encrypt it and put the encryption key in the link — not in the database.",
	"create.how.2.title":          "You send the link",
	"create.how.2.body":           "Chat, e-mail, whatever you use. Link previews in Teams and Slack will not delete it — we wait for a real human click.",
	"create.how.3.title":          "They open the link",
	"create.how.3.body":           "The content shows up once and is deleted from our server. Nobody can open it a second time.",
	"create.result.title":         "Your link is ready",
	"create.result.label":         "One-time link",
	"create.result.copy":          "Copy link",
	"create.result.pass.label":    "Extra password — send it separately",
	"create.result.pass.hint":     "Send it by a different route than the link. We will not show it to you again.",
	"create.result.warn":          "Copy the link now. We will not show it again — we do not hold the whole of it.",

	// -- gate --------------------------------------------------------------
	"gate.title":             "A one-time link · onetime",
	"gate.loading":           "Loading…",
	"gate.h2.text":           "Someone sent you a password",
	"gate.h2.file":           "Someone sent you a file",
	"gate.lead":              "You will see the content only once. The moment you click, it is deleted from our server.",
	"gate.cta":               "Show the content",
	"gate.cta_pass":          "Continue",
	"gate.cta_hint":          "Click when you are ready to save the content right away.",
	"gate.chip.text":         "Text",
	"gate.chip.file":         "File",
	"gate.chip.protected":    "Password protected",
	"gate.why.summary":       "Why do I have to click?",
	"gate.why.body":          "Teams, Slack, Outlook and WhatsApp open links on their own to show you a preview. If we revealed the content straight away, their bot would read it before you did. That is why we wait for a click from a real person.",
	"gate.pass.h2":           "This link is password protected",
	"gate.pass.lead":         "The sender will have given you the password another way — most likely by text message or over the phone.",
	"gate.pass.label":        "Password from the sender",
	"gate.pass.placeholder":  "Password from the sender",
	"gate.pass.cta":          "Show the content",
	"gate.revealed.aria":     "The content shown",
	"gate.revealed.copy":     "Copy",
	"gate.revealed.warn":     "Save the content now. Once you close this page it is gone — it exists nowhere else.",
	"gate.revealed.loop":     "Need to send something back?",
	"gate.revealed.loop_cta": "Create a link",
	"gate.file.download":     "Download the file",
	"gate.file.downloaded":   "Downloaded",
	"gate.file.inapp":        "Downloads often fail inside this app. If the file does not arrive, press the button again — but do not close the page, the file is nowhere else.",
	"gate.text.inapp":        "You are in a browser inside an app, where copying often fails. If the button does nothing, select the text by hand and copy it. Do not close the page — the content is nowhere else.",
	"gate.noscript":          "We cannot show the content without JavaScript. Switch it on and reload the page.",

	// -- receipt -----------------------------------------------------------
	"receipt.title":                 "Link status · onetime",
	"receipt.kicker":                "Link status",
	"receipt.loading":               "Loading…",
	"receipt.state.new.title":       "Waiting to be read",
	"receipt.state.new.sub":         "Nobody has shown the content yet.",
	"receipt.state.consumed.title":  "Read",
	"receipt.state.consumed.sub":    "The content is deleted. Nobody can open the link now.",
	"receipt.state.burned.title":    "Deleted by you",
	"receipt.state.burned.sub":      "The content is gone and cannot be brought back.",
	"receipt.state.destroyed.title": "Deleted after wrong passwords",
	"receipt.state.destroyed.sub":   "Someone got the password wrong too many times, so we deleted the content.",
	"receipt.state.expired.title":   "Validity expired",
	"receipt.state.expired.sub":     "Nobody opened the link in time. The content is deleted.",
	"receipt.dl.created":            "Created",
	"receipt.dl.expires":            "Valid until",
	"receipt.dl.content":            "Content",
	"receipt.dl.peeked":             "Link opened",
	"receipt.dl.consumed":           "Content shown",
	"receipt.dl.aria":               "Link details",
	"receipt.burn.h3":               "Sent the link by mistake?",
	"receipt.burn.cta":              "Delete the link now",
	"receipt.burn.hint":             "The content disappears immediately and nobody can open the link.",
	"receipt.burn.confirm.h3":       "Delete it for good?",
	"receipt.burn.confirm.body":     "The content is deleted right away and cannot be brought back. Anyone opening the link will see that you cancelled it.",
	"receipt.burn.confirm.yes":      "Yes, delete",
	"receipt.burn.confirm.no":       "Back",
	"receipt.bookmark":              "Bookmark this page — there is no other way back to it.",
	"receipt.privacy":               "We store nothing about the recipient — only timestamps.",

	// -- status ------------------------------------------------------------
	"status.title":                   "A one-time link · onetime",
	"status.cta":                     "Create your own link",
	"status.already_read.title":      "This link has already been used",
	"status.already_read.body":       "Someone has already shown the content, and that deleted it. Every link here works exactly once — ask the sender for a new one.",
	"status.already_read.why":        "What if it wasn't me who opened it?",
	"status.already_read.why_body":   "It may have been a bot from your e-mail or chat that opens links on its own — we guard against that, but we cannot promise it never happens. With sensitive material, assume somebody else saw the content and tell the sender to change the password.",
	"status.expired.title":           "This link has expired",
	"status.expired.body":            "Nobody opened it in time. Ask the sender for a new one.",
	"status.not_found.title":         "We don't know this link",
	"status.not_found.body":          "The link probably did not get copied in full. Check it, or ask the sender for a new one.",
	"status.burned.title":            "The sender cancelled this link",
	"status.burned.body":             "They deleted the content before anyone opened it. Ask them for a new link.",
	"status.destroyed.title":         "The content was deleted",
	"status.destroyed.body":          "Someone got the password wrong too many times, so we deleted the content to be safe. Ask the sender for a new link.",
	"status.too_many_attempts.title": "Too many tries in a row",
	"status.too_many_attempts.body":  "You have tried the password too often. We have not deleted the content — come back to the same link in twenty minutes.",
	"status.missing_key.title":       "The end of the link is missing",
	"status.missing_key.body":        "Only part of it came across. Everything after the # is the key to the content — without it we cannot decrypt it. Ask the sender to send you the link again.",
	"status.server_error.title":      "Something broke on our side",
	"status.server_error.body":       "Please try again in a moment. Your content is fine.",
	"status.rate_limited.title":      "One moment, please",
	"status.rate_limited.body":       "There are a lot of requests coming from your network. Please try again in a minute.",
	"status.read_only.title":         "Maintenance in progress",
	"status.read_only.body":          "New links cannot be created right now. Reading still works.",
	"status.preview.title":           "Someone sent you a one-time link",
	"status.preview.page_title":      "Someone sent you a one-time link · onetime",
	"status.preview.body":            "Only the first person to open it sees the content. Then it is deleted.",

	// -- api docs ----------------------------------------------------------
	"api.title":              "API · onetime",
	"api.kicker":             "HTTP API",
	"api.h1.pre":             "One-time links ",
	"api.h1.mark":            "from the command line",
	"api.h1.post":            ".",
	"api.lead":               "Eight endpoints, JSON in and out, no API keys and no sign-up. Same limits as the web app.",
	"api.btn.llms":           "llms.txt",
	"api.btn.openapi":        "OpenAPI",
	"api.toc.title":          "Contents",
	"api.toc_aria":           "Page contents",
	"api.note.title":         "An honest note",
	"api.note.body":          "Encryption happens on the server. The key is part of the link and we throw it away immediately — without the link, the content in our database is unreadable.",
	"api.s.quickstart.title": "Quick start",
	"api.s.quickstart.body":  "Send some text, get two links back: one for the recipient and one for yourself. The base URL is onetime.digitoo.ai and every endpoint lives under /api/v1.",
	"api.s.quickstart.note":  "The response contains the key exactly once — in secret_url, after the #. We never store it, so you have to.",
	"api.s.create.title":     "Creating a link",
	"api.s.create.body":      "The body is JSON. Only secret is required; ttl_days is 1 to 30 (default 14) and passphrase is an optional extra password.",
	"api.s.file.title":       "File upload",
	"api.s.file.body":        "Files go up as multipart/form-data. The file field must come last — the server reads the metadata before it starts streaming the body to disk, so that it never has to hold the whole file in memory.",
	"api.s.generate.title":   "Password generation",
	"api.s.generate.body":    "The server makes the password itself and turns it straight into a link. alphabet is alnum, symbols or hex, length is 8 to 128. With return_value: false the password never appears in the response at all.",
	"api.s.reveal.title":     "Reading",
	"api.s.reveal.body":      "Start with peek: it reports the kind, the size and whether a password is needed, without deleting anything. Only reveal with confirm: true hands out the content and deletes it. For files it returns a ticket good for five minutes against /api/v1/download — after that the file is gone.",
	"api.s.receipt.title":    "Status",
	"api.s.receipt.body":     "The receipt tells you what state the link is in and when things happened to it. It returns nothing about the recipient beyond timestamps.",
	"api.s.burn.title":       "Deleting",
	"api.s.burn.body":        "As long as nobody has read the link, you can delete the content. There is no undo.",
	"api.s.errors.title":     "Errors",
	"api.s.errors.body":      "Errors are application/problem+json per RFC 9457. Branch on the code field, not on the text — the text changes and is translated.",
	"api.s.errors.col_code":  "code",
	"api.s.errors.col_http":  "HTTP",
	"api.s.errors.col_desc":  "When it happens",
	"api.s.limits.title":     "Limits",
	"api.s.limits.body":      "By default text up to 1 MB, files up to 50 MB and validity between 1 and 30 days; the form shows the exact figures. Five wrong passwords in a row lock the link for twenty minutes, and twenty wrong attempts in total delete the content. Rate limiting is per IP and answers 429 with a Retry-After header.",
	"api.s.agents.title":     "For AI agents",
	"api.s.agents.body":      "When an agent has to hand a password to a human, use POST /api/v1/generate with return_value: false. The server makes the password and the agent only ever sees a link — so the password never enters the agent's context, its logs or the conversation history.",
	"api.s.agents.llms":      "A machine-readable description of the service lives at /llms.txt.",

	// -- api error table ---------------------------------------------------
	"api.err.not_found":             "No link exists for this key, or it has already been deleted.",
	"api.err.already_revealed":      "The content was already handed out, and deleted with it.",
	"api.err.burned":                "The sender deleted the content before anyone read it.",
	"api.err.destroyed":             "The content was deleted after twenty wrong password attempts.",
	"api.err.passphrase_required":   "The link has an extra password, but the request carried none.",
	"api.err.bad_passphrase":        "The extra password does not match.",
	"api.err.too_many_attempts":     "Five wrong passwords in a row. Retry-After says how long to wait.",
	"api.err.confirmation_required": "The request body is missing confirm: true.",
	"api.err.payload_too_large":     "The content is over the configured limit.",
	"api.err.empty":                 "The request body carries nothing to store.",
	"api.err.storage_full":          "The server has run out of space for files.",
	"api.err.files_disabled":        "File upload is switched off on this instance.",
	"api.err.read_only":             "The instance is in maintenance mode and accepts no new links.",
	"api.err.quota_exceeded":        "The hourly quota for this IP is used up.",
	"api.err.ticket_expired":        "The download ticket is older than five minutes, or has been used already.",
	"api.err.invalid_ttl":           "ttl_days is outside the permitted range.",
	"api.err.rate_limited":          "Rate limit exceeded for this IP. Retry-After says how long to wait.",
	"api.err.internal":              "An unexpected error on the server side.",

	// -- privacy -----------------------------------------------------------
	"privacy.title":          "Privacy · onetime",
	"privacy.kicker":         "Privacy",
	"privacy.h1":             "How it works and what we store",
	"privacy.lead":           "In short: we hold the content encrypted only until the first read or until it expires. We do not store the key to it — it lives only in your link.",
	"privacy.not.title":      "What we DON'T store",
	"privacy.not.1":          "The content in readable form",
	"privacy.not.2":          "The decryption key — it lives only in your link",
	"privacy.not.3":          "The recipient's full IP address",
	"privacy.not.4":          "Analytics or trackers",
	"privacy.yes.title":      "What we do store",
	"privacy.yes.1":          "The encrypted content until it is read or expires",
	"privacy.yes.2":          "The time of creation and of reading",
	"privacy.yes.3":          "Your language choice, in a cookie",
	"privacy.yes.4":          "Operational logs for 7 days — holding a truncated network, not a full IP address",
	"privacy.tech.summary":   "Technical details",
	"privacy.tech.1":         "Content is encrypted with AES-256-GCM. Each link gets a random key, from which HKDF derives separate keys for the payload and for the metadata.",
	"privacy.tech.2":         "The key lives only in the link fragment, after the #. A browser never sends that to a server of its own accord, so it reaches neither our logs nor any proxy along the way. It is our own page that sends it, in the body of the request your click sets off — and we throw it away once the content is decrypted.",
	"privacy.tech.3":         "An extra password is stretched with Argon2id and stored nowhere, not even as a hash. Five wrong attempts in a row lock the link for twenty minutes; after twenty attempts we delete the content.",
	"privacy.tech.4":         "All traffic runs over TLS. Deleting means deleting the record and the encrypted file, not just flipping a flag in a database.",
	"privacy.operator.title": "Operator",
	"privacy.operator.body":  "The service is operated by Digitoo a.s., registered in the Czech Republic.",
	"privacy.operator.addr":  "Pernerova 697/35, Karlín, 186 00 Prague, Czech Republic",
	"privacy.operator.ico":   "Company ID: 08494584 · VAT ID: CZ08494584",
	"privacy.updated":        "Last updated: 27 Aug 2026",

	// -- strings shipped to the browser ------------------------------------
	"js.lang":                      "en",
	"js.locale":                    "en-GB",
	"js.copy":                      "Copy",
	"js.copied":                    "Copied",
	"js.copy_failed_label":         "Copy failed",
	"js.copy_failed":               "Copying failed. Select the text and copy it by hand.",
	"js.creating":                  "Creating…",
	"js.uploading":                 "Uploading",
	"js.upload_cancel":             "Cancel",
	"js.upload_canceled":           "Upload cancelled.",
	"js.upload_remaining":          "~{t} left",
	"js.unit.of":                   "of",
	"js.unit.sec":                  "s",
	"js.unit.min":                  "min",
	"js.days.one":                  "day",
	"js.days.few":                  "days",
	"js.days.many":                 "days",
	"js.attempts.one":              "try",
	"js.attempts.few":              "tries",
	"js.attempts.many":             "tries",
	"js.summary.expires":           "Expires in {n} {unit}",
	"js.summary.pass":              "with an extra password",
	"js.summary.nopass":            "no extra password",
	"js.expires_on":                "Expires {date}",
	"js.kind.text":                 "Text",
	"js.kind.file":                 "File",
	"js.none":                      "—",
	"js.gate.wrong":                "That password is wrong.",
	"js.gate.attempts_left":        "You have {n} more {unit}. After that the link locks for twenty minutes.",
	"js.gate.last_attempt":         "You have one try left. After that the link locks for twenty minutes.",
	"js.gate.pass_required":        "Enter the password.",
	"js.gate.revealing":            "Revealing…",
	"js.gate.revealed_live":        "The content is shown below. Copy it — it will not load again.",
	"js.gate.downloading":          "Downloading…",
	"js.gate.download_again":       "Download again",
	"js.receipt.h2":                "Link from {date}",
	"js.receipt.burning":           "Deleting…",
	"js.receipt.burned_live":       "The link is deleted.",
	"js.leave_warning":             "You have not copied the link yet.",
	"js.err.generic":               "Something went wrong. Please try again.",
	"js.err.network":               "We could not reach the server. Check your connection.",
	"js.err.not_found":             "We don't know this link.",
	"js.err.already_revealed":      "The content has already been read and is deleted.",
	"js.err.burned":                "The sender cancelled this link.",
	"js.err.destroyed":             "The content is deleted — someone got the password wrong too many times.",
	"js.err.passphrase_required":   "This link is password protected.",
	"js.err.bad_passphrase":        "That password is wrong.",
	"js.err.too_many_attempts":     "Too many tries in a row. Come back in twenty minutes — the content is still here.",
	"js.err.confirmation_required": "Confirm that you want to see the content.",
	"js.err.payload_too_large":     "The content is too large.",
	"js.err.max_size":              "The maximum is {size}.",
	"js.err.empty":                 "Add the content you want to send.",
	"js.err.no_file":               "Choose the file you want to send.",
	"js.err.storage_full":          "We have run out of space. Try again shortly.",
	"js.err.files_disabled":        "File sending is switched off right now.",
	"js.err.read_only":             "Maintenance is in progress. New links cannot be created right now.",
	"js.err.quota_exceeded":        "Too many links have come from your network. Try again shortly.",
	"js.err.ticket_expired":        "The download link was good for five minutes and has expired. You cannot fetch the file now — ask the sender for a new link.",
	"js.err.invalid_ttl":           "Validity has to be between {min} and {max} days.",
	"js.err.rate_limited":          "One moment — a lot of requests are coming from your network. Try again in a minute.",
	"js.err.internal":              "Something broke on our side. Please try again in a moment.",
}
