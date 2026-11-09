import re
from dataclasses import dataclass
from urllib.parse import urlparse

FAIL_VALUES = frozenset({"fail", "softfail", "temperror", "permerror"})

COMPOUND_SUFFIXES = frozenset({
    "com.mx", "com.br", "com.ar", "com.co", "com.pe", "com.es",
    "co.uk", "org.mx", "gob.mx", "com.au",
})

DEFAULT_BRANDS = frozenset("""
netflix amazon paypal microsoft apple google facebook instagram whatsapp
banco bbva santander hsbc citibanamex oxxo mercadolibre dhl fedex ups vivo
claro telcel medicare coinbase binance steam spotify disney uber rappi stripe
""".split())

# Invisible characters used to obfuscate brand names.
_INVISIBLE_CHARS = frozenset(
    chr(c)
    for start, end in (
        (0x00AD, 0x00AD), (0x200B, 0x200F), (0x2060, 0x2064),
        (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xE0100, 0xE01EF),
    )
    for c in range(start, end + 1)
)

# Homoglyphs: characters that look like Latin letters but are from other scripts.
_HOMOGLYPHS = {
    0x0410: "A", 0x0412: "B", 0x0421: "C", 0x0415: "E", 0x041D: "H",
    0x0406: "I", 0x0408: "J", 0x041A: "K", 0x041C: "M", 0x041E: "O",
    0x0420: "P", 0x0405: "S", 0x0422: "T", 0x0425: "X", 0x0423: "Y",
    0x0430: "a", 0x0441: "c", 0x0435: "e", 0x0456: "i", 0x043E: "o",
    0x0440: "p", 0x0455: "s", 0x0445: "x", 0x0443: "y",
    0x051B: "q", 0x051D: "w", 0x0501: "h", 0x0578: "n", 0x0261: "g",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A7: "X",
    0x03B1: "a", 0x03B5: "e", 0x03BF: "o", 0x03C1: "p",
}


def normalize_for_matching(text: str) -> str:
    """Strip invisible characters and map homoglyphs to ASCII for brand detection."""
    if not text:
        return ""
    result = []
    for ch in text:
        if ch in _INVISIBLE_CHARS:
            continue
        codepoint = ord(ch)
        if codepoint in _HOMOGLYPHS:
            result.append(_HOMOGLYPHS[codepoint])
        else:
            result.append(ch)
    return "".join(result)


VOWELS = frozenset("aeiouy")

STOPWORDS = {
    "es": frozenset("""
    el la los las un una unos unas de del que y en se por para con no su al es
    lo como más pero sus le ya este esta entre cuando muy sin sobre también me
    hasta hay donde desde todo nos durante todos uno les ni contra otros eso
    ante ellos esto antes algunos qué unos yo otro otras otra él tanto esa
    estos mucho quienes nada muchos cual poco ella estar estas algunas algo
    nosotros mi mis tú te ti tu tus ellas os mío mía
    """.split()),
    "en": frozenset("""
    the and of to in is you that it was for on are as with his they at be this
    have from or one had by word but not what all were we when your can said
    there use an each which she do how their if will up other about out many
    then them these so some her would make like him into time has look two
    more write go see number no way could people my than first been call who
    its now find long down day did get come made may part
    """.split()),
    "pt": frozenset("""
    um uma de do da dos das em no na nos nas por para com que não se ao aos
    mais mas como foi ser tem seu sua seus suas ou quando muito já está também
    só pelo pela até isso ela ele entre depois sem mesmo ter quem nas esse eles
    você essa num nem suas meu às minha numa pelos elas qual nós lhe deles
    essas esses pelas este fosse dele tu vocês vos lhes meus minhas teu tua
    teus tuas nosso nossa nossos nossas dela delas esta estes estas aquele
    aquela agora precisa pagamento acesse disponível regularização imediata
    acordo liberado senha obrigado prezado conta
    """.split()),
    "it": frozenset("""
    il lo gli le un uno una di del della dei degli delle al allo alla ai agli
    alle da dal dallo dalla dai dagli dalle nel nello nella nei negli nelle
    con sul sullo sulla sui sugli sulle per tra fra che non più come anche ma
    se questo questa sono essere stato
    """.split()),
    "fr": frozenset("""
    les une des du et est que qui dans pour pas au aux ce ces cette ils elles
    on nous vous je avec sur son sa ses mais plus ne par comme tout votre vos
    notre nos leur leurs
    """.split()),
}

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
SPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class AuthResult:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

    @property
    def failed(self) -> bool:
        return any(value in FAIL_VALUES for value in (self.spf, self.dkim, self.dmarc))


@dataclass(frozen=True)
class Evidence:
    message_id: str
    internet_message_id: str
    subject: str
    from_name: str
    from_address: str
    from_domain: str
    reply_to_domain: str | None
    auth: AuthResult
    text: str
    link_domains: tuple[str, ...]
    language: str
    has_attachments: bool
    random_sender: bool
    brand: str | None
    received: str | None


def parse_auth_results(headers: list[dict]) -> AuthResult:
    for header in headers or []:
        name = (header.get("name") or "").strip().lower()
        if name != "authentication-results":
            continue
        value = (header.get("value") or "").lower()
        return AuthResult(
            spf=_extract_mechanism(value, "spf"),
            dkim=_extract_mechanism(value, "dkim"),
            dmarc=_extract_mechanism(value, "dmarc"),
        )
    return AuthResult()


def _extract_mechanism(value: str, key: str) -> str:
    match = re.search(rf"\b{key}\s*=\s*([a-z]+)", value)
    return match.group(1) if match else "unknown"


def registrable_domain(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in COMPOUND_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_random_sender(local: str, domain: str) -> bool:
    local = (local or "").lower()
    domain = (domain or "").lower()
    digits = sum(character.isdigit() for character in local)
    letters = [character for character in local if character.isalpha()]
    vowels = sum(character in VOWELS for character in letters)
    consonants = len(letters) - vowels
    ratio = consonants / vowels if vowels else float(consonants)
    if len(local) >= 12 and (digits >= 4 or ratio > 3):
        return True
    domain_letters = [character for character in domain if character.isalpha()]
    if len(domain) >= 20 and domain_letters:
        domain_vowels = sum(character in VOWELS for character in domain_letters)
        if domain_vowels / len(domain_letters) < 0.2:
            return True
    return False


def detect_language(text: str) -> str:
    tokens = [token for token in WORD_RE.findall((text or "").lower()) if len(token) >= 2]
    counts = {
        language: sum(token in words for token in tokens)
        for language, words in STOPWORDS.items()
    }
    best = max(counts, key=counts.get)
    return best if counts[best] > 0 else "unknown"


def find_brand(text: str, brands: set[str] | frozenset[str]) -> str | None:
    haystack = normalize_for_matching(text or "").lower()
    for brand in sorted(brands, key=len, reverse=True):
        if brand and re.search(rf"(?<!\w){re.escape(brand)}(?!\w)", haystack):
            return brand
    return None


def from_message(msg: dict, brands: set[str] | frozenset[str] | None = None) -> Evidence:
    sender = ((msg.get("from") or {}).get("emailAddress") or {})
    from_name = sender.get("name") or ""
    from_address = sender.get("address") or ""
    local, from_domain = _split_address(from_address)

    raw_content = (msg.get("body") or {}).get("content") or msg.get("bodyPreview") or ""
    visible = SPACE_RE.sub(" ", TAG_RE.sub(" ", raw_content)).strip()

    reply_to_domain = None
    reply_to = msg.get("replyTo") or []
    if reply_to:
        address = ((reply_to[0] or {}).get("emailAddress") or {}).get("address") or ""
        _, host = _split_address(address)
        if host:
            reply_to_domain = registrable_domain(host)

    return Evidence(
        message_id=msg.get("id") or "",
        internet_message_id=msg.get("internetMessageId") or "",
        subject=msg.get("subject") or "",
        from_name=from_name,
        from_address=from_address,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        auth=parse_auth_results(msg.get("internetMessageHeaders") or []),
        text=visible[:400],
        link_domains=_link_domains(raw_content),
        language=detect_language(visible),
        has_attachments=bool(msg.get("hasAttachments")),
        random_sender=is_random_sender(local, from_domain),
        brand=find_brand(f"{from_name} {msg.get('subject') or ''}", brands or DEFAULT_BRANDS),
        received=msg.get("receivedDateTime"),
    )


def _split_address(address: str) -> tuple[str, str]:
    address = (address or "").strip()
    if "@" not in address:
        return address, ""
    local, host = address.rsplit("@", 1)
    host = host.strip().strip("<>").lower()
    if not host or " " in host:
        return local, ""
    return local, host


def _link_domains(raw_content: str) -> tuple[str, ...]:
    domains: list[str] = []
    for url in URL_RE.findall(raw_content or ""):
        host = urlparse(url).hostname or ""
        domain = registrable_domain(host)
        if domain and domain not in domains:
            domains.append(domain)
        if len(domains) >= 10:
            break
    return tuple(domains)
