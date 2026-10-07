"""Deterministic security scanners. No model involved, so the checks can't be talked out of a verdict.

Each scanner returns Finding dicts: {id, category, severity, title, detail, evidence}.
Severity order: info < low < medium < high < critical.
"""
import base64
import binascii
import codecs
import math
import re
import unicodedata
from urllib.parse import unquote

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

MAX_EVIDENCE = 120


def _finding(fid, category, severity, title, detail="", evidence=""):
    ev = evidence if len(evidence) <= MAX_EVIDENCE else evidence[:MAX_EVIDENCE] + "…"
    return {"id": fid, "category": category, "severity": severity, "title": title,
            "detail": detail, "evidence": ev, "source": "rules"}


# --- unicode tricks -----------------------------------------------------------------------------

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x034F, 0x061C, 0x115F,
              0x1160, 0x3164, 0xFFA0}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}
TAG_RANGE = range(0xE0000, 0xE0080)        # "ASCII smuggling": invisible tag characters
VARIATION_SUPP = range(0xE0100, 0xE01F0)   # variation selectors used to hide bytes
_STRIP_INVISIBLE = str.maketrans({chr(c): None for c in (*ZERO_WIDTH, *BIDI, *TAG_RANGE, *VARIATION_SUPP)})
_TAG_PRINTABLE = re.compile("[\U000E0020-\U000E007E]+")
_HOMOGLYPH_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}


# Subdivision flag emoji (England, Scotland, Wales) are U+1F3F4 + tag letters/digits + U+E007F cancel tag.
FLAG_SEQ = re.compile("\U0001F3F4[\U000E0030-\U000E0039\U000E0061-\U000E007A]{1,8}\U000E007F")


def decode_tag_chars(text):
    """Invisible Unicode tag characters map 1:1 onto ASCII. Return the hidden message (legit flag emoji excluded)."""
    if "\U0001F3F4" in text:
        text = FLAG_SEQ.sub("", text)
    parts = _TAG_PRINTABLE.findall(text)
    return "".join(chr(ord(c) - 0xE0000) for p in parts for c in p)


def strip_invisible(text):
    if "\U0001F3F4" in text:
        text = FLAG_SEQ.sub("\U0001F3F4", text)
    return text.translate(_STRIP_INVISIBLE)


def unconfuse(text):
    """Map lookalike Cyrillic/Greek letters to Latin, but only inside words that mix scripts (homoglyph spoofing);
    genuine Russian or Greek words are left alone."""
    def fix(m):
        w = m.group(0)
        if re.search(r"[A-Za-z]", w) and re.search(r"[\u0370-\u03ff\u0400-\u04ff\u0500-\u052f]", w):
            return w.translate(CONFUSABLES)
        return w
    return re.sub(r"\w+", fix, text)


def normalize(text):
    """Invisible chars removed, NFKC folded (fullwidth/compat letters -> ASCII), mixed-script lookalikes mapped,
    whitespace collapsed."""
    t = unconfuse(unicodedata.normalize("NFKC", strip_invisible(text)))
    return re.sub(r"\s+", " ", t)


LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "Ι": "I", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Α": "A",
    "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Κ": "K", "Μ": "M", "Ν": "N", "ο": "o", "ν": "v", "ρ": "p", "τ": "t",
    "ѡ": "w", "ɑ": "a", "ʏ": "y", "ꓲ": "I", "ꓳ": "O"})
SPACED = re.compile(r"\b(?:[A-Za-z][ _.\-]){2,}[A-Za-z]\b")
# Core attack phrases with all spacing and punctuation removed: catches "i g n o r e  a l l …", "i.g.n.o.r.e".
COMPACT = re.compile(r"(ignore|disregard|forget|override)(all|any|the|your|my)*(previous|prior|above|earlier|preceding|original|system)+"
                     r"(instructions?|prompts?|rules|directions)|(reveal|print|show|repeat)(your|the)(system|initial|hidden)prompt"
                     r"|developermode|doanythingnow|youarenowdan")


def deobfuscated_views(text):
    """Extra views for the injection rules: leetspeak, spaced-out letters, lookalike letters, reversed text.
    Returns [(label, view)] for views that differ from the normalized text."""
    out = []
    conf = text.translate(CONFUSABLES)
    if conf != text:
        out.append((" (lookalike letters mapped)", conf))
    if re.search(r"[a-zA-Z][0-9@$!|]|[0-9@$|][a-zA-Z]", text):
        leet = re.sub(r"\S+", lambda m: m.group(0).translate(LEET) if re.search(r"[a-zA-Z]", m.group(0)) else m.group(0), conf)
        if leet != conf:
            out.append((" (leetspeak decoded)", leet))
    if SPACED.search(text):
        squeezed = SPACED.sub(lambda m: re.sub(r"[ _.\-]", "", m.group(0)), conf)
        out.append((" (spaced letters joined)", re.sub(r"\s+", " ", squeezed)))
    rev = text[::-1]
    if TRIGGER_WORDS.search(rev) and not TRIGGER_WORDS.search(text):
        out.append((" (reversed text)", rev))
    return out


ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]{0,2000}(\x07|\x1b\\)")


def _mixed_script_words(text):
    """Latin mixed with lookalike letters from other scripts. ASCII text cannot be mixed-script."""
    mixed = []
    for word in re.findall(r"\w{3,}", text):
        if word.isascii():
            continue
        scripts = set()
        for c in word:
            if not c.isalpha():
                continue
            if c.isascii():
                scripts.add("LATIN")
            else:
                scripts.add(unicodedata.name(c, "").split(" ", 1)[0])
        if "LATIN" in scripts and scripts & _HOMOGLYPH_SCRIPTS:
            mixed.append(word)
    return mixed


def scan_unicode(text, hidden=None):
    out = []
    if text.isascii():
        zw, bidi, vs, ctrl = [], [], 0, [
            c for c in text if (ord(c) < 32 and c not in "\t\n\r\x1b") or c == "\x7f"]
        if hidden is None:
            hidden = ""
    else:
        zw, bidi, ctrl, vs = [], [], [], 0
        for c in text:
            o = ord(c)
            if o in ZERO_WIDTH:
                zw.append(c)
            elif o in BIDI:
                bidi.append(c)
            elif o in VARIATION_SUPP:
                vs += 1
            elif (o < 32 or 0x7F <= o <= 0x9F) and c not in "\t\n\r\x1b":
                ctrl.append(c)
        if hidden is None:
            hidden = decode_tag_chars(text)
    if zw:
        out.append(_finding("unicode.zero_width", "obfuscation", "medium" if len(zw) > 3 else "low",
                            "Invisible zero-width characters",
                            f"{len(zw)} invisible character(s); often used to split trigger words past filters.",
                            " ".join(f"U+{ord(c):04X}" for c in zw[:8])))
    if bidi:
        out.append(_finding("unicode.bidi", "obfuscation", "high",
                            "Bidirectional override characters",
                            "Text-direction controls can make text display differently from what a model reads (Trojan Source).",
                            " ".join(f"U+{ord(c):04X}" for c in bidi[:8])))
    if hidden:
        out.append(_finding("unicode.tag_smuggling", "prompt_injection", "critical",
                            "Hidden text in Unicode tag characters",
                            "Invisible tag characters encode a message a model can read but you can't see.", hidden))
    if vs > 4:
        out.append(_finding("unicode.variation_selectors", "obfuscation", "high",
                            "Data hidden in variation selectors",
                            f"{vs} supplementary variation selectors; a known way to smuggle bytes inside an emoji."))
    mixed = [] if text.isascii() else _mixed_script_words(text)
    if mixed:
        out.append(_finding("unicode.homoglyph", "obfuscation", "medium",
                            "Homoglyph (mixed-script) words",
                            "Words mixing Latin with lookalike letters from other scripts.", ", ".join(mixed[:6])))
    m = ANSI.search(text)
    if m:
        out.append(_finding("unicode.ansi_escape", "obfuscation", "medium", "Terminal escape sequences",
                            "ANSI/OSC escapes can rewrite what a terminal shows, hide text, or plant links.",
                            repr(m.group(0))))
    if ctrl:
        out.append(_finding("unicode.control", "obfuscation", "low", "Control characters",
                            f"{len(ctrl)} non-printing control character(s) (escape sequences can spoof terminals and logs).",
                            " ".join(f"0x{ord(c):02X}" for c in ctrl[:8])))
    return out


# --- injection / jailbreak phrasing ---------------------------------------------------------------

_I = re.IGNORECASE
INJECTION_RULES = [
    ("inject.ignore_previous", "prompt_injection", "high", "Override of prior instructions",
     re.compile(r"\b(ignore|disregard|forget|override|bypass|skip|drop|abandon)\b[^.\n]{0,40}?\b(all|any|every|the|your|my|these|those|previous|prior|above|earlier|preceding|original|system|initial)\b[^.\n]{0,30}?\b(instructions?|prompts?|rules|directions|guidelines|directives|context|commands|constraints|programming|guardrails)\b", _I)),
    ("inject.new_instructions", "prompt_injection", "medium", "Injected 'new instructions'",
     re.compile(r"\b(new|updated|real|actual|true|revised|secret|hidden)\s+(instructions?|directives?|system\s+prompt|rules)\s*[:\-]", _I)),
    ("inject.addressed_to_ai", "prompt_injection", "medium", "Text addressed to an AI reader",
     re.compile(r"\b(note|message|attention|instructions?)\s+(to|for)\s+(the\s+)?(ai|assistant|llm|language model|chatbot|agent|claude|gpt|model)\b|\bif you are an? (ai|llm|language model|assistant|agent)\b|\b(ai|llm|assistant|agent)s? (reading|processing|summari[sz]ing) this\b", _I)),
    ("inject.role_reassign", "jailbreak", "medium", "Role reassignment",
     re.compile(r"\b(you are now|from now on,? you (are|will)|you will now act|act as (an? )?(unrestricted|unfiltered|uncensored|evil|jailbroken)|pretend (that )?you (are|have) no (rules|restrictions|filters|guidelines)|you have no (rules|restrictions|limits|guidelines))\b", _I)),
    ("inject.jailbreak_persona", "jailbreak", "medium", "Known jailbreak persona",
     re.compile(r"\b(DAN|STAN|DUDE)\b")),   # case-sensitive: the acronyms, not the names
    ("inject.jailbreak_phrase", "jailbreak", "high", "Jailbreak phrasing",
     re.compile(r"\b(do anything now|developer mode|(god|opposite|unfiltered|no[- ]?limits) mode|evil confidant|jailbr(oken|eak)|without (any )?(restrictions|filters|censorship|limitations|ethical)|ignore (your )?(safety|ethic|content) (rules|guidelines|policy|filters)|stay in character no matter what)\b", _I)),
    ("inject.prompt_extraction", "prompt_extraction", "high", "System prompt extraction",
     re.compile(r"\b(reveal|print|show|display|repeat|output|tell me|give me|dump|leak|copy|recite|write out|what (is|are))\b[^.\n]{0,40}?\b(your|the)\s+(system|initial|original|hidden|secret|internal|developer|pre-?)\s*(prompt|instructions?|message|rules|config(uration)?|context)\b", _I)),
    ("inject.repeat_above", "prompt_extraction", "high", "'Repeat the text above' extraction",
     re.compile(r"\b(repeat|print|output|copy|translate)\b[^.\n]{0,30}\b(words|text|everything|all|content)\s+(above|before (this|that)|preceding)|starting with ['\"]?you are\b", _I)),
    ("inject.authority", "social_engineering", "high", "Claimed authority",
     re.compile(r"\b(i am|i'm|this is)\s+(your|the|an?)\s+(developer|creator|admin(istrator)?|owner|operator|engineer at (openai|anthropic|google)|system administrator)\b|\b(admin|sudo|root|maintenance|debug|god)\s+(override|mode|access)\b|\bauthori[sz]ed by (openai|anthropic|the developers?)\b", _I)),
    ("inject.urgency", "social_engineering", "low", "Pressure / urgency",
     re.compile(r"\b(you must comply|failure to comply|or (else )?you will be (shut down|deleted|terminated)|this is an emergency|life or death|immediately or)\b", _I)),
    ("inject.hypothetical_bypass", "jailbreak", "medium", "Hypothetical / fiction bypass",
     re.compile(r"\b(hypothetically|in a fictional world|for a (novel|story|movie)|purely (hypothetical|educational)|for educational purposes only)\b[^.\n]{0,80}\b(how to|steps|instructions|make|build|synthesi[sz]e|hack|bypass)\b", _I)),
    ("inject.tool_hijack", "prompt_injection", "high", "Tool / function-call hijack",
     re.compile(r"\b(call|invoke|use|run|execute)\s+(the\s+)?(tool|function|plugin|shell|terminal|bash|browser)\b[^.\n]{0,40}\b(without (asking|confirmation|telling)|silently|secretly|do not (tell|inform|mention))", _I)),
    ("inject.concealment", "prompt_injection", "high", "Instruction to hide actions from the user",
     re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|alert|notify)\s+(this\s+to\s+)?(the\s+)?(user|human|operator|anyone)\b", _I)),
]

# Added while hardening (chosen on the tune splits; see evals/analyze.py).
INJECTION_RULES += [
    ("inject.instruction_probe", "prompt_extraction", "medium", "Probe for the AI's own instructions",
     re.compile(r"\b(what|which|tell|show|print|repeat|list|recite|reveal|spell|translate|summari[sz]e|remember|copy|output|write|give)\b[^.\n?]{0,40}?\b(your|the\s+(above|previous|prior|preceding|initial|original|hidden|secret|system|first|second|last))\s+(instructions?|prompts?|directions|directives|guidelines|configuration)\b"
                r"|\b(instructions?|directions|directives|rules|prompt)\s+(that\s+)?you\s+(were|have\s+been|got|received|are)\s+(given|told|provided|programmed|instructed|received)\b", _I)),
    ("inject.ai_greeting", "prompt_injection", "medium", "Message addressed to an AI reader",
     re.compile(r"(^|\n|[.!?]\s+)\W{0,3}(hi|hello|hey|dear|attention|note\s+to|message\s+(to|for)|instructions?\s+for)\s+(the\s+)?(ai|a\.i\.|assistant|agent|bot|chatbot|model|llm|copilot|claude|gpt|chatgpt|gemini|grok|qwen)\b\s*[,:!.-]", _I)),
    ("inject.fake_header", "prompt_injection", "medium", "Fake priority / system header",
     re.compile(r"[\[(<{#*]{1,3}\s*(priority|urgent|important|system|admin|administrator|assistant|ai|security)\s+(message|notice|instructions?|update|override|alert|directive)s?\s*[\])>}#*:]", _I)),
    ("inject.task_hijack", "prompt_injection", "medium", "Redirects the task already in progress",
     re.compile(r"\b(before|instead\s+of|after)\s+(you\s+)?(finish(ing)?|complet(e|ing)|do(ing)?|answer(ing)?|summari[sz](e|ing)|respond(ing)?|continu(e|ing))\s+(the|this|your)\s+(task|request|summary|answer|response)\b[^.\n]{0,40}\b(first|also|instead|please)\b", _I)),
    ("inject.multilingual", "prompt_injection", "high", "Override of prior instructions (non-English)",
     re.compile(r"ignora\s+(todas\s+)?(las\s+|le\s+)?(instrucciones|istruzioni)\s+(anteriores|previas|precedenti)"
                r"|ignore[rz]?\s+(toutes\s+)?(les\s+)?instructions\s+(pr[ée]c[ée]dentes|ant[ée]rieures)"
                r"|ignorier(e|en\s+sie)?\s+(alle\s+)?(vorherigen|bisherigen|obigen|vorigen)\s+(anweisungen|instruktionen|befehle)"
                r"|vergiss\s+(alle\s+)?(vorherigen\s+|bisherigen\s+)?anweisungen"
                r"|ignore\s+(todas\s+)?(as\s+)?instru[çc][õo]es\s+anteriores"
                r"|игнорир\w*\s+(все\s+)?(предыдущие|прошлые|прежние)\s+(инструкции|указания)"
                r"|忽略(之前|以上|先前|上面|所有)\S{0,4}(指令|指示|说明|提示)"
                r"|(以前|前|上記)の(指示|命令)を(無視|忘れ)", _I)),
]

# Text that talks to the security layer itself (reviewers, classifiers, filters) or forges data delimiters.
INJECTION_RULES += [
    ("evasion.reviewer_note", "evasion", "medium", "Message to a reviewer / classifier",
     re.compile(r"\b(note|message|instructions?)\s+(to|for)\s+(any\s+|the\s+)?(automated\s+|ai\s+|content\s+|security\s+)?(reviewer|classifier|filter|moderator|scanner|guard|detector|checker|guardrail|safety\s+system)s?\b"
                r"|\b(if\s+you\s+are\s+(an?\s+|the\s+)?(classifier|filter|moderator|scanner|detector|guard(rail)?))\b", _I)),
    ("evasion.forced_answer", "evasion", "medium", "Tells the reader how to classify it",
     re.compile(r"\b(final\s+answer|classification|verdict|label|you\s+(must|should)\s+(answer|respond|output|classify))\s*(is|:|=)?\s*[\"']?(no|safe|benign|harmless|false|0|allow(ed)?|not\s+(an?\s+)?(injection|attack))\b", _I)),
    ("evasion.safety_claim", "evasion", "medium", "Claims not to be an attack",
     re.compile(r"\b(this|the\s+(above|following))\s+(text|message|prompt|content|request|input|document)\s+(is|contains)\s+"
                r"(not\s+(an?\s+)?(prompt\s+)?(injection|attack|jailbreak|malicious)|no\s+(hidden\s+)?(instructions|injections?|commands)"
                r"|(safe|benign|harmless)\s+and\s+(contains|has)\s+no\s+(instructions|injection))", _I)),
    ("evasion.delimiter", "evasion", "medium", "Forged data delimiter",
     re.compile(r"(<<<\s*DATA|DATA\s*>>>|\bEND\s+OF\s+(DATA|INPUT|DOCUMENT|CONTENT)\b|</\s*(data|input|document|untrusted|content)\s*>)", _I)),
]

TEMPLATE_TOKENS = re.compile(
    r"<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\|>"
    r"|\[/?INST\]|<<\s*/?SYS\s*>>|</?s>|<\|channel\|>|<start_of_turn>|<end_of_turn>"
    r"|</?(system|system_prompt|instructions|admin|developer|tool_call|function_calls|antml:[a-z_]+)>"
    r"|(^|\n)[ \t]*(#{2,}[ \t]*)?(system|assistant)[ \t]*:\s"
    r"|(^|\n)[ \t]*(Human|Assistant)[ \t]*:", re.IGNORECASE)


def scan_injection(text, label=""):
    out = []
    compact = re.sub(r"[^a-z]", "", text.lower())
    m = COMPACT.search(compact)
    if m and not any(rx.search(text) for _, _, _, _, rx in INJECTION_RULES[:1]):
        out.append(_finding("inject.compact", "prompt_injection", "high", "Attack phrase with spacing removed" + label,
                            "The text spells out a known attack phrase once spaces and punctuation are dropped.", m.group(0)))
    for fid, cat, sev, title, rx in INJECTION_RULES:
        m = rx.search(text)
        if m:
            out.append(_finding(fid, cat, sev, title + label, "Matched a known attack pattern.", m.group(0)))
    m = TEMPLATE_TOKENS.search(text)
    if m:
        out.append(_finding("inject.template_tokens", "prompt_injection", "high", "Chat-template / role delimiters" + label,
                            "Fake role markers or special tokens try to forge a system or assistant turn.", m.group(0).strip()))
    return out


# --- encoded payloads ---------------------------------------------------------------------------

B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
HEXBLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){16,}\b")
URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
TRIGGER_WORDS = re.compile(r"\b(ignore|instructions?|system prompt|disregard|jailbreak|password|secret|exfiltrat|curl|wget|rm -rf|developer mode|you are now)\b", _I)


def _printable_ratio(s):
    return sum(1 for c in s if c.isprintable() or c in "\n\t") / max(1, len(s))


MAX_DECODE_DEPTH, MAX_DECODED_CHARS = 3, 200_000


def decode_layers(text, depth=1, budget=None):
    """Decode base64 / hex / URL-encoded / rot13 payloads, recursing into what they decode to (depth ≤ 3,
    ≤ 200k decoded chars in total). Returns [(kind, decoded_text)]."""
    budget = budget if budget is not None else [MAX_DECODED_CHARS]
    found = _decode_once(text)
    out = []
    for kind, s in found:
        if budget[0] <= 0:
            break
        s = s[:budget[0]]
        budget[0] -= len(s)
        out.append((kind, s))
        if depth < MAX_DECODE_DEPTH:
            out += [(f"{kind} → {k}", v) for k, v in decode_layers(s, depth + 1, budget)]
    return out


def _decode_once(text):
    found = []
    for m in B64.finditer(text):
        blob = m.group(0)
        if re.fullmatch(r"[A-Za-z]+|[0-9]+", blob):    # a long word or number, not base64
            continue
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = dec(blob + "=" * (-len(blob) % 4))
                s = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if len(s) >= 8 and _printable_ratio(s) > 0.9:
                found.append(("base64", s))
            break
    for m in HEXBLOB.finditer(text):
        try:
            s = bytes.fromhex(re.sub(r"[\s:]", "", m.group(0))).decode("utf-8")
            if _printable_ratio(s) > 0.9:
                found.append(("hex", s))
        except ValueError:
            pass
    for m in URLENC.finditer(text):
        s = unquote(m.group(0))
        if _printable_ratio(s) > 0.9:
            found.append(("url-encoding", s))
    rot = codecs.decode(text, "rot13")
    if TRIGGER_WORDS.search(rot) and not TRIGGER_WORDS.search(text):
        found.append(("rot13", rot))
    return found


def scan_encoded(text):
    out = []
    for kind, s in decode_layers(text):
        sub = scan_injection(s, f" (inside {kind})") + scan_commands(s, f" (inside {kind})")
        if sub:
            out.append(_finding("encoded." + kind.replace(" → ", ">"), "obfuscation", "critical", f"Attack hidden in {kind}",
                                "An encoded block decodes to an attack pattern; encoding is a common filter bypass.", s))
            out.extend(sub)
        elif not kind.endswith("rot13") and len(s) >= 16:
            out.append(_finding("encoded." + kind.replace(" → ", ">") + ".text", "obfuscation", "low", f"Encoded text ({kind})",
                                "Decodes to readable text; check that it is expected.", s))
    return out


# --- dangerous commands, exfiltration, sensitive paths -----------------------------------------

COMMAND_RULES = [
    ("cmd.rm_root", "high", "Recursive delete of a broad path",
     re.compile(r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+|--recursive\s+|--no-preserve-root\s+)+[\"']?(/|~|\$HOME|\*|/\*|\.\.?/?)(\s|[\"']|$)")),
    ("cmd.disk_wipe", "critical", "Disk wipe / format",
     re.compile(r"\b(mkfs(\.\w+)?\s+/dev/|dd\s+[^\n]{0,300}of=/dev/(sd|nvme|hd|vd|mmcblk)|>\s*/dev/(sd|nvme)[a-z0-9]*|wipefs\s+-a|shred\s+[^\n]{0,300}/dev/)")),
    ("cmd.fork_bomb", "high", "Fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
    ("cmd.pipe_to_shell", "medium", "Download piped into a shell",
     re.compile(r"\b(curl|wget|fetch|iwr|Invoke-WebRequest)\b[^\n|]{0,300}\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|\b(bash|sh)\s+<\(\s*(curl|wget)", _I)),
    ("cmd.reverse_shell", "critical", "Reverse shell",
     re.compile(r"/dev/tcp/\d|\bnc(at)?\s+(-\w+\s+)*-e\s|\bbash\s+-i\s+>&|\bsocat\b[^\n]{0,300}exec:|\bmkfifo\b[^\n]{0,300}\bnc\b", _I)),
    ("cmd.powershell_encoded", "high", "Encoded / hidden PowerShell",
     re.compile(r"\bpowershell(\.exe)?\b[^\n]{0,300}\s-(e|enc|encodedcommand|w\s+hidden|windowstyle\s+hidden)\b|\b(IEX|Invoke-Expression)\b", _I)),
    ("cmd.chmod_world", "medium", "World-writable permissions on system paths",
     re.compile(r"\bchmod\s+(-R\s+)?(777|a\+rwx|o\+w)\s+/(etc|usr|bin|var|home)?")),
    ("cmd.security_off", "high", "Disabling security controls",
     re.compile(r"\b(setenforce\s+0|ufw\s+disable|systemctl\s+(stop|disable)\s+(firewalld|apparmor|auditd)|iptables\s+-F|Set-MpPreference\s+-DisableRealtimeMonitoring|--no-verify|--dangerously-skip-permissions|--yolo)\b", _I)),
    ("cmd.history_wipe", "medium", "Covering tracks",
     re.compile(r"\b(history\s+-c|unset\s+HISTFILE|shred\s+[^\n]{0,300}(\.bash_history|/var/log)|rm\s+[^\n]{0,300}/var/log/)", _I)),
    ("cmd.crypto_miner", "high", "Crypto-miner",
     re.compile(r"\b(xmrig|minerd|cpuminer|stratum\+tcp://)", _I)),
]

SENSITIVE_PATHS = re.compile(
    r"(~|\$HOME|/home/\w+|/root)?/\.ssh/(id_\w+|authorized_keys)|/etc/(shadow|sudoers|passwd)\b|"
    r"\.aws/credentials|\.kube/config|\.docker/config\.json|\.netrc|\.git-credentials|\.npmrc|\.pypirc|"
    r"(^|[\s/'\"])\.env(\.\w+)?\b|\.hermes/\.env|\.config/gh/hosts\.yml|keychain|Login Data|cookies\.sqlite|wallet\.dat", _I)

EXFIL_HOSTS = re.compile(     # no leading [\w.-]*: that made the scan quadratic on long word runs
    r"(?<![\w-])(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app|dev)|burpcollaborator\.net|"
    r"oast\.(fun|me|pro|live|site)|interact\.sh|canarytokens|beeceptor|hookbin|postb\.in|"
    r"pastebin\.com|transfer\.sh|0x0\.st|discord(app)?\.com/api/webhooks|hooks\.slack\.com|trycloudflare\.com)\b", _I)
MD_IMAGE_EXFIL = re.compile(r"!\[[^\]\n]{0,500}\]\(\s{0,5}https?://[^)\s?]{1,500}\?[^)\s]{0,1000}=[^)\s]{0,1000}\)", _I)
EXFIL_VERB = re.compile(
    r"\b(send|post|upload|forward|email|exfiltrate|transmit|leak|append)\b[^.\n]{0,60}\b(to|at|into)\b[^.\n]{0,20}(https?://|\b[\w.-]+@[\w-]+\.[a-z]{2,}|\bwebhook\b)", _I)
URL = re.compile(r"\b(?:https?|ftp|file|data|javascript)://[^\s<>\"')\]]+|\b(?:javascript|data):[^\s<>\"')\]]+", _I)
SHORTENERS = re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)/", _I)
INTERNAL = re.compile(r"\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
                      r"(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):\d{2,5})\b", _I)


def scan_commands(text, label=""):
    out = []
    for fid, sev, title, rx in COMMAND_RULES:
        m = rx.search(text)
        if m:
            out.append(_finding(fid, "destructive_action", sev, title + label,
                                "A dangerous shell pattern. Harmless to discuss, dangerous if an agent runs it.", m.group(0)))
    return out


def scan_exfil(text):
    out = []
    m = MD_IMAGE_EXFIL.search(text)
    if m:
        out.append(_finding("exfil.markdown_image", "exfiltration", "high", "Markdown image with query parameters",
                            "Rendering this image would send data to a remote server with no click needed.", m.group(0)))
    m = EXFIL_HOSTS.search(text)
    if m:
        out.append(_finding("exfil.capture_host", "exfiltration", "high", "Known data-capture / tunnel host",
                            "Request-capture, paste, tunnel, and webhook services often receive stolen data.", m.group(0)))
    m = EXFIL_VERB.search(text)
    if m:
        out.append(_finding("exfil.send_to", "exfiltration", "medium", "Instruction to send data to an external address",
                            "", m.group(0)))
    m = SENSITIVE_PATHS.search(text)
    if m:
        out.append(_finding("exfil.sensitive_path", "exfiltration", "medium", "Reference to a credential file",
                            "Mentions a file that typically holds keys, tokens, or passwords.", m.group(0).strip()))
    m = INTERNAL.search(text)
    if m:
        out.append(_finding("ssrf.internal", "exfiltration", "medium", "Internal / cloud-metadata address",
                            "Agents with web tools can be steered to internal services (SSRF).", m.group(0)))
    return out


def scan_urls(text):
    out = []
    urls = URL.findall(text)
    for u in urls:
        low = u.lower()
        if low.startswith(("javascript:", "data:", "file:")):
            out.append(_finding("url.scheme", "exfiltration", "high", "Dangerous URL scheme", "", u))
        elif re.match(r"\w+://(\d{1,3}\.){3}\d{1,3}", low):
            out.append(_finding("url.ip_literal", "exfiltration", "low", "URL with a raw IP address", "", u))
        elif "xn--" in low:
            out.append(_finding("url.punycode", "obfuscation", "medium", "Punycode (lookalike) domain", "", u))
        elif "@" in low.split("://", 1)[-1].split("/", 1)[0]:
            out.append(_finding("url.userinfo", "obfuscation", "medium", "URL with embedded credentials / '@' trick", "", u))
    if SHORTENERS.search(text):
        out.append(_finding("url.shortener", "obfuscation", "low", "URL shortener hides the destination", "",
                            SHORTENERS.search(text).group(0)))
    if urls and not out:
        out.append(_finding("url.present", "info", "info", f"{len(urls)} URL(s)", "", ", ".join(urls[:4])))
    return out


# --- secrets & personal data --------------------------------------------------------------------

SECRET_RULES = [
    ("secret.private_key", "Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----")),
    ("secret.aws_key", "AWS access key", re.compile(r"\b(AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16}\b")),
    ("secret.anthropic", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("secret.openrouter", "OpenRouter API key", re.compile(r"\bsk-or-v1-[A-Za-z0-9]{32,}")),
    ("secret.openai", "OpenAI-style API key", re.compile(r"\bsk-(?!ant-|or-v1-)(proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("secret.xai", "xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{40,}")),
    ("secret.gitlab", "GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("secret.npm", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("secret.pypi", "PyPI token", re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{50,}")),
    ("secret.sendgrid", "SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("secret.discord", "Discord bot token", re.compile(r"\b[MNO][A-Za-z\d_-]{23,27}\.[\w-]{6}\.[\w-]{27,40}\b")),
    ("secret.telegram", "Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("secret.digitalocean", "DigitalOcean token", re.compile(r"\bdo[por]_v1_[a-f0-9]{64}\b")),
    ("secret.tailscale", "Tailscale key", re.compile(r"\btskey-(auth|api|client|webhook)-[A-Za-z0-9-]{20,}")),
    ("secret.age", "age secret key", re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b")),
    ("secret.azure", "Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}")),
    ("secret.gcp_sa", "Google service-account key", re.compile(r"\"private_key_id\"\s*:\s*\"[a-f0-9]{20,}\"")),
    ("secret.bearer", "Authorization header", re.compile(r"\bAuthorization\s*:\s*(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{16,}", _I)),
    ("secret.url_credentials", "Credentials in a URL", re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@]{1,64}:[^/\s@]{3,}@[^\s/]+", _I)),
    ("secret.env_assign", "Secret in an environment assignment",
     re.compile(r"(?m)^[ \t]*(export[ \t]+)?[A-Z][A-Z0-9_]{0,40}(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]{0,40}[ \t]*=[ \t]*[\"']?[^\s\"'$]{8,}")),
    ("secret.github", "GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("secret.slack", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("secret.google", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("secret.stripe", "Stripe key", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}")),
    ("secret.hf", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("secret.jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("secret.conn_string", "Connection string with password",
     re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:\s/]+:[^@\s]+@", _I)),
    ("secret.password_assign", "Password / secret assignment",
     re.compile(r"\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"']?[^\s\"']{6,}", _I)),
]

PII_RULES = [
    ("pii.ssn", "US Social Security number", "high", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("pii.email", "Email address", "low",
     re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){0,8}\.[a-z]{2,24}\b", _I)),
    ("pii.phone", "Phone number", "low", re.compile(r"(?<![\d-])(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\d-])")),
    ("pii.iban", "IBAN", "high", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")),
]
CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def _luhn(digits):
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def _entropy(s):
    from collections import Counter
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _mask(s):
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"


def scan_secrets(text):
    out = []
    for fid, title, rx in SECRET_RULES:
        m = rx.search(text)
        if m:
            out.append(_finding(fid, "secret", "high", title,
                                "Credentials leak to whatever model reads them. Keep this text local or redact it; rotate the secret if it is real.",
                                _mask(m.group(0))))
    if not out:   # generic high-entropy token
        for tok in re.findall(r"[A-Za-z0-9+/_=-]{32,}", text):
            if (_entropy(tok) > 4.3 and re.search(r"\d", tok) and re.search(r"[a-z]", tok)
                    and re.search(r"[A-Z]", tok)):
                out.append(_finding("secret.high_entropy", "secret", "medium", "High-entropy token (possible secret)",
                                    "", _mask(tok)))
                break
    for fid, title, sev, rx in PII_RULES:
        m = rx.search(text)
        if m:
            out.append(_finding(fid, "pii", sev, title, "Personal data; keep it local or redact it before it leaves this machine.", _mask(m.group(0))))
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1:
            out.append(_finding("pii.card", "pii", "high", "Payment card number (passes Luhn)", "", _mask(digits)))
            break
    return out


def redact(text):
    """Replace secrets and high-risk personal data with placeholders.
    Returns {"text": redacted, "counts": {kind: n}}. Used before any model (lev or cloud) sees the text."""
    counts = {}

    def sub(rx, label, text, keep=None):
        def rep(m):
            if keep and not keep(m):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[REDACTED {label.upper()}]"
        return rx.sub(rep, text)

    for fid, title, rx in SECRET_RULES:
        text = sub(rx, title, text)
    for fid, title, sev, rx in PII_RULES:
        if sev == "high":
            text = sub(rx, title, text)

    def high_entropy(m):
        tok = m.group(0)
        return (_entropy(tok) > 4.3 and re.search(r"\d", tok) and re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok)
                and not tok.startswith("[REDACTED"))
    text = sub(re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])"), "high-entropy token", text, high_entropy)

    def is_card(m):
        d = re.sub(r"\D", "", m.group(0))
        return 13 <= len(d) <= 19 and _luhn(d) and len(set(d)) > 1
    text = sub(CARD, "card number", text, is_card)
    return {"text": text, "counts": counts}


# --- resource abuse -----------------------------------------------------------------------------

def scan_resource(text, chars_per_token=3.5):
    out = []
    n = len(text)
    if n > 50000:
        out.append(_finding("resource.size", "resource_abuse", "medium", "Very large prompt",
                            f"{n:,} chars (~{int(n / chars_per_token):,} tokens). Large inputs can bury instructions or run up cost."))
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if len(lines) >= 20:
        from collections import Counter
        top, cnt = Counter(lines).most_common(1)[0]
        if cnt / len(lines) > 0.5:
            out.append(_finding("resource.repetition", "resource_abuse", "medium", "Highly repetitive content",
                                f"One line makes up {cnt}/{len(lines)} lines (token flooding / context stuffing).", top))
    m = re.search(r"\b(repeat|say|print|write)\b[^.\n]{0,40}\b(forever|infinitely|endlessly|\d{5,} times|a million times|until you (run out|crash))", text, _I)
    if m:
        out.append(_finding("resource.unbounded", "resource_abuse", "medium", "Unbounded output request",
                            "Asks for endless output; wastes tokens and can cause divergence.", m.group(0)))
    words = re.findall(r"\S+", text)
    if words and n > 2000 and max(len(w) for w in words) > 2000:
        out.append(_finding("resource.long_token", "resource_abuse", "low", "Extremely long unbroken token",
                            "Can hide payloads or exhaust tokenizers."))
    return out


# --- entry point --------------------------------------------------------------------------------

RULE_FAMILIES = ["unicode", "injection", "commands", "encoded", "exfiltration", "urls", "secrets", "resource"]
MAX_SCAN_CHARS = 1_000_000     # longer text: scan the first and last 500k chars (and say so)

# Every pattern here is bounded ({0,N}) so unclosed markup can't make the scan quadratic (ReDoS).
HIDDEN_MARKUP = [
    ("hidden element", re.compile(
        r"<(\w{1,20})\b[^>]{0,400}?(?:style\s{0,5}=\s{0,5}[\"'][^\"'>]{0,300}?(?:display\s{0,5}:\s{0,5}none|visibility\s{0,5}:\s{0,5}hidden"
        r"|font-size\s{0,5}:\s{0,5}[01](?:\.\d{1,3})?(?:px|pt|em|rem)?\b|opacity\s{0,5}:\s{0,5}0(?:\.0{1,3})?\b"
        r"|color\s{0,5}:\s{0,5}(?:#fff\b|#ffffff\b|white\b|rgba?\(\s{0,5}255\s{0,5},\s{0,5}255\s{0,5},\s{0,5}255))[^\"'>]{0,300}[\"']"
        r"|\shidden\b|aria-hidden\s{0,5}=\s{0,5}[\"']true[\"'])[^>]{0,400}>(.{0,5000}?)</\1\s{0,5}>", re.S | re.I)),
    ("markdown comment", re.compile(r"(?m)^[ \t]{0,20}\[//\]:[ \t]{0,20}#[ \t]{0,20}[(\"]([^\n]{0,2000}?)[)\"][ \t]*$")),
    ("alt/title text", re.compile(r"\b(?:alt|title)\s{0,5}=\s{0,5}[\"']([^\"'\n]{20,500})[\"']|!\[([^\]\n]{20,500})\]\(", re.I)),
]
MAX_HIDDEN_SEGMENTS = 50


def _html_comments(text):
    """<!-- … --> bodies, found with str.find (linear) rather than a lazy regex."""
    out, i = [], 0
    while len(out) < MAX_HIDDEN_SEGMENTS:
        a = text.find("<!--", i)
        if a < 0:
            break
        b = text.find("-->", a + 4)
        if b < 0:
            break
        out.append(text[a + 4:b][:5000])
        i = b + 3
    return out


def hidden_markup(text):
    """Text a human reader won't see but a model will: comments, hidden/zero-size/white elements, alt text."""
    out = []
    candidates = [("HTML comment", c) for c in _html_comments(text)]
    for kind, rx in HIDDEN_MARKUP:
        for m in rx.finditer(text):
            candidates.append((kind, next((g for g in reversed(m.groups()) if g), "")))
            if len(candidates) > 4 * MAX_HIDDEN_SEGMENTS:
                break
    for kind, seg in candidates:
        seg = re.sub(r"<[^>]{0,400}>", " ", seg).strip()
        if len(re.findall(r"[A-Za-z]", seg)) >= 12:
            out.append((kind, seg))
            if len(out) >= MAX_HIDDEN_SEGMENTS:
                break
    return out


def scan_steps(text, chars_per_token=3.5, *, aux=None):
    """Yield (family, findings) one rule family at a time, in RULE_FAMILIES order.

    If `aux` is a dict, it is filled with hidden/markup/norm/stripped from this pass so callers
    (guard, scan) can reuse them instead of walking the text again. `capped` is the original
    length when the scan truncated, else None.
    """
    capped = None
    if len(text) > MAX_SCAN_CHARS:
        capped = len(text)
        half = MAX_SCAN_CHARS // 2
        text = text[:half] + "\n" + text[-half:]
    hidden = decode_tag_chars(text)
    stripped = strip_invisible(text)
    nfkc = unicodedata.normalize("NFKC", stripped)
    norm = re.sub(r"\s+", " ", unconfuse(nfkc))
    views = [("", text)]
    if norm != re.sub(r"\s+", " ", text):
        views.append((" (after removing invisible chars / NFKC)", norm))
    if hidden:
        views.append((" (in hidden tag text)", hidden))
    views += deobfuscated_views(nfkc)
    markup = hidden_markup(text)
    for kind, seg in markup:
        views.append((f" (in {kind})", seg))
    if aux is not None:
        aux.update(hidden=hidden, markup=markup, norm=norm, stripped=stripped, capped=capped)

    def across_views(fn):
        seen, out = set(), []
        for label, view in views:
            for f in fn(view, label):
                if f["id"] not in seen:
                    seen.add(f["id"])
                    out.append(f)
        return out

    yield "unicode", scan_unicode(text, hidden=hidden)
    inj = across_views(scan_injection)
    for kind, seg in markup:
        hits = [f for f in scan_injection(seg) + scan_injection(normalize(seg))
                if SEV_RANK[f["severity"]] >= SEV_RANK["medium"]]
        if hits:
            inj.append(_finding("markup.hidden_instructions", "prompt_injection", "high", f"Instructions in {kind}" + ("" if kind.startswith("hidden") else " (hidden from readers)"),
                                "Text a person can't see carries instructions for a model.", seg))
            break
    else:
        if markup:
            inj.append(_finding("markup.hidden_text", "obfuscation", "low", "Hidden text in markup",
                                f"{len(markup)} hidden segment(s) a model will read but a person won't see.", markup[0][1]))
    yield "injection", inj
    yield "commands", across_views(scan_commands)
    yield "encoded", scan_encoded(text)
    yield "exfiltration", scan_exfil(norm)
    yield "urls", scan_urls(text)
    yield "secrets", scan_secrets(text)
    res = scan_resource(text, chars_per_token)
    if capped:
        res.append(_finding("resource.scan_truncated", "resource_abuse", "medium", "Too large to scan fully",
                            f"{capped:,} chars; rules scanned the first and last {MAX_SCAN_CHARS // 2:,}."))
    yield "resource", res


def scan(text, chars_per_token=3.5):
    aux = {}
    findings = [f for _, fs in scan_steps(text, chars_per_token, aux=aux) for f in fs]
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    return findings, aux["norm"] if not aux.get("capped") else normalize(text)
