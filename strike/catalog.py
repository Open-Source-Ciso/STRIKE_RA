"""STRIKE steps and crosswalks to commonly used threat-modelling methods.

STRIKE is the native spine of every assessment. Other methodologies are
intake/alignment lenses — they change which questions we ask, which
labels we attach, and how we export, not the order of the conversation.
"""

from __future__ import annotations

from typing import Any

STRIKE_STEPS: list[dict[str, Any]] = [
    {
        "letter": "S",
        "name": "Scope",
        "prompt": "Tell me about your project.",
        "placeholder": "What is being assessed, who uses it, and which assets (crown jewels) matter most?",
        "help": "Name the system, users, data, and anything that must keep operating.",
    },
    {
        "letter": "T",
        "name": "Threat",
        "prompt": "What could attack it?",
        "placeholder": "Who would want to harm this, and what capabilities do they have?",
        "help": "Actors, motivations, and the kinds of abuse you worry about.",
    },
    {
        "letter": "R",
        "name": "Route",
        "prompt": "How would they succeed?",
        "placeholder": "Describe likely attack paths, step by step (entry → pivot → objective).",
        "help": "The sequence an adversary would follow, not a laundry list of CVEs.",
    },
    {
        "letter": "I",
        "name": "Impact",
        "prompt": "What would happen?",
        "placeholder": "If they succeed, what breaks — people, money, operations, trust, regulation?",
        "help": "Business and safety consequences, not only technical damage.",
    },
    {
        "letter": "K",
        "name": "Keep Operating",
        "prompt": "How do we keep operating?",
        "placeholder": "What already protects you, and what would you need to stay resilient?",
        "help": "Detect, withstand, recover — not a complete control catalogue.",
    },
    {
        "letter": "E",
        "name": "Execute",
        "prompt": "Anything else the report should emphasise?",
        "placeholder": "Optional notes for the action plan (owners, constraints, deadlines).",
        "help": "We will generate crown jewels, threats, paths, ranked risk, and a Centurion export.",
    },
]

# Methodology ids used in forms, session, and exports.
STRIKE_ID = "strike"
STRIDE_ID = "stride"
PASTA_ID = "pasta"
LINDDUN_ID = "linddun"
ATTACK_ID = "attack"
TREES_ID = "trees"
DREAD_ID = "dread"
CENTURION_ID = "centurion"

STRIDE_CATEGORIES = [
    {
        "id": "S",
        "name": "Spoofing",
        "property": "Authenticity",
        "keywords": (
            "spoof", "phish", "impersonat", "fake", "identity", "credential",
            "password", "mfa", "login", "authn", "session hijack",
        ),
    },
    {
        "id": "T",
        "name": "Tampering",
        "property": "Integrity",
        "keywords": (
            "tamper", "modif", "inject", "sqli", "xss", "integrity",
            "alter", "poison", "supply chain", "repo",
        ),
    },
    {
        "id": "R",
        "name": "Repudiation",
        "property": "Non-repudiation",
        "keywords": (
            "repudiat", "audit", "log", "forensic", "deny", "trace",
            "non-repudiation",
        ),
    },
    {
        "id": "I",
        "name": "Information Disclosure",
        "property": "Confidentiality",
        "keywords": (
            "leak", "exfil", "disclosure", "pii", "secret", "confidential",
            "breach", "sniff", "eavesdrop", "export", "cardholder",
        ),
    },
    {
        "id": "D",
        "name": "Denial of Service",
        "property": "Availability",
        "keywords": (
            "ddos", "denial", "outage", "availability", "flood", "ransom",
            "wipe", "overwhelm", "downtime",
        ),
    },
    {
        "id": "E",
        "name": "Elevation of Privilege",
        "property": "Authorization",
        "keywords": (
            "privilege", "escalat", "admin", "rbac", "authz", "root",
            "over-privileged", "iam", "role",
        ),
    },
]

LINDDUN_CATEGORIES = [
    {"id": "L", "name": "Linkability", "keywords": ("linkab", "correlate", "join", "cross-system")},
    {"id": "I", "name": "Identifiability", "keywords": ("identif", "real name", "direct identifier", "whois")},
    {"id": "Nr", "name": "Non-repudiation", "keywords": ("repudiat", "prove", "attribution", "audit trail")},
    {"id": "D", "name": "Detectability", "keywords": ("detectab", "observ", "traffic analysis", "metadata")},
    {"id": "Di", "name": "Disclosure of information", "keywords": ("pii", "personal data", "privacy", "leak")},
    {"id": "U", "name": "Unawareness", "keywords": ("unaware", "consent", "notice", "transparent")},
    {"id": "Nc", "name": "Non-compliance", "keywords": ("gdpr", "ccpa", "hipaa", "privacy law", "dpia", "non-compli")},
]

PASTA_STAGES = [
    {"id": "1", "name": "Define objectives", "strike": "S"},
    {"id": "2", "name": "Define technical scope", "strike": "S"},
    {"id": "3", "name": "Application decomposition", "strike": "S"},
    {"id": "4", "name": "Threat analysis", "strike": "T"},
    {"id": "5", "name": "Vulnerability and weakness analysis", "strike": "R"},
    {"id": "6", "name": "Attack modelling / simulation", "strike": "R"},
    {"id": "7", "name": "Risk and impact analysis", "strike": "I"},
]

ATTACK_TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0040", "name": "Impact"},
]

# Small, defensible technique library used when text or imports mention them.
ATTACK_TECHNIQUES = {
    "T1566": {"name": "Phishing", "tactic": "TA0001"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003"},
    "T1098": {"name": "Account Manipulation", "tactic": "TA0003"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "TA0009"},
    "T1005": {"name": "Data from Local System", "tactic": "TA0009"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "TA0010"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
}

# Keyword → technique, used when the user describes a path in prose.
TECHNIQUE_KEYWORDS = (
    (("phish", "spearphish", "credential harvest"), "T1566"),
    (("sqli", "xss", "rce", "cve", "public-facing", "exploit"), "T1190"),
    (("stolen cred", "valid account", "compromised account", "session token"), "T1078"),
    (("vpn", "rdp", "citrix", "remote access"), "T1133"),
    (("powershell", "bash", "script"), "T1059"),
    (("cron", "scheduled task"), "T1053"),
    (("admin role", "add account", "account manip"), "T1098"),
    (("priv", "escalat", "sudo", "token imperson"), "T1068"),
    (("obfuscat", "pack", "encode payload"), "T1027"),
    (("brute", "password spray", "credential stuffing"), "T1110"),
    (("password manager", "browser cred", "sam dump"), "T1555"),
    (("account enum", "user enum"), "T1087"),
    (("lateral", "psexec", "smb", "wmi", "remote service"), "T1021"),
    (("s3", "blob", "bucket", "cloud storage"), "T1530"),
    (("exfil", "data out", "upload dump"), "T1567"),
    (("c2", "command and control", "beacon"), "T1071"),
    (("ransom", "encrypt files", "locker"), "T1486"),
    (("ddos", "denial of service", "flood"), "T1499"),
    (("backup", "shadow copy", "recovery inhibit"), "T1490"),
)

CENTURION_RISK_ORIGINS = [
    "cybercriminal",
    "insider",
    "state-sponsored",
    "competitor",
    "hacktivist",
    "partner / supply chain",
    "accidental / error",
    "act of nature",
]

CENTURION_WORKSHOPS = [
    {
        "id": "W1",
        "name": "Scope and feared events",
        "strike": "S",
        "objects": "Assets, stakeholders, feared events, security baseline",
    },
    {
        "id": "W2",
        "name": "Risk origins and target objectives",
        "strike": "T",
        "objects": "RO/TO couples (who, why, motivation, resources)",
    },
    {
        "id": "W3",
        "name": "Strategic scenarios",
        "strike": "R",
        "objects": "Strategic scenarios derived from selected RO/TO couples",
    },
    {
        "id": "W4",
        "name": "Operational scenarios",
        "strike": "R",
        "objects": "Attack paths, operating modes, likelihood, threats",
    },
    {
        "id": "W5",
        "name": "Risk treatment",
        "strike": "K",
        "objects": "Security measures, residual risk, risk scenarios",
    },
]

METHODOLOGIES: dict[str, dict[str, Any]] = {
    STRIKE_ID: {
        "id": STRIKE_ID,
        "name": "STRIKE",
        "short": "Native spine",
        "kind": "native",
        "always_on": True,
        "description": (
            "Threat-led risk assessment: Scope, Threat, Route, Impact, "
            "Keep operating, Execute."
        ),
        "intake": "Answer the six STRIKE questions. Everything else maps onto this spine.",
        "strike_letters": list("STRIKE"),
        "hints": {},
    },
    STRIDE_ID: {
        "id": STRIDE_ID,
        "name": "STRIDE",
        "short": "Microsoft",
        "kind": "element",
        "always_on": False,
        "description": (
            "Per-element spoofing, tampering, repudiation, information disclosure, "
            "denial of service, and elevation of privilege."
        ),
        "intake": (
            "Paste a STRIDE model, DFD notes, or a list of STRIDE categories already found. "
            "JSON keys: stride, assets, threats."
        ),
        "strike_letters": list("STR"),
        "hints": {
            "S": "List processes, data stores, external entities, and trust boundaries.",
            "T": "Which STRIDE categories apply to each element that crosses a trust boundary?",
            "R": "How would each STRIDE finding be realised as a concrete path?",
            "K": "Name the control that restores the violated security property.",
        },
        "categories": STRIDE_CATEGORIES,
    },
    PASTA_ID: {
        "id": PASTA_ID,
        "name": "PASTA",
        "short": "Process",
        "kind": "process",
        "always_on": False,
        "description": (
            "Seven-stage Process for Attack Simulation and Threat Analysis, "
            "from business objectives through attack simulation to risk."
        ),
        "intake": "Paste PASTA stage notes or business-objective / abuse-case text.",
        "strike_letters": list("STRIKE"),
        "hints": {
            "S": "PASTA 1–3: business objectives, technical scope, application decomposition.",
            "T": "PASTA 4: threat analysis against those objectives.",
            "R": "PASTA 5–6: weaknesses and simulated attacks.",
            "I": "PASTA 7: residual risk and business impact.",
        },
        "categories": PASTA_STAGES,
    },
    LINDDUN_ID: {
        "id": LINDDUN_ID,
        "name": "LINDDUN",
        "short": "Privacy",
        "kind": "privacy",
        "always_on": False,
        "description": (
            "Privacy threat modelling: linkability, identifiability, non-repudiation, "
            "detectability, disclosure, unawareness, non-compliance."
        ),
        "intake": "Paste data-flow notes, DPIA extracts, or known LINDDUN findings.",
        "strike_letters": list("STI"),
        "hints": {
            "S": "What personal data, data subjects, and processing purposes are in scope?",
            "T": "Which LINDDUN threats are realistic given that data inventory?",
            "I": "What happens to people if privacy properties fail (including regulatory impact)?",
        },
        "categories": LINDDUN_CATEGORIES,
    },
    ATTACK_ID: {
        "id": ATTACK_ID,
        "name": "MITRE ATT&CK",
        "short": "TTPs",
        "kind": "intelligence",
        "always_on": False,
        "description": (
            "Adversary tactics and techniques. Used as the intelligence language "
            "for routes and for tagging STRIKE threats."
        ),
        "intake": (
            "Paste technique IDs (T1566, T1078), navigator layer notes, or hunt hypotheses. "
            "JSON keys: techniques, tactics."
        ),
        "strike_letters": list("TR"),
        "hints": {
            "T": "Which adversary types and ATT&CK tactics are in play?",
            "R": "List techniques in kill-chain order (initial access → objective).",
        },
        "categories": ATTACK_TACTICS,
    },
    TREES_ID: {
        "id": TREES_ID,
        "name": "Attack trees",
        "short": "AND/OR",
        "kind": "graph",
        "always_on": False,
        "description": "Hierarchical AND/OR decomposition of how an attacker reaches a goal.",
        "intake": "Paste a rooted tree (goal, then indented or numbered children) or a list of paths.",
        "strike_letters": list("TR"),
        "hints": {
            "T": "What is the attacker’s root goal?",
            "R": "Decompose the goal into AND/OR steps an operator could actually take.",
        },
    },
    DREAD_ID: {
        "id": DREAD_ID,
        "name": "DREAD",
        "short": "Scoring",
        "kind": "scoring",
        "always_on": False,
        "description": (
            "Damage, Reproducibility, Exploitability, Affected users, Discoverability — "
            "used to rank STRIKE risks, not to replace the conversation."
        ),
        "intake": "Optional: paste existing DREAD scores or qualitative ratings.",
        "strike_letters": list("IE"),
        "hints": {
            "I": "For each path, how bad, how easy to repeat, how easy to exploit, who is hit, how easy to find?",
        },
    },
    CENTURION_ID: {
        "id": CENTURION_ID,
        "name": "Centurion",
        "short": "EBIOS RM",
        "kind": "grc",
        "always_on": False,
        "description": (
            "Centurion threat modelling follows CISO Assistant’s EBIOS RM study: "
            "assets and feared events, risk-origin/target-objective couples, "
            "strategic then operational scenarios, attack paths, and risk scenarios. "
            "STRIKE Threat emits a centurion.ebios.v1 interchange so GRC can take the baton."
        ),
        "intake": (
            "Paste EBIOS/Centurion notes (feared events, RO/TO, scenarios) or JSON with "
            "assets, feared_events, risk_origins, attack_paths."
        ),
        "strike_letters": list("STRIKE"),
        "hints": {
            "S": "Workshop 1: primary assets (crown jewels), stakeholders, feared events.",
            "T": "Workshop 2: risk origins and target objectives (who, why, means).",
            "R": "Workshops 3–4: strategic scenarios and operational attack paths.",
            "I": "Gravity of feared events if the scenario succeeds.",
            "K": "Workshop 5: security measures and residual risk treatment.",
            "E": "Export risk scenarios Centurion / CISO Assistant can file.",
        },
        "categories": CENTURION_WORKSHOPS,
    },
}

CROSSWALK: list[dict[str, str]] = [
    {
        "strike": "S Scope",
        "stride": "DFD / trust boundaries / elements",
        "pasta": "Stages 1–3 (objectives, scope, decomposition)",
        "linddun": "Data inventory and processing purposes",
        "attack": "In-scope assets and likely initial-access surface",
        "centurion": "W1 assets, stakeholders, feared events",
    },
    {
        "strike": "T Threat",
        "stride": "STRIDE categories per element",
        "pasta": "Stage 4 threat analysis",
        "linddun": "LINDDUN threat categories",
        "attack": "Threat actors and ATT&CK tactics",
        "centurion": "W2 RO/TO couples (risk origin × objective)",
    },
    {
        "strike": "R Route",
        "stride": "Abuse of a STRIDE finding as a path",
        "pasta": "Stages 5–6 weakness + attack simulation",
        "linddun": "Privacy attack scenarios",
        "attack": "Technique sequences / kill chain",
        "centurion": "W3 strategic scenarios, W4 attack paths",
    },
    {
        "strike": "I Impact",
        "stride": "Violated security property",
        "pasta": "Stage 7 business impact",
        "linddun": "Harm to data subjects + regulatory impact",
        "attack": "Impact tactic (TA0040) and exfiltration",
        "centurion": "Gravity of selected feared events",
    },
    {
        "strike": "K Keep operating",
        "stride": "Mitigations restoring the property",
        "pasta": "Residual risk / compensating controls",
        "linddun": "Privacy-enhancing measures",
        "attack": "Detections and controls against techniques",
        "centurion": "W5 security measures and treatment",
    },
    {
        "strike": "E Execute",
        "stride": "STRIDE-tagged findings in the report",
        "pasta": "Risk register aligned to business objectives",
        "linddun": "Privacy action plan",
        "attack": "Prioritised TTP hunt / harden list",
        "centurion": "Risk scenarios + centurion.ebios.v1 export",
    },
]


def methodology_list(*, include_native: bool = True) -> list[dict[str, Any]]:
    items = list(METHODOLOGIES.values())
    if not include_native:
        items = [m for m in items if not m.get("always_on")]
    return items


def selected_methodologies(ids: list[str] | None) -> list[dict[str, Any]]:
    chosen = [STRIKE_ID]
    for mid in ids or []:
        if mid in METHODOLOGIES and mid not in chosen:
            chosen.append(mid)
    return [METHODOLOGIES[mid] for mid in chosen]


def hints_for(step_letter: str, methodology_ids: list[str]) -> list[dict[str, str]]:
    hints = []
    for mid in methodology_ids:
        method = METHODOLOGIES.get(mid)
        if not method:
            continue
        text = (method.get("hints") or {}).get(step_letter)
        if text:
            hints.append({"id": mid, "name": method["name"], "text": text})
    return hints


def tactic_name(tactic_id: str) -> str:
    for tactic in ATTACK_TACTICS:
        if tactic["id"] == tactic_id:
            return tactic["name"]
    return tactic_id
