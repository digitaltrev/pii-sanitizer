from __future__ import annotations

PII_RULES: list[tuple[str, list[str]]] = [
    ("Government ID", [
        "social security", "ssn", "tax id", "taxid", "tax_id",
        "tin", "ein", "itin", "government id",
    ]),
    ("Date of Birth", [
        "date of birth", "birth date", "dob", "birth",
    ]),
    ("Name", [
        "first name", "last name", "middle name", "full name",
        "fname", "lname", "mname", "suffix", "prefix", "salutation",
        "name1", "name2", "name3", "dba", "business name", "legal name",
    ]),
    ("Contact – Email", ["email"]),
    ("Contact – Phone", [
        "home phone", "business phone", "mobile phone", "cell phone",
        "work phone", "fax", "phone number", "phone", "mobile", "telephone",
    ]),
    ("Contact – Address", [
        "address line", "addr", "address", "city", "state",
        "zip", "postal", "country", "county", "street",
    ]),
    ("Account ID", [
        "reassigned account", "account number", "acct", "micr",
        "cif", "routing", "card number", "card", "token",
        "member number", "member id", "loan number", "share number",
        "certificate", "aba",
    ]),
    ("Auth / Device", [
        "password", "pin", "secret", "credential", "passphrase",
    ]),
]

NON_PII_HINTS = [
    "balance", "rate", "fee", "charge", "status", "date open",
    "close date", "product code", "branch", "institution",
    "officer", "flag", "ytd", "mtd", "rolling", "limit",
    "gl ", "category", "description", "type", "code",
]


def _classify_one(header: str) -> dict:
    h = header.lower().strip()
    for hint in NON_PII_HINTS:
        if hint in h:
            return {"is_pii": False, "category": "Non-PII"}
    for category, keywords in PII_RULES:
        for kw in keywords:
            if kw in h:
                return {"is_pii": True, "category": category}
    return {"is_pii": False, "category": "Non-PII"}


def classify_headers(headers: list[str]) -> dict[str, dict]:
    return {h: _classify_one(h) for h in headers}
