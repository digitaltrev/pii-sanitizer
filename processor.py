from __future__ import annotations

import hashlib
import hmac
import io
import os
import zipfile
from pathlib import Path

import pandas as pd
from faker import Faker

KEY_PATH = Path(__file__).parent / "key.bin"
_faker = Faker()

_SYNTHETIC: dict[str, object] = {
    "first": _faker.first_name,
    "fname": _faker.first_name,
    "last": _faker.last_name,
    "lname": _faker.last_name,
    "name": _faker.name,
    "email": _faker.email,
    "phone": _faker.phone_number,
    "mobile": _faker.phone_number,
    "cell": _faker.phone_number,
    "fax": _faker.phone_number,
    "address": _faker.street_address,
    "addr": _faker.street_address,
    "street": _faker.street_address,
    "city": _faker.city,
    "state": _faker.state_abbr,
    "zip": _faker.zipcode,
    "postal": _faker.zipcode,
    "dob": lambda: _faker.date_of_birth(minimum_age=18, maximum_age=90).strftime("%m/%d/%Y"),
    "birth": lambda: _faker.date_of_birth(minimum_age=18, maximum_age=90).strftime("%m/%d/%Y"),
    "ssn": _faker.ssn,
    "tax": _faker.ssn,
    "tin": _faker.ssn,
    "ein": _faker.ssn,
}


def load_or_create_key() -> bytes:
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = os.urandom(32)
    KEY_PATH.write_bytes(key)
    return key


def tokenize(value: str, key: bytes) -> str:
    digest = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"TOK_{digest[:16]}"


def _get_synthetic(col: str):
    h = col.lower()
    for keyword, gen in _SYNTHETIC.items():
        if keyword in h:
            return gen
    return lambda: _faker.bothify(text="???-####")


def process_files(
    files: list[tuple[str, pd.DataFrame]],
    actions: dict[str, str],
    key: bytes,
) -> dict[str, pd.DataFrame]:
    results = {}
    for name, df in files:
        out = df.copy()
        for col in out.columns:
            action = actions.get(str(col), "keep")
            if action == "encrypt":
                out[col] = out[col].apply(
                    lambda v, k=key: tokenize(v, k) if pd.notna(v) and str(v).strip() else v
                )
            elif action == "delete":
                out[col] = ""
            elif action == "synthetic":
                gen = _get_synthetic(str(col))
                out[col] = out[col].apply(
                    lambda v: gen() if pd.notna(v) and str(v).strip() else v
                )
        results[name] = out
    return results


def build_zip(results: dict[str, pd.DataFrame]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, df in results.items():
            stem = Path(name).stem
            zf.writestr(f"{stem}_sanitized.csv", df.to_csv(index=False).encode("utf-8"))
    return buf.getvalue()
