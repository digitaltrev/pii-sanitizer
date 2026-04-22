# PII Sanitizer

A local Streamlit app for sanitizing PII in CSV files before sharing data for testing, demos, or analysis.

## What it does

Upload one or more CSVs, and the app auto-detects columns that likely contain PII by header name. For each column you choose one of four actions:

| Action | Result |
|---|---|
| **Keep** | Column passes through unchanged |
| **Keep & Encrypt** | Values replaced with a consistent HMAC token (`TOK_<hex>`) — same input always produces the same token, so joins still work |
| **Delete** | Values blanked out |
| **Synthetic Data** | Values replaced with realistic fake data (names, addresses, SSNs, etc.) via Faker |

Processed files download as a ZIP.

## PII categories detected

Government ID, Date of Birth, Name, Email, Phone, Address, Account ID (account numbers, routing, CIF, MICR, ABA), Auth / Device (passwords, PINs)

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Encryption key

A 32-byte key is generated on first run and saved to `key.bin`. Back it up if you need consistent tokenization across sessions — you can paste it into the sidebar to reuse it. `key.bin` is gitignored and should never be committed.
