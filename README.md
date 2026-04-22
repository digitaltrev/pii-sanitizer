# PII Sanitizer

A local Streamlit app for sanitizing PII in CSV files before sharing data for testing, demos, or analysis.

## What it does

Upload one or more CSVs. The app detects likely PII columns by substring-matching against header names, then lets you choose an action per column:

| Action | Result |
|---|---|
| **Keep** | Column passes through unchanged |
| **Tokenize** | Values replaced with a deterministic HMAC-SHA256 token (`TOK_<16 hex chars>`) — same input always produces the same token, so joins across files are preserved |
| **Delete** | Values blanked out |
| **Synthetic** | Values replaced with realistic fake data via Faker |

Processed files download as a ZIP.

## PII categories detected

Government ID, Date of Birth, Name, Email, Phone, Address, Account ID (account numbers, routing, CIF, MICR, ABA), Auth / Device (passwords, PINs)

Detection is **substring-matching on header names only** — non-English headers and unusual naming conventions won't be caught. Always review the auto-classified columns before processing.

## Known limitations

**Tokenization is one-way hashing, not encryption.** `tokenize()` is HMAC-SHA256 truncated to 16 hex chars (64 bits). Tokens can't be reversed without the key, but:

- **Collision risk at scale:** birthday collisions occur around ~4 billion values. Fine for small datasets; use caution on large member tables where token collisions would silently break joins.
- **Low-entropy inputs are brute-forceable:** SSNs, DOBs, zip codes, and phone numbers have small enough input spaces that anyone who obtains the key can reverse all tokens by exhaustive hashing. Don't treat tokens as a substitute for access controls on the key.

**Synthetic data is not consistent across files.** The same raw value produces a different fake value each run, so joins between two synthetic files on a shared ID won't hold. The tokenize path preserves joins; synthetic does not.

**`key.bin` is stored next to the app.** Be careful not to commit it if you're working in a directory you push elsewhere.

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Encryption key

A 32-byte key is generated on first run and saved to `key.bin`. Back it up if you need consistent tokenization across sessions — paste it into the sidebar to reuse it. `key.bin` is gitignored and should never be committed.
