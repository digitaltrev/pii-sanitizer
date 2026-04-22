from __future__ import annotations

import csv
import io
import textwrap

import pandas as pd
import streamlit as st

from pii_detector import classify_headers
from processor import build_zip, load_or_create_key, process_files

st.set_page_config(page_title="PII Sanitizer", layout="wide")

ACTION_LABELS = {
    "keep": "Keep",
    "encrypt": "Tokenize",
    "delete": "Delete",
    "synthetic": "Synthetic Data",
}
LABEL_TO_KEY = {v: k for k, v in ACTION_LABELS.items()}
ACTION_BG = {
    "keep": "#d4edda",
    "encrypt": "#cce5ff",
    "delete": "#f8d7da",
    "synthetic": "#fff3cd",
}
SAMPLE_LEN = 28


# ── helpers ────────────────────────────────────────────────────────────────

def _detect_sep(raw: bytes) -> str:
    try:
        sample = raw[:4096].decode("utf-8", errors="replace")
        return csv.Sniffer().sniff(sample, delimiters=",\t|;").delimiter
    except Exception:
        return ","


def _read_raw(raw: bytes, sep: str) -> list[list[str]]:
    text = raw.decode("utf-8", errors="replace")
    rows = list(csv.reader(io.StringIO(text), delimiter=sep))
    if not rows:
        return rows
    max_w = max(len(r) for r in rows)
    return [r + [""] * (max_w - len(r)) for r in rows]


def _parse_csv(raw: bytes, header_row: int, sep: str) -> pd.DataFrame:
    return pd.read_csv(
        io.BytesIO(raw),
        header=header_row,
        sep=sep,
        dtype=str,
        on_bad_lines="skip",
        engine="python",
    )


def _sample_values(df: pd.DataFrame) -> dict[str, str]:
    out = {}
    for col in df.columns:
        vals = df[col].dropna().astype(str)
        vals = vals[vals.str.strip() != ""]
        picks = vals.head(3).tolist()
        out[str(col)] = " | ".join(
            textwrap.shorten(v, width=SAMPLE_LEN, placeholder="…") for v in picks
        )
    return out


# ── session state ──────────────────────────────────────────────────────────

def _init():
    for k, v in {
        "enc_key": None,
        "files": [],
        "files_key": None,
        "uploaded_raws": {},
        "actions": {},
        "header_row": 0,
        "classifications": {},
        "table_version": 0,
        "header_confirmed": False,
        "selected_raw_row": None,
        "samples": {},
        "_raw_rows": [],
        "_sep": ",",
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v
    if st.session_state.enc_key is None:
        st.session_state.enc_key = load_or_create_key()


# ── callbacks ──────────────────────────────────────────────────────────────

def _confirm_header():
    row = st.session_state.selected_raw_row
    if row is None:
        return
    st.session_state.header_row = row
    parsed_files = []
    all_headers: list[str] = []
    for name, raw in st.session_state.uploaded_raws.items():
        sep = _detect_sep(raw)
        df = _parse_csv(raw, row, sep)
        parsed_files.append((name, df))
        for col in df.columns:
            s = str(col)
            if s not in all_headers:
                all_headers.append(s)
    st.session_state.files = parsed_files
    clsf = classify_headers(all_headers)
    st.session_state.classifications = clsf
    st.session_state.actions = {
        col: ("delete" if info["is_pii"] else "keep")
        for col, info in clsf.items()
    }
    if parsed_files:
        st.session_state.samples = _sample_values(parsed_files[0][1])
    st.session_state.table_version += 1
    st.session_state.header_confirmed = True


def _bulk(action: str):
    for col, info in st.session_state.classifications.items():
        if info["is_pii"]:
            st.session_state.actions[col] = action
    st.session_state.table_version += 1


def _reset_all():
    for col, info in st.session_state.classifications.items():
        st.session_state.actions[col] = "delete" if info["is_pii"] else "keep"
    st.session_state.table_version += 1


# ── table helpers ──────────────────────────────────────────────────────────

def _live_actions(editor_key: str) -> dict[str, str]:
    live = dict(st.session_state.actions)
    edited_rows = st.session_state.get(editor_key, {}).get("edited_rows", {})
    cols = list(st.session_state.classifications.keys())
    for idx_str, changes in edited_rows.items():
        idx = int(idx_str)
        if idx < len(cols) and "Action" in changes:
            key = LABEL_TO_KEY.get(changes["Action"])
            if key:
                live[cols[idx]] = key
    return live


def _build_editor_df(actions: dict[str, str]) -> pd.DataFrame:
    rows = []
    for col, info in st.session_state.classifications.items():
        rows.append({
            "Column": col,
            "Action": ACTION_LABELS.get(actions.get(col, "keep"), "Keep"),
            "PII?": "Yes" if info["is_pii"] else "No",
            "Category": info["category"],
            "Sample Values": st.session_state.samples.get(col, ""),
        })
    return pd.DataFrame(rows)


def _style_df(df: pd.DataFrame, actions: dict[str, str]):
    cols = list(st.session_state.classifications.keys())

    def row_colors(row):
        col = cols[row.name] if row.name < len(cols) else None
        bg = ACTION_BG.get(actions.get(col, "keep"), "") if col else ""
        return [f"background-color: {bg}" for _ in row]

    return df.style.apply(row_colors, axis=1)


# ── app ────────────────────────────────────────────────────────────────────

_init()
st.title("PII Sanitizer")

# sidebar
with st.sidebar:
    st.subheader("Encryption Key")
    st.code(st.session_state.enc_key.hex()[:32] + "…", language=None)
    st.caption("Back this up — needed to re-tokenize consistently across sessions.")
    pasted = st.text_input("Paste existing key (hex) to reuse")
    if pasted:
        try:
            k = bytes.fromhex(pasted.strip())
            if len(k) == 32:
                st.session_state.enc_key = k
                st.success("Key loaded.")
            else:
                st.error("Must be 32 bytes (64 hex chars).")
        except ValueError:
            st.error("Invalid hex.")

# ── 1. Upload ──────────────────────────────────────────────────────────────
st.header("1. Upload CSV Files")
uploaded = st.file_uploader(
    "Drop your CSV files here",
    type="csv",
    accept_multiple_files=True,
)

if uploaded:
    files_key = tuple(sorted(f.name for f in uploaded))
    if files_key != st.session_state.files_key:
        st.session_state.files_key = files_key
        st.session_state.header_confirmed = False
        st.session_state.header_row = 0
        st.session_state.selected_raw_row = None
        st.session_state.uploaded_raws = {f.name: f.read() for f in uploaded}
        first_raw = st.session_state.uploaded_raws[uploaded[0].name]
        sep = _detect_sep(first_raw)
        st.session_state._sep = sep
        st.session_state._raw_rows = _read_raw(first_raw, sep)

# ── 2. Header Row ──────────────────────────────────────────────────────────
if uploaded:
    if not st.session_state.header_confirmed:
        st.header("2. Find Your Header Row")
        st.caption("Click the row that contains your column names, then click Confirm.")
        raw_rows = st.session_state._raw_rows
        if raw_rows:
            event = st.dataframe(
                pd.DataFrame(raw_rows[:20]),
                use_container_width=True,
                hide_index=False,
                on_select="rerun",
                selection_mode="single-row",
                key="header_picker",
            )
            if event and event.selection.rows:
                st.session_state.selected_raw_row = event.selection.rows[0]
        sel = st.session_state.selected_raw_row
        if sel is not None and sel < len(raw_rows):
            preview = raw_rows[sel][:8]
            st.info(f"Row {sel} selected → {preview}")
        st.button(
            "Confirm Header Row",
            disabled=(sel is None),
            on_click=_confirm_header,
        )
    else:
        st.success(
            f"✓ Header row {st.session_state.header_row} confirmed — "
            f"{len(st.session_state.files)} file(s), "
            f"{len(st.session_state.classifications)} columns"
        )

# ── 3. Configure Columns ───────────────────────────────────────────────────
if st.session_state.header_confirmed and st.session_state.classifications:
    st.header("3. Configure Columns")

    c1, c2, c3, c4 = st.columns(4)
    c1.button("Delete All PII", on_click=_bulk, args=("delete",))
    c2.button("Encrypt All PII", on_click=_bulk, args=("encrypt",))
    c3.button("Synthetic All PII", on_click=_bulk, args=("synthetic",))
    c4.button("Reset to Defaults", on_click=_reset_all)

    editor_key = f"tbl_{st.session_state.table_version}"
    actions = _live_actions(editor_key)
    st.session_state.actions.update(actions)  # keep session state in sync

    styled = _style_df(_build_editor_df(actions), actions)
    st.data_editor(
        styled,
        use_container_width=True,
        hide_index=True,
        key=editor_key,
        column_config={
            "Column": st.column_config.TextColumn("Column", disabled=True),
            "Action": st.column_config.SelectboxColumn(
                "Action",
                options=list(ACTION_LABELS.values()),
                required=True,
            ),
            "PII?": st.column_config.TextColumn("PII?", disabled=True, width="small"),
            "Category": st.column_config.TextColumn("Category", disabled=True),
            "Sample Values": st.column_config.TextColumn("Sample Values", disabled=True),
        },
    )

    # ── 4. Preview ─────────────────────────────────────────────────────────
    if st.session_state.files:
        with st.expander("Preview (first file, 3 rows, transformations applied)"):
            preview_result = process_files(
                st.session_state.files[:1],
                st.session_state.actions,
                st.session_state.enc_key,
            )
            for name, df in preview_result.items():
                st.caption(name)
                st.dataframe(df.head(3), use_container_width=True)

    # ── 5. Process & Download ───────────────────────────────────────────────
    st.header("4. Process & Download")
    if st.button("Process Files", type="primary"):
        with st.spinner("Processing…"):
            results = process_files(
                st.session_state.files,
                st.session_state.actions,
                st.session_state.enc_key,
            )
            zip_bytes = build_zip(results)
        st.download_button(
            "⬇ Download sanitized files (.zip)",
            data=zip_bytes,
            file_name="sanitized_files.zip",
            mime="application/zip",
        )
