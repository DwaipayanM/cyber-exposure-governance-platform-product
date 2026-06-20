"""CSV / spreadsheet formula-injection protection for exported files.

A common weakness in security tools is that they export untrusted data to CSV.
If a cell value begins with '=', '+', '-', '@', or a control character, Excel /
Google Sheets / LibreOffice will interpret it as a live formula when the file is
opened (CSV / formula injection, CWE-1236). Because this product ingests
externally supplied vulnerability, asset, and IDS data, every export is passed
through this sanitiser so a malicious cell cannot become an executable formula in
the recipient's spreadsheet.
"""
from __future__ import annotations

import pandas as pd

# Leading characters that spreadsheet apps may treat as the start of a formula.
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: object) -> object:
    """Neutralise a single value if it could be read as a spreadsheet formula."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if text and text[0] in DANGEROUS_PREFIXES:
        # Prefix with an apostrophe so the spreadsheet treats it as plain text.
        return "'" + text
    return value


def sanitize_df_for_export(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of df with all object/string cells made injection-safe."""
    safe = df.copy()
    for col in safe.columns:
        if safe[col].dtype == object:
            safe[col] = safe[col].map(sanitize_cell)
    return safe
