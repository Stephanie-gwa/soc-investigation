"""
kql.py — a small interpreter for a practical subset of Kusto Query Language (KQL).

Supports pipelines like:

    SigninLogs
    | where ResultType == 50126
    | summarize count() by IPAddress, bin(TimeGenerated, 1h)
    | where count_ > 20
    | order by count_ desc

Supported stages: where, summarize count() by, extend (bin only), project,
order by, take/limit. This is intentionally small — enough to run every
query used in the investigation, not a full KQL engine.
"""
import re
import pandas as pd

TIME_COL = "TimeGenerated"

OPS = {
    "==": lambda s, v: s == v,
    "!=": lambda s, v: s != v,
    ">=": lambda s, v: s >= v,
    "<=": lambda s, v: s <= v,
    ">": lambda s, v: s > v,
    "<": lambda s, v: s < v,
    "contains": lambda s, v: s.astype(str).str.contains(re.escape(v), case=False, na=False),
    "!contains": lambda s, v: ~s.astype(str).str.contains(re.escape(v), case=False, na=False),
    "startswith": lambda s, v: s.astype(str).str.startswith(v),
    "in": lambda s, v: s.isin(v),
}

BIN_RE = re.compile(r"bin\(\s*(\w+)\s*,\s*(\d+)([hms d])\s*\)", re.IGNORECASE)


class KqlError(Exception):
    pass


def _coerce(val: str):
    val = val.strip()
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    if val.startswith("(") and val.endswith(")"):
        items = [v.strip().strip('"').strip("'") for v in val[1:-1].split(",")]
        return items
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


def _split_top_level(text: str, sep: str):
    """Split on sep, but not inside parentheses or quotes."""
    parts, depth, buf, quote = [], 0, "", None
    for ch in text:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf += ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    parts.append(buf)
    return [p.strip() for p in parts if p.strip() != ""]


def _apply_where(df: pd.DataFrame, expr: str) -> pd.DataFrame:
    m = re.match(r"(\w+)\s*(==|!=|>=|<=|>|<|contains|!contains|startswith|in)\s*(.+)", expr.strip())
    if not m:
        raise KqlError(f"Could not parse where clause: '{expr}'")
    col, op, raw_val = m.group(1), m.group(2), m.group(3)
    if col not in df.columns:
        raise KqlError(f"Unknown column '{col}'")
    val = _coerce(raw_val)
    series = df[col]
    if pd.api.types.is_numeric_dtype(series) and isinstance(val, str):
        try:
            val = float(val) if "." in val else int(val)
        except ValueError:
            pass
    fn = OPS.get(op)
    if not fn:
        raise KqlError(f"Unsupported operator '{op}'")
    return df[fn(series, val)]


def _apply_summarize(df: pd.DataFrame, expr: str) -> pd.DataFrame:
    # e.g. "count() by IPAddress, bin(TimeGenerated, 1h)"
    m = re.match(r"count\(\)\s*by\s*(.+)", expr.strip(), re.IGNORECASE)
    if not m:
        raise KqlError(f"Only 'count() by ...' summarize is supported, got: '{expr}'")
    group_exprs = _split_top_level(m.group(1), ",")
    group_cols = []
    work = df.copy()
    for g in group_exprs:
        bm = BIN_RE.match(g.strip())
        if bm:
            col, n, unit = bm.group(1), int(bm.group(2)), bm.group(3).lower()
            freq = {"h": "h", "m": "min", "s": "s", "d": "D"}[unit]
            work[f"{col}_bin"] = pd.to_datetime(work[col]).dt.floor(f"{n}{freq}")
            group_cols.append(f"{col}_bin")
        else:
            col = g.strip()
            if col not in work.columns:
                raise KqlError(f"Unknown column '{col}' in summarize")
            group_cols.append(col)
    out = work.groupby(group_cols, dropna=False).size().reset_index(name="count_")
    return out


def _apply_order_by(df: pd.DataFrame, expr: str) -> pd.DataFrame:
    parts = expr.strip().split()
    col = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    if col not in df.columns:
        raise KqlError(f"Unknown column '{col}' in order by")
    return df.sort_values(col, ascending=not desc)


def _apply_project(df: pd.DataFrame, expr: str) -> pd.DataFrame:
    cols = [c.strip() for c in expr.split(",")]
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise KqlError(f"Unknown column(s) in project: {', '.join(missing)}")
    return df[cols]


def run_kql(tables: dict, query: str) -> dict:
    """tables: {table_name: DataFrame}. Returns {columns, rows, row_count}."""
    stages = _split_top_level(query.strip(), "|")
    if not stages:
        raise KqlError("Empty query")
    table_name = stages[0].strip()
    if table_name not in tables:
        raise KqlError(f"Unknown table '{table_name}'. Available: {', '.join(tables.keys())}")
    df = tables[table_name].copy()

    for stage in stages[1:]:
        stage = stage.strip()
        if stage.lower().startswith("where "):
            df = _apply_where(df, stage[6:])
        elif stage.lower().startswith("summarize "):
            df = _apply_summarize(df, stage[10:])
        elif stage.lower().startswith("order by "):
            df = _apply_order_by(df, stage[9:])
        elif stage.lower().startswith("project "):
            df = _apply_project(df, stage[8:])
        elif stage.lower().startswith("take ") or stage.lower().startswith("limit "):
            n = int(re.split(r"\s+", stage)[1])
            df = df.head(n)
        elif stage.lower().startswith("sort by "):
            df = _apply_order_by(df, stage[8:])
        else:
            raise KqlError(f"Unsupported stage: '{stage}'")

    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].astype(str)

    df = df.fillna("")
    return {
        "columns": list(df.columns),
        "rows": df.to_dict(orient="records"),
        "row_count": int(len(df)),
    }
