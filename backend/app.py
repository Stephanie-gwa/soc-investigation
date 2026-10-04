import os
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
import pandas as pd

import data as seed
from kql import run_kql, KqlError

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# ---- in-memory "workspace" (regenerated fresh each process start) ----
SIGNIN_LOGS = seed.build_signin_logs()
AUDIT_LOGS = seed.build_audit_logs()
ALERTS = {a["id"]: a for a in seed.build_alerts()}
ROSTER = seed.build_org_roster()

CASE_STATE = {
    "status": "New",              # New -> Investigating -> Contained -> Closed
    "notes": [],                  # analyst free-text notes, timestamped
    "containment": {
        "revoked_sessions": False,
        "removed_mfa_method": False,
        "removed_inbox_rule": False,
        "removed_forwarding": False,
        "revoked_oauth_consent": False,
        "blocked_ip": False,
        "forced_password_reset": False,
    },
}

TABLES = {"SigninLogs": SIGNIN_LOGS, "AuditLogs": AUDIT_LOGS}


# ---------------------------------------------------------------- helpers
def df_to_records(df: pd.DataFrame):
    out = df.copy()
    for c in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[c]):
            out[c] = out[c].astype(str)
    return out.fillna("").to_dict(orient="records")


# ---------------------------------------------------------------- static
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ---------------------------------------------------------------- alerts
@app.route("/api/alerts")
def list_alerts():
    return jsonify(list(ALERTS.values()))


@app.route("/api/alerts/<alert_id>")
def get_alert(alert_id):
    a = ALERTS.get(alert_id)
    if not a:
        return jsonify({"error": "not found"}), 404
    out = dict(a)
    out["caseState"] = CASE_STATE if a.get("primary") else None
    return jsonify(out)


@app.route("/api/alerts/<alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id):
    a = ALERTS.get(alert_id)
    if not a:
        return jsonify({"error": "not found"}), 404
    body = request.get_json(force=True) or {}
    status = body.get("status")
    if status:
        a["status"] = status
        if a.get("primary"):
            CASE_STATE["status"] = status
    return jsonify(a)


# ---------------------------------------------------------------- logs
@app.route("/api/signin-logs")
def signin_logs():
    df = SIGNIN_LOGS.copy()
    user = request.args.get("user")
    ip = request.args.get("ip")
    result = request.args.get("resultType")
    limit = int(request.args.get("limit", 200))
    if user:
        df = df[df["UserPrincipalName"] == user]
    if ip:
        df = df[df["IPAddress"] == ip]
    if result is not None and result != "":
        df = df[df["ResultType"] == int(result)]
    df = df.sort_values("TimeGenerated", ascending=False).head(limit)
    return jsonify(df_to_records(df))


@app.route("/api/audit-logs")
def audit_logs():
    df = AUDIT_LOGS.copy()
    user = request.args.get("user")
    if user:
        df = df[df["InitiatedBy"] == user]
    df = df.sort_values("TimeGenerated")
    return jsonify(df_to_records(df))


# ---------------------------------------------------------------- KQL
@app.route("/api/kql", methods=["POST"])
def kql_run():
    body = request.get_json(force=True) or {}
    query = body.get("query", "")
    try:
        result = run_kql(TABLES, query)
        return jsonify(result)
    except KqlError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:  # pragma: no cover - defensive
        return jsonify({"error": f"Query failed: {e}"}), 400


@app.route("/api/kql/schema")
def kql_schema():
    return jsonify({name: list(df.columns) for name, df in TABLES.items()})


# ---------------------------------------------------------------- baseline
@app.route("/api/users/<path:upn>/baseline")
def baseline(upn):
    """Typical locations / times / devices / IPs for a user, computed from
    all sign-ins that are NOT from the known attacker IP (i.e. their history)."""
    df = SIGNIN_LOGS[(SIGNIN_LOGS["UserPrincipalName"] == upn)
                      & (SIGNIN_LOGS["IPAddress"] != seed.ATTACKER_IP)]
    if df.empty:
        return jsonify({"error": "no sign-in history for user"}), 404

    df = df.copy()
    df["hour"] = pd.to_datetime(df["TimeGenerated"]).dt.hour
    locations = (df.groupby(["City", "Country"]).size()
                 .reset_index(name="count").sort_values("count", ascending=False))
    devices = (df.groupby(["DeviceOS", "Browser"]).size()
               .reset_index(name="count").sort_values("count", ascending=False))
    ips = df["IPAddress"].value_counts().reset_index()
    ips.columns = ["IPAddress", "count"]

    return jsonify({
        "user": upn,
        "signInCount": int(len(df)),
        "typicalHourRange": [int(df["hour"].min()), int(df["hour"].max())],
        "locations": locations.to_dict(orient="records"),
        "devices": devices.to_dict(orient="records"),
        "ipAddresses": ips.to_dict(orient="records"),
        "hourHistogram": df["hour"].value_counts().sort_index().to_dict(),
    })


@app.route("/api/compare")
def compare():
    """Compare a candidate sign-in event against a user's baseline —
    used for the 'baseline & compare' / false-positive-vs-malicious step."""
    upn = request.args.get("user")
    signin_id = request.args.get("signInId")
    row = SIGNIN_LOGS[SIGNIN_LOGS["Id"] == signin_id]
    if row.empty:
        return jsonify({"error": "sign-in not found"}), 404
    row = row.iloc[0]

    base = SIGNIN_LOGS[(SIGNIN_LOGS["UserPrincipalName"] == upn)
                        & (SIGNIN_LOGS["Id"] != signin_id)
                        & (SIGNIN_LOGS["IPAddress"] != seed.ATTACKER_IP)]
    known_ips = set(base["IPAddress"])
    known_devices = set(zip(base["DeviceOS"], base["Browser"]))
    known_countries = set(base["Country"])
    hour = pd.to_datetime(row["TimeGenerated"]).hour
    typical_hours = set(pd.to_datetime(base["TimeGenerated"]).dt.hour) if not base.empty else set()

    flags = {
        "newCountry": row["Country"] not in known_countries,
        "newIp": row["IPAddress"] not in known_ips,
        "newDevice": (row["DeviceOS"], row["Browser"]) not in known_devices,
        "unusualHour": hour not in typical_hours,
        "legacyAuthNoMfa": row["ConditionalAccessStatus"] == "notApplied",
    }
    verdict = "Likely malicious" if sum(flags.values()) >= 3 else (
        "Needs review" if sum(flags.values()) >= 1 else "Consistent with baseline")

    return jsonify({"signIn": df_to_records(pd.DataFrame([row]))[0], "flags": flags, "verdict": verdict})


# ---------------------------------------------------------------- mitre
MITRE_MAP = [
    {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access",
     "evidence": "Hundreds of failed sign-ins from 154.72.184.23 across 24+ accounts, "
                 "two consecutive nights, low-and-slow cadence."},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence",
     "evidence": "Attacker authenticated successfully to the CEO's real account using "
                 "harvested credentials — no exploit needed."},
    {"id": "T1556.006", "name": "Modify Authentication Process: Multi-Factor Authentication",
     "tactic": "Persistence / Defense Evasion",
     "evidence": "Attacker registered their own phone number as an MFA method on the "
                 "compromised account 6 minutes after sign-in."},
    {"id": "T1114.003", "name": "Email Collection: Email Forwarding Rule", "tactic": "Collection",
     "evidence": "Hidden inbox rule created to move finance-related email to RSS Subscriptions "
                 "and mark as read; a forwarding rule sent copies to a lookalike domain."},
    {"id": "T1550.001", "name": "Use Alternate Authentication Material / Legacy Auth Abuse",
     "tactic": "Defense Evasion",
     "evidence": "All attacker activity used the legacy Exchange IMAP protocol, which is not "
                 "subject to Conditional Access / MFA enforcement."},
]


@app.route("/api/mitre")
def mitre():
    return jsonify(MITRE_MAP)


# ---------------------------------------------------------------- timeline
@app.route("/api/incident/<alert_id>/timeline")
def incident_timeline(alert_id):
    events = []
    spray = SIGNIN_LOGS[(SIGNIN_LOGS["IPAddress"] == seed.ATTACKER_IP)
                         & (SIGNIN_LOGS["ResultType"] == 50126)]
    if not spray.empty:
        first, last = spray["TimeGenerated"].min(), spray["TimeGenerated"].max()
        events.append({
            "time": str(first), "phase": "Reconnaissance",
            "title": "Password spray begins",
            "detail": f"First failed sign-in from {seed.ATTACKER_IP} (Lagos, Nigeria). "
                       f"Spray continues intermittently through {str(last)}.",
        })
    breach = SIGNIN_LOGS[(SIGNIN_LOGS["UserPrincipalName"] == seed.CEO_UPN)
                          & (SIGNIN_LOGS["ResultType"] == 0)
                          & (SIGNIN_LOGS["IPAddress"] == seed.ATTACKER_IP)]
    if not breach.empty:
        events.append({
            "time": str(breach.iloc[0]["TimeGenerated"]), "phase": "Initial Access",
            "title": "Successful sign-in to CEO account",
            "detail": f"Login from {seed.ATTACKER_IP} via legacy IMAP, bypassing MFA enforcement.",
        })
    for _, r in AUDIT_LOGS[AUDIT_LOGS["IPAddress"] == seed.ATTACKER_IP].iterrows():
        events.append({
            "time": str(r["TimeGenerated"]), "phase": "Persistence / Collection",
            "title": r["OperationName"], "detail": r["AdditionalDetails"],
        })
    events.sort(key=lambda e: e["time"])
    return jsonify(events)


# ---------------------------------------------------------------- notes / containment
@app.route("/api/incident/<alert_id>/notes", methods=["GET", "POST"])
def incident_notes(alert_id):
    if request.method == "POST":
        body = request.get_json(force=True) or {}
        text = (body.get("text") or "").strip()
        if not text:
            return jsonify({"error": "note text required"}), 400
        CASE_STATE["notes"].append({"time": datetime.utcnow().isoformat(), "text": text})
    return jsonify(CASE_STATE["notes"])


@app.route("/api/incident/<alert_id>/containment", methods=["GET", "POST"])
def incident_containment(alert_id):
    if request.method == "POST":
        body = request.get_json(force=True) or {}
        action = body.get("action")
        if action not in CASE_STATE["containment"]:
            return jsonify({"error": "unknown action"}), 400
        CASE_STATE["containment"][action] = True
        if all(CASE_STATE["containment"].values()):
            CASE_STATE["status"] = "Contained"
            ALERTS["alert-001"]["status"] = "Contained"
        elif CASE_STATE["status"] == "New":
            CASE_STATE["status"] = "Investigating"
            ALERTS["alert-001"]["status"] = "Investigating"
    return jsonify(CASE_STATE)


@app.route("/api/incident/<alert_id>/report")
def incident_report(alert_id):
    a = ALERTS.get(alert_id)
    if not a:
        return jsonify({"error": "not found"}), 404
    spray = SIGNIN_LOGS[(SIGNIN_LOGS["IPAddress"] == seed.ATTACKER_IP)
                         & (SIGNIN_LOGS["ResultType"] == 50126)]
    accounts_hit = spray["UserPrincipalName"].nunique()
    persistence = AUDIT_LOGS[AUDIT_LOGS["IPAddress"] == seed.ATTACKER_IP]

    lines = []
    lines.append(f"# Incident Report — {a['title']}")
    lines.append("")
    lines.append(f"**Company:** {seed.COMPANY}  ")
    lines.append(f"**Affected account:** {seed.CEO_NAME} ({seed.CEO_UPN})  ")
    lines.append(f"**Severity:** {a['severity']}  ")
    lines.append(f"**Status:** {CASE_STATE['status']}  ")
    lines.append(f"**Report generated:** {datetime.utcnow().isoformat()}Z")
    lines.append("")
    lines.append("## Summary")
    lines.append(
        f"Between {seed.SPRAY_NIGHT_1.date()} and {seed.SPRAY_NIGHT_2.date()}, an attacker "
        f"operating from {seed.ATTACKER_IP} (Lagos, Nigeria) conducted a low-and-slow password "
        f"spray against {accounts_hit} accounts at {seed.COMPANY} using the legacy Exchange IMAP "
        f"protocol, which bypasses Conditional Access and MFA enforcement. On "
        f"{seed.BREACH_TIME.isoformat()}, the attacker successfully authenticated to the CEO's "
        f"account, {seed.CEO_UPN}. Within 19 minutes the attacker registered a rogue MFA method, "
        f"created a hidden inbox rule to conceal finance-related email, added an external mail "
        f"forwarding rule to a lookalike domain, and consented to an unverified third-party "
        f"OAuth application with mail read/send scope — consistent with a business email "
        f"compromise (BEC) / invoice fraud setup."
    )
    lines.append("")
    lines.append("## Timeline")
    for e in incident_timeline(alert_id).json:
        lines.append(f"- **{e['time']}** — [{e['phase']}] {e['title']}: {e['detail']}")
    lines.append("")
    lines.append("## Persistence & malicious actions confirmed")
    for _, r in persistence.iterrows():
        lines.append(f"- {r['OperationName']}: {r['AdditionalDetails']}")
    lines.append("")
    lines.append("## MITRE ATT&CK mapping")
    for m in MITRE_MAP:
        lines.append(f"- **{m['id']} {m['name']}** ({m['tactic']}) — {m['evidence']}")
    lines.append("")
    lines.append("## Containment actions")
    for k, v in CASE_STATE["containment"].items():
        label = k.replace("_", " ").capitalize()
        lines.append(f"- [{'x' if v else ' '}] {label}")
    lines.append("")
    if CASE_STATE["notes"]:
        lines.append("## Analyst notes")
        for n in CASE_STATE["notes"]:
            lines.append(f"- {n['time']}: {n['text']}")
        lines.append("")
    lines.append("## Recommendations")
    lines.append(
        "- Disable legacy authentication protocols (IMAP/POP/SMTP AUTH) tenant-wide.\n"
        "- Enforce Conditional Access requiring MFA + compliant device for all admin and "
        "executive accounts.\n"
        "- Enable MFA registration alerts and sign-in risk policies (Identity Protection).\n"
        "- Force password reset and full session/token revocation for all 24 targeted accounts.\n"
        "- Block the lookalike domain and report it for takedown.\n"
        "- Notify finance team of invoice-fraud exposure window; verify no fraudulent "
        "payments were sent."
    )
    return jsonify({"markdown": "\n".join(lines)})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
