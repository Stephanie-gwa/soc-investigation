# CEO Account Takeover Investigation — SOC Analyst Project

A fully functional, self-contained simulation of the investigation described in the
"Detect. Investigate. Respond. Get Hired." project brief: a CEO's account is signed
into at 3 AM from Lagos, and you work the case end-to-end — triage, baseline &
compare, hunt backwards with KQL, check persistence, contain, and report.

It's a real Flask API backed by a generated (but internally consistent) evidence set —
Azure AD–style sign-in logs, audit logs, an alert queue — plus a console-style web UI
with a working **KQL query engine** (supports `where`, `summarize count() by ... ,
bin()`, `order by`, `project`, `take`).

## What's inside

```
backend/
  app.py          Flask REST API (alerts, logs, KQL, baseline, containment, report)
  data.py         Generates the synthetic evidence set (sign-in logs, audit logs, alerts)
  kql.py          Mini KQL interpreter (pandas-backed)
  requirements.txt
frontend/
  index.html      SOC console UI: alert queue + 5-step investigation workspace
  style.css
  app.js          Talks to the API, renders everything, runs KQL queries live
```

## Run it

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** — Flask serves both the API and the frontend.

## The scenario

**Company:** Northgate Holdings
**Account:** Marcus Webb, CEO (`m.webb@northgateholdings.com`)

1. An attacker (`154.72.184.23`, Lagos, Nigeria) runs a two-night, low-and-slow
   password spray against 24+ accounts over the legacy Exchange **IMAP** protocol —
   which isn't covered by Conditional Access / MFA.
2. On night three they successfully authenticate to the CEO's account.
3. Within 19 minutes: they register their own MFA method, plant a hidden inbox rule
   that hides finance-related email, add an external forwarding rule to a lookalike
   domain, and consent to a rogue OAuth mail app — classic BEC / invoice-fraud setup.
4. A second alert (Priya Anand, legitimate Dubai travel) is included on purpose as a
   **false positive** to compare against, matching the "baseline & compare" step.

## Walking through the app

- **Alert queue** — three alerts, styled like a real SIEM incident queue. Click the
  "Impossible travel activity" alert to open the case.
- **1. Triage** — the alert detail and the exact sign-in event that fired it.
- **2. Baseline & compare** — the CEO's real 14-day baseline (locations, hours,
  devices, IPs) computed live from the sign-in logs, compared against the flagged
  event — and, side by side, why Priya's Dubai alert is a benign false positive.
- **3. Hunt backwards** — a working KQL console. Run the exact query from the brief
  (`SigninLogs | where ResultType == 50126 | summarize count() by IPAddress,
  bin(TimeGenerated, 1h) | where count_ > 20 | order by count_ desc`) or the other
  presets, and see the reconstructed attack timeline.
- **4. Persistence & actions** — the malicious audit log entries, plus a containment
  checklist (revoke sessions, remove rogue MFA, delete the inbox rule, block the IP,
  etc.) that actually updates the case status as you work it.
- **5. Report & close** — MITRE ATT&CK mapping, analyst notes, and a generated
  Markdown incident report you can download — a portfolio piece for interviews.

## Notes on the KQL engine

`backend/kql.py` is a small, real interpreter (not a lookup table) built on pandas.
It parses the pipeline syntax and supports enough of the language to run the queries
this investigation needs. Try writing your own — e.g.:

```
AuditLogs
| where OperationName contains "Inbox"
```

Unsupported syntax returns a clear error rather than failing silently.
