"""
data.py — generates the synthetic (but realistic-shaped) evidence set for the
"CEO Account Takeover" investigation: Azure AD sign-in logs, audit logs,
an alert queue, and a small org roster. Everything is deterministic (seeded)
so the investigation is reproducible.
"""
import random
from datetime import datetime, timedelta
import pandas as pd

random.seed(42)

COMPANY = "Northgate Holdings"
DOMAIN = "northgateholdings.com"

CEO_UPN = f"m.webb@{DOMAIN}"
CEO_NAME = "Marcus Webb"

FP_UPN = f"p.anand@{DOMAIN}"
FP_NAME = "Priya Anand"

ATTACKER_IP = "154.72.184.23"
ATTACKER_LOC = ("Lagos", "Nigeria", 6.5244, 3.3792)

CORP_IP = "198.51.100.10"
CORP_LOC = ("Austin", "United States", 30.2672, -97.7431)

DUBAI_LOC = ("Dubai", "United Arab Emirates", 25.2048, 55.2708)

ROSTER = [
    ("a.brooks", "Alan Brooks"), ("s.kim", "Sora Kim"), ("j.oduya", "John Oduya"),
    ("l.martins", "Lena Martins"), ("d.osei", "David Osei"), ("r.chen", "Ray Chen"),
    ("t.nguyen", "Tam Nguyen"), ("m.farouk", "Mona Farouk"), ("k.ellis", "Kara Ellis"),
    ("b.singh", "Bala Singh"), ("c.owusu", "Chidi Owusu"), ("e.varga", "Eva Varga"),
    ("f.diallo", "Fatou Diallo"), ("g.lindqvist", "Greta Lindqvist"), ("h.park", "Hana Park"),
    ("i.mensah", "Ini Mensah"), ("n.reyes", "Nico Reyes"), ("o.adeyemi", "Ola Adeyemi"),
    ("p.anand", "Priya Anand"), ("q.wu", "Quan Wu"), ("v.silva", "Vitor Silva"),
    ("w.hassan", "Wael Hassan"), ("x.zhou", "Xin Zhou"), ("y.abara", "Yemi Abara"),
    ("z.novak", "Zoe Novak"), ("a.kowalski", "Anya Kowalski"), ("b.mutua", "Brian Mutua"),
    ("c.duarte", "Carla Duarte"), ("d.ibrahim", "Deka Ibrahim"), ("e.fontaine", "Elise Fontaine"),
]

# "Now" anchor for the whole scenario: the incident is discovered the morning after breach.
NOW = datetime(2026, 9, 3, 8, 0, 0)
BREACH_TIME = datetime(2026, 9, 3, 3, 0, 0)          # night of discovery
SPRAY_NIGHT_1 = datetime(2026, 9, 1, 1, 15, 0)         # "Day -3"
SPRAY_NIGHT_2 = datetime(2026, 9, 2, 1, 40, 0)         # "Day -2"


def _rows_signin(**kw):
    base = dict(
        UserPrincipalName=None, UserDisplayName=None, AppDisplayName="Office 365 Exchange Online",
        IPAddress=None, City=None, Country=None, Latitude=None, Longitude=None,
        DeviceOS="Windows 11", Browser="Edge 128", DeviceId="", ResultType=0,
        ResultDescription="Success", ConditionalAccessStatus="success",
        IsInteractive=True, RiskLevel="none", RiskState="none",
    )
    base.update(kw)
    return base


def _gen_baseline_signins():
    """Two weeks of normal CEO + normal colleague sign-ins."""
    rows = []
    start = NOW - timedelta(days=14)
    day = start
    while day < NOW - timedelta(days=1):
        if day.weekday() < 5:  # weekdays only
            # CEO: laptop sign-in ~7:45am, phone check ~12:30pm, both from Austin/corp IP
            t1 = day.replace(hour=7, minute=random.randint(30, 55))
            rows.append(_rows_signin(
                UserPrincipalName=CEO_UPN, UserDisplayName=CEO_NAME,
                IPAddress=CORP_IP, City=CORP_LOC[0], Country=CORP_LOC[1],
                Latitude=CORP_LOC[2], Longitude=CORP_LOC[3],
                DeviceOS="Windows 11", Browser="Edge 128", DeviceId="CEO-LAPTOP-01",
                AppDisplayName="Office 365 Exchange Online",
                TimeGenerated=t1.isoformat(),
            ))
            t2 = day.replace(hour=12, minute=random.randint(15, 45))
            rows.append(_rows_signin(
                UserPrincipalName=CEO_UPN, UserDisplayName=CEO_NAME,
                IPAddress=CORP_IP, City=CORP_LOC[0], Country=CORP_LOC[1],
                Latitude=CORP_LOC[2], Longitude=CORP_LOC[3],
                DeviceOS="iOS 17", Browser="Outlook Mobile", DeviceId="CEO-IPHONE-01",
                AppDisplayName="Microsoft Authentication Broker",
                IsInteractive=True,
                TimeGenerated=t2.isoformat(),
            ))
            # Colleague (Priya): normal Austin sign-in too, except the Dubai trip below
            t3 = day.replace(hour=8, minute=random.randint(0, 30))
            rows.append(_rows_signin(
                UserPrincipalName=FP_UPN, UserDisplayName=FP_NAME,
                IPAddress="198.51.100.44", City=CORP_LOC[0], Country=CORP_LOC[1],
                Latitude=CORP_LOC[2], Longitude=CORP_LOC[3],
                DeviceOS="Windows 11", Browser="Chrome 128", DeviceId="PANAND-LAPTOP-01",
                TimeGenerated=t3.isoformat(),
            ))
        day += timedelta(days=1)
    return rows


def _gen_false_positive_travel():
    """Priya Anand's legitimate Dubai trip — the 'Atypical travel' alert that's a false positive."""
    t = (NOW - timedelta(days=2)).replace(hour=9, minute=5)
    return [_rows_signin(
        UserPrincipalName=FP_UPN, UserDisplayName=FP_NAME,
        IPAddress="94.200.201.15", City=DUBAI_LOC[0], Country=DUBAI_LOC[1],
        Latitude=DUBAI_LOC[2], Longitude=DUBAI_LOC[3],
        DeviceOS="Windows 11", Browser="Chrome 128", DeviceId="PANAND-LAPTOP-01",
        AppDisplayName="Office 365 Exchange Online",
        ConditionalAccessStatus="success", RiskLevel="medium", RiskState="atRisk",
        TimeGenerated=t.isoformat(),
    )]


def _gen_password_spray():
    """Two nights of failed password-spray sign-ins across ~28 accounts from the attacker IP."""
    rows = []
    for night in (SPRAY_NIGHT_1, SPRAY_NIGHT_2):
        targets = random.sample(ROSTER, 24)
        t = night
        for uid, name in targets:
            attempts = random.randint(1, 4)
            for _ in range(attempts):
                t += timedelta(seconds=random.randint(15, 90))
                rows.append(_rows_signin(
                    UserPrincipalName=f"{uid}@{DOMAIN}", UserDisplayName=name,
                    IPAddress=ATTACKER_IP, City=ATTACKER_LOC[0], Country=ATTACKER_LOC[1],
                    Latitude=ATTACKER_LOC[2], Longitude=ATTACKER_LOC[3],
                    DeviceOS="Unknown", Browser="python-requests/2.31", DeviceId="",
                    AppDisplayName="Exchange Online IMAP", ResultType=50126,
                    ResultDescription="Error validating credentials due to invalid username or password",
                    ConditionalAccessStatus="notApplied", IsInteractive=False,
                    RiskLevel="medium", RiskState="atRisk",
                    TimeGenerated=t.isoformat(),
                ))
        # a few failed attempts against the CEO too, each night, before the eventual hit
        t2 = night + timedelta(minutes=random.randint(5, 40))
        rows.append(_rows_signin(
            UserPrincipalName=CEO_UPN, UserDisplayName=CEO_NAME,
            IPAddress=ATTACKER_IP, City=ATTACKER_LOC[0], Country=ATTACKER_LOC[1],
            Latitude=ATTACKER_LOC[2], Longitude=ATTACKER_LOC[3],
            DeviceOS="Unknown", Browser="python-requests/2.31", DeviceId="",
            AppDisplayName="Exchange Online IMAP", ResultType=50126,
            ResultDescription="Error validating credentials due to invalid username or password",
            ConditionalAccessStatus="notApplied", IsInteractive=False,
            RiskLevel="medium", RiskState="atRisk",
            TimeGenerated=t2.isoformat(),
        ))
    return rows


def _gen_breach_signin():
    """The successful 3AM login to the CEO account — the impossible-travel alert trigger."""
    return [_rows_signin(
        UserPrincipalName=CEO_UPN, UserDisplayName=CEO_NAME,
        IPAddress=ATTACKER_IP, City=ATTACKER_LOC[0], Country=ATTACKER_LOC[1],
        Latitude=ATTACKER_LOC[2], Longitude=ATTACKER_LOC[3],
        DeviceOS="Unknown", Browser="python-requests/2.31", DeviceId="",
        AppDisplayName="Exchange Online IMAP", ResultType=0, ResultDescription="Success",
        ConditionalAccessStatus="notApplied", IsInteractive=False,
        RiskLevel="high", RiskState="atRisk",
        TimeGenerated=BREACH_TIME.isoformat(),
    )]


def build_signin_logs() -> pd.DataFrame:
    rows = (_gen_baseline_signins() + _gen_false_positive_travel()
            + _gen_password_spray() + _gen_breach_signin())
    df = pd.DataFrame(rows)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df = df.sort_values("TimeGenerated").reset_index(drop=True)
    df.insert(0, "Id", [f"sl-{i:05d}" for i in range(len(df))])
    return df


def build_audit_logs() -> pd.DataFrame:
    rows = []

    def row(t, op, category, initiator, target, result, ip, details):
        rows.append(dict(
            TimeGenerated=t.isoformat(), OperationName=op, Category=category,
            InitiatedBy=initiator, TargetResource=target, Result=result,
            IPAddress=ip, AdditionalDetails=details,
        ))

    # Benign background noise
    row(NOW - timedelta(days=6, hours=2), "Reset password", "UserManagement",
        "it.helpdesk@%s" % DOMAIN, "d.osei@%s" % DOMAIN, "success", CORP_IP,
        "Self-service password reset")
    row(NOW - timedelta(days=4, hours=5), "Add app role assignment to service principal",
        "ApplicationManagement", "it.helpdesk@%s" % DOMAIN, "Expense-Reporting-App",
        "success", CORP_IP, "Routine license/app rollout")
    row(NOW - timedelta(days=3, hours=1), "Update user", "UserManagement",
        "hr.admin@%s" % DOMAIN, "e.fontaine@%s" % DOMAIN, "success", CORP_IP,
        "Title change")

    # Malicious persistence, minutes after the 3AM breach
    mfa_t = BREACH_TIME + timedelta(minutes=6)
    row(mfa_t, "Register security info", "UserManagement", CEO_UPN, CEO_UPN,
        "success", ATTACKER_IP,
        "Registered authentication phone number +234-701-XXX-XXXX to account")

    rule_t = BREACH_TIME + timedelta(minutes=11)
    row(rule_t, "New-InboxRule", "ExchangeAdmin", CEO_UPN, CEO_UPN, "success", ATTACKER_IP,
        "Created rule 'Clutter' — if subject or body contains 'invoice','wire','payment' "
        "then move to RSS Subscriptions folder and mark as read (hides finance emails "
        "from the CEO's Inbox and Focused view)")

    forward_t = BREACH_TIME + timedelta(minutes=13)
    row(forward_t, "Set-Mailbox", "ExchangeAdmin", CEO_UPN, CEO_UPN, "success", ATTACKER_IP,
        "ForwardingSmtpAddress set to finance-noreply@northgate-holdlngs.com "
        "(lookalike domain), DeliverToMailboxAndForward=False")

    consent_t = BREACH_TIME + timedelta(minutes=19)
    row(consent_t, "Consent to application", "ApplicationManagement", CEO_UPN,
        "MailSync Pro (unverified publisher)", "success", ATTACKER_IP,
        "Granted Mail.Read, Mail.Send, offline_access via OAuth consent grant")

    df = pd.DataFrame(rows)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df = df.sort_values("TimeGenerated").reset_index(drop=True)
    df.insert(0, "Id", [f"al-{i:05d}" for i in range(len(df))])
    return df


def build_alerts():
    return [
        {
            "id": "alert-001",
            "title": "Impossible travel activity",
            "severity": "High",
            "status": "New",
            "user": CEO_UPN,
            "userDisplayName": CEO_NAME,
            "createdTime": BREACH_TIME.isoformat(),
            "description": (
                f"{CEO_NAME}'s account signed in from Lagos, Nigeria at 03:00, which is not "
                "reachable given the account's most recent sign-in location, without the user "
                "having used a known travel pattern."
            ),
            "primary": True,
            "mitre": ["T1078 — Valid Accounts", "T1110.003 — Password Spraying",
                      "T1556.006 — MFA Manipulation", "T1114.003 — Email Forwarding Rule"],
        },
        {
            "id": "alert-002",
            "title": "Atypical travel",
            "severity": "Medium",
            "status": "Closed — Benign Positive",
            "user": FP_UPN,
            "userDisplayName": FP_NAME,
            "createdTime": (NOW - timedelta(days=2)).replace(hour=9, minute=6).isoformat(),
            "description": (
                f"{FP_NAME}'s account signed in from Dubai, United Arab Emirates from a new location."
            ),
            "primary": False,
            "mitre": [],
        },
        {
            "id": "alert-003",
            "title": "Password spray attack against multiple accounts",
            "severity": "High",
            "status": "New",
            "user": "multiple",
            "userDisplayName": "24+ accounts",
            "createdTime": SPRAY_NIGHT_2.isoformat(),
            "description": (
                f"More than 20 failed sign-ins per hour from a single IP address ({ATTACKER_IP}) "
                "across more than 20 distinct user accounts over two consecutive nights."
            ),
            "primary": False,
            "mitre": ["T1110.003 — Password Spraying"],
        },
    ]


def build_org_roster():
    return [{"upn": f"{uid}@{DOMAIN}", "name": name} for uid, name in ROSTER] + [
        {"upn": CEO_UPN, "name": CEO_NAME}, {"upn": FP_UPN, "name": FP_NAME},
    ]
