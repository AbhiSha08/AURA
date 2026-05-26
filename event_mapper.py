#!/usr/bin/env python3
"""
AURA: Automated User-Risk Analysis — Deterministic Rule Engine
event_mapper.py

Maps Windows Event Logs to MITRE ATT&CK framework using static dictionaries
and compiled regex pattern matching. Zero external AI/API dependencies.

Author: Elite SOC Architect / Lead Python Developer
"""

import json
import csv
import argparse
import os
import re
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import logging

# MITRE ATT&CK STIX ingestor — network-resilient, 24 h cached in Streamlit
from mitre_ingestor import get_mitre_data

# ─── Logging Setup ────────────────────────────────────────────────────────────
# `force=True` (Python 3.8+) ensures this config wins over any prior
# basicConfig call made by importers (e.g., Streamlit's app.py).
# This fixes the double-basicConfig / silent file-logger bug from the audit.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
    force=True,
)
logger = logging.getLogger(__name__)

# ─── Output path ──────────────────────────────────────────────────────────────
OUTPUT_FILE = "mapped_events.json"


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK RULE DICTIONARIES
# ══════════════════════════════════════════════════════════════════════════════

# Maps Windows Event IDs to base MITRE ATT&CK classifications.
# Justification_Template supports {process}, {target_user}, {subject_user} tokens.
EVENT_ID_RULES: Dict[int, Dict[str, Any]] = {

    # ── Execution ─────────────────────────────────────────────────────────────
    4688: {
        "Technique_ID": "T1059",
        "Confidence_Score": 3,
        "Justification_Template": (
            "Process creation (4688): '{process}' was spawned. Base confidence is low; "
            "process-level rules may elevate severity if suspicious patterns are detected."
        ),
    },
    4103: {
        "Technique_ID": "T1059.001",
        "Confidence_Score": 6,
        "Justification_Template": (
            "PowerShell module logging (4103) captured. "
            "Indicates an active PS execution pipeline that may require investigation."
        ),
    },
    4104: {
        "Technique_ID": "T1059.001",
        "Confidence_Score": 8,
        "Justification_Template": (
            "PowerShell script block logging (4104) captured. Script block content "
            "was recorded — commonly associated with obfuscated or complex PS commands."
        ),
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    4625: {
        "Technique_ID": "T1110",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Failed logon (4625) for account '{target_user}'. "
            "Repeated failures are a strong indicator of brute-force or password-spray activity."
        ),
    },
    4740: {
        "Technique_ID": "T1110.001",
        "Confidence_Score": 7,
        "Justification_Template": (
            "Account lockout triggered (4740) for '{target_user}'. "
            "Lockouts are a reliable indicator of automated credential attacks."
        ),
    },
    4771: {
        "Technique_ID": "T1110",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Kerberos pre-authentication failed (4771) for '{target_user}'. "
            "May indicate credential attacks or enumeration against Kerberos infrastructure."
        ),
    },
    4776: {
        "Technique_ID": "T1003",
        "Confidence_Score": 5,
        "Justification_Template": (
            "NTLM credential validation event (4776). "
            "May indicate pass-the-hash or NTLM relay attack in progress."
        ),
    },
    4768: {
        "Technique_ID": "T1558.001",
        "Confidence_Score": 3,
        "Justification_Template": (
            "Kerberos TGT requested (4768). Baseline activity; suspicious "
            "if occurring for unusual or service accounts at off-hours."
        ),
    },
    4769: {
        "Technique_ID": "T1558.003",
        "Confidence_Score": 5,
        "Justification_Template": (
            "Kerberos service ticket requested (4769). "
            "High volume or RC4 encryption type requests indicate Kerberoasting."
        ),
    },
    4724: {
        "Technique_ID": "T1531",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Password reset attempted (4724) for '{target_user}' by '{subject_user}'. "
            "Unauthorized password resets indicate account takeover activity."
        ),
    },
    4726: {
        "Technique_ID": "T1531",
        "Confidence_Score": 7,
        "Justification_Template": (
            "User account '{target_user}' was deleted (4726) by '{subject_user}'. "
            "Unauthorized account deletions are used by threat actors to disrupt operations or remove access."
        ),
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────
    4624: {
        "Technique_ID": "T1021",
        "Confidence_Score": 3,
        "Justification_Template": (
            "Successful logon (4624) for '{target_user}'. "
            "Logon type and source IP are key context for lateral movement determination."
        ),
    },
    4648: {
        "Technique_ID": "T1550.002",
        "Confidence_Score": 7,
        "Justification_Template": (
            "Logon with explicit credentials (4648) by '{subject_user}' targeting '{target_user}'. "
            "Consistent with pass-the-hash or credential relay attacks."
        ),
    },
    5140: {
        "Technique_ID": "T1021.002",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Network share accessed (5140). SMB access from remote hosts "
            "can indicate lateral movement via admin shares (C$, ADMIN$)."
        ),
    },
    5145: {
        "Technique_ID": "T1021.002",
        "Confidence_Score": 4,
        "Justification_Template": (
            "Network share object access check (5145). "
            "Sensitive share access may indicate data staging or lateral movement preparation."
        ),
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    4720: {
        "Technique_ID": "T1136.001",
        "Confidence_Score": 8,
        "Justification_Template": (
            "New local account '{target_user}' created (4720) by '{subject_user}'. "
            "Unauthorized account creation is a high-confidence persistence indicator."
        ),
    },
    4722: {
        "Technique_ID": "T1078",
        "Confidence_Score": 5,
        "Justification_Template": (
            "User account enabled (4722) for '{target_user}'. "
            "Re-enabling dormant or disabled accounts is a known persistence technique."
        ),
    },
    4728: {
        "Technique_ID": "T1098",
        "Confidence_Score": 7,
        "Justification_Template": (
            "Account added to global security group (4728). "
            "Privileged group membership changes are a persistence mechanism."
        ),
    },
    4732: {
        "Technique_ID": "T1098",
        "Confidence_Score": 7,
        "Justification_Template": (
            "Account added to local security group (4732), e.g., Administrators. "
            "Local privilege group changes are a high-risk persistence indicator."
        ),
    },
    4756: {
        "Technique_ID": "T1098",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Account added to universal security group (4756). "
            "Group membership modification may indicate privilege escalation or persistence."
        ),
    },
    4738: {
        "Technique_ID": "T1098",
        "Confidence_Score": 5,
        "Justification_Template": (
            "User account '{target_user}' was changed (4738) by '{subject_user}'. "
            "Account modification is standard for credential modification or persistence setting."
        ),
    },
    4698: {
        "Technique_ID": "T1053.005",
        "Confidence_Score": 8,
        "Justification_Template": (
            "Scheduled task created (4698) by '{subject_user}'. "
            "Scheduled tasks are a common and effective persistence mechanism."
        ),
    },
    4702: {
        "Technique_ID": "T1053.005",
        "Confidence_Score": 7,
        "Justification_Template": (
            "Scheduled task modified (4702). Attackers hijack legitimate tasks "
            "to maintain persistence while blending with normal system activity."
        ),
    },
    4697: {
        "Technique_ID": "T1543.003",
        "Confidence_Score": 8,
        "Justification_Template": (
            "New Windows service installed (4697). "
            "Unauthorized service creation is a high-confidence persistence indicator."
        ),
    },
    7045: {
        "Technique_ID": "T1543.003",
        "Confidence_Score": 8,
        "Justification_Template": (
            "New service registered in System event log (7045). "
            "Service-based persistence is difficult to detect without proper monitoring."
        ),
    },

    # ── Defense Evasion ───────────────────────────────────────────────────────
    4657: {
        "Technique_ID": "T1112",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Registry value modified (4657). Registry changes can disable security "
            "controls, establish run-key persistence, or tamper with audit policies."
        ),
    },
    1102: {
        "Technique_ID": "T1562.002",
        "Confidence_Score": 9,
        "Justification_Template": (
            "The Windows security log was cleared (1102) by '{subject_user}'. "
            "Clearing security logs is a major indicator of threat actor activity to evade forensic analysis."
        ),
    },
    1100: {
        "Technique_ID": "T1562",
        "Confidence_Score": 8,
        "Justification_Template": (
            "The Windows Event Log service was shut down (1100). "
            "This service stoppage is commonly used by adversaries to prevent activity logging."
        ),
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    # Bug fix: 'Privilege Escalation' was missing from TACTIC_SEVERITY_MAP
    # AND from EVENT_ID_RULES in the prior codebase. Both are now corrected.
    4672: {
        "Technique_ID": "T1078",
        "Confidence_Score": 6,
        "Justification_Template": (
            "Special privileges assigned at logon (4672) for '{subject_user}'. "
            "Sensitive privileges (SeDebugPrivilege, SeImpersonatePrivilege) are escalation indicators."
        ),
    },
    4673: {
        "Technique_ID": "T1078",
        "Confidence_Score": 5,
        "Justification_Template": (
            "Privileged service invoked (4673) by '{subject_user}'. "
            "Indicates active use of sensitive Windows privilege tokens."
        ),
    },

    # ── Collection ────────────────────────────────────────────────────────────
    4663: {
        "Technique_ID": "T1039",
        "Confidence_Score": 5,
        "Justification_Template": (
            "Object access audit (4663) triggered. File access on shared drives "
            "may indicate data collection or staging for exfiltration."
        ),
    },

    # ── Benign / Informational ────────────────────────────────────────────────
    4634: {
        "Technique_ID": "None",
        "Confidence_Score": 0,
        "Justification_Template": "Account logoff (4634). Normal operational activity.",
    },
    4647: {
        "Technique_ID": "None",
        "Confidence_Score": 0,
        "Justification_Template": "User-initiated logoff (4647). Normal operational activity.",
    },
    4689: {
        "Technique_ID": "None",
        "Confidence_Score": 0,
        "Justification_Template": "Process termination (4689). Normal process lifecycle event.",
    },
    4660: {
        "Technique_ID": "None",
        "Confidence_Score": 0,
        "Justification_Template": "Object deletion (4660). May be routine file cleanup activity.",
    },
}


# Process-level rules: matched against ProcessName or CommandLine.
# Fields: field ('ProcessName' | 'CommandLine'), pattern, MITRE fields, Justification.
# The rule with the highest Confidence_Score that matches wins.
PROCESS_RULES: List[Dict[str, Any]] = [

    # ── Critical — Credential Dumping ─────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"(mimikatz|sekurlsa|lsadump|kerberos::|vault::|dpapi::)", re.I
        ),
        "Technique_ID": "T1003.001",
        "Confidence_Score": 10,
        "Justification": (
            "Mimikatz or LSASS-targeting keyword detected in command line. "
            "This is a critical indicator of in-memory credential theft."
        ),
    },

    # ── PowerShell Encoded Command ─────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"powershell[^\n]{0,100}(-enc(odedcommand)?|-e\s)\s+[A-Za-z0-9+/=]{20,}",
            re.I,
        ),
        "Technique_ID": "T1059.001",
        "Confidence_Score": 9,
        "Justification": (
            "PowerShell executed with Base64-encoded payload via -EncodedCommand/-enc. "
            "This obfuscation pattern is a hallmark of post-exploitation PowerShell activity."
        ),
    },

    # ── PowerShell Download Cradle ─────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"(New-Object\s+Net\.WebClient|\.DownloadString\(|\.DownloadFile\(|"
            r"Invoke-WebRequest\b|\biwr\b|Start-BitsTransfer)",
            re.I,
        ),
        "Technique_ID": "T1105",
        "Confidence_Score": 9,
        "Justification": (
            "PowerShell download cradle detected. Remote payload staging via "
            "WebClient or BitsTransfer is a common C2 staging technique."
        ),
    },

    # ── PowerShell Invoke-Expression ───────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(r"(Invoke-Expression\b|IEX\s*\(|\bIEX\b)", re.I),
        "Technique_ID": "T1059.001",
        "Confidence_Score": 8,
        "Justification": (
            "Invoke-Expression (IEX) detected. Used to execute dynamically constructed "
            "or downloaded code, commonly bypassing script-level defenses."
        ),
    },

    # ── PowerShell Execution Policy Bypass ────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"powershell[^\n]*(ExecutionPolicy\s+Bypass|ExecutionPolicy\s+Unrestricted"
            r"|-ep\s+bypass|-w(indowstyle)?\s+hid)",
            re.I,
        ),
        "Technique_ID": "T1059.001",
        "Confidence_Score": 8,
        "Justification": (
            "PowerShell launched with -ExecutionPolicy Bypass or hidden window flag. "
            "These flags are standard evasion tactics that suppress security warnings."
        ),
    },

    # ── MSHTA ─────────────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"mshta(\.exe)?$", re.I),
        "Technique_ID": "T1218.005",
        "Confidence_Score": 8,
        "Justification": (
            "mshta.exe execution detected. Frequently abused to execute malicious HTA "
            "scripts while bypassing application whitelisting controls."
        ),
    },

    # ── CertUtil LOLBin ────────────────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"certutil(\.exe)?\s+.*(-decode|-urlcache|-verifyctl|-f)", re.I
        ),
        "Technique_ID": "T1140",
        "Confidence_Score": 9,
        "Justification": (
            "CertUtil used with suspicious flags (-decode, -urlcache, -verifyctl). "
            "A well-documented LOLBin technique for payload decoding and file downloads."
        ),
    },

    # ── Regsvr32 Squiblydoo ────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"regsvr32(\.exe)?$", re.I),
        "Technique_ID": "T1218.010",
        "Confidence_Score": 7,
        "Justification": (
            "regsvr32.exe invoked. Frequently abused to execute COM scriptlets "
            "(squiblydoo attack), bypassing application control without touching disk."
        ),
    },

    # ── Rundll32 ──────────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"rundll32(\.exe)?$", re.I),
        "Technique_ID": "T1218.011",
        "Confidence_Score": 7,
        "Justification": (
            "rundll32.exe execution detected. Used to load and execute malicious DLLs "
            "or JavaScript via ieframe/shell32, evading detection."
        ),
    },

    # ── WMIC ──────────────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"wmic(\.exe)?$", re.I),
        "Technique_ID": "T1047",
        "Confidence_Score": 7,
        "Justification": (
            "WMIC execution detected. WMI is abused for remote execution, lateral "
            "movement, and persistence while evading traditional AV detection."
        ),
    },

    # ── Schtasks Create / Modify ───────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"schtasks(\.exe)?\s+.*(/(create|change|run))", re.I
        ),
        "Technique_ID": "T1053.005",
        "Confidence_Score": 8,
        "Justification": (
            "schtasks.exe used to create or modify a scheduled task. "
            "Attackers leverage scheduled tasks for persistence and privilege escalation."
        ),
    },

    # ── Net User Add ──────────────────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(r"net(\.exe)?\s+user\s+\S+\s+\S*\s*/?add", re.I),
        "Technique_ID": "T1136.001",
        "Confidence_Score": 9,
        "Justification": (
            "net.exe user /add detected. Creating local accounts via net.exe "
            "is a classic post-exploitation persistence technique."
        ),
    },

    # ── Net Group / LocalGroup Add ─────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"net(\.exe)?\s+(localgroup|group)\s+\S+\s+\S+\s+/?add", re.I
        ),
        "Technique_ID": "T1098",
        "Confidence_Score": 9,
        "Justification": (
            "net.exe used to add an account to a security group. "
            "Privilege group manipulation is a high-confidence persistence indicator."
        ),
    },

    # ── PsExec / Remote Execution ─────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"(psexec|paexec|psexesvc)(\.exe)?$", re.I),
        "Technique_ID": "T1569.002",
        "Confidence_Score": 9,
        "Justification": (
            "PsExec or equivalent remote execution tool detected. "
            "Widely abused for lateral movement and remote command execution in enterprise environments."
        ),
    },

    # ── BITSAdmin ─────────────────────────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"bitsadmin(\.exe)?\s+.*(/(transfer|download|addfile|resume|complete))",
            re.I,
        ),
        "Technique_ID": "T1197",
        "Confidence_Score": 8,
        "Justification": (
            "BITSAdmin used to transfer files. BITS is abused to download payloads "
            "using a trusted Windows service, bypassing firewall inspection."
        ),
    },

    # ── Netsh Firewall Modification ───────────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"netsh(\.exe)?\s+.*(advfirewall\s+set|firewall\s+(add|delete|set).*allow"
            r"|advfirewall\s+firewall)",
            re.I,
        ),
        "Technique_ID": "T1562.004",
        "Confidence_Score": 9,
        "Justification": (
            "netsh.exe used to modify firewall rules. Attackers open ports or disable "
            "firewall policies to enable C2 communication or lateral movement."
        ),
    },

    # ── Registry Modification (reg.exe) ───────────────────────────────────────
    {
        "field": "CommandLine",
        "pattern": re.compile(
            r"reg(\.exe)?\s+(add|delete|copy)\s+(HKLM|HKCU|HKCR|HKU)", re.I
        ),
        "Technique_ID": "T1112",
        "Confidence_Score": 8,
        "Justification": (
            "reg.exe used to add, delete, or copy registry keys. "
            "Used for persistence (run keys), defense evasion, and configuration tampering."
        ),
    },

    # ── MSBuild LOLBin ────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"msbuild(\.exe)?$", re.I),
        "Technique_ID": "T1127.001",
        "Confidence_Score": 7,
        "Justification": (
            "MSBuild.exe execution detected outside a build context. "
            "Used to compile and execute embedded C# payloads, bypassing application control."
        ),
    },

    # ── WScript / CScript ─────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"(wscript|cscript)(\.exe)?$", re.I),
        "Technique_ID": "T1059.005",
        "Confidence_Score": 6,
        "Justification": (
            "Windows Script Host (wscript/cscript) execution detected. "
            "Frequently used to execute malicious VBScript or JScript payloads."
        ),
    },

    # ── At.exe (Legacy Scheduler) ──────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"^at(\.exe)?$", re.I),
        "Technique_ID": "T1053.002",
        "Confidence_Score": 8,
        "Justification": (
            "at.exe (legacy scheduler) detected. Often used as an alternative to schtasks.exe "
            "to evade task-specific monitoring."
        ),
    },

    # ── Whoami ────────────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"whoami(\.exe)?$", re.I),
        "Technique_ID": "T1033",
        "Confidence_Score": 5,
        "Justification": (
            "whoami.exe executed. Commonly run immediately post-compromise "
            "to identify current user context and privilege level."
        ),
    },

    # ── System Information Enumeration ────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"(systeminfo|hostname)(\.exe)?$", re.I),
        "Technique_ID": "T1082",
        "Confidence_Score": 5,
        "Justification": (
            "System information enumeration tool executed. "
            "Used during post-exploitation reconnaissance to fingerprint the target."
        ),
    },

    # ── Network Discovery ─────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(
            r"(ipconfig|nslookup|ping|arp|netstat|route)(\.exe)?$", re.I
        ),
        "Technique_ID": "T1016",
        "Confidence_Score": 4,
        "Justification": (
            "Network configuration/discovery tool executed. "
            "Used during post-exploitation to enumerate network topology."
        ),
    },

    # ── Process Enumeration ───────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"tasklist(\.exe)?$", re.I),
        "Technique_ID": "T1057",
        "Confidence_Score": 4,
        "Justification": (
            "tasklist.exe executed. Attackers enumerate processes to identify "
            "security tools, AV products, and running services on the host."
        ),
    },

    # ── CMD Shell ─────────────────────────────────────────────────────────────
    {
        "field": "ProcessName",
        "pattern": re.compile(r"^cmd(\.exe)?$", re.I),
        "Technique_ID": "T1059.003",
        "Confidence_Score": 4,
        "Justification": (
            "cmd.exe process detected. While common, cmd.exe spawning from "
            "non-interactive or suspicious parent processes warrants investigation."
        ),
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# LOG SANITIZER  (unchanged from original — DLP redaction for displayed output)
# ══════════════════════════════════════════════════════════════════════════════

class LogSanitizer:
    """
    Redacts PII and sensitive credentials from text before display or export.
    Applied to CommandLine, ProcessName, and principal fields in the UI layer.
    """

    _KNOWN_SYSTEM = frozenset({
        r"NT AUTHORITY\SYSTEM",
        r"NT AUTHORITY\LOCAL SERVICE",
        r"NT AUTHORITY\NETWORK SERVICE",
        r"NT AUTHORITY\ANONYMOUS LOGON",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "SYSTEM",
    })

    _SECRET_PATTERNS: tuple = (
        (
            re.compile(
                r"((?:-enc(?:odedcommand)?|--encodedcommand)\\s+)([A-Za-z0-9+/=]{20,})",
                re.I,
            ),
            r"\1[REDACTED_SECRET]",
        ),
        (
            re.compile(r"(?i)(ConvertTo-SecureString\s+)(['\"]).*?\2"),
            r"\1\2[REDACTED_SECRET]\2",
        ),
        (
            re.compile(r"(?i)(/user:)([^\s]+)"),
            r"\1[REDACTED_SECRET]",
        ),
        (
            re.compile(
                r"(?i)(--password|--passwd|--pass|--token|--apikey|--api-key)\s*=\s*(\S+)"
            ),
            r"\1=[REDACTED_SECRET]",
        ),
        (
            re.compile(
                r"(?i)(--password|--passwd|--pass|--token|--apikey|--api-key)\s+(\S+)"
            ),
            r"\1 [REDACTED_SECRET]",
        ),
        (
            re.compile(r"(?i)(/password:|/pass:)([^\s]+)"),
            r"\1[REDACTED_SECRET]",
        ),
    )

    _USER_PATH = re.compile(r"(?i)([A-Za-z]:\\Users\\)([^\\]+)(\\)?")
    _IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    _IPV6 = re.compile(
        r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|"
        r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b|"
        r"\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b|"
        r"\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b|"
        r"\b(?:[0-9A-Fa-f]{1,4}:){1,6}::(?:[0-9A-Fa-f]{1,4}:){0,6}"
        r"[0-9A-Fa-f]{1,4}\b",
        re.I,
    )

    def sanitize_secrets(self, text: str) -> str:
        """Redact passwords, tokens, encoded payloads, and credential flags."""
        out = text
        for pattern, repl in self._SECRET_PATTERNS:
            out = pattern.sub(repl, out)
        return out

    def sanitize_windows_user_paths(self, text: str) -> str:
        """Redact human usernames in C:\\Users\\<name>\\ paths."""
        def _repl(match: re.Match) -> str:
            if match.group(3):
                return f"{match.group(1)}[REDACTED_USER]\\"
            return f"{match.group(1)}[REDACTED_USER]"
        return self._USER_PATH.sub(_repl, text)

    def sanitize_ips(self, text: str) -> str:
        """Redact IPv4 and common IPv6 address forms."""
        out = self._IPV4.sub("[REDACTED_IP]", text)
        return self._IPV6.sub("[REDACTED_IP]", out)

    def sanitize_principal(self, principal: str) -> str:
        """Redact DOMAIN\\user principals; preserve well-known system accounts."""
        p = principal.strip()
        if not p:
            return p
        if p.upper() in {k.upper() for k in self._KNOWN_SYSTEM}:
            return p
        if "\\" in p:
            domain, _user = p.rsplit("\\", 1)
            return f"{domain}\\[REDACTED_USER]"
        return "[REDACTED_USER]"

    def sanitize_all(self, text: str) -> str:
        """Apply secret, path, and IP redaction (for command lines and process paths)."""
        out = self.sanitize_secrets(text)
        out = self.sanitize_windows_user_paths(out)
        return self.sanitize_ips(out)


# ══════════════════════════════════════════════════════════════════════════════
# RULE ENGINE  (replaces GenAIAnalyzer — zero external dependencies)
# ══════════════════════════════════════════════════════════════════════════════

class RuleEngine:
    """
    Deterministic MITRE ATT&CK mapper.

    For each event:
      1. Looks up the base classification in EVENT_ID_RULES.
      2. Scans all PROCESS_RULES against ProcessName and CommandLine.
      3. Selects the result with the highest Confidence_Score.
      4. Enriches via RiskScoringEngine (risk score, severity, IOCs, kill chain).
      5. Enriches with official MITRE ATT&CK STIX 2.1 metadata (description,
         tactics cross-reference, ATT&CK URL) via the cached STIX ingestor.
    """

    def __init__(self) -> None:
        self.sanitizer = LogSanitizer()
        # _mitre_db is lazy-loaded on first use via the `mitre_db` property.
        # This avoids blocking server startup with a network fetch.
        self._mitre_db: Optional[Dict[str, Any]] = None
        logger.info(
            f"RuleEngine initialised — "
            f"{len(EVENT_ID_RULES)} EventID rules, "
            f"{len(PROCESS_RULES)} process rules loaded."
        )

    @property
    def mitre_db(self) -> Dict[str, Any]:
        """Lazy-load the MITRE ATT&CK STIX dictionary on first access."""
        if self._mitre_db is None:
            self._mitre_db = get_mitre_data()
            logger.info(
                f"MITRE ATT&CK STIX DB ready: {len(self._mitre_db)} techniques."
            )
        return self._mitre_db

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single event and return the full MITRE-enriched analysis dict."""
        event_id = self._parse_event_id(event)

        base = self._match_event_id(event_id, event)
        proc = self._match_process_rules(event)

        # Pick the higher-confidence result
        if proc and proc.get("Confidence_Score", 0) > base.get("Confidence_Score", 0):
            result = proc
        else:
            result = base

        # Step 4 — augment with official MITRE ATT&CK STIX metadata FIRST
        result = self._enrich_from_mitre(result)

        # Step 5 — risk score, severity, IOCs, kill chain (local heuristics based on dynamic Tactic)
        result = RiskScoringEngine.enrich_analysis(result, event)

        return result

    def analyze_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify a list of events. Deterministic — no batching needed."""
        return [self.analyze_event(e) for e in events]

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_event_id(self, event: Dict[str, Any]) -> Optional[int]:
        raw = event.get("EventID")
        if raw is None:
            return None
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None

    def _match_event_id(
        self, event_id: Optional[int], event: Dict[str, Any]
    ) -> Dict[str, Any]:
        if event_id is not None and event_id in EVENT_ID_RULES:
            rule = dict(EVENT_ID_RULES[event_id])  # shallow copy
            template = rule.pop("Justification_Template", "")
            rule["Justification"] = self._fill_template(template, event)
            return rule

        return {
            "Technique_ID": "None",
            "Confidence_Score": 0,
            "Justification": (
                f"EventID {event_id} is not mapped to a known MITRE ATT&CK technique. "
                "Treat as informational."
            ),
        }

    def _match_process_rules(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the highest-confidence matching process rule, or None."""
        best: Optional[Dict[str, Any]] = None
        best_score = -1

        process_name = event.get("ProcessName", "") or ""
        command_line = event.get("CommandLine", "") or ""

        for rule in PROCESS_RULES:
            text = process_name if rule["field"] == "ProcessName" else command_line
            if not text:
                continue
            if rule["pattern"].search(text):
                score = rule.get("Confidence_Score", 0)
                if score > best_score:
                    best_score = score
                    best = {
                        "Technique_ID": rule["Technique_ID"],
                        "Confidence_Score": rule["Confidence_Score"],
                        "Justification": rule["Justification"],
                    }
        return best

    def _fill_template(self, template: str, event: Dict[str, Any]) -> str:
        """Substitute event fields into a justification template string."""
        process = event.get("ProcessName", "Unknown") or "Unknown"
        target_user = (
            event.get("TargetUserName")
            or event.get("SubjectUserName")
            or "Unknown"
        )
        subject_user = event.get("SubjectUserName", "Unknown") or "Unknown"
        try:
            return template.format(
                process=process,
                target_user=target_user,
                subject_user=subject_user,
            )
        except (KeyError, IndexError):
            return template

    # STIX tactic phase names → Lockheed Martin Kill Chain phases
    _STIX_TACTIC_TO_KILL_CHAIN: Dict[str, str] = {
        "reconnaissance": "Reconnaissance",
        "resource-development": "Weaponization",
        "initial-access": "Delivery",
        "execution": "Exploitation",
        "persistence": "Installation",
        "privilege-escalation": "Installation",
        "defense-evasion": "Installation",
        "credential-access": "Command & Control",
        "discovery": "Command & Control",
        "lateral-movement": "Command & Control",
        "collection": "Actions on Objectives",
        "command-and-control": "Command & Control",
        "exfiltration": "Actions on Objectives",
        "impact": "Actions on Objectives",
    }

    def _enrich_from_mitre(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Augment a result dict with official MITRE ATT&CK STIX metadata:
          • Appends the official technique description to Justification.
          • Cross-references Kill_Chain_Phase using STIX tactic names
            (only overrides if the current value is 'Unknown').
          • Appends the ATT&CK technique URL to Mitigation_Steps.

        Performs a two-pass lookup: exact Technique_ID first, then the
        parent technique ID (e.g. T1059 for T1059.001) as a fallback.
        """
        technique_id: str = result.get("Technique_ID", "None") or "None"
        if technique_id in ("None", ""):
            result["Tactic"] = "None"
            result["Technique_Name"] = "None"
            return result

        # Two-pass lookup: sub-technique → parent technique
        entry = self.mitre_db.get(technique_id)
        if not entry:
            parent_id = technique_id.split(".")[0]
            entry = self.mitre_db.get(parent_id)

        if not entry:
            result["Tactic"] = "None"
            result["Technique_Name"] = "Unknown"
            return result  # Not in STIX DB — leave result unchanged

        # Dynamically inject Tactic and Technique_Name from STIX
        result["Technique_Name"] = entry.get("name", "Unknown")
        tactics = entry.get("tactics", [])
        if tactics:
            # e.g., 'command-and-control' -> 'Command and Control'
            result["Tactic"] = tactics[0].replace("-", " ").title()
        else:
            result["Tactic"] = "Unknown"

        # ── 1. Enrich Justification with official MITRE description ────────
        mitre_desc = entry.get("description", "")
        if mitre_desc:
            existing = result.get("Justification", "")
            result["Justification"] = (
                f"{existing}\n\n"
                f"[MITRE ATT&CK — {technique_id}] {mitre_desc}"
            )

        # ── 2. Cross-reference Kill_Chain_Phase via STIX tactics ───────────
        if result.get("Kill_Chain_Phase", "Unknown") == "Unknown":
            for tactic_phase in entry.get("tactics", []):
                kc = self._STIX_TACTIC_TO_KILL_CHAIN.get(tactic_phase.lower())
                if kc:
                    result["Kill_Chain_Phase"] = kc
                    break

        # ── 3. Append official ATT&CK URL to Mitigation_Steps ─────────────
        mitre_url = entry.get("url", "")
        if not mitre_url and technique_id not in ("None", ""):
            # Construct URL from ID if not present in entry
            mitre_url = (
                "https://attack.mitre.org/techniques/"
                + technique_id.replace(".", "/") + "/"
            )
        if mitre_url:
            existing_mit = result.get("Mitigation_Steps", "")
            result["Mitigation_Steps"] = (
                f"{existing_mit}\n\n"
                f"[MITRE ATT&CK Reference] {mitre_url}"
            )

        return result


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING ENGINE  (audit fixes applied)
# ══════════════════════════════════════════════════════════════════════════════

class RiskScoringEngine:
    """Calculates enterprise-grade risk scores (1-12) and assigns threat actions."""

    # Audit fix: 'Privilege Escalation' was missing — added at severity 3.
    TACTIC_SEVERITY_MAP: Dict[str, int] = {
        "Reconnaissance": 1,
        "Resource Development": 1,
        "Initial Access": 2,
        "Execution": 2,
        "Persistence": 2,
        "Defense Evasion": 2,
        "Privilege Escalation": 3,   # ← Bug fix: was absent, defaulted to 1
        "Credential Access": 3,
        "Discovery": 2,
        "Lateral Movement": 3,
        "Collection": 3,
        "Command and Control": 3,
        "Exfiltration": 4,
        "Impact": 4,
    }

    @staticmethod
    def map_confidence_to_level(confidence_score: int) -> int:
        """Convert 0-10 confidence score to 1-3 confidence level."""
        if confidence_score <= 3:
            return 1
        elif confidence_score <= 7:
            return 2
        else:
            return 3

    @staticmethod
    def get_severity_from_tactic(tactic: str) -> int:
        """Map MITRE ATT&CK tactic to severity level (1-4)."""
        if tactic == "None":
            return 1
        for key, severity in RiskScoringEngine.TACTIC_SEVERITY_MAP.items():
            if key.lower() in tactic.lower():
                return severity
        return 1

    @staticmethod
    def calculate_risk_score(confidence_score: int, tactic: str) -> int:
        """Risk score (1-12) = Severity (1-4) × Confidence Level (1-3)."""
        # Audit fix: clamp confidence to [0, 10] using min() before computation.
        # Previous code used floor division which incorrectly mapped 11 → 1.
        clamped = min(max(confidence_score, 0), 10)
        severity = RiskScoringEngine.get_severity_from_tactic(tactic)
        confidence_level = RiskScoringEngine.map_confidence_to_level(clamped)
        return min(severity * confidence_level, 12)

    @staticmethod
    def assign_threat_severity(risk_score: int) -> str:
        if risk_score <= 3:
            return "Low"
        elif risk_score <= 7:
            return "Medium"
        elif risk_score <= 9:
            return "High"
        else:
            return "Critical"

    @staticmethod
    def assign_status(risk_score: int) -> str:
        if risk_score <= 3:
            return "Auto-closed"
        elif risk_score <= 7:
            return "Queued"
        elif risk_score <= 9:
            return "Alert"
        else:
            return "Isolate"

    @staticmethod
    def extract_iocs(event: Dict[str, Any]) -> List[str]:
        """Extract Indicators of Compromise (IOCs) from raw event data."""
        iocs: List[str] = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        url_pattern = re.compile(r"https?://[^\s]+")

        command_line = event.get("CommandLine", "") or ""
        if command_line:
            iocs.extend(ip_pattern.findall(command_line))
            iocs.extend(url_pattern.findall(command_line))

        process_name = event.get("ProcessName", "") or ""
        safe_procs = {"explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe"}
        if process_name and process_name.lower() not in safe_procs:
            iocs.append(f"ProcessName:{process_name}")

        return list(set(iocs))

    @staticmethod
    def enrich_analysis(
        analysis: Dict[str, Any], event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich an analysis dict with risk scoring, IOCs, kill chain, and mitigations."""
        tactic = analysis.get("Tactic", "None")
        confidence = analysis.get("Confidence_Score", 0)

        risk_score = RiskScoringEngine.calculate_risk_score(confidence, tactic)
        threat_severity = RiskScoringEngine.assign_threat_severity(risk_score)
        status = RiskScoringEngine.assign_status(risk_score)
        iocs = RiskScoringEngine.extract_iocs(event)
        technique_name = analysis.get("Technique_Name", "Unknown")
        kill_chain_phase = RiskScoringEngine._map_to_kill_chain(tactic, technique_name)

        analysis["Risk_Score"] = risk_score
        analysis["Threat_Severity"] = threat_severity
        analysis["Status"] = status
        analysis["IOCs"] = iocs
        analysis["Kill_Chain_Phase"] = kill_chain_phase
        analysis["Threat_Actor"] = "Unknown"
        analysis["Mitigation_Steps"] = RiskScoringEngine._generate_mitigation_steps(
            tactic, technique_name
        )
        return analysis

    @staticmethod
    def _map_to_kill_chain(tactic: str, technique_name: str) -> str:
        mapping = {
            "Reconnaissance": "Reconnaissance",
            "Resource Development": "Weaponization",
            "Initial Access": "Delivery",
            "Execution": "Exploitation",
            "Persistence": "Installation",
            "Privilege Escalation": "Installation",
            "Defense Evasion": "Installation",
            "Credential Access": "Command & Control",
            "Discovery": "Command & Control",
            "Lateral Movement": "Command & Control",
            "Collection": "Actions on Objectives",
            "Command and Control": "Command & Control",
            "Exfiltration": "Actions on Objectives",
            "Impact": "Actions on Objectives",
        }
        for key, phase in mapping.items():
            if key.lower() in tactic.lower():
                return phase
        return "Unknown"

    @staticmethod
    def _generate_mitigation_steps(tactic: str, technique_name: str) -> str:
        mitigations = {
            "PowerShell": (
                "Disable PowerShell v2; enable Script Block Logging (4104); "
                "enforce Constrained Language Mode; monitor -EncodedCommand usage."
            ),
            "Command-line": (
                "Restrict interactive shell access; implement AppLocker/WDAC policies; "
                "monitor cmd.exe spawning from Office or browser processes."
            ),
            "Execution": (
                "Monitor process creation events; restrict execution via AppLocker; "
                "deploy EDR with behavioural detection."
            ),
            "Persistence": (
                "Audit scheduled tasks (4698/4702) and registry run keys; "
                "monitor service installations; review startup folder contents."
            ),
            "Lateral Movement": (
                "Segment network with micro-perimeters; enforce MFA; "
                "restrict SMB access; monitor PsExec and WMI lateral movement."
            ),
            "Credential Access": (
                "Enforce strong passwords + MFA; monitor 4625/4740 lockout events; "
                "protect LSASS with Credential Guard; disable NTLM where possible."
            ),
            "Defense Evasion": (
                "Enable WDAC/AppLocker; monitor LOLBin usage (regsvr32, mshta, rundll32); "
                "audit registry modifications; use attack surface reduction rules."
            ),
            "Privilege Escalation": (
                "Apply least-privilege principle; monitor 4672 special privilege events; "
                "enable UAC; audit local administrator group membership changes."
            ),
            "Discovery": (
                "Monitor reconnaissance utilities (whoami, systeminfo, ipconfig); "
                "alert on unusual enumeration sequences post-logon."
            ),
            "Exfiltration": (
                "Monitor outbound connections; deploy DLP; segment sensitive data; "
                "alert on large data transfers to external IPs."
            ),
            "Impact": (
                "Maintain offline backups; test incident response plan; "
                "implement network isolation runbooks for ransomware scenarios."
            ),
        }
        for key, steps in mitigations.items():
            if key.lower() in technique_name.lower() or key.lower() in tactic.lower():
                return steps
        return (
            "Apply defence-in-depth: monitor and log relevant events, "
            "enforce least privilege, and maintain up-to-date endpoint protection."
        )


# ══════════════════════════════════════════════════════════════════════════════
# EVENT LOG PARSER
# ══════════════════════════════════════════════════════════════════════════════

class EventLogParser:
    """Handles parsing of Windows Event Log files (CSV and JSON formats)."""

    @staticmethod
    def detect_file_type(file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            return "csv"
        elif ext == ".json":
            return "json"
        raise ValueError(f"Unsupported file type: '{ext}'. Use .csv or .json.")

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    events.append(EventLogParser._normalize_event(row))
        except Exception as exc:
            logger.error(f"Failed to parse CSV '{file_path}': {exc}")
            raise
        return events

    @staticmethod
    def parse_json(file_path: str) -> List[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                raise ValueError("JSON must contain an object or an array of objects.")
            return [EventLogParser._normalize_event(item) for item in data]
        except Exception as exc:
            logger.error(f"Failed to parse JSON '{file_path}': {exc}")
            raise

    @staticmethod
    def parse_uploaded(content: bytes, suffix: str) -> List[Dict[str, Any]]:
        """Parse bytes from a Streamlit file upload (avoids touching the FS)."""
        import io
        suffix = suffix.lower().lstrip(".")
        try:
            if suffix == "json":
                data = json.loads(content.decode("utf-8"))
                if isinstance(data, dict):
                    data = [data]
                return [EventLogParser._normalize_event(item) for item in data]
            elif suffix == "csv":
                text = content.decode("utf-8")
                reader = csv.DictReader(io.StringIO(text))
                return [
                    EventLogParser._normalize_event(row) for row in reader
                ]
            else:
                raise ValueError(f"Unsupported upload type: .{suffix}")
        except Exception as exc:
            logger.error(f"Failed to parse uploaded file: {exc}")
            raise

    @staticmethod
    def _flatten_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intelligently flattens a nested Windows Event Log dictionary.
        Handles:
          - Standard flat structures.
          - Deeply nested 'Event -> System / EventData' structures.
          - XML-to-JSON list formats inside 'EventData -> Data'.
        """
        flat: Dict[str, Any] = {}
        
        def recurse(d: Any):
            if not isinstance(d, dict):
                return
            for k, v in d.items():
                if k == "Data" and isinstance(v, list):
                    # Handle the XML-to-JSON EventData list format
                    for item in v:
                        if isinstance(item, dict):
                            name = item.get("@Name") or item.get("Name")
                            val = item.get("#text") or item.get("Value") or item.get("$")
                            if name and val is not None:
                                flat[str(name)] = val
                elif isinstance(v, dict):
                    # Check if it has a leaf value like {"#text": ...} or similar
                    leaf_found = False
                    for leaf_key in ["#text", "@SystemTime", "$", "Value"]:
                        if leaf_key in v:
                            flat[k] = v[leaf_key]
                            leaf_found = True
                            break
                    if not leaf_found:
                        recurse(v)
                elif isinstance(v, list):
                    for item in v:
                        recurse(item)
                else:
                    flat[k] = v

        recurse(event)
        return flat

    @staticmethod
    def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalise raw event fields to a consistent schema.
        Handles flat, nested, and XML-to-JSON format variants.
        """
        flat = EventLogParser._flatten_event(event)
        
        def get_field(keys: List[str], default: Any = "") -> Any:
            for k in keys:
                if k in flat:
                    return flat[k]
            return default
            
        normalized = {
            "EventID": get_field(["EventID", "Id", "event_id"]),
            "TimeCreated": get_field(
                ["TimeCreated", "SystemTime", "time_created"], 
                datetime.now(timezone.utc).isoformat()
            ),
            "ComputerName": get_field(["ComputerName", "Computer", "host", "MachineName"], "Unknown"),
            "ProcessName": get_field(["ProcessName", "NewProcessName", "Image", "process_name"]),
            "CommandLine": get_field(["CommandLine", "command_line"]),
            "ParentProcessName": get_field(["ParentProcessName", "ParentImage", "parent_process_name"]),
            "SubjectUserName": get_field(["SubjectUserName", "SubjectUser", "user_name", "user"]),
            "SubjectDomainName": get_field(["SubjectDomainName", "SubjectDomain"]),
            "TargetUserName": get_field(["TargetUserName", "TargetUser"]),
            "TargetDomainName": get_field(["TargetDomainName", "TargetDomain"]),
        }
        # Drop None and empty strings for a cleaner payload
        return {k: v for k, v in normalized.items() if v is not None and v != ""}


# ══════════════════════════════════════════════════════════════════════════════
# EVENT MAPPER  (CLI orchestrator — uses RuleEngine)
# ══════════════════════════════════════════════════════════════════════════════

class EventMapper:
    """CLI orchestrator: parse → analyse → save → print."""

    def __init__(self) -> None:
        self.parser = EventLogParser()
        self.analyzer = RuleEngine()
        self.results: List[Dict[str, Any]] = []

    def process_file(self, file_path: str) -> None:
        logger.info(f"Parsing events from '{file_path}'")
        file_type = self.parser.detect_file_type(file_path)
        events = (
            self.parser.parse_csv(file_path)
            if file_type == "csv"
            else self.parser.parse_json(file_path)
        )
        if not events:
            logger.warning("No events found in file.")
            return

        logger.info(f"Analysing {len(events)} events…")
        for idx, event in enumerate(events, 1):
            analysis = self.analyzer.analyze_event(event)
            self.results.append({
                "Event": event,
                "Analysis": analysis,
                "ProcessedAt": datetime.now(timezone.utc).isoformat(),
            })
        self.save_results()
        logger.info(f"Done. Results written to '{OUTPUT_FILE}'.")

    def save_results(self) -> None:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2, ensure_ascii=False)

    def print_results(self) -> None:
        if not self.results:
            print("No results to display.")
            return
        print("\n" + "=" * 80)
        print("AURA THREAT ANALYSIS RESULTS")
        print("=" * 80)
        for idx, result in enumerate(self.results, 1):
            event = result["Event"]
            analysis = result["Analysis"]
            print(f"\nEvent #{idx}  —  EventID: {event.get('EventID', 'N/A')}")
            print(f"  Process  : {event.get('ProcessName', 'N/A')}")
            if event.get("CommandLine"):
                print(f"  Command  : {event['CommandLine']}")
            print("-" * 50)
            score = analysis.get("Confidence_Score", 0)
            print(f"  Tactic   : {analysis.get('Tactic', 'N/A')}")
            print(f"  Technique: {analysis.get('Technique_ID')} — {analysis.get('Technique_Name')}")
            print(f"  Confidence: {self._confidence_meter(score)}")
            print(f"  Risk Score: {analysis.get('Risk_Score')}/12  |  Severity: {analysis.get('Threat_Severity')}")
            print(f"  Status   : {analysis.get('Status')}")
            print(f"  Justification: {analysis.get('Justification')}")
        print("\n" + "=" * 80)

    @staticmethod
    def _confidence_meter(score: int) -> str:
        if score == 0:
            return "✅ NONE (0/10)"
        elif score <= 3:
            return f"🔵 LOW ({score}/10)"
        elif score <= 6:
            return f"🟡 MEDIUM ({score}/10)"
        elif score <= 8:
            return f"🟠 HIGH ({score}/10)"
        else:
            return f"🔴 CRITICAL ({score}/10)"


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Reconfigure stdout/stderr to UTF-8 to prevent charmap codec errors when printing emojis on Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="AURA — Map Windows Event Logs to MITRE ATT&CK (deterministic engine)"
    )
    ap.add_argument("file_path", help="Path to the event log file (.csv or .json)")
    args = ap.parse_args()

    if not os.path.exists(args.file_path):
        print(f"Error: file not found — '{args.file_path}'")
        sys.exit(1)

    try:
        mapper = EventMapper()
        mapper.process_file(args.file_path)
        mapper.print_results()
    except KeyboardInterrupt:
        print("\nAnalysis interrupted.")
        sys.exit(1)
    except Exception as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
