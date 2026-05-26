#!/usr/bin/env python3
"""
AURA — MITRE ATT&CK STIX 2.1 Ingestor
mitre_ingestor.py

Downloads the official MITRE Enterprise ATT&CK STIX 2.1 bundle once every
24 hours, parses it into a lightweight Technique-ID → metadata dictionary,
and exposes it via `get_mitre_data()`.

Caching strategy
────────────────
• When run inside a Streamlit process  → @st.cache_data(ttl=86400) is applied,
  so the 10 MB file is fetched and parsed at most once per day per worker.
• When run from the CLI (event_mapper.py __main__)  → a module-level singleton
  dict is used so the fetch happens at most once per process lifetime.

Fallback
────────
If the network fetch fails for any reason (timeout, DNS, rate-limit) the
function returns _FALLBACK_DB — a hardcoded dictionary covering every technique
referenced by the 31 EventID rules and 25 process rules in event_mapper.py.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)

# ─── Source ───────────────────────────────────────────────────────────────────
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_FETCH_TIMEOUT_S = 20  # seconds


# ══════════════════════════════════════════════════════════════════════════════
# FALLBACK DATABASE
# Covers every Technique_ID referenced by our deterministic rules so the app
# never crashes on a network failure.
# ══════════════════════════════════════════════════════════════════════════════
_FALLBACK_DB: Dict[str, Dict[str, Any]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, "
            "scripts, or binaries. These interfaces and languages provide ways of "
            "interacting with computer systems and are a common feature across many platforms."
        ),
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for execution. "
            "PowerShell is a powerful interactive command-line interface and scripting "
            "environment included in Windows. Adversaries can use it to run .NET code, "
            "download payloads, and bypass execution policies."
        ),
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059/003/",
        "description": (
            "Adversaries may abuse the Windows command shell for execution. "
            "The Windows command shell (cmd.exe) is the primary command prompt on Windows "
            "systems and can be used to control almost all aspects of a system."
        ),
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059/005/",
        "description": (
            "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming "
            "language created by Microsoft with interoperability with Windows APIs. "
            "Malicious VB content may also be delivered as an email attachment."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a means "
            "of gaining initial access, persistence, privilege escalation, or defense evasion. "
            "Compromised credentials may be used to bypass access controls placed on resources."
        ),
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactics": ["persistence", "privilege-escalation"],
        "url": "https://attack.mitre.org/techniques/T1098/",
        "description": (
            "Adversaries may manipulate accounts to maintain and/or elevate access to victim "
            "systems. Account manipulation may consist of any action that preserves adversary "
            "access to a compromised account, such as modifying credentials or permissions."
        ),
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1003/",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login information, "
            "in the form of a hash or a cleartext password. Credentials can be obtained from "
            "OS caches, memory, or structured files."
        ),
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1003/001/",
        "description": (
            "Adversaries may attempt to access credential material stored in the process "
            "memory of the Local Security Authority Subsystem Service (LSASS). After a user "
            "logs on, the system generates and stores a variety of credential materials in LSASS."
        ),
    },
    "T1021": {
        "name": "Remote Services",
        "tactics": ["lateral-movement"],
        "url": "https://attack.mitre.org/techniques/T1021/",
        "description": (
            "Adversaries may use Valid Accounts to log into a service that accepts remote "
            "connections, such as Telnet, SSH, and VNC. The adversary may then perform "
            "actions as the logged-on user."
        ),
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactics": ["lateral-movement"],
        "url": "https://attack.mitre.org/techniques/T1021/002/",
        "description": (
            "Adversaries may use Valid Accounts to interact with a remote network share "
            "using Server Message Block (SMB). The adversary may then perform file copy "
            "operations or execute binaries on the remote system using admin shares such as C$."
        ),
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1047/",
        "description": (
            "Adversaries may abuse Windows Management Instrumentation (WMI) to execute "
            "malicious commands and payloads. WMI is natively available on Windows and "
            "provides an interface for performing system management tasks."
        ),
    },
    "T1053.002": {
        "name": "At",
        "tactics": ["execution", "persistence", "privilege-escalation"],
        "url": "https://attack.mitre.org/techniques/T1053/002/",
        "description": (
            "Adversaries may abuse the at utility to perform task scheduling for initial "
            "or recurring execution of malicious code. The at utility exists as an executable "
            "within Windows for scheduling tasks at a specified time and date."
        ),
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactics": ["execution", "persistence", "privilege-escalation"],
        "url": "https://attack.mitre.org/techniques/T1053/005/",
        "description": (
            "Adversaries may abuse the Windows Task Scheduler to perform task scheduling "
            "for initial or recurring execution of malicious code. Adversaries may use "
            "task scheduling to execute programs at system startup or on a scheduled basis."
        ),
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["command-and-control"],
        "url": "https://attack.mitre.org/techniques/T1105/",
        "description": (
            "Adversaries may transfer tools or other files from an external system into "
            "a compromised environment. Files may be copied from an external adversary "
            "controlled system through the command-and-control channel or through other tools."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when "
            "passwords are unknown or when password hashes are obtained. Without knowledge "
            "of the password, an adversary may opt to try multiple passwords."
        ),
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": (
            "Adversaries with no prior knowledge of legitimate credentials within the system "
            "or environment may guess passwords to attempt access to accounts. Adversaries "
            "may attempt to guess credentials of known users."
        ),
    },
    "T1112": {
        "name": "Modify Registry",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1112/",
        "description": (
            "Adversaries may interact with the Windows Registry to hide configuration "
            "information within Registry keys, remove information as part of cleaning up, "
            "or as part of other techniques to aid in persistence and execution."
        ),
    },
    "T1127.001": {
        "name": "MSBuild",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1127/001/",
        "description": (
            "Adversaries may use MSBuild to proxy execution of code through a trusted "
            "Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build "
            "platform used by Visual Studio and can execute inline C# or VB code."
        ),
    },
    "T1136.001": {
        "name": "Local Account",
        "tactics": ["persistence"],
        "url": "https://attack.mitre.org/techniques/T1136/001/",
        "description": (
            "Adversaries may create a local account to maintain access to victim systems. "
            "Local accounts are those configured by an organization for use by users, "
            "remote support, services, or for administration on a single system."
        ),
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1140/",
        "description": (
            "Adversaries may use Obfuscated Files or Information to hide artifacts of an "
            "intrusion from analysis. They may require separate mechanisms to decode or "
            "deobfuscate the information depending on how it was encoded."
        ),
    },
    "T1197": {
        "name": "BITS Jobs",
        "tactics": ["defense-evasion", "persistence"],
        "url": "https://attack.mitre.org/techniques/T1197/",
        "description": (
            "Adversaries may abuse BITS (Background Intelligent Transfer Service) to "
            "download, execute, and clean up after running malicious code. BITS is commonly "
            "used by updaters and messengers and can be abused to avoid triggering firewalls."
        ),
    },
    "T1218.005": {
        "name": "Mshta",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1218/005/",
        "description": (
            "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files "
            "and Javascript or VBScript through a trusted Windows utility. Mshta.exe is a "
            "utility that executes Microsoft HTML Applications (HTA) files."
        ),
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1218/010/",
        "description": (
            "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. "
            "Regsvr32.exe is a command-line program used to register and unregister object "
            "linking and embedding controls, including DLLs, on Windows systems."
        ),
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1218/011/",
        "description": (
            "Adversaries may abuse rundll32.exe to proxy execution of malicious code. "
            "Using Rundll32.exe, vice executing directly, may avoid triggering security "
            "tools that may not monitor execution of the Rundll32.exe process."
        ),
    },
    "T1531": {
        "name": "Account Access Removal",
        "tactics": ["impact"],
        "url": "https://attack.mitre.org/techniques/T1531/",
        "description": (
            "Adversaries may interrupt availability of system and network resources by "
            "inhibiting access to accounts utilized by legitimate users. Accounts may be "
            "deleted, locked, or manipulated to remove access to accounts."
        ),
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactics": ["persistence", "privilege-escalation"],
        "url": "https://attack.mitre.org/techniques/T1543/003/",
        "description": (
            "Adversaries may create or modify Windows services to repeatedly execute "
            "malicious payloads as part of persistence. When Windows boots up, it starts "
            "programs or applications called services that perform background system functions."
        ),
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactics": ["defense-evasion", "lateral-movement"],
        "url": "https://attack.mitre.org/techniques/T1550/002/",
        "description": (
            "Adversaries may 'pass the hash' using stolen password hashes to move "
            "laterally within an environment, bypassing normal system access controls. "
            "Pass the Hash is a method of authenticating without access to the plaintext password."
        ),
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactics": ["credential-access", "collection"],
        "url": "https://attack.mitre.org/techniques/T1557/",
        "description": (
            "Adversaries may attempt to position themselves between two or more networked "
            "devices using an adversary-in-the-middle technique to support follow-on behaviors "
            "such as network sniffing or transmitted data manipulation."
        ),
    },
    "T1558.001": {
        "name": "Golden Ticket",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1558/001/",
        "description": (
            "Adversaries who have the KRBTGT account password hash may forge Kerberos "
            "ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets "
            "enable adversaries to generate authentication material for any account."
        ),
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1558/003/",
        "description": (
            "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff "
            "network traffic to obtain a ticket-granting service (TGS) ticket that may be "
            "vulnerable to Brute Force cracking (Kerberoasting)."
        ),
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1562/",
        "description": (
            "Adversaries may impair defenses to evade detection and avoid security controls. "
            "This may include disabling or bypassing security services, firewalls, and audit logs."
        ),
    },
    "T1562.002": {
        "name": "Disable Windows Event Logging",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1562/002/",
        "description": (
            "Adversaries may disable Windows Event Logging to prevent system activity and "
            "security audits from being recorded, evading detection during post-compromise actions."
        ),
    },
    "T1562.004": {
        "name": "Disable or Modify System Firewall",
        "tactics": ["defense-evasion"],
        "url": "https://attack.mitre.org/techniques/T1562/004/",
        "description": (
            "Adversaries may disable or modify system firewalls in order to bypass controls "
            "limiting network usage. Changes could be temporary or permanently altering "
            "settings to allow commands or malicious code to execute."
        ),
    },
    "T1569.002": {
        "name": "Service Execution",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1569/002/",
        "description": (
            "Adversaries may abuse the Windows service control manager to execute malicious "
            "commands or payloads. The Windows service control manager (services.exe) handles "
            "system services and can be used to execute programs at startup or on command."
        ),
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactics": ["discovery"],
        "url": "https://attack.mitre.org/techniques/T1033/",
        "description": (
            "Adversaries may attempt to identify the primary user, currently logged in user, "
            "set of users that commonly use a system, or whether a user is actively using "
            "the system. Adversaries may use this information to shape follow-on behaviors."
        ),
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactics": ["collection"],
        "url": "https://attack.mitre.org/techniques/T1039/",
        "description": (
            "Adversaries may search network shares on computers they have compromised to "
            "find files of interest. Sensitive data can be collected from remote systems "
            "via shared drives on network resources."
        ),
    },
    "T1057": {
        "name": "Process Discovery",
        "tactics": ["discovery"],
        "url": "https://attack.mitre.org/techniques/T1057/",
        "description": (
            "Adversaries may attempt to get information about running processes on a system. "
            "Information obtained could be used to gain an understanding of common software "
            "or security solutions running on a system."
        ),
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ["discovery"],
        "url": "https://attack.mitre.org/techniques/T1082/",
        "description": (
            "An adversary may attempt to get detailed information about the operating system "
            "and hardware, including version, patches, hotfixes, service packs, and "
            "architecture. Adversaries may use this information to shape follow-on behaviors."
        ),
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactics": ["discovery"],
        "url": "https://attack.mitre.org/techniques/T1016/",
        "description": (
            "Adversaries may look for details about the network configuration and settings "
            "of systems they access or through information discovery of remote systems. "
            "Several operating system administration utilities exist that can be used to gather this information."
        ),
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# STIX PARSING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _truncate_description(text: str, max_sentences: int = 3) -> str:
    """Return the first `max_sentences` sentences of a description string."""
    if not text:
        return ""
    # Split on ". " to get sentences; reassemble
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    truncated = " ".join(parts[:max_sentences])
    if not truncated.endswith((".", "!", "?")):
        truncated += "."
    return truncated


def _parse_stix_bundle(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Parse a STIX 2.1 bundle dict into:
        { "T1059": { name, tactics, description, url }, ... }

    Only processes non-revoked attack-pattern objects from the enterprise bundle.
    """
    db: Dict[str, Dict[str, Any]] = {}

    for obj in data.get("objects", []):
        # Only attack-patterns (techniques / sub-techniques)
        if obj.get("type") != "attack-pattern":
            continue
        # Skip revoked or deprecated entries
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # ── Extract Technique ID ──────────────────────────────────────────────
        technique_id: Optional[str] = None
        mitre_url: str = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                mitre_url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # ── Extract tactics from kill_chain_phases ────────────────────────────
        tactics: List[str] = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # ── Truncate description ──────────────────────────────────────────────
        description = _truncate_description(obj.get("description", ""), max_sentences=3)

        db[technique_id] = {
            "name": obj.get("name", "Unknown"),
            "tactics": tactics,
            "description": description,
            "url": mitre_url,
        }

    logger.info(f"STIX parse complete: {len(db)} techniques extracted.")
    return db


# ══════════════════════════════════════════════════════════════════════════════
# FETCH + PARSE FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def _fetch_and_parse() -> Dict[str, Dict[str, Any]]:
    """
    Download the MITRE ATT&CK Enterprise STIX 2.1 bundle and return the
    parsed technique dictionary.  Falls back to _FALLBACK_DB on any error.
    """
    try:
        logger.info(f"Fetching MITRE ATT&CK STIX bundle from: {_STIX_URL}")
        req = Request(_STIX_URL, headers={"User-Agent": "AURA-ThreatIntel/1.0"})
        with urlopen(req, timeout=_FETCH_TIMEOUT_S) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8"))
        db = _parse_stix_bundle(data)
        if not db:
            raise ValueError("STIX parse returned an empty dictionary.")
        # Merge fetched STIX data with the fallback baseline to guarantee all rule techniques populate
        merged_db = dict(_FALLBACK_DB)
        merged_db.update(db)
        return merged_db
    except Exception as exc:
        logger.warning(
            f"MITRE STIX fetch/parse failed ({exc}). "
            f"Falling back to built-in database ({len(_FALLBACK_DB)} techniques)."
        )
        return dict(_FALLBACK_DB)


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT — conditionally cached
#
# Strategy:
#   • Streamlit context  → wrap with @st.cache_data(ttl=86400, show_spinner=False)
#     The 10 MB bundle is fetched & parsed at most once per 24 h per worker.
#   • CLI / non-Streamlit → module-level singleton (fetched once per process).
# ══════════════════════════════════════════════════════════════════════════════

try:
    import streamlit as st  # noqa: F401  (imported for caching only)

    @st.cache_data(ttl=86400, show_spinner=False)
    def get_mitre_data() -> Dict[str, Dict[str, Any]]:
        """
        Return the MITRE ATT&CK technique dictionary.
        Cached by Streamlit for 24 hours; network-resilient via fallback.
        """
        return _fetch_and_parse()

except (ImportError, Exception):
    # CLI mode or Streamlit not available — use a simple module-level singleton.
    _cli_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def get_mitre_data() -> Dict[str, Dict[str, Any]]:  # type: ignore[misc]
        """
        Return the MITRE ATT&CK technique dictionary (CLI singleton version).
        """
        global _cli_cache
        if _cli_cache is None:
            _cli_cache = _fetch_and_parse()
        return _cli_cache
