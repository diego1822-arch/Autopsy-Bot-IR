🤖 Autopsy-Bot: Automated Forensic Triage Tool (Incident Response)
🛡️ Project Overview and Purpose
Autopsy-Bot is a digital forensics and incident response (IR) tool built using Python.

The primary goal of this tool is to automate and expedite the initial collection of critical evidence (triage) on a potentially compromised system, focusing on the "golden hour" where volatile evidence is most at risk of being lost.

This project demonstrates a thorough understanding of Windows forensic artifacts and advanced scripting for security automation.

🎯 Demonstrated Technical Skills
This project covers key skills in Scripting, Digital Forensics, and Data Analysis, highly valued in roles like Threat Hunter, Incident Response Analyst, and SecOps.

Incident Response (IR) Workflow: Understanding the forensic triage process and the importance of evidence chain of custody.

Windows Forensic Artifacts: Collection of crucial evidence following an attack, including:

Volatile Artifacts: Active Process Listings (tasklist /svc) and Network Connections (netstat -ano).

Persistence Artifacts: Automated analysis of common Windows Registry Run Keys (reg query) to detect malware persistence.

Data Analysis with Python Pandas: Utilization of the Pandas library to consolidate all collected timestamps and generate a chronologically ordered Forensic Timeline (forensic_timeline.csv).

Advanced Automation: Use of the subprocess and os modules to directly interact with system commands and securely package the final evidence (zipfile).

🚀 Execution Phases
The script executes sequentially, ensuring that volatile data is captured first:

PHASE 1: Critical Triage Collection

Captures processes (tasklist /svc) and network connections (netstat -ano).

Simulates collection of recently accessed files (LNK artifacts).

PHASE 1.5: Persistence Analysis

Queries key Registry paths for automatic execution (HKLM\Run, HKCU\Run).

PHASE 2: Timeline Construction

Uses Pandas to generate and save the forensic_timeline.csv with the chronological sequence of all collected events.

PHASE 3: Evidence Packaging

Compresses all collected files into a single 'Evidence Bag' (.zip) named using the hostname and timestamp.

⚙️ Usage and Requirements
Requirements
Python 3.x

Libraries: pandas, colorama

Bash

pip install -r requirements.txt
Execution
Ensure your virtual environment is active.

Run the main file:

Bash

python autopsy_bot.py
Output
The script will create a folder (EVIDENCE_[HOSTNAME]_[TIMESTAMP]) containing all log files and a final ZIP file (the Evidence Bag).