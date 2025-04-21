class MitreMapper:
    def __init__(self):
        self.mapping = {
            (0, 0): {'tactic': 'None', 'technique': 'None'},  # BENIGN, BENIGN
            (2, 1): {'tactic': 'TA0043', 'technique': 'T1595 - Active Scanning'},  # Directory Bruteforce, Reconnaissance
            (1, 1): {'tactic': 'TA0043', 'technique': 'T1595 - Active Scanning'},  # Network Scan, Reconnaissance
            (3, 1): {'tactic': 'TA0043', 'technique': 'T1595 - Active Scanning'},  # Web Vulnerability Scan, Reconnaissance
            (4, 2): {'tactic': 'TA0006', 'technique': 'T1110 - Brute Force'},  # Account Bruteforce, Establish Foothold
            (5, 1): {'tactic': 'TA0007', 'technique': 'T1087 - Account Discovery'},  # Account Discovery, Reconnaissance
            (6, 2): {'tactic': 'TA0002', 'technique': 'T1190 - Exploit Public-Facing Application'},  # SQL Injection, Establish Foothold
            (7, 3): {'tactic': 'TA0008', 'technique': 'T1021 - Remote Services'},  # Backdoor, Lateral Movement
            (8, 2): {'tactic': 'TA0002', 'technique': 'T1059 - Command and Scripting Interpreter'},  # Command Injection, Establish Foothold
            (10, 2): {'tactic': 'TA0002', 'technique': 'T1185 - Browser Session Hijacking'},  # CSRF, Establish Foothold
            (11, 4): {'tactic': 'TA0010', 'technique': 'T1041 - Exfiltration Over C2 Channel'},  # Malware Download, Data Exfiltration
            (7, 4): {'tactic': 'TA0010', 'technique': 'T1041 - Exfiltration Over C2 Channel'},  # Backdoor, Data Exfiltration
            (11, 2): {'tactic': 'TA0003', 'technique': 'T1105 - Ingress Tool Transfer'}  # Malware Download, Establish Foothold
        }

    def map_to_mitre(self, activity, stage):
        """Map numeric activity and stage to MITRE ATT&CK."""
        return self.mapping.get((activity, stage), {'tactic': 'Unknown', 'technique': 'Unknown'})
    