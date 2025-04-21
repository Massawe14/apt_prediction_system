class RemediationSuggester:
    def __init__(self):
        self.activity_decode = {
            0: 'BENIGN', 1: 'Network Scan', 2: 'Directory Bruteforce', 3: 'Web Vulnerability Scan',
            4: 'Account Bruteforce', 5: 'Account Discovery', 6: 'SQL Injection', 7: 'Backdoor',
            8: 'Command Injection', 10: 'CSRF', 11: 'Malware Download'
        }
        self.stage_decode = {
            0: 'BENIGN', 1: 'Reconnaissance', 2: 'Establish Foothold', 3: 'Lateral Movement', 4: 'Data Exfiltration'
        }

    def suggest(self, alert):
        """Suggest remediation actions based on alert."""
        severity = alert['severity']
        activity = self.activity_decode.get(alert['activity'], 'Unknown')
        stage = self.stage_decode.get(alert['stage'], 'Unknown')
        src_ip = alert['src_ip']
        dst_ip = alert['dst_ip']

        suggestions = []
        if severity in ['High', 'Critical']:
            suggestions.append(f"Isolate endpoint {src_ip} from the network.")
            suggestions.append(f"Block IP {dst_ip} on the firewall.")

        if activity == 'Directory Bruteforce':
            suggestions.append("Limit directory access and monitor for unauthorized attempts.")
        elif activity == 'Network Scan':
            suggestions.append("Review network logs for scanning patterns.")
        elif activity == 'Web Vulnerability Scan':
            suggestions.append("Scan web applications for vulnerabilities and patch them.")
        elif activity == 'Account Bruteforce':
            suggestions.append("Enforce stronger password policies and enable MFA.")
        elif activity == 'Account Discovery':
            suggestions.append("Audit account enumeration attempts.")
        elif activity == 'SQL Injection':
            suggestions.append("Sanitize database inputs and apply security patches.")
        elif activity == 'Backdoor':
            suggestions.append("Remove unauthorized processes and scan for persistence mechanisms.")
        elif activity == 'Command Injection':
            suggestions.append("Validate input to command-line interfaces.")
        elif activity == 'CSRF':
            suggestions.append("Implement CSRF tokens in web applications.")
        elif activity == 'Malware Download':
            suggestions.append("Run antivirus scan and investigate delivery vector (e.g., phishing).")

        if stage == 'Reconnaissance':
            suggestions.append("Increase monitoring of network traffic for further probing.")
        elif stage == 'Establish Foothold':
            suggestions.append("Check for unauthorized software or exploits on the endpoint.")
        elif stage == 'Lateral Movement':
            suggestions.append("Restrict lateral network access and review compromised accounts.")
        elif stage == 'Data Exfiltration':
            suggestions.append("Analyze outbound traffic for data leaks and secure sensitive data.")

        return suggestions if suggestions else ["Monitor and investigate further."]
    