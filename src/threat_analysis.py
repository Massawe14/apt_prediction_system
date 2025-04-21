import pandas as pd
from datetime import datetime

class ThreatAnalyzer:
    def __init__(self):
        self.alert_history = []
        self.activity_decode = {
            0: 'BENIGN', 1: 'Network Scan', 2: 'Directory Bruteforce', 3: 'Web Vulnerability Scan',
            4: 'Account Bruteforce', 5: 'Account Discovery', 6: 'SQL Injection', 7: 'Backdoor',
            8: 'Command Injection', 10: 'CSRF', 11: 'Malware Download'
        }
        self.stage_decode = {
            0: 'BENIGN', 1: 'Reconnaissance', 2: 'Establish Foothold', 3: 'Lateral Movement', 4: 'Data Exfiltration'
        }
        self.activity_counts = {
            'BENIGN': 51848, 'Directory Bruteforce': 9968, 'Network Scan': 7740,
            'Web Vulnerability Scan': 2574, 'Account Bruteforce': 141, 'Account Discovery': 136,
            'SQL Injection': 55, 'Backdoor': 20, 'Command Injection': 12, 'CSRF': 7, 'Malware Download': 2
        }
        self.stage_counts = {
            'BENIGN': 51848, 'Reconnaissance': 11909, 'Establish Foothold': 8600,
            'Lateral Movement': 137, 'Data Exfiltration': 9
        }

    def assess_severity(self, activity, stage):
        """Categorize threat severity based on decoded activity and stage."""
        activity_str = self.activity_decode.get(activity, 'Unknown')
        stage_str = self.stage_decode.get(stage, 'Unknown')
        severity_map = {
            ('BENIGN', 'BENIGN'): 'Low',
            ('Directory Bruteforce', 'Reconnaissance'): 'Medium',
            ('Network Scan', 'Reconnaissance'): 'Medium',
            ('Web Vulnerability Scan', 'Reconnaissance'): 'Medium',
            ('Account Bruteforce', 'Establish Foothold'): 'High',
            ('Account Discovery', 'Reconnaissance'): 'Medium',
            ('SQL Injection', 'Establish Foothold'): 'High',
            ('Backdoor', 'Lateral Movement'): 'Critical',
            ('Command Injection', 'Establish Foothold'): 'High',
            ('CSRF', 'Establish Foothold'): 'High',
            ('Malware Download', 'Data Exfiltration'): 'Critical',
            ('Backdoor', 'Data Exfiltration'): 'Critical',
            ('Malware Download', 'Establish Foothold'): 'High'
        }
        return severity_map.get((activity_str, stage_str), 'Medium')

    def generate_alert(self, flow_data, activity, stage):
        """Create a real-time alert with decoded values."""
        activity_str = self.activity_decode.get(activity, 'Unknown')
        stage_str = self.stage_decode.get(stage, 'Unknown')
        severity = self.assess_severity(activity, stage)
        alert = {
            'timestamp': flow_data.get('Timestamp', str(datetime.now())),
            'src_ip': flow_data.get('Src_IP', 'Unknown'),
            'dst_ip': flow_data.get('Dst_IP', 'Unknown'),
            'severity': severity,
            'activity': activity_str,
            'stage': stage_str,
            'affected_endpoint': flow_data.get('Src_IP', 'Unknown'),
            'frequency_in_training': {
                'activity': self.activity_counts.get(activity_str, 0),
                'stage': self.stage_counts.get(stage_str, 0)
            }
        }
        self.alert_history.append(alert)
        return alert

    def get_apt_stages(self, predictions):
        """Extract progression of APT stages with decoded values."""
        return [(self.activity_decode.get(act, 'Unknown'), self.stage_decode.get(stg, 'Unknown')) 
                for act, stg in zip(predictions['activity'], predictions['stage'])]

    def trend_analysis(self):
        if not self.alert_history:
            return []
        df = pd.DataFrame(self.alert_history)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        trend = df.groupby(df['timestamp'].dt.floor('15s')).size().reset_index(name='count')
        return trend.to_dict(orient='records')

    def top_threats(self, limit=5):
        if not self.alert_history:
            return []
        df = pd.DataFrame(self.alert_history)
        severity_weight = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        df['weight'] = df['severity'].map(severity_weight)
        top = df.groupby(['activity', 'stage']).agg({'weight': 'sum', 'timestamp': 'count'}).rename(columns={'timestamp': 'frequency'})
        top = top.sort_values(by=['weight', 'frequency'], ascending=False).head(limit)
        return top.reset_index().to_dict(orient='records')
    