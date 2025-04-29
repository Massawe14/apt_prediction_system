import pandas as pd
from datetime import datetime
import shap # type: ignore
import numpy as np

class ThreatAnalyzer:
    def __init__(self, model=None, feature_names=None, normal_stats=None):
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
        self.model = model
        self.feature_names = feature_names
        self.explainer = None
        if model and feature_names:
            self.explainer = shap.TreeExplainer(model)
        self.normal_stats = normal_stats  # Dictionary with mean and std for features (for anomaly scores)

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

    def compute_anomaly_score(self, features):
        """Compute anomaly score based on z-scores of features."""
        if not self.normal_stats or not self.feature_names:
            return 0.0
        z_scores = []
        for i, feature_value in enumerate(features):
            feature_name = self.feature_names[i]
            mean = self.normal_stats.get(feature_name, {}).get('mean', 0)
            std = self.normal_stats.get(feature_name, {}).get('std', 1)
            z = abs((feature_value - mean) / std) if std != 0 else 0
            z_scores.append(z)
        return float(np.mean(z_scores))  # Average z-score as anomaly score

    def compute_threat_score(self, severity, confidence_activity, confidence_stage, activity_str, stage_str):
        """Compute a composite threat score."""
        severity_weight = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        severity_score = severity_weight.get(severity, 2)
        
        # Normalize frequency (scale to 0-1 based on max count)
        max_activity_count = max(self.activity_counts.values(), default=1)
        max_stage_count = max(self.stage_counts.values(), default=1)
        freq_score = (self.activity_counts.get(activity_str, 0) / max_activity_count +
            self.stage_counts.get(stage_str, 0) / max_stage_count) / 2
        
        # Weighted combination: 40% severity, 40% confidence, 20% frequency
        threat_score = (0.4 * severity_score / 4 + 
            0.4 * (confidence_activity + confidence_stage) / 2 +
            0.2 * (1 - freq_score))  # Inverse frequency for rarity
        return float(threat_score)

    def generate_alert(self, flow_data, activity, stage, features=None):
        """Create a real-time alert with decoded values, SHAP contributions, and scores."""
        activity_str = self.activity_decode.get(activity, 'Unknown')
        stage_str = self.stage_decode.get(stage, 'Unknown')
        severity = self.assess_severity(activity, stage)
        
        # Initialize scores
        confidence_activity = 0.0
        confidence_stage = 0.0
        anomaly_score = self.compute_anomaly_score(features) if features else 0.0
        
        # Get confidence scores from model probabilities
        if self.model and features is not None:
            try:
                features_array = np.array(features).reshape(1, -1)
                # Assume model predicts both activity and stage; adjust if separate models
                probas = self.model.predict_proba(features_array)
                # If model outputs probabilities for one task, split or adjust logic
                if len(probas) == 2:  # Assuming two outputs: activity and stage
                    confidence_activity = float(probas[0][0, activity])
                    confidence_stage = float(probas[1][0, stage])
                else:  # Single output for activity (adjust for stage if needed)
                    confidence_activity = float(probas[0][activity])
            except Exception as e:
                print(f"Error computing confidence scores: {e}")

        # Compute threat score
        threat_score = self.compute_threat_score(severity, confidence_activity, confidence_stage, activity_str, stage_str)

        # Initialize alert dictionary
        alert = {
            'timestamp': flow_data.get('Timestamp', str(datetime.now())),
            'src_ip': flow_data.get('Src IP', 'Unknown'),
            'dst_ip': flow_data.get('Dst IP', 'Unknown'),
            'severity': severity,
            'activity': activity_str,
            'stage': stage_str,
            'affected_endpoint': flow_data.get('Src IP', 'Unknown'),
            'confidence': {
                'activity': confidence_activity,
                'stage': confidence_stage
            },
            'anomaly_score': anomaly_score,
            'threat_score': threat_score,
            'frequency_in_training': {
                'activity': self.activity_counts.get(activity_str, 0),
                'stage': self.stage_counts.get(stage_str, 0)
            },
            'top_features': []
        }

        # Compute SHAP values for explainability
        if self.explainer and features is not None and self.feature_names:
            try:
                features_array = np.array(features).reshape(1, -1)
                shap_values = self.explainer.shap_values(features_array)
                
                if isinstance(shap_values, list):
                    shap_values_activity = shap_values[activity]
                else:
                    shap_values_activity = shap_values

                shap_abs = np.abs(shap_values_activity[0])
                top_indices = np.argsort(shap_abs)[-5:][::-1]
                alert['top_features'] = [
                    {
                        'feature': self.feature_names[idx],
                        'shap_value': float(shap_values_activity[0][idx]),
                        'feature_value': float(features_array[0][idx])
                    }
                    for idx in top_indices
                ]
            except Exception as e:
                print(f"Error computing SHAP values: {e}")
                alert['top_features'] = [{'error': str(e)}]

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
    