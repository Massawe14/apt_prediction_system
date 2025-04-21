import numpy as np

activity_encode = {
    'BENIGN': 0, 'Network Scan': 1, 'Directory Bruteforce': 2, 'Web Vulnerability Scan': 3,
    'Account Bruteforce': 4, 'Account Discovery': 5, 'SQL Injection': 6, 'Backdoor': 7,
    'Command Injection': 8, 'CSRF': 10, 'Malware Download': 11
}
activity_decode = {v: k for k, v in activity_encode.items()}
stage_encode = {
    'BENIGN': 0, 'Reconnaissance': 1, 'Establish Foothold': 2, 'Lateral Movement': 3, 'Data Exfiltration': 4
}
stage_decode = {v: k for k, v in stage_encode.items()}

def preprocess_data(df, scaler, is_training=False):
    """Preprocess network flow data, handling labeled (training) or unlabeled (prediction) data."""
    df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_')
    df = df.drop(columns=['Flow_ID', 'Timestamp'], errors='ignore')
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    if is_training:
        # For training data with labels
        if 'Activity' in df.columns:
            df['Activity'] = df['Activity'].map(activity_encode)
        if 'Stage' in df.columns:
            df['Stage'] = df['Stage'].map(stage_encode)
        else:
            # Infer Stage from Activity if missing (example mapping)
            activity_to_stage = {
                0: 0, 1: 1, 2: 1, 3: 1, 4: 2, 5: 1, 6: 2, 7: 3, 8: 2, 10: 2, 11: 4
            }
            df['Stage'] = df['Activity'].map(activity_to_stage)
        numerical_cols = [col for col in df.columns if col not in ['Activity', 'Stage']]
    else:
        # For prediction data (unlabeled)
        numerical_cols = df.columns  # Use all columns as numerical features

    df[numerical_cols] = scaler.transform(df[numerical_cols])
    return df

def create_sequences(df, seq_length=5, is_training=False):
    """Create sequences, returning labels only for training data."""
    # Removed sort_values since Timestamp is dropped earlier
    X = []
    y_activity = []  # Only used for training
    y_stage = []     # Only used for training
    numerical_cols = [col for col in df.columns if col not in ['Activity', 'Stage']]

    for i in range(len(df) - seq_length):
        X.append(df.iloc[i:i + seq_length][numerical_cols].values)
        if is_training:
            y_activity.append(df.iloc[i + seq_length]['Activity'])
            y_stage.append(df.iloc[i + seq_length]['Stage'])

    X = np.array(X)
    if is_training:
        return X, np.array(y_activity), np.array(y_stage)
    return X, None, None  # No labels for prediction