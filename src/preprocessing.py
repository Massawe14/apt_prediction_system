import logging
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    df = df.copy()
    logger.info(f"preprocess_data: Input DataFrame columns: {df.columns.tolist()}")
    
    # Replace spaces and slashes in column names with underscores
    df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_')
    
    # Drop unwanted columns
    df = df.drop(columns=['Flow_ID', 'Timestamp'], errors='ignore')
    
    # Replace infinite values and drop NaNs
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    if is_training:
        # For training data with labels
        if 'Activity' not in df.columns or 'Stage' not in df.columns:
            logger.error("Activity and Stage columns are required for training")
            raise ValueError("Activity and Stage columns are required for training")
        df['Activity'] = df['Activity'].map(activity_encode)
        df['Stage'] = df['Stage'].map(stage_encode)
        numerical_cols = [col for col in df.columns if col not in ['Activity', 'Stage']]
        # Apply scaler
        df[numerical_cols] = scaler.fit_transform(df[numerical_cols])
    else:
        # For prediction data (unlabeled)
        numerical_cols = [col for col in df.columns if col not in ['Activity', 'Stage']]
        if not numerical_cols:
            logger.error("No numerical columns found for inference")
            raise ValueError("No numerical columns found for inference")
        df[numerical_cols] = scaler.transform(df[numerical_cols])
    
    return df

def create_sequences(df, seq_length=5, is_training=False):
    """Create sequences, returning labels only for training data."""
    logger.info(f"create_sequences: Input DataFrame shape: {df.shape}")
    X = []
    y_activity = [] if is_training else None
    y_stage = [] if is_training else None
    numerical_cols = [col for col in df.columns if col not in ['Activity', 'Stage']]
    logger.info(f"create_sequences: Numerical columns: {numerical_cols}")
    
    for i in range(len(df) - seq_length):
        X.append(df.iloc[i:i + seq_length][numerical_cols].values)
        if is_training:
            y_activity.append(df.iloc[i + seq_length]['Activity'])
            y_stage.append(df.iloc[i + seq_length]['Stage'])
    
    X = np.array(X)
    if is_training:
        return X, np.array(y_activity), np.array(y_stage)
    return X, None, None  # No labels for prediction