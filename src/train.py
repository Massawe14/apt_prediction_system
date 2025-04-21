import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from stable_baselines3.common.vec_env import DummyVecEnv
from sb3_contrib import RecurrentPPO
from src.environment import APTEnv
import pickle

activity_encode = {
    'BENIGN': 0, 'Network Scan': 1, 'Directory Bruteforce': 2, 'Web Vulnerability Scan': 3,
    'Account Bruteforce': 4, 'Account Discovery': 5, 'SQL Injection': 6, 'Backdoor': 7,
    'Command Injection': 8, 'CSRF': 10, 'Malware Download': 11
}
stage_encode = {
    'BENIGN': 0, 'Reconnaissance': 1, 'Establish Foothold': 2, 'Lateral Movement': 3, 'Data Exfiltration': 4
}

df = pd.read_csv('../data/processed_apt_datasets.csv')
df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_')
df = df.drop(columns=['Flow_ID', 'Timestamp'], errors='ignore')
df = df.replace([np.inf, -np.inf], np.nan).dropna()

df['Activity'] = df['Activity'].map(activity_encode)
df['Stage'] = df['Stage'].map(stage_encode)

numerical_cols = df.columns[:-2]
scaler = StandardScaler()
df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

def create_sequences(df, seq_length=5):
    X, y_activity, y_stage = [], [], []
    for i in range(len(df) - seq_length):
        X.append(df.iloc[i:i + seq_length][numerical_cols].values)
        y_activity.append(df.iloc[i + seq_length]['Activity'])
        y_stage.append(df.iloc[i + seq_length]['Stage'])
    return np.array(X), np.array(y_activity), np.array(y_stage)

X, y_activity, y_stage = create_sequences(df)
max_activity = max(activity_encode.values())  # 11
num_stages = len(stage_encode)  # 5

env = DummyVecEnv([lambda: APTEnv(X, y_activity, y_stage, max_activity, num_stages)])
model = RecurrentPPO("MlpLstmPolicy", env, verbose=1, n_steps=2048, batch_size=64)
model.learn(total_timesteps=100000)

model.save("../models/ppo_apt_model.zip")
with open("../models/scaler.pkl", 'wb') as f:
    pickle.dump(scaler, f)
