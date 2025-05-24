import sys
import os
import logging
import time
import asyncio
import pickle
import pandas as pd
import numpy as np
import uvicorn
from contextlib import asynccontextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from stable_baselines3.common.vec_env import DummyVecEnv
from sb3_contrib import RecurrentPPO
from src.preprocessing import preprocess_data, create_sequences, activity_decode, stage_decode
from src.environment import APTEnv
from src.visualizations import generate_visualizations, generate_reports
from src.capture import NetworkCapture
from src.threat_analysis import ThreatAnalyzer
from src.geolocation import GeoLocator
from src.mitre_mapping import MitreMapper
from src.remediation import RemediationSuggester
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

latest_dashboard = None

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODEL_PATH = os.path.join(BASE_DIR, "models", "ppo_apt_model.zip")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.pkl")

logger.info(f"Loading model from: {MODEL_PATH}")
logger.info(f"Loading scaler from: {SCALER_PATH}")

try:
    model = RecurrentPPO.load(MODEL_PATH)
except FileNotFoundError as e:
    logger.error(f"Model file not found: {MODEL_PATH}")
    raise e
except Exception as e:
    logger.error(f"Error loading model: {e}")
    raise e

try:
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
except FileNotFoundError as e:
    logger.error(f"Scaler file not found: {SCALER_PATH}")
    raise e
except Exception as e:
    logger.error(f"Error loading scaler: {e}")
    raise e

capturer = NetworkCapture(interface='any', capture_duration=15)
threat_analyzer = ThreatAnalyzer()
geo_locator = GeoLocator()
mitre_mapper = MitreMapper()
remediator = RemediationSuggester()

# Function to convert IP address to integer
def ip_to_int(ip):
    try:
        octets = ip.split('.')
        return int(octets[0]) * 256**3 + int(octets[1]) * 256**2 + int(octets[2]) * 256 + int(octets[3])
    except Exception:
        return 0  # Default value for invalid IPs

# Protocol mapping
protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}  # Add more as needed

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(capture_and_predict_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        logger.info("Capture loop cancelled")

app = FastAPI(title="APT Real-Time Prediction Dashboard API", lifespan=lifespan)

origins = ["*"] # Or restrict to specific domains for security

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def predict_from_data(df, is_training=False):
    start_time = time.time()
    logger.info(f"Processing {len(df)} records for prediction")
    
    # Initial preprocessing to match training data
    df = df.copy()
    df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_')  # Match preprocess_data's column naming
    
    # Drop unwanted columns
    df = df.drop(columns=['Flow_ID', 'Timestamp'], errors='ignore')
    
    # Convert string columns to numeric
    df['Src_IP'] = df['Src_IP'].apply(ip_to_int)
    df['Dst_IP'] = df['Dst_IP'].apply(ip_to_int)
    df['Protocol'] = df['Protocol'].map(lambda x: protocol_map.get(x, 0))  # Default to 0 for unknown
    
    # Ensure Src_Port and Dst_Port are integers
    df['Src_Port'] = pd.to_numeric(df['Src_Port'], errors='coerce').fillna(0).astype(int)
    df['Dst_Port'] = pd.to_numeric(df['Dst_Port'], errors='coerce').fillna(0).astype(int)
    
    # Apply preprocessing and scaling
    df_processed = preprocess_data(df, scaler, is_training=is_training)
    X, y_activity, y_stage = create_sequences(df_processed, seq_length=5, is_training=is_training)

    if len(X) == 0:
        logger.warning("Not enough data to create sequences (need at least 5 records)")
        return {"error": "Not enough data to create sequences (need at least 5 records)"}

    max_activity = max(activity_decode.keys())  # 11
    num_stages = len(stage_decode)  # 5
    dummy_y_activity = np.zeros(len(X)) if not is_training else y_activity
    dummy_y_stage = np.zeros(len(X)) if not is_training else y_stage
    env = DummyVecEnv([lambda: APTEnv(X, dummy_y_activity, dummy_y_stage, max_activity, num_stages)])

    predictions = []
    obs = env.reset()
    lstm_states = None
    episode_starts = np.ones((env.num_envs,), dtype=bool)
    max_steps = env.envs[0].unwrapped.max_steps

    for _ in range(min(max_steps, len(X))):
        action, lstm_states = model.predict(obs, state=lstm_states, episode_start=episode_starts)
        obs, _, done, _ = env.step(action)
        predictions.append(action)
        episode_starts = done
        if done.any():
            break

    y_pred_activity = [p[0][0] for p in predictions]
    y_pred_stage = [p[0][1] for p in predictions]
    if is_training:
        y_true_activity = y_activity[:len(y_pred_activity)]
        y_true_stage = y_stage[:len(y_pred_stage)]
    else:
        y_true_activity = None
        y_true_stage = None

    pred_activity_decoded = [activity_decode.get(act, 'Unknown') for act in y_pred_activity]
    pred_stage_decoded = [stage_decode.get(stg, 'Unknown') for stg in y_pred_stage]
    true_activity_decoded = [activity_decode.get(act, 'Unknown') for act in y_true_activity] if y_true_activity is not None else None
    true_stage_decoded = [stage_decode.get(stg, 'Unknown') for stg in y_true_stage] if y_true_stage is not None else None

    alerts = []
    apt_stages = threat_analyzer.get_apt_stages({"activity": y_pred_activity, "stage": y_pred_stage})
    for i, (flow, activity, stage) in enumerate(zip(df.to_dict('records')[-len(y_pred_activity):], y_pred_activity, y_pred_stage)):
        if activity != 0 or stage != 0:
            alert = threat_analyzer.generate_alert(flow, activity, stage)
            alert['mitre'] = mitre_mapper.map_to_mitre(activity, stage)
            alert['remediation'] = remediator.suggest(alert)
            alerts.append(alert)

    geo_data = {flow['Src_IP']: geo_locator.get_location(flow['Src_IP']) for flow in df.to_dict('records') if 'Src_IP' in flow}

    # Log state before generating reports and visualizations
    logger.info(f"is_training: {is_training}, y_true_activity: {y_true_activity}, y_true_stage: {y_true_stage}")
    
    # Generate reports only in training mode with valid true labels
    reports = {}
    if is_training and y_true_activity is not None and y_true_stage is not None:
        reports = generate_reports(y_true_activity, y_pred_activity, y_true_stage, y_pred_stage)
    
    # Pass is_training to generate_visualizations to handle inference mode
    y_true_activity_safe = y_true_activity if y_true_activity is not None else []
    y_true_stage_safe = y_true_stage if y_true_stage is not None else []
    visualizations = generate_visualizations(df_processed, y_true_activity_safe, y_pred_activity, y_true_stage_safe, y_pred_stage, X, threat_analyzer.trend_analysis(), geo_data, is_training=is_training)

    prediction_time = time.time() - start_time

    result = {
        "key_metrics": {
            "threat_severity": {alert['severity'] for alert in alerts} if alerts else {'Low'},
            "apt_stages": apt_stages
        },
        "predictions": {"activity": pred_activity_decoded, "stage": pred_stage_decoded},
        "alerts": alerts,
        "trend_analysis": threat_analyzer.trend_analysis(),
        "actionable_insights": {
            "top_threats": threat_analyzer.top_threats(),
            "mitre_mapping": {alert['src_ip']: alert['mitre'] for alert in alerts}
        },
        "visualizations": visualizations,
        "model_performance": {"prediction_time": prediction_time}
    }
    if is_training and y_true_activity is not None and y_true_stage is not None:
        result["true_values"] = {"activity": true_activity_decoded, "stage": true_stage_decoded}
        result["model_performance"]["classification_reports"] = reports

    return result

async def capture_and_predict_loop():
    global latest_dashboard
    while True:
        try:
            df = await capturer.capture_traffic()
            logger.info(f"Captured {len(df)} records with columns: {df.columns.tolist()}")
            if not df.empty:
                logger.info(f"Sample data: {df.head().to_dict()}")
            if not df.empty and len(df) >= 5:
                latest_dashboard = await predict_from_data(df, is_training=False)
                logger.info("Dashboard updated successfully")
            else:
                logger.warning("Insufficient data captured (need at least 5 records)")
        except Exception as e:
            logger.error(f"Error in capture loop: {e}")
        await asyncio.sleep(15)

@app.get("/dashboard")
async def get_dashboard():
    if latest_dashboard is None:
        logger.info("Dashboard requested but no data available yet")
        raise HTTPException(status_code=503, detail="No dashboard data available yet")
    return latest_dashboard

class NetworkData(BaseModel):
    data: list[dict]

@app.post("/predict")
async def predict_apt_manual(network_data: NetworkData):
    df = pd.DataFrame(network_data.data)
    result = await predict_from_data(df, is_training=False)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="167.99.37.95", port=8000)
    
