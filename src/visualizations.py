import io
import base64
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report

def plot_to_base64():
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=300)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    return img_base64

def generate_visualizations(df, y_true_activity, y_pred_activity, y_true_stage, y_pred_stage, X, trend_data, geo_data, is_training=False):
    visualizations = {}

    # Confusion Matrices (only if in training mode with valid true labels)
    if is_training and len(y_true_activity) > 0 and len(y_true_stage) > 0:
        plt.figure(figsize=(16, 6))
        plt.subplot(1, 2, 1)
        cm_activity = confusion_matrix(y_true_activity, y_pred_activity)
        sns.heatmap(cm_activity, annot=True, fmt='d', cmap='Blues')
        plt.title("Activity Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.subplot(1, 2, 2)
        cm_stage = confusion_matrix(y_true_stage, y_pred_stage)
        sns.heatmap(cm_stage, annot=True, fmt='d', cmap='Greens')
        plt.title("Stage Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        visualizations["confusion_matrix"] = plot_to_base64()
        plt.close()

    # Network Traffic Overview
    # Note: 'Timestamp' was dropped earlier, so this will fail unless preserved elsewhere
    # For now, we'll skip this or use a placeholder if Timestamp isn't available
    if 'Timestamp' in df.columns:
        plt.figure(figsize=(10, 6))
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        traffic = df.groupby(df['Timestamp'].dt.floor('15s')).agg({'Total_Length_of_Fwd_Packet': 'sum'}).reset_index()
        plt.plot(traffic['Timestamp'], traffic['Total_Length_of_Fwd_Packet'], label='Fwd Traffic')
        plt.title("Network Traffic Overview (15s Intervals)")
        plt.xlabel("Time")
        plt.ylabel("Total Fwd Packet Length")
        plt.legend()
        visualizations["traffic_overview"] = plot_to_base64()
        plt.close()

    # Trend Analysis
    plt.figure(figsize=(10, 6))
    trend_df = pd.DataFrame(trend_data)
    plt.plot(trend_df['timestamp'], trend_df['count'], marker='o')
    plt.title("APT Detection Trend Over Time")
    plt.xlabel("Time")
    plt.ylabel("Number of Detections")
    visualizations["trend_analysis"] = plot_to_base64()
    plt.close()

    # Geolocation Map (simplified scatter plot)
    plt.figure(figsize=(12, 8))
    for ip, geo in geo_data.items():
        if geo['latitude'] and geo['longitude']:
            plt.scatter(geo['longitude'], geo['latitude'], label=f"{ip} ({geo['city']})")
    plt.title("Geolocation of Suspicious IPs")
    plt.xlabel("Longitude")
    plt.ylabel("Latitude")
    plt.legend()
    visualizations["geolocation_map"] = plot_to_base64()
    plt.close()

    return visualizations

def generate_reports(y_true_activity, y_pred_activity, y_true_stage, y_pred_stage):
    return {
        "activity": classification_report(y_true_activity, y_pred_activity, zero_division=0, output_dict=True),
        "stage": classification_report(y_true_stage, y_pred_stage, zero_division=0, output_dict=True)
    }
