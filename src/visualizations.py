import io
import base64
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import networkx as nx
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
    
    # Ensure Timestamp is in datetime format
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    
    # Generate Session Correlation IDs
    df['Session Correlation ID'] = df.apply(
        lambda row: f"{row['Src_IP']}-{row['Dst_IP']}-{row['Src_Port']}-{row['Dst_Port']}-{row['Protocol']}-{int(row['Timestamp'].timestamp())}",
        axis=1
    )

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
    if 'Timestamp' in df.columns:
        plt.figure(figsize=(10, 6))
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

    # Threat Graph
    plt.figure(figsize=(12, 8))
    G = nx.DiGraph()
    for idx, row in df.iterrows():
        src_ip = row['Src_IP']
        dst_ip = row['Dst_IP']
        flow_id = row['Flow_ID']
        is_suspicious = y_pred_activity[idx] == 'malicious' if len(y_pred_activity) > idx else False  # Example condition
        G.add_node(src_ip, label=src_ip)
        G.add_node(dst_ip, label=dst_ip)
        G.add_edge(src_ip, dst_ip, flow_id=flow_id, suspicious=is_suspicious, session_id=row['Session Correlation ID'])
    
    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=500)
    nx.draw_networkx_labels(G, pos, labels=nx.get_node_attributes(G, 'label'))
    
    # Draw edges: red for suspicious, black for normal
    for edge in G.edges(data=True):
        color = 'red' if edge[2]['suspicious'] else 'black'
        nx.draw_networkx_edges(G, pos, edgelist=[(edge[0], edge[1])], edge_color=color)
    
    plt.title("Threat Graph: IP Interactions")
    visualizations["threat_graph"] = plot_to_base64()
    plt.close()

    # Host-Level Story Building
    plt.figure(figsize=(12, 8))
    host_events = df.groupby('Src_IP').agg({
        'Timestamp': ['min', 'max'],
        'Flow_ID': 'count',
        'Session Correlation ID': 'nunique',
        'Total Length of Fwd Packet': 'sum'
    }).reset_index()
    host_events.columns = ['Src_IP', 'First_Seen', 'Last_Seen', 'Flow_Count', 'Unique_Sessions', 'Total_Fwd_Bytes']
    
    for _, row in host_events.iterrows():
        plt.plot([row['First_Seen'], row['Last_Seen']], [row['Src_IP'], row['Src_IP']], marker='o', label=f"{row['Src_IP']} ({row['Flow_Count']} flows)")
    
    plt.title("Host-Level Activity Timeline")
    plt.xlabel("Time")
    plt.ylabel("Source IP")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    visualizations["host_timeline"] = plot_to_base64()
    plt.close()

    return visualizations

def generate_reports(y_true_activity, y_pred_activity, y_true_stage, y_pred_stage):
    return {
        "activity": classification_report(y_true_activity, y_pred_activity, zero_division=0, output_dict=True),
        "stage": classification_report(y_true_stage, y_pred_stage, zero_division=0, output_dict=True)
    }
