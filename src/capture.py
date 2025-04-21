import pyshark
import pandas as pd
import asyncio
from datetime import datetime
from collections import defaultdict
import numpy as np

FLOW_FEATURES = [
    'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp',
    'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet',
    'Total Length of Bwd Packet', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWR Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Fwd Segment Size Avg',
    'Bwd Segment Size Avg', 'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
    'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'FWD Init Win Bytes',
    'Bwd Init Win Bytes', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean',
    'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

class NetworkCapture:
    def __init__(self, interface='Wi-Fi', capture_duration=15):
        self.interface = interface
        self.capture_duration = capture_duration
        self.flows = defaultdict(lambda: {
            'packets': [], 'start_time': None, 'end_time': None,
            'fwd_packets': 0, 'bwd_packets': 0, 'fwd_bytes': 0, 'bwd_bytes': 0
        })
        self.tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    async def capture_traffic(self):
        print(f"Starting capture on interface: {self.interface}")

        def capture_sync():
            asyncio.set_event_loop(asyncio.new_event_loop())  # Create and set an event loop for the thread
            capture = pyshark.LiveCapture(interface=self.interface, tshark_path=self.tshark_path)
            start_time = datetime.now()

            for packet in capture.sniff_continuously():
                self._process_packet(packet)
                if (datetime.now() - start_time).seconds >= self.capture_duration:
                    break

            capture.close()
            return self._finalize_flows()

        loop = asyncio.get_running_loop()
        flows_data = await loop.run_in_executor(None, capture_sync)
        df = pd.DataFrame(flows_data, columns=FLOW_FEATURES)
        self.flows.clear()
        print(f"Capture complete. Total flows: {len(df)}")
        return df

    def _process_packet(self, packet):
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = int(packet[packet.transport_layer].srcport)
            dst_port = int(packet[packet.transport_layer].dstport)
            protocol = packet.highest_layer
            flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
            timestamp = float(packet.sniff_time.timestamp())
            pkt_len = int(packet.length)

            flow = self.flows[flow_id]
            if not flow['packets']:
                flow['start_time'] = timestamp
            flow['end_time'] = timestamp
            flow['packets'].append({
                'timestamp': timestamp, 'length': pkt_len,
                'is_fwd': src_ip < dst_ip,  # Simple heuristic for direction
                'tcp': 'tcp' in packet and hasattr(packet, 'tcp') and packet.tcp
            })
            if flow['packets'][-1]['is_fwd']:
                flow['fwd_packets'] += 1
                flow['fwd_bytes'] += pkt_len
            else:
                flow['bwd_packets'] += 1
                flow['bwd_bytes'] += pkt_len

        except AttributeError:
            pass

    def _finalize_flows(self):
        flows_data = []
        for flow_id, flow in self.flows.items():
            if not flow['packets']:
                continue

            duration = (flow['end_time'] - flow['start_time']) * 1e6  # microseconds
            total_packets = len(flow['packets'])
            fwd_pkts = flow['fwd_packets']
            bwd_pkts = flow['bwd_packets']
            fwd_bytes = flow['fwd_bytes']
            bwd_bytes = flow['bwd_bytes']
            pkt_lengths = [p['length'] for p in flow['packets']]
            iats = np.diff([p['timestamp'] for p in flow['packets']]) * 1e6  # microseconds
            fwd_iats = np.diff([p['timestamp'] for p in flow['packets'] if p['is_fwd']]) * 1e6 if fwd_pkts > 1 else [0]
            bwd_iats = np.diff([p['timestamp'] for p in flow['packets'] if not p['is_fwd']]) * 1e6 if bwd_pkts > 1 else [0]
            fwd_lens = [p['length'] for p in flow['packets'] if p['is_fwd']]
            bwd_lens = [p['length'] for p in flow['packets'] if not p['is_fwd']]

            flow_data = {
                'Flow ID': flow_id,
                'Src IP': flow_id.split('-')[0],
                'Src Port': int(flow_id.split('-')[2]),
                'Dst IP': flow_id.split('-')[1],
                'Dst Port': int(flow_id.split('-')[3]),
                'Protocol': flow_id.split('-')[4],
                'Timestamp': datetime.fromtimestamp(flow['start_time']).strftime('%Y-%m-%d %H:%M:%S.%f'),
                'Flow Duration': duration,
                'Total Fwd Packet': fwd_pkts,
                'Total Bwd packets': bwd_pkts,
                'Total Length of Fwd Packet': fwd_bytes,
                'Total Length of Bwd Packet': bwd_bytes,
                'Fwd Packet Length Max': max(fwd_lens) if fwd_lens else 0,
                'Fwd Packet Length Min': min(fwd_lens) if fwd_lens else 0,
                'Fwd Packet Length Mean': np.mean(fwd_lens) if fwd_lens else 0,
                'Fwd Packet Length Std': np.std(fwd_lens) if fwd_lens else 0,
                'Bwd Packet Length Max': max(bwd_lens) if bwd_lens else 0,
                'Bwd Packet Length Min': min(bwd_lens) if bwd_lens else 0,
                'Bwd Packet Length Mean': np.mean(bwd_lens) if bwd_lens else 0,
                'Bwd Packet Length Std': np.std(bwd_lens) if bwd_lens else 0,
                'Flow Bytes/s': (fwd_bytes + bwd_bytes) / (duration / 1e6) if duration > 0 else 0,
                'Flow Packets/s': total_packets / (duration / 1e6) if duration > 0 else 0,
                'Flow IAT Mean': np.mean(iats) if len(iats) > 0 else 0,
                'Flow IAT Std': np.std(iats) if len(iats) > 0 else 0,
                'Flow IAT Max': max(iats) if len(iats) > 0 else 0,
                'Flow IAT Min': min(iats) if len(iats) > 0 else 0,
                'Fwd IAT Total': sum(fwd_iats) if len(fwd_iats) > 0 else 0,
                'Fwd IAT Mean': np.mean(fwd_iats) if len(fwd_iats) > 0 else 0,
                'Fwd IAT Std': np.std(fwd_iats) if len(fwd_iats) > 0 else 0,
                'Fwd IAT Max': max(fwd_iats) if len(fwd_iats) > 0 else 0,
                'Fwd IAT Min': min(fwd_iats) if len(fwd_iats) > 0 else 0,
                'Bwd IAT Total': sum(bwd_iats) if len(bwd_iats) > 0 else 0,
                'Bwd IAT Mean': np.mean(bwd_iats) if len(bwd_iats) > 0 else 0,
                'Bwd IAT Std': np.std(bwd_iats) if len(bwd_iats) > 0 else 0,
                'Bwd IAT Max': max(bwd_iats) if len(bwd_iats) > 0 else 0,
                'Bwd IAT Min': min(bwd_iats) if len(bwd_iats) > 0 else 0,
                'Fwd PSH Flags': sum(1 for p in flow['packets'] if p['is_fwd'] and p['tcp'] and p['tcp'].flags_push == '1'),
                'Bwd PSH Flags': sum(1 for p in flow['packets'] if not p['is_fwd'] and p['tcp'] and p['tcp'].flags_push == '1'),
                'Fwd URG Flags': sum(1 for p in flow['packets'] if p['is_fwd'] and p['tcp'] and p['tcp'].flags_urg == '1'),
                'Bwd URG Flags': sum(1 for p in flow['packets'] if not p['is_fwd'] and p['tcp'] and p['tcp'].flags_urg == '1'),
                'Fwd Header Length': sum(20 + (40 if 'ip' in p and p['ip'].version == '6' else 20) for p in flow['packets'] if p['is_fwd']),
                'Bwd Header Length': sum(20 + (40 if 'ip' in p and p['ip'].version == '6' else 20) for p in flow['packets'] if not p['is_fwd']),
                'Fwd Packets/s': fwd_pkts / (duration / 1e6) if duration > 0 else 0,
                'Bwd Packets/s': bwd_pkts / (duration / 1e6) if duration > 0 else 0,
                'Packet Length Min': min(pkt_lengths) if pkt_lengths else 0,
                'Packet Length Max': max(pkt_lengths) if pkt_lengths else 0,
                'Packet Length Mean': np.mean(pkt_lengths) if pkt_lengths else 0,
                'Packet Length Std': np.std(pkt_lengths) if pkt_lengths else 0,
                'Packet Length Variance': np.var(pkt_lengths) if pkt_lengths else 0,
                'FIN Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_fin == '1'),
                'SYN Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_syn == '1'),
                'RST Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_reset == '1'),
                'PSH Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_push == '1'),
                'ACK Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_ack == '1'),
                'URG Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_urg == '1'),
                'CWR Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_cwr == '1'),
                'ECE Flag Count': sum(1 for p in flow['packets'] if p['tcp'] and p['tcp'].flags_ecn == '1'),
                'Down/Up Ratio': bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0,
                'Average Packet Size': (fwd_bytes + bwd_bytes) / total_packets if total_packets > 0 else 0,
                'Fwd Segment Size Avg': fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0,
                'Bwd Segment Size Avg': bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0,
                'Fwd Bytes/Bulk Avg': 0,  # Placeholder; requires bulk detection
                'Fwd Packet/Bulk Avg': 0,
                'Fwd Bulk Rate Avg': 0,
                'Bwd Bytes/Bulk Avg': 0,
                'Bwd Packet/Bulk Avg': 0,
                'Bwd Bulk Rate Avg': 0,
                'Subflow Fwd Packets': fwd_pkts,
                'Subflow Fwd Bytes': fwd_bytes,
                'Subflow Bwd Packets': bwd_pkts,
                'Subflow Bwd Bytes': bwd_bytes,
                'FWD Init Win Bytes': int(flow['packets'][0]['tcp'].window_size) if flow['packets'] and flow['packets'][0]['is_fwd'] and flow['packets'][0]['tcp'] else -1,
                'Bwd Init Win Bytes': int(flow['packets'][0]['tcp'].window_size) if flow['packets'] and not flow['packets'][0]['is_fwd'] and flow['packets'][0]['tcp'] else -1,
                'Fwd Act Data Pkts': sum(1 for p in flow['packets'] if p['is_fwd'] and p['length'] > 0),
                'Fwd Seg Size Min': min(fwd_lens) if fwd_lens else 0,
                'Active Mean': duration if total_packets > 1 else 0,  # Simplified; assumes flow is active
                'Active Std': 0,
                'Active Max': duration if total_packets > 1 else 0,
                'Active Min': duration if total_packets > 1 else 0,
                'Idle Mean': 0,  # Placeholder; requires idle period detection
                'Idle Std': 0,
                'Idle Max': 0,
                'Idle Min': 0
            }
            flows_data.append(flow_data)
        return flows_data

def test_capture_sync():
    capturer = NetworkCapture(interface='Wi-Fi')
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    df = loop.run_until_complete(capturer.capture_traffic())
    print(df.head())
    loop.close()

if __name__ == "__main__":
    test_capture_sync()
