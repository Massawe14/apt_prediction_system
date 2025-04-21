
---

### How It Works

1. **Real-Time Capture**:
   - `NetworkCapture` uses `pyshark` to capture packets on the specified interface (`eth0` by default) for 15 seconds.
   - It extracts basic flow features per packet. In a production environment, you’d aggregate packets into flows using tools like CICFlowMeter or custom logic to compute features like `Flow_Duration` accurately.

2. **Periodic Prediction**:
   - The `capture_and_predict_loop` runs on startup, capturing traffic every 15 seconds, processing it, and storing predictions in `latest_predictions`.
   - The `/latest` endpoint serves these predictions on demand.

3. **Manual Testing**:
   - The `/predict` endpoint remains for manual input, useful for debugging or testing with pre-collected data.

---

### Enhancements for Production

1. **Accurate Flow Aggregation**:
   - Replace the simplified `_extract_flow_features` with a flow-based approach:
     - Use `pyshark` with a flow tracking dictionary to aggregate packets by 5-tuple (src IP, src port, dst IP, dst port, protocol).
     - Compute statistics (e.g., `Flow_Duration`, `Flow_Bytes_s`) over the 15-second window.
   - Alternatively, integrate CICFlowMeter to process live `.pcap` files into CSV flows.

2. **Buffering**:
   - Store captured flows in a buffer (e.g., list or queue) to maintain sequence continuity across 15-second intervals, ensuring the model sees a sliding window of historical data.

3. **Scalability**:
   - Run capture in a separate thread or process to avoid blocking the API.
   - Use a message queue (e.g., Redis) to decouple capture and prediction.

4. **Security**:
   - Add authentication to the API endpoints.
   - Validate input data more strictly.

---

### Testing

1. **Run the API**:
   ```bash
   python src/api.py