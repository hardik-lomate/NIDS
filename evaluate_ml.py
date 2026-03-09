"""
evaluate_ml.py
Offline evaluation script to measure MLDetector accuracy (Precision, Recall, FPR).
Generates a mock dataset of "normal" and "anomalous" feature vectors to test the Isolation Forest.
"""

import sys
import logging
import random
try:
    from sklearn.metrics import precision_score, recall_score, confusion_matrix
    from ml_detector import MLDetector
except ImportError:
    print("scikit-learn not found. Please pip install scikit-learn to run ML evaluation.")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def generate_mock_data(num_normal=800, num_anomalous=200):
    """
    Generates synthetic feature vectors matching MLDetector.FEATURE_NAMES
    Normal: lower packet counts, fewer unique IPs/ports, low entropy.
    Anomalous: high packet counts, very high port entropy (scans), high SYN ratio.
    """
    data = []
    labels = []  # 1 for normal, -1 for anomaly (sklearn format)

    # Normal dataset
    for _ in range(num_normal):
        packet_count = random.uniform(5, 50)
        byte_count = packet_count * random.uniform(100, 1000)
        unique_dst_ips = random.randint(1, 3)
        unique_dst_ports = random.randint(1, 4)
        syn_ratio = random.uniform(0.0, 0.1)
        icmp_ratio = random.uniform(0.0, 0.05)
        avg_pkt_size = byte_count / packet_count
        protocol_entropy = random.uniform(0.0, 1.0)
        port_entropy = random.uniform(0.0, 1.0)
        dns_flag = float(random.choice([0, 1]))

        features = [
            packet_count, byte_count, unique_dst_ips, unique_dst_ports,
            syn_ratio, icmp_ratio, avg_pkt_size, protocol_entropy,
            port_entropy, dns_flag
        ]
        data.append(features)
        labels.append(1)

    # Anomalous dataset
    for _ in range(num_anomalous):
        packet_count = random.uniform(500, 5000)
        byte_count = packet_count * random.uniform(40, 100)
        unique_dst_ips = random.randint(1, 20)
        unique_dst_ports = random.randint(50, 500)
        syn_ratio = random.uniform(0.8, 1.0)
        icmp_ratio = random.uniform(0.0, 0.1)
        avg_pkt_size = byte_count / packet_count
        protocol_entropy = random.uniform(0.0, 0.5)
        port_entropy = random.uniform(3.0, 5.0)
        dns_flag = 0.0

        features = [
            packet_count, byte_count, unique_dst_ips, unique_dst_ports,
            syn_ratio, icmp_ratio, avg_pkt_size, protocol_entropy,
            port_entropy, dns_flag
        ]
        data.append(features)
        labels.append(-1)

    # Shuffle
    combined = list(zip(data, labels))
    random.shuffle(combined)
    data[:], labels[:] = zip(*combined)
    
    return data, labels

def main():
    print("==========================================")
    print(" ML Anomaly Detector - Offline Evaluation ")
    print("==========================================")

    print("[*] Generating 1000 synthetic samples (800 Normal, 200 Anomalous)...")
    train_data, _ = generate_mock_data(800, 0) # Train purely on normal
    test_data, y_true = generate_mock_data(400, 100) # Test mixed

    detector = MLDetector({
        "ml": {
            "enabled": True,
            "contamination": 0.05,
            "min_samples": 50,
            "n_estimators": 50
        }
    })

    print("[*] Training Isolation Forest on Normal Data...")
    with detector._training_lock:
        detector._training_data = train_data
    detector._train()

    print("[*] Running inference on Test Data...")
    y_pred = []
    
    with detector._model_lock:
        scaled = detector._scaler.transform(test_data)
        predictions = detector._model.predict(scaled)
        y_pred = list(predictions)

    # Calculate metrics
    # Note: For sklearn, anomalies are -1. Let's map anomalies to True (positive class) for standard metrics.
    # Anomaly = Positive (1) for metric calculation
    y_true_binary = [1 if y == -1 else 0 for y in y_true]
    y_pred_binary = [1 if y == -1 else 0 for y in y_pred]

    precision = precision_score(y_true_binary, y_pred_binary, zero_division=0)
    recall = recall_score(y_true_binary, y_pred_binary, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true_binary, y_pred_binary).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n[+] Evaluation Results:")
    print(f"    Total Test Samples : {len(y_true)}")
    print(f"    True Anomalies     : {sum(y_true_binary)}")
    print(f"    Detected Anomalies : {sum(y_pred_binary)}")
    print("------------------------------------------")
    print(f"    Precision (PPV)    : {precision:.4f}  (True Anomalies / Detected Anomalies)")
    print(f"    Recall (TPR)       : {recall:.4f}  (Detected Anomalies / True Total Anomalies)")
    print(f"    False Positive Rate: {fpr:.4f}  (False Alarms / Total Normal Traffic)")
    print("------------------------------------------")
    if precision < 0.8:
        print("[!] Note: Isolation Forest on untuned traffic usually yields lower precision (more False Positives).")
    else:
        print("[+] Good precision achieved for synthetic profiles.")

if __name__ == "__main__":
    main()
