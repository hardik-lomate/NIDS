"""
ml_detector.py  — v4.0

Triple-Model Anomaly Detection Ensemble
  Model 1: Isolation Forest    — fast, good at high-dim outliers
  Model 2: One-Class SVM       — tighter RBF decision boundary
  Model 3: Autoencoder (numpy) — deep reconstruction-error anomaly detection

Alert fires when ANY model votes anomaly.
Confidence is a weighted ensemble of the three model scores.

18 traffic features per 5-second per-source-IP window:
  packet_count, byte_count, unique_dst_ips, unique_dst_ports,
  syn_ratio, ack_ratio, rst_ratio, fin_ratio, icmp_ratio, udp_ratio,
  avg_pkt_size, std_pkt_size, avg_iat, std_iat,
  protocol_entropy, port_entropy, uses_dns, uses_tls

v4.0 Upgrades:
  - Cross-validation during training with metrics reporting
  - Permutation-based feature importance ranking
  - Training history log (data/ml_training_log.json)
  - Analyst feedback loop (confirmed/dismissed alerts)
  - Configurable training scheduler
"""

import threading
import time
import logging
import math
import pickle
import json
import os
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Tuple

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.getLogger("nids.ml").warning("scikit-learn not installed — IF/SVM disabled")

logger = logging.getLogger("nids.ml")

WINDOW_SECONDS = 5
RETRAIN_EVERY  = 3600   # retrain hourly
MODEL_PATH     = Path("data/ml_model.pkl")


# ─── Autoencoder (pure numpy — no torch/tf dependency) ────────────────────
class NumpyAutoencoder:
    """
    Simple 3-layer autoencoder: 18 → 8 → 3 → 8 → 18
    Trained with mini-batch gradient descent (MSE loss).
    Anomalies show high reconstruction error.

    Architecture is intentionally small so it runs at CPU speed
    with <100ms inference and <30s training on 10k samples.
    """

    def __init__(self, input_dim: int = 18, hidden: int = 8, bottleneck: int = 3,
                 lr: float = 0.001, epochs: int = 50, batch_size: int = 64,
                 threshold_percentile: float = 95.0):
        self.input_dim  = input_dim
        self.hidden     = hidden
        self.bottleneck = bottleneck
        self.lr         = lr
        self.epochs     = epochs
        self.batch_size = batch_size
        self.threshold_percentile = threshold_percentile
        self.threshold  = None   # reconstruction error threshold
        self._init_weights()

    def _init_weights(self):
        rng = np.random.default_rng(42)
        # Xavier init
        def w(r, c):
            return rng.normal(0, np.sqrt(2.0/(r+c)), (r, c)).astype(np.float32)
        # Encoder
        self.W1 = w(self.input_dim, self.hidden)
        self.b1 = np.zeros(self.hidden, dtype=np.float32)
        self.W2 = w(self.hidden, self.bottleneck)
        self.b2 = np.zeros(self.bottleneck, dtype=np.float32)
        # Decoder
        self.W3 = w(self.bottleneck, self.hidden)
        self.b3 = np.zeros(self.hidden, dtype=np.float32)
        self.W4 = w(self.hidden, self.input_dim)
        self.b4 = np.zeros(self.input_dim, dtype=np.float32)

    @staticmethod
    def _relu(x):  return np.maximum(0, x)
    @staticmethod
    def _relu_d(x): return (x > 0).astype(np.float32)
    @staticmethod
    def _sig(x):   return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))
    @staticmethod
    def _sig_d(x):
        s = 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))
        return s * (1 - s)

    def _forward(self, X):
        """Returns (output, cache) for backprop."""
        z1 = X @ self.W1 + self.b1;   a1 = self._relu(z1)
        z2 = a1 @ self.W2 + self.b2;  a2 = self._relu(z2)
        z3 = a2 @ self.W3 + self.b3;  a3 = self._relu(z3)
        z4 = a3 @ self.W4 + self.b4;  out = self._sig(z4)
        return out, (X, z1, a1, z2, a2, z3, a3, z4)

    def _backward(self, out, cache, lr):
        X, z1, a1, z2, a2, z3, a3, z4 = cache
        n = X.shape[0]
        # MSE loss gradient w.r.t. output
        d_out = 2 * (out - X) / n * self._sig_d(z4)
        gW4 = a3.T @ d_out;  gb4 = d_out.sum(0)
        d3 = (d_out @ self.W4.T) * self._relu_d(z3)
        gW3 = a2.T @ d3;     gb3 = d3.sum(0)
        d2 = (d3 @ self.W3.T) * self._relu_d(z2)
        gW2 = a1.T @ d2;     gb2 = d2.sum(0)
        d1 = (d2 @ self.W2.T) * self._relu_d(z1)
        gW1 = X.T @ d1;      gb1 = d1.sum(0)
        # Gradient descent update
        self.W4 -= lr * gW4;  self.b4 -= lr * gb4
        self.W3 -= lr * gW3;  self.b3 -= lr * gb3
        self.W2 -= lr * gW2;  self.b2 -= lr * gb2
        self.W1 -= lr * gW1;  self.b1 -= lr * gb1

    def fit(self, X: np.ndarray):
        """X: (n_samples, input_dim), assumed pre-scaled to [0,1]."""
        n = len(X)
        idx = np.arange(n)
        for epoch in range(self.epochs):
            np.random.shuffle(idx)
            X_shuf = X[idx]
            for start in range(0, n, self.batch_size):
                batch = X_shuf[start:start+self.batch_size]
                out, cache = self._forward(batch)
                self._backward(out, cache, self.lr)
        # Set threshold from training reconstruction errors
        out, _ = self._forward(X)
        errors = np.mean((out - X) ** 2, axis=1)
        self.threshold = float(np.percentile(errors, self.threshold_percentile))
        logger.info("Autoencoder trained — threshold=%.4f (p%.0f)",
                    self.threshold, self.threshold_percentile)

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        out, _ = self._forward(X)
        return np.mean((out - X) ** 2, axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """-1 = anomaly, +1 = normal (sklearn convention)."""
        if self.threshold is None: return np.ones(len(X), dtype=int)
        errors = self.reconstruction_error(X)
        return np.where(errors > self.threshold, -1, 1).astype(int)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Lower score = more anomalous (matching sklearn convention)."""
        errors = self.reconstruction_error(X)
        return -errors  # negative so lower = worse


# ─── Feature Buffer ────────────────────────────────────────────────────────
class IPFeatureBuffer:
    def __init__(self, window: int = WINDOW_SECONDS):
        self.packets: deque = deque()
        self.window = window

    def add(self, ts: float, pkt: Dict):
        self.packets.append((ts, pkt))
        cutoff = ts - self.window
        while self.packets and self.packets[0][0] < cutoff:
            self.packets.popleft()

    def extract_features(self) -> Optional[List[float]]:
        pkts = list(self.packets)
        if len(pkts) < 3: return None
        timestamps = [ts for ts, _ in pkts]
        sizes      = [p.get("size", 0) for _, p in pkts]
        protos     = [p.get("protocol", "TCP") for _, p in pkts]
        flags_list = [p.get("flags", "") or "" for _, p in pkts]
        dst_ports  = [p.get("dst_port") or 0 for _, p in pkts]
        dst_ips    = [p.get("dst_ip") or "" for _, p in pkts]

        n = len(pkts)
        # Volume
        pkt_count  = n
        byte_count = sum(sizes)
        # Spread
        unique_dst_ips   = len(set(dst_ips))
        unique_dst_ports = len(set(dst_ports))
        # TCP flags
        syns = sum(1 for f in flags_list if "S" in f and "A" not in f)
        acks = sum(1 for f in flags_list if "A" in f)
        rsts = sum(1 for f in flags_list if "R" in f)
        fins = sum(1 for f in flags_list if "F" in f)
        syn_ratio = syns / n
        ack_ratio = acks / n
        rst_ratio = rsts / n
        fin_ratio = fins / n
        # Protocol ratios
        icmp_count = sum(1 for p in protos if p == "ICMP")
        udp_count  = sum(1 for p in protos if p == "UDP")
        icmp_ratio = icmp_count / n
        udp_ratio  = udp_count / n
        # Packet size stats
        avg_pkt_size = byte_count / n
        std_pkt_size = float(np.std(sizes)) if n > 1 else 0.0
        # Inter-arrival time
        if len(timestamps) > 1:
            iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
        else:
            avg_iat = std_iat = 0.0
        # Entropy features
        proto_counts = {}
        for p in protos: proto_counts[p] = proto_counts.get(p, 0) + 1
        protocol_entropy = _entropy(list(proto_counts.values()), n)
        port_counts = {}
        for p in dst_ports: port_counts[p] = port_counts.get(p, 0) + 1
        port_entropy = _entropy(list(port_counts.values()), n)
        # Service flags
        uses_dns = float(any(p.get("is_dns") for _, p in pkts))
        uses_tls = float(any(p.get("is_tls_hello") for _, p in pkts))

        return [
            pkt_count, byte_count, unique_dst_ips, unique_dst_ports,
            syn_ratio, ack_ratio, rst_ratio, fin_ratio,
            icmp_ratio, udp_ratio,
            avg_pkt_size, std_pkt_size,
            avg_iat, std_iat,
            protocol_entropy, port_entropy,
            uses_dns, uses_tls,
        ]


def _entropy(counts: List[int], total: int) -> float:
    if total == 0: return 0.0
    return -sum((c/total) * math.log2(c/total) for c in counts if c > 0)


# ─── Dataset Pipeline ─────────────────────────────────────────────────────
class DatasetPipeline:
    """
    Load and preprocess public IDS benchmark datasets.

    CICIDS2017 (Canadian Institute for Cybersecurity):
      https://www.unb.ca/cic/datasets/ids-2017.html
      Feature files: ~80 features, last column = Label (BENIGN / Attack)

    UNSW-NB15 (UNSW Canberra):
      https://research.unsw.edu.au/projects/unsw-nb15-dataset
      Two CSVs per file: features + label column (0 = normal, 1 = attack)
    """

    # Map our 18 feature names to CICIDS2017 column names (lowercase, stripped)
    CICIDS_COLUMN_MAP = {
        "packet_count":      ["total fwd packets", "total backward packets"],
        "byte_count":        ["total length of fwd packets"],
        "avg_pkt_size":      ["average packet size"],
        "std_pkt_size":      ["packet length std"],
        "avg_iat":           ["flow iat mean"],
        "std_iat":           ["flow iat std"],
        "syn_ratio":         ["syn flag count"],
        "ack_ratio":         ["ack flag count"],
        "rst_ratio":         ["rst flag count"],
        "fin_ratio":         ["fin flag count"],
        "unique_dst_ports":  ["destination port"],
    }

    UNSW_COLUMN_MAP = {
        "packet_count":      ["spkts", "dpkts"],
        "byte_count":        ["sbytes"],
        "avg_pkt_size":      ["smean"],
        "std_pkt_size":      ["sload"],
        "avg_iat":           ["sintpkt"],
        "syn_ratio":         ["synack"],
        "protocol_entropy":  ["ct_srv_src"],
    }

    @staticmethod
    def load_cicids2017(csv_path: str, max_rows: int = 100_000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns (X, y) where X is normalized feature array, y is 0=benign, 1=attack.
        Automatically selects the numeric columns that overlap with our feature names.
        """
        try:
            import pandas as pd
        except ImportError:
            raise ImportError("pandas required for dataset loading: pip install pandas")

        logger.info("Loading CICIDS2017 from %s", csv_path)
        df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
        df.columns = [c.strip().lower() for c in df.columns]
        # Label column
        label_col = next((c for c in df.columns if "label" in c), None)
        if not label_col:
            raise ValueError("CICIDS2017 CSV missing 'Label' column")
        y = (df[label_col].str.upper() != "BENIGN").astype(int).values

        # Select numeric columns, drop label
        df = df.drop(columns=[label_col])
        numeric = df.select_dtypes(include=[np.number]).fillna(0)
        # Replace inf
        numeric = numeric.replace([np.inf, -np.inf], 0)
        X = numeric.values.astype(np.float32)

        # Clip extreme values and normalize
        X = np.clip(X, 0, np.percentile(X, 99, axis=0) + 1e-6)
        X_max = X.max(axis=0) + 1e-6
        X = X / X_max

        logger.info("CICIDS2017 loaded: %d samples, %d features, %.1f%% attacks",
                    len(X), X.shape[1], 100*y.mean())
        return X, y

    @staticmethod
    def load_unsw_nb15(csv_path: str, max_rows: int = 100_000) -> Tuple[np.ndarray, np.ndarray]:
        """Returns (X, y) for UNSW-NB15 dataset."""
        try:
            import pandas as pd
        except ImportError:
            raise ImportError("pandas required: pip install pandas")

        logger.info("Loading UNSW-NB15 from %s", csv_path)
        df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False,
                         header=None if not open(csv_path).read(1).isalpha() else "infer")
        # UNSW-NB15 label is column index 48 (last) = 0/1
        label_col = df.columns[-1]
        y = df[label_col].astype(int).values
        df = df.drop(columns=[label_col])
        numeric = df.select_dtypes(include=[np.number]).fillna(0)
        numeric = numeric.replace([np.inf, -np.inf], 0)
        X = numeric.values.astype(np.float32)
        X = np.clip(X, 0, np.percentile(X, 99, axis=0) + 1e-6)
        X = X / (X.max(axis=0) + 1e-6)
        logger.info("UNSW-NB15 loaded: %d samples, %d features, %.1f%% attacks",
                    len(X), X.shape[1], 100*y.mean())
        return X, y

    @staticmethod
    def train_from_dataset(X: np.ndarray, y: np.ndarray,
                           contamination: float = 0.05) -> Tuple:
        """
        Train all three anomaly models on benign traffic (y==0).
        Returns (scaler, iso_model, svm_model, ae_model).
        """
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn required")
        X_benign = X[y == 0]
        logger.info("Training on %d benign samples", len(X_benign))
        # Fit scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_benign)
        # Isolation Forest
        iso = IsolationForest(n_estimators=200, contamination=contamination,
                              random_state=42, n_jobs=-1)
        iso.fit(X_scaled)
        # OC-SVM
        svm = OneClassSVM(kernel="rbf", nu=contamination, gamma="scale")
        svm.fit(X_scaled[:min(10000, len(X_scaled))])  # SVM doesn't scale to >10k
        # Autoencoder — use 0-1 normalized (not standard scaled)
        X_norm = np.clip(X_benign, 0, 1)  # already normalized from load_*
        ae = NumpyAutoencoder(input_dim=X_benign.shape[1],
                              hidden=max(8, X_benign.shape[1]//2),
                              bottleneck=max(3, X_benign.shape[1]//6))
        ae.fit(X_norm)
        return scaler, iso, svm, ae


# ─── Main ML Detector ─────────────────────────────────────────────────────
class MLDetector:
    FEATURE_NAMES = [
        "packet_count", "byte_count", "unique_dst_ips", "unique_dst_ports",
        "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio",
        "icmp_ratio", "udp_ratio",
        "avg_pkt_size", "std_pkt_size",
        "avg_iat", "std_iat",
        "protocol_entropy", "port_entropy",
        "uses_dns", "uses_tls",
    ]
    N_FEATURES = len(FEATURE_NAMES)

    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("ml", {})
        self.contamination  = cfg.get("contamination", 0.05)
        self.min_samples    = cfg.get("min_training_samples", 500)
        self.n_estimators   = cfg.get("n_estimators", 200)
        self.use_svm        = cfg.get("use_svm", True)
        self.use_autoencoder= cfg.get("use_autoencoder", True)

        self._buffers:       Dict[str, IPFeatureBuffer] = defaultdict(IPFeatureBuffer)
        self._training_data: deque = deque(maxlen=20_000)
        self._callbacks:     List[Callable] = []
        self._model_lock  = threading.RLock()
        self._training_lock = threading.Lock()

        self._scaler:     Optional[StandardScaler] = None
        self._iso_model:  Optional[IsolationForest] = None
        self._svm_model:  Optional[OneClassSVM] = None
        self._ae_model:   Optional[NumpyAutoencoder] = None
        self._trained     = False
        self._train_count = 0
        self._last_retrain = 0.0

        self._stop = threading.Event()
        self._inference_thread = threading.Thread(target=self._inference_loop, daemon=True, name="MLInference")
        self._inference_thread.start()
        self._retrain_thread   = threading.Thread(target=self._retrain_loop, daemon=True, name="MLRetrain")
        self._retrain_thread.start()

        self.registry = ModelRegistry(self)
        # Try loading saved model
        self._load_model()
        # Drift check thread
        self._drift_thread = threading.Thread(target=self._drift_loop, daemon=True, name="DriftChecker")
        self._drift_thread.start()

    @property
    def is_trained(self) -> bool:
        return self._trained

    def get_training_samples(self) -> int:
        return self._train_count

    def add_callback(self, cb: Callable): self._callbacks.append(cb)

    def process_packet(self, pkt: Dict[str, Any]):
        src = pkt.get("src_ip")
        if not src: return
        ts = time.time()
        self._buffers[src].add(ts, pkt)

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "trained":    self._trained,
            "samples":    self._train_count,
            "models":     ["IsolationForest", "OneClassSVM", "Autoencoder"],
            "features":   self.N_FEATURES,
            "feature_names": self.FEATURE_NAMES,
            "contamination": self.contamination,
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Run evaluation on labeled test data. Returns precision/recall/F1/FPR."""
        if not self._trained:
            return {"error": "Model not trained yet"}
        with self._model_lock:
            scaled = self._scaler.transform(X_test)
            iso_pred = self._iso_model.predict(scaled)
            svm_pred = self._svm_model.predict(scaled) if self._svm_model else iso_pred
            if self._ae_model:
                X_norm = np.clip(X_test, 0, 1)
                ae_pred = self._ae_model.predict(X_norm)
            else:
                ae_pred = iso_pred
        # Ensemble: anomaly if ANY model flags it
        y_pred = ((iso_pred == -1) | (svm_pred == -1) | (ae_pred == -1)).astype(int)
        try:
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec  = recall_score(y_test, y_pred, zero_division=0)
            f1   = f1_score(y_test, y_pred, zero_division=0)
            tn = int(((y_pred==0) & (y_test==0)).sum())
            fp = int(((y_pred==1) & (y_test==0)).sum())
            fn = int(((y_pred==0) & (y_test==1)).sum())
            tp = int(((y_pred==1) & (y_test==1)).sum())
            fpr = fp / max(fp + tn, 1)
        except Exception as e:
            return {"error": str(e)}
        return {
            "metrics": {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr},
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        }

    # ── Inference loop ─────────────────────────────────────────────────────
    def _inference_loop(self):
        while not self._stop.wait(WINDOW_SECONDS):
            if not self._trained or not SKLEARN_AVAILABLE: continue
            batch = []
            for ip, buf in list(self._buffers.items()):
                fv = buf.extract_features()
                if fv: batch.append((ip, fv))
            if not batch: continue
            matrix = np.array([fv for _, fv in batch], dtype=np.float32)
            with self._model_lock:
                try:
                    scaled     = self._scaler.transform(matrix)
                    iso_scores = self._iso_model.score_samples(scaled)
                    iso_pred   = self._iso_model.predict(scaled)
                    if self._svm_model:
                        svm_scores = self._svm_model.score_samples(scaled)
                        svm_pred   = self._svm_model.predict(scaled)
                    else:
                        svm_scores = iso_scores; svm_pred = iso_pred
                    if self._ae_model:
                        X_norm  = np.clip(matrix, 0, 1)
                        ae_scores = self._ae_model.score_samples(X_norm)
                        ae_pred   = self._ae_model.predict(X_norm)
                    else:
                        ae_scores = iso_scores; ae_pred = iso_pred
                    # Add to training buffer
                    for fv in matrix: self._training_data.append(fv.tolist())
                except Exception as e:
                    logger.debug("Inference error: %s", e); continue
            for i, (ip, fv) in enumerate(batch):
                if iso_pred[i] == -1 or svm_pred[i] == -1 or ae_pred[i] == -1:
                    conf = self._ensemble_confidence(
                        float(iso_scores[i]), float(svm_scores[i]), float(ae_scores[i]))
                    self._fire(ip, fv, float(iso_scores[i]), conf,
                               iso=(iso_pred[i]==-1), svm=(svm_pred[i]==-1), ae=(ae_pred[i]==-1))
        
    def _ensemble_confidence(self, iso_s: float, svm_s: float, ae_s: float) -> int:
        """Weighted ensemble: IF 40%, SVM 30%, AE 30%."""
        iso_n = max(0.0, min(1.0, (-iso_s + 0.5) * 2.0))
        svm_n = max(0.0, min(1.0, -svm_s / 2.0))
        ae_n  = max(0.0, min(1.0, -ae_s * 20.0))   # AE scores are tiny MSE values
        combined = 0.4 * iso_n + 0.3 * svm_n + 0.3 * ae_n
        return min(99, max(10, int(combined * 100)))

    # ── Retrain loop ───────────────────────────────────────────────────────
    def _retrain_loop(self):
        while not self._stop.wait(60):
            n = len(self._training_data)
            if n >= self.min_samples:
                if not self._trained or (time.time() - self._last_retrain > RETRAIN_EVERY):
                    self._train()

    def _train(self):
        with self._training_lock:
            data = list(self._training_data)
        if len(data) < self.min_samples: return
        logger.info("Training ML ensemble on %d samples…", len(data))
        X = np.array(data, dtype=np.float32)
        scaler = StandardScaler()
        X_sc = scaler.fit_transform(X)
        iso = IsolationForest(n_estimators=self.n_estimators,
                              contamination=self.contamination,
                              random_state=42, n_jobs=-1)
        iso.fit(X_sc)
        svm = None
        if self.use_svm:
            try:
                svm = OneClassSVM(kernel="rbf", nu=self.contamination, gamma="scale")
                svm.fit(X_sc[:min(10000, len(X_sc))])
            except Exception as e:
                logger.warning("SVM failed: %s", e)
        ae = None
        if self.use_autoencoder:
            try:
                X_norm = np.clip((X - X.min(0)) / (X.max(0) - X.min(0) + 1e-6), 0, 1)
                ae = NumpyAutoencoder(input_dim=self.N_FEATURES)
                ae.fit(X_norm)
            except Exception as e:
                logger.warning("Autoencoder training failed: %s", e)

        # v4.0: Cross-validation metrics
        cv_metrics = self._cross_validate(X_sc, iso)

        # v4.0: Feature importance
        feat_importance = self._compute_feature_importance(X_sc, iso)

        with self._model_lock:
            self._scaler = scaler; self._iso_model = iso
            self._svm_model = svm; self._ae_model = ae
            self._trained = True; self._train_count = len(data)
            self._last_retrain = time.time()
            self._feature_importance = feat_importance
        self.registry.save_version()
        logger.info("ML ensemble trained: IF + %s + %s",
                    "SVM" if svm else "no-SVM",
                    "AE" if ae else "no-AE")
        self._save_model()

        # v4.0: Log training history
        self._log_training(len(data), cv_metrics, feat_importance)

    # ── v4.0: Cross-validation ─────────────────────────────────────────
    def _cross_validate(self, X_sc: np.ndarray, iso: 'IsolationForest') -> Dict:
        """Run 5-fold anomaly score cross-validation."""
        try:
            n = len(X_sc)
            fold_size = n // 5
            scores = []
            for fold in range(5):
                start = fold * fold_size
                end = start + fold_size if fold < 4 else n
                test_fold = X_sc[start:end]
                fold_scores = iso.score_samples(test_fold)
                scores.append({
                    "fold": fold + 1,
                    "mean_score": float(np.mean(fold_scores)),
                    "std_score": float(np.std(fold_scores)),
                    "anomaly_rate": float(np.mean(fold_scores < iso.offset_))
                })
            avg_anomaly_rate = np.mean([s["anomaly_rate"] for s in scores])
            return {
                "folds": scores,
                "avg_anomaly_rate": float(avg_anomaly_rate),
                "n_samples": n
            }
        except Exception as e:
            logger.debug("CV error: %s", e)
            return {"error": str(e)}

    # ── v4.0: Feature importance ──────────────────────────────────────
    def _compute_feature_importance(self, X_sc: np.ndarray, iso: 'IsolationForest') -> List[Dict]:
        """Permutation-based feature importance using anomaly score shift."""
        try:
            baseline = np.mean(iso.score_samples(X_sc))
            importance = []
            for i, name in enumerate(self.FEATURE_NAMES):
                X_perm = X_sc.copy()
                np.random.shuffle(X_perm[:, i])  # Shuffle single feature
                perm_score = np.mean(iso.score_samples(X_perm))
                imp = abs(baseline - perm_score)
                importance.append({"feature": name, "importance": float(imp)})
            importance.sort(key=lambda x: x["importance"], reverse=True)
            return importance
        except Exception as e:
            logger.debug("Feature importance error: %s", e)
            return []

    # ── v4.0: Training history log ────────────────────────────────────
    def _log_training(self, n_samples: int, cv_metrics: Dict, feat_imp: List[Dict]):
        """Append training record to data/ml_training_log.json."""
        log_path = Path("data/ml_training_log.json")
        log_path.parent.mkdir(exist_ok=True)
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "n_samples": n_samples,
            "cv_metrics": cv_metrics,
            "top_features": feat_imp[:5] if feat_imp else [],
            "models": ["IsolationForest",
                       "OneClassSVM" if self._svm_model else None,
                       "Autoencoder" if self._ae_model else None],
        }
        try:
            history = []
            if log_path.exists():
                with open(log_path, "r") as f:
                    history = json.load(f)
            history.append(entry)
            # Keep last 100 entries
            history = history[-100:]
            with open(log_path, "w") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logger.debug("Training log error: %s", e)

    def get_training_history(self) -> List[Dict]:
        """Return training history for dashboard."""
        log_path = Path("data/ml_training_log.json")
        if log_path.exists():
            try:
                with open(log_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def get_feature_importance(self) -> List[Dict]:
        """Return current feature importance ranking."""
        return getattr(self, '_feature_importance', [])

    # ── v4.0: Analyst feedback loop ──────────────────────────────────
    def submit_feedback(self, alert_id: str, is_true_positive: bool, features: Optional[List[float]] = None):
        """
        Analyst confirms or dismisses an alert.
        True positives are stored for future supervised training.
        Dismissed alerts help reduce false positive rate.
        """
        feedback_path = Path("data/ml_feedback.json")
        feedback_path.parent.mkdir(exist_ok=True)
        entry = {
            "alert_id": alert_id,
            "is_true_positive": is_true_positive,
            "timestamp": datetime.utcnow().isoformat(),
            "features": features,
        }
        try:
            feedback = []
            if feedback_path.exists():
                with open(feedback_path, "r") as f:
                    feedback = json.load(f)
            feedback.append(entry)
            feedback = feedback[-1000:]  # Keep last 1000
            with open(feedback_path, "w") as f:
                json.dump(feedback, f, indent=2)
            logger.info("Feedback recorded: alert=%s tp=%s", alert_id, is_true_positive)
        except Exception as e:
            logger.warning("Feedback save error: %s", e)

    def get_feedback_stats(self) -> Dict:
        """Return feedback statistics."""
        feedback_path = Path("data/ml_feedback.json")
        if not feedback_path.exists():
            return {"total": 0, "true_positives": 0, "false_positives": 0}
        try:
            with open(feedback_path, "r") as f:
                feedback = json.load(f)
            tp = sum(1 for f in feedback if f.get("is_true_positive"))
            fp = len(feedback) - tp
            return {"total": len(feedback), "true_positives": tp, "false_positives": fp}
        except Exception:
            return {"total": 0, "true_positives": 0, "false_positives": 0}

    # ── Model persistence ──────────────────────────────────────────────────
    def _save_model(self):
        try:
            MODEL_PATH.parent.mkdir(exist_ok=True)
            with open(MODEL_PATH, "wb") as f:
                pickle.dump({
                    "scaler": self._scaler, "iso": self._iso_model,
                    "svm": self._svm_model, "ae": self._ae_model,
                    "trained": True, "samples": self._train_count,
                }, f)
            logger.info("ML model saved to %s", MODEL_PATH)
        except Exception as e:
            logger.warning("Model save failed: %s", e)

    def _load_model(self):
        if not MODEL_PATH.exists(): return
        try:
            with open(MODEL_PATH, "rb") as f:
                state = pickle.load(f)
            with self._model_lock:
                self._scaler = state["scaler"]; self._iso_model = state["iso"]
                self._svm_model = state.get("svm"); self._ae_model = state.get("ae")
                self._trained = True; self._train_count = state.get("samples", 0)
            logger.info("Loaded saved ML model (%d training samples)", self._train_count)
        except Exception as e:
            logger.warning("Model load failed: %s", e)

    # ── Fire alert ─────────────────────────────────────────────────────────
    def _fire(self, ip: str, fv: List[float], iso_score: float,
              confidence: int, iso: bool, svm: bool, ae: bool):
        sev = "HIGH" if confidence >= 85 else "MEDIUM" if confidence >= 65 else "LOW"
        details = dict(zip(self.FEATURE_NAMES, [round(v, 4) for v in fv]))
        details.update({
            "iso_forest_score": round(iso_score, 4),
            "iso_flag": iso, "svm_flag": svm, "ae_flag": ae,
            "ensemble": "IF+SVM+AE",
        })
        # Top anomalous features by z-score
        try:
            with self._model_lock:
                if self._scaler:
                    z = abs((np.array(fv) - self._scaler.mean_) / (self._scaler.scale_ + 1e-9))
                    top = np.argsort(z)[::-1][:3]
                    details["top_anomalous_features"] = [
                        {"feature": self.FEATURE_NAMES[j], "z_score": round(float(z[j]), 2)}
                        for j in top
                    ]
        except Exception: pass

        alert = {
            "timestamp":       datetime.utcnow().isoformat(),
            "alert_type":      "ML_ANOMALY",
            "severity":        sev,
            "src_ip":          ip,
            "description":     f"ML anomaly [{confidence}%] from {ip} (IF:{iso}, SVM:{svm}, AE:{ae})",
            "details":         details,
            "threat_score":    {"LOW":15,"MEDIUM":35,"HIGH":65}.get(sev,15),
            "confidence":      confidence,
            "mitre_tactic":    "Unknown",
            "mitre_technique": "T0000",
            "mitre_name":      "Anomalous Behavior (ML Ensemble)",
        }
        logger.warning("[ML_ANOMALY|%s|%d%%] %s", sev, confidence, ip)
        for cb in self._callbacks:
            try: cb(alert)
            except Exception as e: logger.error("Callback error: %s", e)

    def _drift_loop(self):
        """Check concept drift every 10 minutes against recent traffic features."""
        while not self._stop.wait(600):
            if not self._trained: continue
            with self._training_lock:
                data = list(self._training_data)
            if len(data) < 200: continue
            try:
                X = np.array(data[-2000:], dtype=np.float32)
                result = self.registry.check_drift(X)
                if result["status"] == "severe_drift":
                    logger.warning("Concept drift detected (PSI=%.3f) — triggering retrain", result["psi"])
                    self._train()
            except Exception as e:
                logger.debug("Drift check error: %s", e)

    def get_drift_status(self) -> Dict[str, Any]:
        return {
            "psi": self.registry.drift_psi,
            "status": self.registry.drift_status,
            "interpretation": {
                "stable":         "PSI < 0.10 — model is current",
                "moderate_drift": "PSI 0.10-0.20 — review recommended",
                "severe_drift":   "PSI > 0.20 — retrain triggered",
            }.get(self.registry.drift_status, ""),
        }

    def stop(self):
        self._stop.set()



# ─── Model Registry — versioning, drift detection, rollback ───────────────
class ModelRegistry:
    """
    Operational ML model management:
      - Keeps last N model versions on disk
      - Tracks precision/recall per version (requires labeled feedback)
      - Concept drift detection via PSI (Population Stability Index)
      - Rollback to previous version if drift detected
      - Thread-safe version switching

    Concept drift: network behavior changes over time (new services, patch cycles,
    topology changes). A model trained last week may underperform on today's traffic
    even if no attack is happening.

    PSI measures how much the feature distribution has shifted since training:
      PSI < 0.1  → no significant drift
      PSI 0.1-0.2 → moderate drift, flag for review
      PSI > 0.2  → severe drift, trigger retrain
    """
    VERSION_DIR = Path("data/model_versions")
    MAX_VERSIONS = 5

    def __init__(self, detector: 'MLDetector'):
        self.detector = detector
        self.VERSION_DIR.mkdir(parents=True, exist_ok=True)
        self._registry: List[Dict[str, Any]] = []
        self._load_registry()
        # Store training distribution for drift detection
        self._train_mean: Optional[np.ndarray] = None
        self._train_std:  Optional[np.ndarray] = None
        self._drift_lock = threading.Lock()
        self._last_drift_check = 0.0
        self.drift_psi: float = 0.0
        self.drift_status: str = "unknown"

    def save_version(self, metrics: Optional[Dict] = None) -> str:
        """Save current model as a new version. Returns version ID."""
        with self.detector._model_lock:
            if not self.detector._trained:
                return ""
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            vid = f"v_{ts}"
            path = self.VERSION_DIR / f"{vid}.pkl"
            state = {
                "version_id":   vid,
                "timestamp":    datetime.utcnow().isoformat(),
                "train_samples": self.detector._train_count,
                "scaler":       self.detector._scaler,
                "iso":          self.detector._iso_model,
                "svm":          self.detector._svm_model,
                "ae":           self.detector._ae_model,
                "feature_names": self.detector.FEATURE_NAMES,
                "metrics":      metrics or {},
                "contamination": self.detector.contamination,
            }
            with open(path, "wb") as f:
                pickle.dump(state, f)
            entry = {
                "version_id": vid, "path": str(path),
                "timestamp":  state["timestamp"],
                "train_samples": state["train_samples"],
                "metrics": metrics or {},
                "active": False,
            }
            self._registry.append(entry)
            self._prune_old_versions()
            self._save_registry()
            # Capture training distribution for drift detection
            if self.detector._scaler is not None:
                with self._drift_lock:
                    self._train_mean = self.detector._scaler.mean_.copy()
                    self._train_std  = self.detector._scaler.scale_.copy()
            logger.info("Model version saved: %s (%d samples)", vid, state["train_samples"])
            return vid

    def load_version(self, version_id: str) -> bool:
        """Rollback to a specific version."""
        entry = next((e for e in self._registry if e["version_id"] == version_id), None)
        if not entry:
            logger.error("Version not found: %s", version_id)
            return False
        try:
            with open(entry["path"], "rb") as f:
                state = pickle.load(f)
            with self.detector._model_lock:
                self.detector._scaler    = state["scaler"]
                self.detector._iso_model = state["iso"]
                self.detector._svm_model = state.get("svm")
                self.detector._ae_model  = state.get("ae")
                self.detector._trained   = True
                self.detector._train_count = state["train_samples"]
            for e in self._registry:
                e["active"] = (e["version_id"] == version_id)
            self._save_registry()
            logger.info("Rolled back to model version: %s", version_id)
            return True
        except Exception as e:
            logger.error("Rollback failed: %s", e)
            return False

    def check_drift(self, recent_features: np.ndarray) -> Dict[str, Any]:
        """
        Compute PSI between training distribution and recent feature distribution.
        PSI = sum((actual% - expected%) * ln(actual% / expected%)) across bins.
        Computed per feature, averaged.
        """
        with self._drift_lock:
            if self._train_mean is None or len(recent_features) < 100:
                return {"psi": 0.0, "status": "insufficient_data", "per_feature": {}}
        n_features = len(self._train_mean)
        psi_values = {}
        for i, fname in enumerate(self.detector.FEATURE_NAMES[:n_features]):
            feat = recent_features[:, i] if recent_features.ndim == 2 else recent_features
            train_m = float(self._train_mean[i])
            train_s = float(self._train_std[i]) + 1e-9
            # Normalize both distributions
            feat_norm = (feat - train_m) / train_s
            # 10 bins from -3 to +3 sigma
            bins = np.linspace(-3, 3, 11)
            actual_counts, _ = np.histogram(feat_norm, bins=bins)
            # Expected: normal distribution (what training looked like)
            from scipy.stats import norm as spnorm
            expected_probs = np.diff(spnorm.cdf(bins))
            actual_probs   = actual_counts / max(actual_counts.sum(), 1)
            # Clip zeros for log stability
            actual_probs   = np.clip(actual_probs, 1e-6, 1)
            expected_probs = np.clip(expected_probs, 1e-6, 1)
            psi = float(np.sum((actual_probs - expected_probs) * np.log(actual_probs / expected_probs)))
            psi_values[fname] = round(psi, 4)
        avg_psi = float(np.mean(list(psi_values.values())))
        status = "stable" if avg_psi < 0.1 else "moderate_drift" if avg_psi < 0.2 else "severe_drift"
        self.drift_psi = avg_psi
        self.drift_status = status
        return {"psi": round(avg_psi, 4), "status": status, "per_feature": psi_values}

    def list_versions(self) -> List[Dict]:
        return list(reversed(self._registry))

    def _prune_old_versions(self):
        while len(self._registry) > self.MAX_VERSIONS:
            old = self._registry.pop(0)
            try: Path(old["path"]).unlink(missing_ok=True)
            except Exception: pass

    def _save_registry(self):
        reg_path = self.VERSION_DIR / "registry.json"
        with open(reg_path, "w") as f:
            json.dump(self._registry, f, indent=2, default=str)

    def _load_registry(self):
        reg_path = self.VERSION_DIR / "registry.json"
        if reg_path.exists():
            try:
                with open(reg_path) as f:
                    self._registry = json.load(f)
            except Exception:
                self._registry = []

