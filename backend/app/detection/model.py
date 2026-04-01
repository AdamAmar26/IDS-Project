import os
import logging
import pickle
from typing import Dict, List, Tuple, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import FEATURE_NAMES, MODEL_PATH, MIN_TRAINING_SAMPLES, CONTAMINATION

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest anomaly detector that trains on baseline windows."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False
        self.training_data: List[List[float]] = []
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _features_to_vector(self, features: Dict[str, float]) -> List[float]:
        return [float(features.get(name, 0)) for name in self.feature_names]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as fh:
                    data = pickle.load(fh)
                self.model = data["model"]
                self.training_data = data.get("training_data", [])
                self.is_trained = True
                logger.info("Loaded trained model with %d samples", len(self.training_data))
            except Exception as exc:
                logger.warning("Could not load model: %s", exc)

    def _save_model(self):
        os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
        with open(MODEL_PATH, "wb") as fh:
            pickle.dump({"model": self.model, "training_data": self.training_data}, fh)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def add_training_sample(self, features: Dict[str, float]) -> bool:
        """Append a sample; auto-train once MIN_TRAINING_SAMPLES is reached."""
        self.training_data.append(self._features_to_vector(features))
        if len(self.training_data) >= MIN_TRAINING_SAMPLES and not self.is_trained:
            return self.train()
        return False

    def train(self, force: bool = False) -> bool:
        if not force and len(self.training_data) < MIN_TRAINING_SAMPLES:
            return False
        if len(self.training_data) < 2:
            return False
        X = np.array(self.training_data)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self.model.fit(X)
        self.is_trained = True
        self._save_model()
        logger.info("Model trained on %d samples", len(self.training_data))
        return True

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, features: Dict[str, float]) -> Tuple[float, bool, Dict[str, float]]:
        """Return (anomaly_score, is_anomaly, top_deviating_features)."""
        if not self.is_trained or self.model is None:
            return 0.0, False, {}

        vector = np.array([self._features_to_vector(features)])
        raw_score = float(self.model.decision_function(vector)[0])
        anomaly_score = -raw_score
        is_anomaly = int(self.model.predict(vector)[0]) == -1

        mean_vec = np.mean(self.training_data, axis=0)
        std_vec = np.std(self.training_data, axis=0) + 1e-10
        fv = self._features_to_vector(features)
        deviations = {
            name: round(abs(fv[i] - mean_vec[i]) / std_vec[i], 3)
            for i, name in enumerate(self.feature_names)
        }
        top = dict(sorted(deviations.items(), key=lambda x: x[1], reverse=True)[:5])

        return round(anomaly_score, 4), is_anomaly, top

    def retrain(self, data: List[List[float]]) -> bool:
        """Retrain on a fresh dataset (e.g. recent non-anomalous windows)."""
        if len(data) < 2:
            return False
        self.training_data = list(data)
        X = np.array(data)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self.model.fit(X)
        self.is_trained = True
        self._save_model()
        logger.info("Model retrained on %d samples", len(data))
        return True
