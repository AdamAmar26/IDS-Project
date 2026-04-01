import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import numpy as np
from app.detection.model import AnomalyDetector


def _make_detector(n_samples=30):
    """Create and train a detector with synthetic baseline data."""
    det = AnomalyDetector.__new__(AnomalyDetector)
    det.model = None
    det.explainer = None
    det.is_trained = False
    det.training_data = []
    from app.config import FEATURE_NAMES
    det.feature_names = FEATURE_NAMES

    rng = np.random.RandomState(42)
    for _ in range(n_samples):
        sample = {name: float(rng.uniform(0, 5)) for name in FEATURE_NAMES}
        det.training_data.append(det._features_to_vector(sample))

    from sklearn.ensemble import IsolationForest
    X = np.array(det.training_data)
    det.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    det.model.fit(X)
    det.is_trained = True
    det._build_explainer()
    return det


def test_score_returns_top_features():
    det = _make_detector()
    features = {name: 0.0 for name in det.feature_names}
    features["failed_login_count"] = 100.0
    features["unique_dest_ports"] = 50.0

    score, is_anomaly, top = det.score(features)

    assert isinstance(score, float)
    assert isinstance(is_anomaly, bool)
    assert isinstance(top, dict)
    assert len(top) <= 5
    assert len(top) >= 1


def test_shap_values_are_signed():
    det = _make_detector()
    features = {name: 0.0 for name in det.feature_names}
    features["bytes_sent"] = 999999.0

    _, _, top = det.score(features)

    has_negative = any(v < 0 for v in top.values())
    has_positive = any(v > 0 for v in top.values())
    assert has_negative or has_positive, "SHAP values should have signed magnitudes"


def test_untrained_detector_returns_zero():
    det = AnomalyDetector.__new__(AnomalyDetector)
    det.model = None
    det.explainer = None
    det.is_trained = False
    det.training_data = []
    from app.config import FEATURE_NAMES
    det.feature_names = FEATURE_NAMES

    score, is_anomaly, top = det.score({"failed_login_count": 10})
    assert score == 0.0
    assert is_anomaly is False
    assert top == {}


def test_zscore_fallback():
    det = _make_detector()
    det.explainer = None

    features = {name: 0.0 for name in det.feature_names}
    features["failed_login_count"] = 100.0

    top = det._zscore_top_features(
        np.array([det._features_to_vector(features)])
    )
    assert len(top) <= 5
    assert all(v >= 0 for v in top.values()), "Z-score values should be non-negative"
