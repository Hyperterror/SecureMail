"""
ML anomaly detection engine using Isolation Forest.

Answers the question: "Is this TLS session behaving unusually compared
with the other TLS sessions in this capture?"

This is NOT a classifier that claims to detect attacks.
It surfaces statistical outliers for analyst review.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """Isolation Forest–based anomaly detector for TLS session features."""

    MIN_SESSIONS = 5  # Minimum sessions needed for meaningful ML results

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: str | float = "auto",
        random_state: int = 42,
    ):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit_and_predict(self, features: np.ndarray) -> np.ndarray:
        """
        Fit the model on this capture's sessions and return anomaly scores.

        Args:
            features: 2D array of shape (n_sessions, n_features).

        Returns:
            1D array of anomaly scores in [0.0, 1.0] where
            1.0 = most anomalous, 0.0 = most normal.

        If fewer than MIN_SESSIONS are provided, returns 0.5 (neutral)
        for all sessions since the model cannot learn meaningful patterns.
        """
        n_samples = features.shape[0]

        if n_samples < self.MIN_SESSIONS:
            return np.full(n_samples, 0.5)

        # Scale features so Isolation Forest treats them equally
        scaled = self.scaler.fit_transform(features)

        # Fit and compute decision function
        self.model.fit(scaled)
        self._fitted = True

        # decision_function: positive = normal, negative = anomalous
        raw_scores = self.model.decision_function(scaled)

        # Normalize to [0, 1] where 1 = most anomalous
        score_range = raw_scores.max() - raw_scores.min()
        if score_range < 1e-8:
            # All sessions are identical — none are anomalous
            return np.full(n_samples, 0.1)

        normalized = 1.0 - (raw_scores - raw_scores.min()) / score_range

        return normalized

    @property
    def is_fitted(self) -> bool:
        return self._fitted
