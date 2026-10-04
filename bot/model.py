import json
import time
import joblib
import numpy as np
import pandas as pd
import sklearn
from .config import FEATURES, FEATURE_SCHEMA_VERSION, MODEL_PATH, REPORT_PATH
from .features import validate_frame


class Detector:
    def __init__(self, model_path=MODEL_PATH, report_path=REPORT_PATH):
        if not model_path.exists():
            raise FileNotFoundError('Model not found. Run python model_training.py first.')
        bundle = joblib.load(model_path)
        if bundle.get('feature_schema_version') != FEATURE_SCHEMA_VERSION or bundle.get('features') != FEATURES:
            raise ValueError('Model feature schema differs from this code. Retrain the model.')
        if bundle.get('sklearn_version') != sklearn.__version__:
            raise ValueError('scikit-learn version differs from the saved model. Install the pinned requirements or retrain.')
        self.model = bundle['model']
        self.threshold = float(bundle['threshold'])
        self.reference = bundle['reference']
        self.report = json.loads(report_path.read_text(encoding='utf-8'))

    def score(self, frame):
        values = validate_frame(frame)
        start = time.perf_counter()
        # The same log1p transformation is used in training and every inference path.
        scores = -self.model.score_samples(np.log1p(values))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return scores, scores >= self.threshold, elapsed_ms

    def explain(self, features):
        """Baseline comparisons are context, not causal explanations of the forest."""
        unusual = []
        for name in FEATURES:
            value = float(features[name])
            ref = self.reference[name]
            if value > ref['p99']:
                unusual.append((value / max(ref['p99'], 1), f'{name.replace("_", " ")} above the normal training 99th percentile'))
            elif value < ref['p01']:
                unusual.append((ref['p01'] / max(value, 1), f'{name.replace("_", " ")} below the normal training 1st percentile'))
        unusual.sort(reverse=True)
        if unusual:
            return '; '.join(item[1] for item in unusual[:2])
        return 'The combination of flow measurements falls outside the learned baseline.'

    def predict_records(self, records):
        if not records:
            return []
        frame = pd.DataFrame([record['features'] for record in records])
        scores, anomalies, elapsed_ms = self.score(frame)
        results = []
        for record, score, anomaly in zip(records, scores, anomalies):
            result = dict(record)
            result.update(score=float(score), anomaly=bool(anomaly),
                          reason=self.explain(record['features']) if anomaly else 'Within the learned baseline',
                          inference_ms=elapsed_ms / len(records))
            results.append(result)
        return results
