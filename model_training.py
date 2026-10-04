"""Train only on benign flows; select a threshold on validation; report untouched test results."""
import argparse
import gzip
import hashlib
import json
import platform
from pathlib import Path
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, roc_auc_score, precision_recall_curve)
from bot.config import (ROOT, DATA_DIR, ARTIFACT_DIR, FEATURES, FEATURE_SCHEMA_VERSION,
                        MODEL_PATH, REPORT_PATH, DEMO_PATH)
from bot.features import load_dataset, validate_frame


def select_threshold(labels, scores, max_fpr=.05):
    """Optimize validation F1 subject to a validation false-positive budget."""
    labels = np.asarray(labels)
    if len(np.unique(labels)) != 2:
        raise ValueError('Validation data must include normal and attack flows.')
    p, r, thresholds = precision_recall_curve(labels, scores)
    f1 = 2 * p[:-1] * r[:-1] / np.maximum(p[:-1] + r[:-1], 1e-12)
    # TP = recall * positives; FP = TP * (1 / precision - 1).
    fp = r[:-1] * (labels == 1).sum() * (1 / np.maximum(p[:-1], 1e-12) - 1)
    fpr = fp / (labels == 0).sum()
    f1[fpr > max_fpr + 1e-12] = -1
    if np.max(f1) < 0:
        return float(np.nextafter(np.max(scores), np.inf))
    return float(thresholds[int(np.argmax(f1))])


def metrics(labels, scores, threshold):
    pred = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, pred, labels=[0, 1]).ravel()
    return dict(rows=len(labels), normal=int((labels == 0).sum()), attack=int((labels == 1).sum()),
                accuracy=float(accuracy_score(labels, pred)), precision=float(precision_score(labels, pred, zero_division=0)),
                recall=float(recall_score(labels, pred, zero_division=0)), f1=float(f1_score(labels, pred, zero_division=0)),
                roc_auc=float(roc_auc_score(labels, scores)), false_positive_rate=float(fp / max(tn + fp, 1)),
                confusion_matrix={'true_normal': int(tn), 'false_alert': int(fp),
                                  'missed_attack': int(fn), 'detected_attack': int(tp)})


def dataset_sha256(csv_path):
    """Identify CSV contents consistently whether the input is compressed or plain."""
    sha = hashlib.sha256()
    opener = gzip.open if csv_path.suffix.lower() == '.gz' else open
    with opener(csv_path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def train(csv_path, max_fpr=.05):
    if not 0 < max_fpr < 1:
        raise ValueError('max-fpr must be between 0 and 1.')
    ARTIFACT_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    frame, cleaning = load_dataset(csv_path)
    X = validate_frame(frame)
    y = (frame.dataset_label.str.upper() != 'BENIGN').astype(int)
    if y.value_counts().min() < 100 or len(y.unique()) != 2:
        raise ValueError('At least 100 benign and 100 attack examples are required.')
    # Identical feature vectors stay together: duplicates cannot leak across splits.
    groups = pd.util.hash_pandas_object(X, index=False).to_numpy()
    train_ids, rest = next(GroupShuffleSplit(n_splits=1, train_size=.6, random_state=42).split(X, y, groups))
    v, t = next(GroupShuffleSplit(n_splits=1, train_size=.5, random_state=43).split(X.iloc[rest], y.iloc[rest], groups[rest]))
    val_ids, test_ids = rest[v], rest[t]
    benign_ids = train_ids[y.iloc[train_ids].to_numpy() == 0]
    assert not set(groups[train_ids]) & set(groups[val_ids])
    assert not set(groups[train_ids]) & set(groups[test_ids])
    assert not set(groups[val_ids]) & set(groups[test_ids])
    print(f'Training Isolation Forest on {len(benign_ids):,} benign flows...', flush=True)
    model = IsolationForest(n_estimators=250, max_samples=1024, contamination='auto',
                            random_state=42, n_jobs=-1)
    model.fit(np.log1p(X.iloc[benign_ids]))
    val_scores = -model.score_samples(np.log1p(X.iloc[val_ids]))
    threshold = select_threshold(y.iloc[val_ids], val_scores, max_fpr)
    # Test labels never influence training or threshold selection.
    test_scores = -model.score_samples(np.log1p(X.iloc[test_ids]))
    reference = {name: {'p01': float(X.iloc[benign_ids][name].quantile(.01)),
                        'p50': float(X.iloc[benign_ids][name].median()),
                        'p99': float(X.iloc[benign_ids][name].quantile(.99))} for name in FEATURES}
    bundle = dict(model=model, threshold=threshold, reference=reference, features=FEATURES,
                  feature_schema_version=FEATURE_SCHEMA_VERSION, sklearn_version=sklearn.__version__)
    joblib.dump(bundle, MODEL_PATH)
    test = frame.iloc[test_ids].copy()
    test.to_csv(DATA_DIR / 'test_flows.csv', index=False)
    # The demo is a shuffled subset of the held-out partition, not invented traffic.
    demo = test.sample(n=min(5000, len(test)), random_state=2026).reset_index(drop=True)
    demo.to_csv(DEMO_PATH, index=False)
    # Preserve hashes to make the evaluation reproducible and its input traceable.
    report = dict(created_at=datetime.now(timezone.utc).isoformat(), dataset_file=csv_path.name,
                  dataset_sha256=dataset_sha256(csv_path), cleaning=cleaning, labels=frame.dataset_label.value_counts().to_dict(),
                  features=FEATURES, feature_schema_version=FEATURE_SCHEMA_VERSION,
                  algorithm='Isolation Forest', transform='log1p of each feature',
                  parameters={'n_estimators': 250, 'max_samples': 1024, 'random_state': 42},
                  split={'method': 'GroupShuffleSplit by identical feature vector', 'random_states': [42, 43],
                         'train_rows': len(train_ids), 'benign_training_rows': len(benign_ids),
                         'excluded_attack_training_rows': int(y.iloc[train_ids].sum()),
                         'validation_rows': len(val_ids), 'test_rows': len(test_ids), 'overlapping_feature_groups': 0},
                  threshold=threshold, threshold_selection=f'Max validation F1 with validation FPR <= {max_fpr:.1%}',
                  validation=metrics(y.iloc[val_ids], val_scores, threshold),
                  test=metrics(y.iloc[test_ids], test_scores, threshold),
                  versions={'python': platform.python_version(), 'scikit-learn': sklearn.__version__,
                            'pandas': pd.__version__, 'numpy': np.__version__},
                  limitations=['Evaluation covers this CICIDS2017 Friday DDoS file only.',
                               'Random group split from one day is not an independent network or chronological test.',
                               'Threshold calibration uses labeled validation examples; the forest itself uses only benign examples.',
                               'Live segmentation approximates CICFlowMeter; accuracy on this machine\'s live traffic is unmeasured.',
                               'An anomaly score is not an attack probability.'])
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report['test'], indent=2), flush=True)
    print(f'Saved model, report, held-out flows, and 5,000-flow demonstration in {ROOT}', flush=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, default=DATA_DIR / 'network_traffic.csv.gz')
    parser.add_argument('--max-fpr', type=float, default=.05)
    args = parser.parse_args()
    try:
        train(args.csv, args.max_fpr)
    except (ValueError, FileNotFoundError) as exc:
        parser.exit(1, f'Training failed: {exc}\n')
