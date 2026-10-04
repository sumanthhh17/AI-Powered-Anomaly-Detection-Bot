from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / 'data'
ARTIFACT_DIR = ROOT / 'artifacts'
RUNTIME_DIR = ROOT / 'runtime'
MODEL_PATH = ARTIFACT_DIR / 'anomaly_model.joblib'
REPORT_PATH = ARTIFACT_DIR / 'evaluation.json'
DEMO_PATH = DATA_DIR / 'demo_flows.csv'
DB_PATH = RUNTIME_DIR / 'events.sqlite3'

# The single feature contract used by the CSV reader, model, and packet aggregator.
# CICFlowMeter durations are microseconds; packet lengths are transport payload bytes.
FEATURE_COLUMNS = {
    'flow_duration_us': 'Flow Duration',
    'fwd_packets': 'Total Fwd Packets',
    'bwd_packets': 'Total Backward Packets',
    'fwd_bytes': 'Total Length of Fwd Packets',
    'bwd_bytes': 'Total Length of Bwd Packets',
    'fwd_length_max': 'Fwd Packet Length Max',
    'bwd_length_max': 'Bwd Packet Length Max',
    'fwd_length_min': 'Fwd Packet Length Min',
    'bwd_length_min': 'Bwd Packet Length Min',
    'fwd_length_mean': 'Fwd Packet Length Mean',
    'bwd_length_mean': 'Bwd Packet Length Mean',
}
FEATURES = list(FEATURE_COLUMNS)
FEATURE_SCHEMA_VERSION = 1
