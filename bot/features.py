import numpy as np
import pandas as pd
from .config import FEATURES, FEATURE_COLUMNS


def validate_frame(frame):
    """Reject missing/invalid features rather than silently guessing their values."""
    missing = [name for name in FEATURES if name not in frame.columns]
    if missing:
        raise ValueError('Missing flow features: ' + ', '.join(missing))
    result = frame[FEATURES].apply(pd.to_numeric, errors='raise').astype(float)
    if not np.isfinite(result.to_numpy()).all() or (result < 0).any().any():
        raise ValueError('Flow features must be finite, non-negative numbers.')
    if (result['fwd_packets'] < 1).any():
        raise ValueError('A flow must contain at least one forward packet.')
    for name in ['fwd_packets', 'bwd_packets']:
        if (result[name] != np.floor(result[name])).any():
            raise ValueError('Packet counts must be integers.')
    return result


def load_dataset(path):
    """Read a plain/gzipped CICIDS CSV or an already normalized flow CSV."""
    raw = pd.read_csv(path)
    raw.columns = raw.columns.str.strip()
    raw = raw.rename(columns={v: k for k, v in FEATURE_COLUMNS.items()})
    missing = [name for name in FEATURES if name not in raw.columns]
    if missing:
        raise ValueError('Dataset is missing columns: ' + ', '.join(missing))
    values = raw[FEATURES].apply(pd.to_numeric, errors='coerce')
    valid = np.isfinite(values.to_numpy()).all(axis=1) & (values >= 0).all(axis=1)
    valid &= values['fwd_packets'] >= 1
    for name in ['fwd_packets', 'bwd_packets']:
        valid &= values[name] == np.floor(values[name])
    label_col = next((n for n in ['dataset_label', 'Label'] if n in raw), None)
    if label_col is None:
        raise ValueError('Training/replay CSV requires a Label or dataset_label column.')
    labels = raw[label_col].astype('string').str.strip()
    valid &= labels.notna() & labels.ne('')
    frame = values.loc[valid].reset_index(drop=True)
    frame['dataset_label'] = labels.loc[valid].to_numpy()
    return frame, {'input_rows': len(raw), 'valid_rows': len(frame),
                   'dropped_rows': int((~valid).sum())}
