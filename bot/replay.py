import threading
from .config import DEMO_PATH, FEATURES
from .features import load_dataset


class ReplayController:
    """Replay a fixed held-out sample in batches, without transmitting packets."""
    def __init__(self, detector, store):
        self.detector, self.store = detector, store
        self.frame = None
        self.session_id = None
        self.thread = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.lock = threading.Lock()
        self.cursor = 0
        self.rate = 50
        self.state = 'idle'

    def start(self, rate=50):
        rate = int(rate)
        if rate not in [10, 50, 100]:
            raise ValueError('Replay speed must be 10, 50, or 100 flows per second.')
        with self.lock:
            if self.thread and self.thread.is_alive():
                self.rate = rate
                self.pause_event.clear()
                self.state = 'running'
                self.store.set_status(self.session_id, 'running')
                return 'Dataset replay resumed.'
            if self.frame is None:
                self.frame, _ = load_dataset(DEMO_PATH)
            self.stop_event.clear()
            self.pause_event.clear()
            self.cursor = 0
            self.rate = rate
            self.session_id = self.store.create_session('dataset replay')
            self.state = 'running'
            self.thread = threading.Thread(target=self._run, daemon=True, name='dataset-replay')
            self.thread.start()
            return 'Dataset replay started. No network packets are transmitted.'

    def pause(self):
        with self.lock:
            if self.thread and self.thread.is_alive():
                self.pause_event.set()
                self.state = 'paused'
                self.store.set_status(self.session_id, 'paused')
                return 'Replay paused. Events remain saved.'
            return 'No replay is currently running.'

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
        with self.lock:
            if self.state in ['running', 'paused']:
                self.store.set_status(self.session_id, 'stopped')
            self.state = 'stopped'
        return 'Replay stopped. Start a new replay to create a separate session.'

    def _run(self):
        try:
            while self.cursor < len(self.frame) and not self.stop_event.is_set():
                with self.lock:
                    paused = self.pause_event.is_set()
                    if not paused:
                        end = min(self.cursor + self.rate, len(self.frame))
                        batch = self.frame.iloc[self.cursor:end]
                        records = [{'features': {name: float(row[name]) for name in FEATURES},
                                    'dataset_label': str(row['dataset_label'])} for _, row in batch.iterrows()]
                        self.store.add(self.session_id, self.detector.predict_records(records))
                        self.cursor = end
                if self.stop_event.wait(.1 if paused else 1):
                    break
            with self.lock:
                if self.cursor >= len(self.frame):
                    self.state = 'completed'
                    self.store.set_status(self.session_id, 'completed')
        except Exception as exc:
            with self.lock:
                self.state = 'error'
                self.store.set_status(self.session_id, 'error', str(exc))
