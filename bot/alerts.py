"""Optional Slack delivery. Local detection remains independent of delivery failures."""
import logging
import os
import queue
import threading
import time
from dotenv import load_dotenv
from .config import ROOT

LOG = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self, enabled=False, cooldown=60):
        self.enabled = enabled
        self.cooldown = cooldown
        self.client = None
        self.channel = None
        self.sent = 0
        self.failed = 0
        self.suppressed = 0
        self.last_sent = {}
        self.queue = queue.Queue(maxsize=200)
        self.worker = None
        if enabled:
            load_dotenv(ROOT / '.env')
            token, self.channel = os.getenv('SLACK_TOKEN'), os.getenv('SLACK_CHANNEL')
            if not token or not self.channel:
                raise ValueError('--slack requires SLACK_TOKEN and SLACK_CHANNEL in .env.')
            from slack_sdk import WebClient
            self.client = WebClient(token=token, timeout=5)
            self.worker = threading.Thread(target=self._run, daemon=True, name='slack-alerts')
            self.worker.start()

    def submit(self, record):
        if not self.enabled or not record['anomaly']:
            return
        key = (record.get('source_ip'), record.get('destination_ip'), record.get('destination_port'))
        now = time.monotonic()
        if now - self.last_sent.get(key, float('-inf')) < self.cooldown:
            self.suppressed += 1
            return
        if len(self.last_sent) > 10000:
            self.last_sent = {k: t for k, t in self.last_sent.items() if now - t < self.cooldown}
        self.last_sent[key] = now
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.suppressed += 1

    def _run(self):
        while True:
            record = self.queue.get()
            try:
                if record is None:
                    return
                self.client.chat_postMessage(
                    channel=self.channel,
                    text=(f"Network anomaly flagged: {record.get('source_ip', 'unknown')} → "
                          f"{record.get('destination_ip', 'unknown')}:{record.get('destination_port', '?')}\n"
                          f"Score: {record['score']:.4f}. {record['reason']}\n"
                          'Investigate this flow; an anomaly alone does not confirm an attack.'))
                self.sent += 1
            except Exception as exc:
                # Avoid printing credentials, request bodies, or an SDK exception's response.
                self.failed += 1
                LOG.warning('Slack delivery failed (%s); local events remain saved.', type(exc).__name__)
            finally:
                self.queue.task_done()

    def close(self):
        if self.worker:
            try:
                self.queue.put(None, timeout=1)
                self.worker.join(timeout=6)
            except queue.Full:
                LOG.warning('Slack queue still busy at shutdown.')
