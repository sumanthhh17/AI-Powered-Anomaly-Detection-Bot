import gzip
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
import numpy as np
import pandas as pd
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, Padding, wrpcap
from bot.config import FEATURES, ROOT, MODEL_PATH, REPORT_PATH, DATA_DIR
from bot.features import validate_frame, load_dataset
from bot.flows import FlowAggregator
from bot.model import Detector
from bot.replay import ReplayController
from bot.storage import EventStore
from bot.alerts import SlackNotifier
from model_training import select_threshold, metrics, dataset_sha256
from dashboard import create_app


def packet(src='192.0.2.1', dst='192.0.2.2', sport=42000, dport=443, payload=20,
           timestamp=1700000000.0, flags='PA', udp=False):
    transport = UDP(sport=sport,dport=dport) if udp else TCP(sport=sport,dport=dport,flags=flags)
    p = Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src=src,dst=dst)/transport
    if payload:
        p = p/Raw(b'x'*payload)
    p = Ether(bytes(p))
    p.time = timestamp
    return p


class FlowTests(unittest.TestCase):
    def test_bidirectional_features_and_tcp_close(self):
        flow = FlowAggregator()
        t = 1700000000.0
        packets = [packet(payload=20,timestamp=t),
                   packet(src='192.0.2.2',dst='192.0.2.1',sport=443,dport=42000,payload=40,timestamp=t+.5),
                   packet(payload=60,timestamp=t+1,flags='FA'),
                   packet(src='192.0.2.2',dst='192.0.2.1',sport=443,dport=42000,payload=0,timestamp=t+1.5,flags='FA')]
        records=[]
        for p in packets:
            records.extend(flow.feed(p))
        self.assertEqual(len(records),1)
        self.assertEqual(records[0]['features'], dict(flow_duration_us=1500000,fwd_packets=2,bwd_packets=2,
            fwd_bytes=80,bwd_bytes=40,fwd_length_max=60,bwd_length_max=40,fwd_length_min=20,
            bwd_length_min=0,fwd_length_mean=40,bwd_length_mean=20))
        self.assertEqual(flow.flush(),[])

    def test_udp_expiry_and_zero_backward(self):
        flow=FlowAggregator(idle_timeout=2)
        p=packet(payload=8,udp=True)
        self.assertEqual(flow.feed(p),[])
        records=flow.expire(float(p.time)+2)
        f=records[0]['features']
        self.assertEqual(f['bwd_length_min'],0)
        self.assertEqual(f['bwd_length_mean'],0)
        self.assertEqual(f['fwd_bytes'],8)
        self.assertEqual(f['flow_duration_us'],0)
        self.assertEqual(records[0]['protocol'],'UDP')

    def test_padding_is_not_payload(self):
        p=packet(payload=0)/Padding(b'\x00'*20)
        flow=FlowAggregator()
        flow.feed(p)
        self.assertEqual(flow.flush()[0]['features']['fwd_bytes'],0)

    def test_fragment_and_ipv6_are_excluded(self):
        flow=FlowAggregator()
        p=packet(); p[IP].flags='MF'
        flow.feed(p)
        p6=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IPv6()/TCP(); p6.time=1700000000
        flow.feed(p6)
        self.assertEqual(flow.flush(),[])
        self.assertEqual(flow.ignored_packets,2)

    def test_duration_rollover_out_of_order_and_capacity(self):
        flow=FlowAggregator(max_duration=1,max_flows=1)
        p=packet(timestamp=1700000000)
        flow.feed(p)
        self.assertEqual(len(flow.feed(packet(timestamp=1700000001.1))),1)
        flow.feed(packet(timestamp=1700000000.9))
        self.assertEqual(flow.out_of_order_packets,1)
        self.assertEqual(len(flow.feed(packet(sport=42001,timestamp=1700000001.2))),1)
        self.assertEqual(flow.evicted_flows,1)


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector=Detector()

    def test_compressed_csv_preserves_cleaning_features_labels_and_hash(self):
        source = DATA_DIR / 'demo_flows.csv'
        scratch = ROOT / 'runtime' / 'tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            compressed = Path(folder) / 'flows.csv.gz'
            with gzip.open(compressed, 'wb') as stream:
                stream.write(source.read_bytes())
            plain_frame, plain_cleaning = load_dataset(source)
            zipped_frame, zipped_cleaning = load_dataset(compressed)
            pd.testing.assert_frame_equal(plain_frame, zipped_frame)
            self.assertEqual(plain_cleaning, zipped_cleaning)
            self.assertEqual(dataset_sha256(source), dataset_sha256(compressed))

    def test_reject_invalid_and_missing_features(self):
        for bad in [pd.DataFrame([{'packet_size':100}]),pd.DataFrame([{n:float('nan') for n in FEATURES}]),
                    pd.DataFrame([{n:-1 for n in FEATURES}])]:
            with self.assertRaises(ValueError):
                self.detector.score(bad)

    def test_feature_order_does_not_change_predictions(self):
        frame,_=load_dataset(DATA_DIR/'demo_flows.csv')
        scores,flags,_=self.detector.score(frame.iloc[:20])
        scores2,flags2,_=self.detector.score(frame.iloc[:20][list(reversed(FEATURES))])
        np.testing.assert_array_equal(scores,scores2)
        np.testing.assert_array_equal(flags,flags2)

    def test_packet_and_csv_inference_use_same_contract(self):
        flow=FlowAggregator()
        flow.feed(packet())
        records=flow.flush()
        prediction=self.detector.predict_records(records)[0]
        frame=pd.DataFrame([records[0]['features']])
        score,flag,_=self.detector.score(frame)
        self.assertEqual(prediction['score'],float(score[0]))
        self.assertEqual(prediction['anomaly'],bool(flag[0]))

    def test_saved_test_report_reproduces(self):
        frame,_=load_dataset(DATA_DIR/'test_flows.csv')
        scores,_,_=self.detector.score(frame)
        labels=(frame.dataset_label.str.upper()!='BENIGN').astype(int)
        result=metrics(labels,scores,self.detector.threshold)
        self.assertEqual(result['confusion_matrix'],self.detector.report['test']['confusion_matrix'])
        self.assertAlmostEqual(result['f1'],self.detector.report['test']['f1'])
        self.assertEqual(self.detector.report['split']['overlapping_feature_groups'],0)

    def test_threshold_validation_budget(self):
        labels=np.array([0,0,0,0,1,1,1,1])
        scores=np.array([.1,.2,.3,.4,.35,.5,.6,.7])
        threshold=select_threshold(labels,scores,max_fpr=.1)
        self.assertGreater(threshold,.4)
        self.assertEqual(sum((scores>=threshold)&(labels==0)),0)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / 'runtime' / 'tests'
        scratch.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=scratch)
        self.store=EventStore(Path(self.temp.name)/'events.sqlite3')
        self.detector=Detector()

    def tearDown(self):
        self.temp.cleanup()

    def test_persistence_and_session_isolation(self):
        frame,_=load_dataset(DATA_DIR/'demo_flows.csv')
        records=[{'features':row[FEATURES].to_dict(),'dataset_label':row.dataset_label} for _,row in frame.iloc[:10].iterrows()]
        first=self.store.create_session('dataset replay')
        self.store.add(first,self.detector.predict_records(records))
        second=self.store.create_session('pcap file')
        self.assertEqual(self.store.snapshot(second)['total'],0)
        self.assertEqual(self.store.snapshot(first)['total'],10)
        self.assertEqual(len(self.store.export(first)),10)
        self.assertEqual(EventStore(self.store.path).snapshot(first)['total'],10)

    def test_replay_start_pause_resume_stop(self):
        replay=ReplayController(self.detector,self.store)
        try:
            replay.start(100)
            deadline=time.monotonic()+4
            while replay.cursor==0 and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertGreater(replay.cursor,0)
            replay.pause()
            count=replay.cursor
            time.sleep(.2)
            self.assertEqual(replay.cursor,count)
            sid=replay.session_id
            replay.start(50)
            deadline=time.monotonic()+3
            while replay.cursor==count and time.monotonic()<deadline:
                time.sleep(.05)
            self.assertGreater(replay.cursor,count)
            self.assertEqual(replay.session_id,sid)
            replay.stop()
            self.assertEqual(self.store.snapshot(sid)['session']['status'],'stopped')
        finally:
            replay.stop()

    def test_dashboard_health_callbacks_and_export(self):
        app=create_app(self.detector,self.store)
        client=app.server.test_client()
        self.assertEqual(client.get('/').status_code,200)
        self.assertEqual(client.get('/health').json['feature_count'],11)
        self.assertEqual(client.get('/evaluation.json').json['test']['rows'],self.detector.report['test']['rows'])
        self.assertEqual(client.get('/_dash-layout').status_code,200)
        self.assertEqual(client.get('/_dash-dependencies').status_code,200)
        refresh_key=next(key for key in app.callback_map if 'total-flows' in key)
        outputs=[{'id':o.component_id,'property':o.component_property} for o in app.callback_map[refresh_key]['output']]
        response=client.post('/_dash-update-component',json={'output':refresh_key,'outputs':outputs,
            'inputs':[{'id':'refresh','property':'n_intervals','value':1},{'id':'session-picker','property':'value','value':'latest'}],
            'state':[],'changedPropIds':['refresh.n_intervals']})
        self.assertEqual(response.status_code,200,response.data)
        self.assertEqual(response.json['response']['total-flows']['children'],'0')
        # A real exported CSV must contain predictions and canonical measurements.
        flow=FlowAggregator(); flow.feed(packet())
        sid=self.store.create_session('pcap file')
        self.store.add(sid,self.detector.predict_records(flow.flush()))
        response=client.get('/export/latest.csv')
        self.assertEqual(response.status_code,200,response.data)
        self.assertIn('attachment',response.headers['Content-Disposition'])
        content=response.data.decode('utf-8')
        self.assertIn('flow_duration_us',content)
        self.assertIn('192.0.2.1',content)

    def test_slack_default_never_sends(self):
        notifier=SlackNotifier()
        notifier.submit({'anomaly':True})
        self.assertFalse(notifier.enabled)
        self.assertIsNone(notifier.client)
        self.assertIsNone(notifier.worker)

    def test_pcap_command_runs_end_to_end(self):
        capture_path=Path(self.temp.name)/'test.pcap'
        wrpcap(str(capture_path),[packet(),packet(flags='RA',timestamp=1700000000.1)])
        database_path=Path(self.temp.name)/'pcap.sqlite3'
        result=subprocess.run([sys.executable,str(ROOT/'sniffer.py'),'--pcap',str(capture_path),
                               '--database',str(database_path)],cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        snapshot=EventStore(database_path).snapshot()
        self.assertEqual(snapshot['total'],1)
        self.assertEqual(snapshot['session']['status'],'completed')
        self.assertEqual(snapshot['events'][0]['source_ip'],'192.0.2.1')


if __name__=='__main__':
    unittest.main(verbosity=2)
