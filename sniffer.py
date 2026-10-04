"""Capture real traffic or read a PCAP, aggregate flows, and persist model predictions."""
import argparse
import logging
import time
from pathlib import Path
from scapy.all import AsyncSniffer, PcapReader, get_if_list
from bot.alerts import SlackNotifier
from bot.config import DB_PATH
from bot.flows import FlowAggregator
from bot.model import Detector
from bot.storage import EventStore


def run_capture(args):
    detector, store = Detector(), EventStore(args.database)
    notifier = SlackNotifier(enabled=args.slack)
    aggregator = FlowAggregator(idle_timeout=args.idle_timeout, max_duration=args.max_duration)
    mode = 'pcap file' if args.pcap else 'live capture'
    sid = store.create_session(mode)
    pending = []
    total = 0

    def persist(force=False):
        nonlocal total
        if not pending or (len(pending) < 100 and not force):
            return
        scored = detector.predict_records(pending)
        store.add(sid, scored)
        total += len(scored)
        flagged = sum(r['anomaly'] for r in scored)
        for record in scored:
            notifier.submit(record)
        print(f'Saved {len(scored)} flows; {flagged} flagged. Session total: {total}', flush=True)
        pending.clear()

    def packet_callback(packet):
        pending.extend(aggregator.feed(packet))
        persist()

    print(f'Started {mode}. Session {sid}. Dashboard: http://127.0.0.1:8050', flush=True)
    capture = None
    status = 'completed'
    try:
        if args.pcap:
            with PcapReader(str(args.pcap)) as reader:
                for packet in reader:
                    packet_callback(packet)
        else:
            # Capture for one second at a time: expiration and inference run on one thread.
            # Scapy's callback only collects a bounded batch; processing is sequential.
            from collections import deque
            packets = deque(maxlen=20000)
            dropped = 0
            def collect(packet):
                nonlocal dropped
                if len(packets) == packets.maxlen:
                    dropped += 1
                packets.append(packet)
            capture = AsyncSniffer(iface=args.interface, filter='ip and (tcp or udp)', prn=collect, store=False)
            capture.start()
            started = time.monotonic()
            while args.seconds is None or time.monotonic() - started < args.seconds:
                time.sleep(1)
                # Surface permission/driver errors raised by the background sniffer.
                if capture.exception is not None:
                    raise RuntimeError(f'Packet capture failed: {capture.exception}')
                while packets:
                    packet_callback(packets.popleft())
                pending.extend(aggregator.expire(time.time()))
                persist(force=True)
            capture.stop()
            capture = None
            while packets:
                packet_callback(packets.popleft())
            print(f'Capture queue drops: {dropped}', flush=True)
    except KeyboardInterrupt:
        status = 'stopped'
        print('Stopping capture and saving remaining flows...', flush=True)
    except Exception as exc:
        status = 'error'
        store.set_status(sid, 'error', str(exc))
        raise
    finally:
        if capture is not None:
            try:
                capture.stop()
            except Exception:
                pass
            # Include packets buffered before an interrupt.
            while packets:
                packet_callback(packets.popleft())
        pending.extend(aggregator.flush())
        persist(force=True)
        if status != 'error':
            store.set_status(sid, status)
        notifier.close()
        print(f'Finished. {total} flows; ignored packets: {aggregator.ignored_packets}; '
              f'out of order: {aggregator.out_of_order_packets}; capacity evictions: {aggregator.evicted_flows}', flush=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--pcap', type=Path, help='Read a local PCAP; no capture driver needed.')
    source.add_argument('--interface', help='Network interface name from --list-interfaces.')
    parser.add_argument('--list-interfaces', action='store_true')
    parser.add_argument('--seconds', type=float, help='Optional live-capture time limit.')
    parser.add_argument('--idle-timeout', type=float, default=30)
    parser.add_argument('--max-duration', type=float, default=120)
    parser.add_argument('--slack', action='store_true', help='Explicitly enable configured Slack delivery.')
    parser.add_argument('--database', type=Path, default=DB_PATH, help='Optional event database path.')
    args = parser.parse_args()
    if args.list_interfaces:
        print('\n'.join(get_if_list()))
    else:
        if args.seconds is not None and args.seconds <= 0:
            parser.error('--seconds must be positive.')
        if args.pcap and not args.pcap.is_file():
            parser.error('PCAP file does not exist.')
        try:
            run_capture(args)
        except Exception as exc:
            parser.exit(1, f'{exc}\nFor Windows live capture, install Npcap and run with capture permissions, or use dataset replay.\n')
