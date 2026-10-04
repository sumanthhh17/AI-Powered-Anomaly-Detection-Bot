"""A bounded bidirectional IPv4 TCP/UDP flow aggregator, shared by PCAP and live capture."""
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from scapy.layers.inet import IP, TCP, UDP


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    first: float
    last: float
    fwd_count: int = 0
    bwd_count: int = 0
    fwd_total: int = 0
    bwd_total: int = 0
    fwd_min: int | None = None
    bwd_min: int | None = None
    fwd_max: int = 0
    bwd_max: int = 0
    fin_directions: set = field(default_factory=set)

    def add(self, forward, payload_len, timestamp, fin=False):
        prefix = 'fwd' if forward else 'bwd'
        setattr(self, prefix + '_count', getattr(self, prefix + '_count') + 1)
        setattr(self, prefix + '_total', getattr(self, prefix + '_total') + payload_len)
        low = getattr(self, prefix + '_min')
        setattr(self, prefix + '_min', payload_len if low is None else min(low, payload_len))
        setattr(self, prefix + '_max', max(getattr(self, prefix + '_max'), payload_len))
        self.last = max(self.last, timestamp)
        if fin:
            self.fin_directions.add(forward)

    def record(self):
        return dict(source_ip=self.src, destination_ip=self.dst, source_port=self.sport,
                    destination_port=self.dport, protocol=self.protocol,
                    flow_started_at=datetime.fromtimestamp(self.first, timezone.utc).isoformat(),
                    features=dict(flow_duration_us=round(max(self.last - self.first, 0) * 1_000_000),
                                  fwd_packets=self.fwd_count, bwd_packets=self.bwd_count,
                                  fwd_bytes=self.fwd_total, bwd_bytes=self.bwd_total,
                                  fwd_length_max=self.fwd_max, bwd_length_max=self.bwd_max,
                                  fwd_length_min=self.fwd_min or 0, bwd_length_min=self.bwd_min or 0,
                                  fwd_length_mean=self.fwd_total / max(self.fwd_count, 1),
                                  bwd_length_mean=self.bwd_total / max(self.bwd_count, 1)))


class FlowAggregator:
    def __init__(self, idle_timeout=30.0, max_duration=120.0, max_flows=50000):
        if min(idle_timeout, max_duration, max_flows) <= 0:
            raise ValueError('Flow limits must be positive.')
        self.idle_timeout, self.max_duration, self.max_flows = idle_timeout, max_duration, max_flows
        self.flows = OrderedDict()
        self.last_sweep = 0.0
        self.ignored_packets = 0
        self.out_of_order_packets = 0
        self.evicted_flows = 0

    def expire(self, timestamp):
        expired = [key for key, flow in self.flows.items()
                   if timestamp - flow.last >= self.idle_timeout or timestamp - flow.first >= self.max_duration]
        return [self.flows.pop(key).record() for key in expired]

    def feed(self, packet):
        timestamp = float(packet.time)
        completed = []
        if timestamp - self.last_sweep >= 1:
            completed.extend(self.expire(timestamp))
            self.last_sweep = timestamp
        if IP not in packet:
            self.ignored_packets += 1
            return completed
        ip = packet[IP]
        # Fragment reassembly is not implemented. Exclude fragments consistently.
        if ip.frag != 0 or int(ip.flags) & 1 or not isinstance(ip.payload, (TCP, UDP)):
            self.ignored_packets += 1
            return completed
        transport = ip.payload
        proto = 'TCP' if isinstance(transport, TCP) else 'UDP'
        left, right = (ip.src, int(transport.sport)), (ip.dst, int(transport.dport))
        key = (proto, *sorted([left, right]))
        existing = self.flows.get(key)
        if existing and timestamp < existing.last:
            self.out_of_order_packets += 1
            return completed
        if existing and (timestamp - existing.last >= self.idle_timeout or timestamp - existing.first >= self.max_duration):
            completed.append(self.flows.pop(key).record())
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                _, oldest = self.flows.popitem(last=False)
                completed.append(oldest.record())
                self.evicted_flows += 1
            self.flows[key] = Flow(ip.src, ip.dst, int(transport.sport), int(transport.dport), proto, timestamp, timestamp)
        flow = self.flows[key]
        forward = left == (flow.src, flow.sport)
        # Use transport payload, excluding IP/TCP/UDP headers and Ethernet padding.
        if ip.len is None or ip.ihl is None or (proto == 'TCP' and transport.dataofs is None):
            ip = IP(bytes(ip))
            transport = ip.payload
        header_len = int(transport.dataofs) * 4 if proto == 'TCP' else 8
        declared_payload = max(int(ip.len) - int(ip.ihl) * 4 - header_len, 0)
        if proto == 'UDP' and transport.len is not None:
            declared_payload = min(declared_payload, max(int(transport.len) - 8, 0))
        payload_len = min(declared_payload, len(bytes(transport.payload)))
        flags = int(transport.flags) if proto == 'TCP' else 0
        flow.add(forward, payload_len, timestamp, fin=bool(flags & 1))
        self.flows.move_to_end(key)
        if flags & 4 or len(flow.fin_directions) == 2:
            completed.append(self.flows.pop(key).record())
        return completed

    def flush(self):
        result = [flow.record() for flow in self.flows.values()]
        self.flows.clear()
        return result
