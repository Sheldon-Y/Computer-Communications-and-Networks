#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP Analyzer - pure standard library, parses pcap (Ethernet/IPv4/TCP)
Outputs per-connection details and aggregate statistics following the provided format.

Now supports multiple connection *episodes* for the same 4-tuple:
if a new SYN (without ACK) arrives after a prior episode has FIN/RSTed,
a *new* connection object is created (matching tshark's tcp.stream behavior more closely).
"""

import sys
import struct
import socket

PCAP_MAGIC_USEC_BE = 0xa1b2c3d4
PCAP_MAGIC_USEC_LE = 0xd4c3b2a1
PCAP_MAGIC_NSEC_BE = 0xa1b23c4d
PCAP_MAGIC_NSEC_LE = 0x4d3cb2a1

ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_IP = 0x0800
ETH_HDR_LEN = 14

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_ACK = 0x10

def seq_diff(a, b):
    return ((a - b + (1 << 32)) % (1 << 32))

def seq_ge(a, b):
    return seq_diff(a, b) < (1 << 31)

class PcapReader:
    def __init__(self, f):
        self.f = f
        self.endian = '>'
        self.ts_resolution = 1e-6
        self._read_global_header()

    def _read_exact(self, n):
        b = self.f.read(n)
        if len(b) != n:
            return None
        return b

    def _read_global_header(self):
        gh = self._read_exact(24)
        if gh is None or len(gh) < 24:
            raise ValueError("Invalid pcap global header")
        magic = struct.unpack(">I", gh[:4])[0]
        if magic == PCAP_MAGIC_USEC_BE:
            self.endian = '>'
            self.ts_resolution = 1e-6
        elif magic == PCAP_MAGIC_USEC_LE:
            self.endian = '<'
            self.ts_resolution = 1e-6
        elif magic == PCAP_MAGIC_NSEC_BE:
            self.endian = '>'
            self.ts_resolution = 1e-9
        elif magic == PCAP_MAGIC_NSEC_LE:
            self.endian = '<'
            self.ts_resolution = 1e-9
        else:
            magic_le = struct.unpack("<I", gh[:4])[0]
            if magic_le in (PCAP_MAGIC_USEC_LE, PCAP_MAGIC_NSEC_LE):
                self.endian = '<'
                self.ts_resolution = 1e-6 if magic_le == PCAP_MAGIC_USEC_LE else 1e-9
            else:
                raise ValueError("Unrecognized pcap magic number: 0x%08x" % magic)

    def __iter__(self):
        return self

    def __next__(self):
        ph = self._read_exact(16)
        if ph is None:
            raise StopIteration
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(self.endian + "IIII", ph)
        data = self._read_exact(incl_len)
        if data is None:
            raise StopIteration
        ts = ts_sec + ts_sub * self.ts_resolution
        return ts, data, incl_len, orig_len

def parse_ethernet(frame):
    if len(frame) < ETH_HDR_LEN:
        return None, None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = ETH_HDR_LEN
    for _ in range(2):
        if ethertype in (ETH_P_8021Q, ETH_P_8021AD):
            if len(frame) < offset + 4:
                return None, None
            ethertype = struct.unpack("!H", frame[offset+2:offset+4])[0]
            offset += 4
        else:
            break
    return ethertype, offset

def parse_ipv4(packet, offset):
    if len(packet) < offset + 20:
        return None
    vihl = packet[offset]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None
    total_length = struct.unpack("!H", packet[offset+2:offset+4])[0]
    proto = packet[offset+9]
    src = socket.inet_ntoa(packet[offset+12:offset+16])
    dst = socket.inet_ntoa(packet[offset+16:offset+20])
    if len(packet) < offset + total_length:
        end = len(packet)
    else:
        end = offset + total_length
    return {
        "ihl": ihl,
        "proto": proto,
        "src": src,
        "dst": dst,
        "payload_offset": offset + ihl,
        "end_offset": end,
        "total_length": total_length,
    }

def parse_tcp(segment, offset, end_offset):
    if end_offset - offset < 20:
        return None
    tcph = segment[offset:offset+20]
    src_port, dst_port, seq, ack, data_offset_reserved_flags, window, checksum, urgptr = struct.unpack("!HHIIHHHH", tcph)
    data_offset = (data_offset_reserved_flags >> 12) & 0xF
    header_len = data_offset * 4
    flags = data_offset_reserved_flags & 0x01FF
    if end_offset - offset < header_len:
        return None
    options = segment[offset+20: offset+header_len]
    payload_offset = offset + header_len
    payload_len = max(0, end_offset - payload_offset)
    win_scale = None
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        l = options[i+1]
        if l < 2 or i + l > len(options):
            break
        if kind == 3 and l == 3:
            win_scale = options[i+2]
        i += l

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "window": window,
        "win_scale": win_scale,
        "payload_len": payload_len,
    }

class EndpointState:
    __slots__ = ("seen_syn", "seen_fin", "seen_rst", "pkt_count", "data_bytes", "win_scale", "win_samples")
    def __init__(self):
        self.seen_syn = False
        self.seen_fin = False
        self.seen_rst = False
        self.pkt_count = 0
        self.data_bytes = 0
        self.win_scale = 0
        self.win_samples = []

class DirectionRTT:
    def __init__(self):
        self.pending = {}  # end_seq -> first-send time
        self.sent_seq_starts = set()  # (seq_start, end_seq)

    def on_send_data(self, seq, length, t):
        if length <= 0:
            return
        end_seq = (seq + length) % (1 << 32)
        key = (seq, end_seq)
        if key in self.sent_seq_starts:
            return
        self.sent_seq_starts.add(key)
        if end_seq not in self.pending:
            self.pending[end_seq] = t

    def on_ack(self, ack_num, t):
        rtts = []
        to_delete = []
        for end_seq, send_time in list(self.pending.items()):
            if seq_ge(ack_num, end_seq):
                rtts.append(t - send_time)
                to_delete.append(end_seq)
        for end_seq in to_delete:
            self.pending.pop(end_seq, None)
        return rtts

class Connection:
    __slots__ = (
        "src", "sport", "dst", "dport",
        "a", "b",
        "first_ts", "last_ts",
        "pre_established",
        "data_after_fin",
        "first_fin_ts",
        "has_rst",
        "rtt_a", "rtt_b",
        "rtt_samples",
    )
    def __init__(self, src, sport, dst, dport, ts, first_pkt_is_syn):
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.a = EndpointState()
        self.b = EndpointState()
        self.first_ts = ts
        self.last_ts = ts
        self.pre_established = not first_pkt_is_syn
        self.data_after_fin = False
        self.first_fin_ts = None
        self.has_rst = False
        self.rtt_a = DirectionRTT()
        self.rtt_b = DirectionRTT()
        self.rtt_samples = []

    def status_str(self):
        if self.has_rst:
            return "R"
        s = int(self.a.seen_syn) + int(self.b.seen_syn)
        f = int(self.a.seen_fin) + int(self.b.seen_fin)
        return f"S{s}F{f}"

    def is_complete(self):
        s = int(self.a.seen_syn) + int(self.b.seen_syn)
        f = int(self.a.seen_fin) + int(self.b.seen_fin)
        return s >= 1 and f >= 1

    def mark_payload_after_fin(self):
        self.data_after_fin = True

    def mark_rst(self):
        self.has_rst = True
        self.a.seen_rst = True
        self.b.seen_rst = True

def analyze_pcap(filename):
    # Multiple episodes per 4-tuple:
    # - connections: dict[(src,sport,dst,dport,episode_idx)] -> Connection
    # - last_active: dict[(src,sport,dst,dport)] -> composite key of the latest episode
    # - counters: dict[(src,sport,dst,dport)] -> last episode index (int)
    connections = {}
    order_keys = []
    last_active = {}
    counters = {}

    def new_conn_key(base):
        idx = counters.get(base, 0) + 1
        counters[base] = idx
        return base + (idx,)

    with open(filename, "rb") as f:
        reader = PcapReader(f)
        for ts, frame, incl_len, orig_len in reader:
            ethertype, off = parse_ethernet(frame)
            if ethertype != ETH_P_IP or off is None:
                continue
            ip = parse_ipv4(frame, off)
            if not ip or ip["proto"] != 6:
                continue
            tcp = parse_tcp(frame, ip["payload_offset"], ip["end_offset"])
            if not tcp:
                continue

            src, dst = ip["src"], ip["dst"]
            sport, dport = tcp["src_port"], tcp["dst_port"]
            flags = tcp["flags"]
            syn = bool(flags & TCP_FLAG_SYN)
            fin = bool(flags & TCP_FLAG_FIN)
            rst = bool(flags & TCP_FLAG_RST)
            ackf = bool(flags & TCP_FLAG_ACK)
            payload_len = tcp["payload_len"]

            base = (src, sport, dst, dport)
            revb = (dst, dport, src, sport)

            # Try the most recent episode for either direction
            key_in_use = last_active.get(base) or last_active.get(revb)
            conn = connections.get(key_in_use) if key_in_use else None

            # Start a new episode if:
            # - we see a new initial SYN (no ACK) AND
            # - there is an existing episode AND that episode has FIN (any side) or RST (closed/aborted)
            need_new = False
            if syn and not ackf and conn is not None:
                fin_total = int(conn.a.seen_fin) + int(conn.b.seen_fin)
                if fin_total > 0 or conn.has_rst:
                    need_new = True

            if conn is None or need_new:
                # Create new connection episode, canonical direction = this first observed packet
                comp_key = new_conn_key(base)
                conn = Connection(src, sport, dst, dport, ts, syn)
                connections[comp_key] = conn
                order_keys.append(comp_key)
                # update last_active for both directions to this episode
                last_active[base] = comp_key
                last_active[revb] = comp_key

            # Determine direction within this episode
            if src == conn.src and sport == conn.sport and dst == conn.dst and dport == conn.dport:
                out_ep, in_ep = conn.a, conn.b
                out_rtt, in_rtt = conn.rtt_a, conn.rtt_b
            else:
                out_ep, in_ep = conn.b, conn.a
                out_rtt, in_rtt = conn.rtt_b, conn.rtt_a

            out_ep.pkt_count += 1
            if payload_len > 0:
                out_ep.data_bytes += payload_len

            if syn:
                out_ep.seen_syn = True
            if fin:
                out_ep.seen_fin = True
                # record first FIN timestamp if not already
                if conn.first_fin_ts is None:
                    conn.first_fin_ts = ts
            if rst:
                conn.mark_rst()

            # Window scale in SYN / SYN-ACK
            if syn and tcp["win_scale"] is not None:
                out_ep.win_scale = tcp["win_scale"]

            # Advertised receive window (scaled)
            scale = out_ep.win_scale if out_ep.win_scale is not None else 0
            conn_val = tcp["window"] << scale
            out_ep.win_samples.append(conn_val)

            # RTT
            if payload_len > 0:
                out_rtt.on_send_data(tcp["seq"], payload_len, ts)
            if ackf:
                rtts = in_rtt.on_ack(tcp["ack"], ts)
                if rtts:
                    conn.rtt_samples.extend(rtts)

            if conn.first_fin_ts is not None and payload_len > 0 and ts > conn.first_fin_ts:
                conn.mark_payload_after_fin()

            if ts < conn.first_ts:
                conn.first_ts = ts
            if ts > conn.last_ts:
                conn.last_ts = ts

    return connections, order_keys

def compute_statistics(connections, order_keys):
    complete_connections = []
    rst_count = 0
    open_count = 0
    pre_established_count = 0

    durations = []
    rtt_means = []
    pkt_totals = []
    rwnd_samples = []

    for comp_key in order_keys:
        conn = connections[comp_key]
        if conn.has_rst:
            rst_count += 1
        if conn.pre_established:
            pre_established_count += 1

        syn_total = int(conn.a.seen_syn) + int(conn.b.seen_syn)
        fin_total = int(conn.a.seen_fin) + int(conn.b.seen_fin)
        if fin_total == 0:
            open_count += 1
        elif conn.data_after_fin:
            open_count += 1

        if syn_total >= 1 and fin_total >= 1:
            complete_connections.append(conn)
            durations.append(conn.last_ts - conn.first_ts)
            if conn.rtt_samples:
                rtt_means.append(sum(conn.rtt_samples) / len(conn.rtt_samples))
            pkt_totals.append(conn.a.pkt_count + conn.b.pkt_count)
            rwnd_samples.extend(conn.a.win_samples)
            rwnd_samples.extend(conn.b.win_samples)

    aggregates = {
        "complete_count": len(complete_connections),
        "rst_count": rst_count,
        "open_count": open_count,
        "pre_established_count": pre_established_count,
        "durations": durations,
        "rtt_means": rtt_means,
        "pkt_totals": pkt_totals,
        "rwnd_samples": rwnd_samples,
        "complete_connections": complete_connections,
    }
    return aggregates

def mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)

def format_output(connections, order_keys, aggregates):
    out_lines = []

    out_lines.append("A) Total number of connections:\n")
    out_lines.append(str(len(order_keys)))
    out_lines.append("")
    out_lines.append("B) Connections' details:\n")

    for idx, comp_key in enumerate(order_keys, start=1):
        conn = connections[comp_key]
        out_lines.append(f"Connection {idx}:")
        out_lines.append(f"Source Address: {conn.src}")
        out_lines.append(f"Destination address: {conn.dst}")
        out_lines.append(f"Source Port: {conn.sport}")
        out_lines.append(f"Destination Port: {conn.dport}")
        out_lines.append(f"Status: {conn.status_str()}")
        if conn.is_complete():
            out_lines.append("(Only if the connection is complete provide the following information)")
            out_lines.append(f"Start time: {conn.first_ts:.6f}")
            out_lines.append(f"End Time: {conn.last_ts:.6f}")
            out_lines.append(f"Duration: {conn.last_ts - conn.first_ts:.6f}")
            pkts_s2d, pkts_d2s = conn.a.pkt_count, conn.b.pkt_count
            bytes_s2d, bytes_d2s = conn.a.data_bytes, conn.b.data_bytes
            out_lines.append(f"Number of packets sent from Source to Destination: {pkts_s2d}")
            out_lines.append(f"Number of packets sent from Destination to Source: {pkts_d2s}")
            out_lines.append(f"Total number of packets: {pkts_s2d + pkts_d2s}")
            out_lines.append(f"Number of data bytes sent from Source to Destination: {bytes_s2d}")
            out_lines.append(f"Number of data bytes sent from Destination to Source: {bytes_d2s}")
            out_lines.append(f"Total number of data bytes: {bytes_s2d + bytes_d2s}")
        out_lines.append("END")
        out_lines.append("+++++++++++++++++++++++++++++++++")

    out_lines.append("## C) General\n")
    out_lines.append(f"The total number of complete TCP connections: {aggregates['complete_count']}")
    out_lines.append(f"The number of reset TCP connections: {aggregates['rst_count']}")
    out_lines.append(f"The number of TCP connections that were still open when the trace capture ended: {aggregates['open_count']}")
    out_lines.append(f"The number of TCP connections established before the capture started: {aggregates['pre_established_count']}")
    out_lines.append("")
    out_lines.append("## D) Complete TCP connections:\n")

    durs = aggregates["durations"]
    rtts = aggregates["rtt_means"]
    pkts = aggregates["pkt_totals"]
    rwnds = aggregates["rwnd_samples"]

    def fmt_min_mean_max(nums, intify=False, mean_prec=6):
        if not nums:
            if intify:
                return ("0", "0", "0")
            return ("0.000000", "0.000000", "0.000000")
        if intify:
            mn = str(min(nums))
            mx = str(max(nums))
            mu = f"{mean(nums):.2f}"
            return (mn, mu, mx)
        else:
            mn = f"{min(nums):.{mean_prec}f}"
            mx = f"{max(nums):.{mean_prec}f}"
            mu = f"{mean(nums):.{mean_prec}f}"
            return (mn, mu, mx)

    mn, mu, mx = fmt_min_mean_max(durs, intify=False, mean_prec=6)
    out_lines.append(f"Minimum time duration: {mn}")
    out_lines.append(f"Mean time duration: {mu}")
    out_lines.append(f"Maximum time duration: {mx}")
    out_lines.append("")

    mn, mu, mx = fmt_min_mean_max(rtts, intify=False, mean_prec=6)
    out_lines.append(f"Minimum RTT value: {mn}")
    out_lines.append(f"Mean RTT value: {mu}")
    out_lines.append(f"Maximum RTT value: {mx}")
    out_lines.append("")

    mn, mu, mx = fmt_min_mean_max(pkts, intify=True)
    out_lines.append(f"Minimum number of packets including both send/received: {mn}")
    out_lines.append(f"Mean number of packets including both send/received: {mu}")
    out_lines.append(f"Maximum number of packets including both send/received: {mx}")
    out_lines.append("")

    if rwnds:
        mn = f"{min(rwnds)}"
        mx = f"{max(rwnds)}"
        mu = f"{mean(rwnds):.2f}"
    else:
        mn = "0"; mx = "0"; mu = "0.00"
    out_lines.append(f"Minimum receive window size including both send/received: {mn}")
    out_lines.append(f"Mean receive window size including both send/received: {mu}")
    out_lines.append(f"Maximum receive window size including both send/received: {mx}")

    return "\n".join(out_lines)

def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print("Usage: python tcp_analyzer.py <pcap_file>")
        print("Defaulting to sample-capture-file.cap in current directory if present.")
        filename = "sample-capture-file.cap"
    else:
        filename = argv[0]
    try:
        connections, order_keys = analyze_pcap(filename)
    except FileNotFoundError:
        sys.stderr.write(f"Error: file not found: {filename}\n")
        sys.exit(1)
    except ValueError as e:
        sys.stderr.write(f"Error reading pcap: {e}\n")
        sys.exit(1)

    aggregates = compute_statistics(connections, order_keys)
    output = format_output(connections, order_keys, aggregates)
    print(output)

if __name__ == "__main__":
    main()
