"""
Project AEGIS — DNS Monitor Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-DNSMON
Role: Monitors DNS traffic for malicious patterns.
      Detects DNS tunneling, high-entropy (DGA) domains,
      beaconing behavior, and TXT record abuse.

      Works in two modes:
      1. Live capture via Scapy (when available)
      2. Log-based / programmatic (standalone fallback)
"""

import json
import logging
import math
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Callable, Dict, List, Optional, Tuple

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    DNS_LOG_FILE,
    DNS_POLL_INTERVAL,
    DNS_ENTROPY_THRESHOLD,
    DNS_RESPONSE_SIZE_THRESHOLD,
    DNS_BEACON_QUERY_THRESHOLD,
    DNS_BEACON_WINDOW,
    DNS_TXT_QUERY_THRESHOLD,
    DNS_TXT_WINDOW,
    DNS_TUNNEL_QUERY_THRESHOLD,
    DNS_TUNNEL_WINDOW,
    DNS_ALERT_COOLDOWN,
    DNS_LARGE_RESPONSE_THRESHOLD,
    DNS_ENTROPY_WHITELIST,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.dnsmon")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(DNS_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── DATA MODELS ──────────────────────────────────────────────────────────────
@dataclass
class DnsQuery:
    """A single DNS query observation."""
    timestamp: float
    domain: str
    query_type: str          # A, AAAA, TXT, MX, CNAME, etc.
    source_ip: str
    query_size: int          # bytes
    response_size: int       # bytes (0 if no response seen)


@dataclass
class DnsThreat:
    """A DNS-based threat alert."""
    timestamp: str
    threat_type: str         # DNS_TUNNEL, HIGH_ENTROPY, BEACONING, TXT_ABUSE, LARGE_RESPONSE
    risk_level: str          # CRITICAL, HIGH, MEDIUM, LOW
    domain: str
    query_count: int
    reasoning: str
    action_taken: str
    evidence: Dict = field(default_factory=dict)


# ─── ENTROPY CALCULATION ──────────────────────────────────────────────────────
class EntropyCalculator:
    """Calculates Shannon entropy for domain name analysis."""

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Compute Shannon entropy (bits per character) of a string.

        Higher entropy = more random-looking = more suspicious for DGA.
        Legitimate domains typically < 3.5 bits/char.
        DGA domains and DNS tunnel subdomains often > 4.0 bits/char.
        """
        if not data:
            return 0.0
        # Count character frequency
        length = len(data)
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def domain_entropy(domain: str) -> float:
        """Compute entropy of the most suspicious part of a domain.

        Uses the subdomain (everything before the second-level domain)
        since that's where DGA/tunneling randomness appears.
        """
        if not domain:
            return 0.0

        domain = domain.lower().strip(".")

        # Check entropy whitelist
        for suffix in DNS_ENTROPY_WHITELIST:
            if domain.endswith(suffix):
                # For whitelisted domains, only check sub-subdomain
                # e.g., for abc.def.cloudfront.net, check 'abc'
                sub = domain.replace(suffix, "").rstrip(".")
                if not sub:
                    return 0.0
                parts = sub.split(".")
                check_part = parts[-1] if parts else sub
                return EntropyCalculator.shannon_entropy(check_part)

        # Split domain into parts and analyze subdomain
        parts = domain.split(".")
        if len(parts) <= 2:
            # Just domain.tld — not enough data for entropy analysis
            return 0.0

        # Join all subdomain parts (everything before the last two parts)
        subdomain = ".".join(parts[:-2])
        if not subdomain:
            return 0.0

        return EntropyCalculator.shannon_entropy(subdomain)


# ─── DNS REASONING ENGINE ─────────────────────────────────────────────────────
class DnsReasoningEngine:
    """Analyzes DNS queries and flags suspicious patterns."""

    def __init__(self):
        # Per-domain tracking: domain -> list of query timestamps
        self._domain_tracker: Dict[str, List[float]] = defaultdict(list)
        # Per-domain: domain -> list of (timestamp, query_size, response_size)
        self._domain_size_tracker: Dict[str, List[Tuple[float, int, int]]] = defaultdict(list)
        # Per-domain: domain -> last alert time (cooldown)
        self._alerted_domains: Dict[str, float] = {}
        # TXT query tracking: domain -> list of timestamps
        self._txt_tracker: Dict[str, List[float]] = defaultdict(list)
        # Interval tracking for beaconing
        self._interval_tracker: Dict[str, List[float]] = defaultdict(list)

    def _is_on_cooldown(self, domain: str, now: float) -> bool:
        last_alert = self._alerted_domains.get(domain, 0)
        return (now - last_alert) < DNS_ALERT_COOLDOWN

    def _purge_old(self, domain: str, now: float) -> None:
        """Remove tracking data outside the relevant windows."""
        cutoff_tunnel = now - DNS_TUNNEL_WINDOW
        cutoff_beacon = now - DNS_BEACON_WINDOW
        cutoff_txt = now - DNS_TXT_WINDOW

        self._domain_tracker[domain] = [
            t for t in self._domain_tracker[domain] if t >= cutoff_tunnel
        ]
        self._domain_size_tracker[domain] = [
            entry for entry in self._domain_size_tracker[domain]
            if entry[0] >= cutoff_tunnel
        ]
        self._txt_tracker[domain] = [
            t for t in self._txt_tracker[domain] if t >= cutoff_txt
        ]
        # Only keep recent intervals for beaconing
        self._interval_tracker[domain] = [
            t for t in self._interval_tracker[domain] if t >= cutoff_beacon
        ]

        # Clean up empty entries
        for tracker in [self._domain_tracker, self._domain_size_tracker,
                        self._txt_tracker, self._interval_tracker]:
            if domain in tracker and not tracker[domain]:  # type: ignore[operator, index]
                del tracker[domain]  # type: ignore[attr-defined]

    def evaluate(self, query: DnsQuery) -> Optional[DnsThreat]:
        """Evaluate a single DNS query and return a threat if detected.

        Checks (in priority order):
        1. DNS tunneling (high query count + large responses)
        2. High entropy domain (DGA detection)
        3. Beaconing (regular interval queries)
        4. TXT record abuse
        5. Large response sizes
        """
        now = time.time()
        domain = query.domain.lower()
        domain_stripped = domain.strip(".")

        if not domain_stripped:
            return None

        # Cooldown check
        if self._is_on_cooldown(domain_stripped, now):
            return None

        # Track the query
        self._domain_tracker[domain_stripped].append(now)
        self._domain_size_tracker[domain_stripped].append(
            (now, query.query_size, query.response_size)
        )

        # Track intervals for beaconing
        timestamps = self._domain_tracker[domain_stripped]
        if len(timestamps) >= 2:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
            self._interval_tracker[domain_stripped] = intervals[-10:]  # Keep last 10

        # Track TXT queries separately
        if query.query_type == "TXT":
            self._txt_tracker[domain_stripped].append(now)

        # Purge old data
        self._purge_old(domain_stripped, now)

        # Update timestamps for analysis
        timestamps = self._domain_tracker.get(domain_stripped, [])

        # ── Check 1: High entropy domain (DGA / tunneling subdomain) ──
        entropy = EntropyCalculator.domain_entropy(domain_stripped)
        if entropy >= DNS_ENTROPY_THRESHOLD:
            self._alerted_domains[domain_stripped] = now
            reasoning = (
                f"High-entropy domain detected: '{domain_stripped}' "
                f"(Shannon entropy: {entropy:.2f}). "
                f"Entropy above threshold ({DNS_ENTROPY_THRESHOLD}) suggests "
                f"DGA-generated domain or DNS tunnel subdomain."
            )
            action = "ALERT_AND_MONITOR" if entropy < 4.5 else "FLAG_FOR_AUTOBLOCK"
            risk = "CRITICAL" if entropy >= 4.5 else "HIGH"

            return DnsThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="HIGH_ENTROPY",
                risk_level=risk,
                domain=domain_stripped,
                query_count=len(timestamps),
                reasoning=reasoning,
                action_taken=action,
                evidence={
                    "entropy": round(entropy, 2),
                    "threshold": DNS_ENTROPY_THRESHOLD,
                    "domain_parts": domain_stripped.split("."),
                    "total_queries": len(timestamps),
                },
            )

        # ── Check 2: Beaconing detection (regular intervals) ──
        intervals = self._interval_tracker.get(domain_stripped, [])
        if len(intervals) >= DNS_BEACON_QUERY_THRESHOLD - 1:
            avg_interval = sum(intervals) / len(intervals)
            # Low variance in intervals suggests automated beaconing
            if len(intervals) >= 3:
                variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                stddev = math.sqrt(variance)
                # If stddev is low relative to the average, it's beaconing
                if avg_interval > 0 and stddev < (avg_interval * 0.3):
                    self._alerted_domains[domain_stripped] = now
                    reasoning = (
                        f"DNS beaconing detected: '{domain_stripped}' queried "
                        f"{len(timestamps)} times with regular intervals "
                        f"(avg {avg_interval:.1f}s, stddev {stddev:.2f}s). "
                        f"This pattern suggests C2 beaconing or data exfiltration."
                    )
                    return DnsThreat(
                        timestamp=datetime.now().isoformat(),
                        threat_type="BEACONING",
                        risk_level="HIGH",
                        domain=domain_stripped,
                        query_count=len(timestamps),
                        reasoning=reasoning,
                        action_taken="ALERT_AND_MONITOR",
                        evidence={
                            "avg_interval": round(avg_interval, 1),
                            "stddev": round(stddev, 2),
                            "intervals": [round(i, 1) for i in intervals[:10]],
                            "total_queries": len(timestamps),
                        },
                    )

        # ── Check 3: DNS tunneling (high volume + large responses) ──
        if len(timestamps) >= DNS_TUNNEL_QUERY_THRESHOLD:
            # Check if any responses were unusually large
            size_entries = self._domain_size_tracker.get(domain_stripped, [])
            large_responses = [e for e in size_entries if e[2] >= DNS_LARGE_RESPONSE_THRESHOLD]
            avg_response = sum(e[2] for e in size_entries) / len(size_entries) if size_entries else 0

            if large_responses or avg_response >= DNS_RESPONSE_SIZE_THRESHOLD:
                self._alerted_domains[domain_stripped] = now
                reasoning = (
                    f"DNS tunneling suspected: '{domain_stripped}' received "
                    f"{len(large_responses)} large responses (>{DNS_LARGE_RESPONSE_THRESHOLD}B) "
                    f"out of {len(timestamps)} queries. "
                    f"Average response size: {avg_response:.0f}B. "
                    f"This pattern is consistent with DNS tunneling for data exfiltration."
                )
                return DnsThreat(
                    timestamp=datetime.now().isoformat(),
                    threat_type="DNS_TUNNEL",
                    risk_level="CRITICAL",
                    domain=domain_stripped,
                    query_count=len(timestamps),
                    reasoning=reasoning,
                    action_taken="FLAG_FOR_AUTOBLOCK",
                    evidence={
                        "total_queries": len(timestamps),
                        "large_responses": len(large_responses),
                        "avg_response_size": round(avg_response, 1),
                        "max_response_size": max(e[2] for e in size_entries) if size_entries else 0,
                    },
                )

            # Even without large responses, very high query volume is suspicious
            if len(timestamps) >= DNS_TUNNEL_QUERY_THRESHOLD * 2:
                self._alerted_domains[domain_stripped] = now
                reasoning = (
                    f"High-volume DNS queries to '{domain_stripped}': "
                    f"{len(timestamps)} queries in {DNS_TUNNEL_WINDOW}s. "
                    f"Unusually high query rate may indicate DNS tunneling."
                )
                return DnsThreat(
                    timestamp=datetime.now().isoformat(),
                    threat_type="DNS_TUNNEL",
                    risk_level="HIGH",
                    domain=domain_stripped,
                    query_count=len(timestamps),
                    reasoning=reasoning,
                    action_taken="ALERT_AND_MONITOR",
                    evidence={
                        "total_queries": len(timestamps),
                        "window_seconds": DNS_TUNNEL_WINDOW,
                        "queries_per_second": round(len(timestamps) / max(DNS_TUNNEL_WINDOW, 1), 2),
                    },
                )

        # ── Check 4: TXT record abuse ──
        txt_queries = self._txt_tracker.get(domain_stripped, [])
        if len(txt_queries) >= DNS_TXT_QUERY_THRESHOLD:
            self._alerted_domains[domain_stripped] = now
            reasoning = (
                f"TXT record abuse detected: '{domain_stripped}' received "
                f"{len(txt_queries)} TXT queries within the monitoring window. "
                f"Excessive TXT queries often indicate DNS tunneling via TXT records."
            )
            return DnsThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="TXT_ABUSE",
                risk_level="MEDIUM",
                domain=domain_stripped,
                query_count=len(txt_queries),
                reasoning=reasoning,
                action_taken="LOG_AND_WATCH",
                evidence={
                    "total_txt_queries": len(txt_queries),
                    "window_seconds": DNS_TXT_WINDOW,
                },
            )

        # ── Check 5: Large response (possible data exfil) ──
        if query.response_size >= DNS_LARGE_RESPONSE_THRESHOLD:
            self._alerted_domains[domain_stripped] = now
            reasoning = (
                f"Large DNS response detected: {query.response_size}B "
                f"from '{domain_stripped}' (query type: {query.query_type}). "
                f"Responses over {DNS_LARGE_RESPONSE_THRESHOLD}B may indicate "
                f"data exfiltration via DNS."
            )
            return DnsThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="LARGE_RESPONSE",
                risk_level="MEDIUM",
                domain=domain_stripped,
                query_count=1,
                reasoning=reasoning,
                action_taken="LOG_AND_WATCH",
                evidence={
                    "response_size": query.response_size,
                    "query_type": query.query_type,
                    "threshold": DNS_LARGE_RESPONSE_THRESHOLD,
                },
            )

        return None

    def cleanup(self) -> None:
        """Periodic cleanup of stale tracking data."""
        now = time.time()
        cutoff = now - max(DNS_TUNNEL_WINDOW, DNS_BEACON_WINDOW, DNS_TXT_WINDOW)

        for domain in list(self._domain_tracker.keys()):
            self._domain_tracker[domain] = [
                t for t in self._domain_tracker[domain] if t >= cutoff
            ]
            if not self._domain_tracker[domain]:
                del self._domain_tracker[domain]

        for domain in list(self._domain_size_tracker.keys()):
            self._domain_size_tracker[domain] = [
                e for e in self._domain_size_tracker[domain] if e[0] >= cutoff
            ]
            if not self._domain_size_tracker[domain]:
                del self._domain_size_tracker[domain]

        for domain in list(self._txt_tracker.keys()):
            self._txt_tracker[domain] = [
                t for t in self._txt_tracker[domain] if t >= cutoff
            ]
            if not self._txt_tracker[domain]:
                del self._txt_tracker[domain]


# ─── DNS CAPTURE ──────────────────────────────────────────────────────────────
class DnsCapture:
    """Captures DNS traffic from available sources.

    Tries Scapy first for live capture, then falls back gracefully.
    """

    @staticmethod
    def check_scapy_available() -> bool:
        """Check if Scapy is available for live DNS capture."""
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False

    def __init__(self):
        self._scapy_available = self.check_scapy_available()

    def is_available(self) -> bool:
        """Return True if live capture is available."""
        return self._scapy_available

    def start_capture(self, callback: Callable[[DnsQuery], None]) -> Optional[object]:
        """Start live DNS capture via Scapy (if available).

        Returns the sniffer object or None if Scapy unavailable.
        """
        if not self._scapy_available:
            _logger.info("Scapy not available — DNS monitor will use programmatic mode.")
            return None

        try:
            from scapy.all import AsyncSniffer, DNS  # type: ignore[import-untyped,attr-defined]

            def process_packet(pkt) -> None:
                try:
                    if not pkt.haslayer(DNS):
                        return

                    dns = pkt[DNS]
                    if not dns.qd or not dns.qr:  # Only process queries, not responses
                        return

                    qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype_code = dns.qd.qtype
                    qtype_map = {1: "A", 28: "AAAA", 15: "MX", 5: "CNAME",
                                 16: "TXT", 33: "SRV", 255: "ANY", 6: "SOA",
                                 12: "PTR", 2: "NS"}
                    qtype = qtype_map.get(qtype_code, f"TYPE{qtype_code}")

                    # Estimate query size from the DNS layer
                    qsize = len(dns.qd.qname) if dns.qd.qname else 0

                    # Get source IP
                    if pkt.haslayer("IP"):
                        src_ip = pkt["IP"].src
                    else:
                        src_ip = "0.0.0.0"  # nosec B104

                    # Approximate response size from DNS response
                    response_size = 0
                    if dns.ancount > 0 and dns.an:
                        response_size = len(bytes(dns.an))

                    query = DnsQuery(
                        timestamp=time.time(),
                        domain=qname,
                        query_type=qtype,
                        source_ip=src_ip,
                        query_size=qsize,
                        response_size=response_size,
                    )
                    callback(query)

                except Exception as e:
                    _logger.debug(f"DNS packet parse error: {e}")

            sniffer = AsyncSniffer(
                filter="udp port 53",
                prn=process_packet,
                store=False,
            )
            sniffer.start()
            _logger.info("DNS capture started via Scapy.")
            return sniffer

        except ImportError:
            _logger.info("Scapy DNS capture unavailable.")
            return None
        except Exception as e:
            _logger.warning(f"DNS capture init failed: {e}")
            return None


# ─── DNS MONITOR ──────────────────────────────────────────────────────────────
class DnsMonitor:
    """Monitors DNS traffic for malicious patterns.

    Works in two modes:
    1. Live Scapy capture (when available)
    2. Programmatic feed (queries submitted via feed_query())
    """

    def __init__(self, on_threat: Optional[Callable[[DnsThreat], None]] = None):
        self.on_threat: Callable[[DnsThreat], None] = on_threat or self._default_handler
        self._engine = DnsReasoningEngine()
        self._capture = DnsCapture()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sniffer: Optional[object] = None
        self._stop_event = Event()
        self._query_buffer: List[DnsQuery] = []
        self._buffer_lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def feed_query(self, query: DnsQuery) -> None:
        """Submit a DNS query for analysis (programmatic mode)."""
        with self._buffer_lock:
            self._query_buffer.append(query)

    def feed_queries(self, queries: List[DnsQuery]) -> None:
        """Submit multiple DNS queries at once."""
        with self._buffer_lock:
            self._query_buffer.extend(queries)

    # ── Internal Processing ──────────────────────────────────────────────────

    def _process_query(self, query: DnsQuery) -> None:
        """Process a single DNS query through the reasoning engine."""
        try:
            threat = self._engine.evaluate(query)
            if threat:
                _logger.warning(json.dumps(asdict(threat)))
                self.on_threat(threat)
        except Exception as e:
            _logger.debug(f"DNS query evaluation error: {e}")

    def _dns_callback(self, query: DnsQuery) -> None:
        """Callback for live Scapy capture — buffers query for processing thread."""
        self.feed_query(query)  # Buffer under lock, processed in _run_loop

    def _run_loop(self) -> None:
        """Main monitoring loop — processes buffered queries."""
        print(f"  [DNSMON] DNS monitor active. Checking every {DNS_POLL_INTERVAL}s.\n")

        while not self._stop_event.is_set():
            try:
                # Process buffered queries
                with self._buffer_lock:
                    pending = list(self._query_buffer)
                    self._query_buffer.clear()

                for query in pending:
                    self._process_query(query)

                # Periodic cleanup
                self._engine.cleanup()

            except Exception as e:
                _logger.error(f"DNS monitor scan error: {e}\n{traceback.format_exc()}")

            if self._stop_event.wait(DNS_POLL_INTERVAL):
                break

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the DNS monitor.

        Tries to start live Scapy capture first. Falls back to
        programmatic mode where queries must be submitted via feed_query().
        """
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        # Try to start live capture
        self._sniffer = self._capture.start_capture(self._dns_callback)

        if self._sniffer is not None:
            print("  [AEGIS] DNS Monitor online — live capture via Scapy.\n")
            _logger.info("DNS monitor started with live Scapy capture.")
        else:
            print("  [AEGIS] DNS Monitor online — programmatic mode (no Scapy).\n")
            print("  [DNSMON] Feed queries via DnsMonitor.feed_query() or --test-dns.\n")
            _logger.info("DNS monitor started in programmatic mode.")

        # Start processing thread
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="AEGIS-DnsMon"
        )
        self._thread.start()
        _logger.info("DNS monitor processing thread started.")

    def stop(self) -> None:
        """Stop the DNS monitor and clean up."""
        self._running = False
        self._stop_event.set()

        # Stop live capture
        if self._sniffer is not None:
            try:
                if hasattr(self._sniffer, "stop"):
                    self._sniffer.stop()
            except Exception:
                _logger.debug("DNS sniffer stop failed")
            self._sniffer = None

        # Join processing thread
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                _logger.debug("DNS monitor thread join failed")

        _logger.info("DNS monitor stopped.")
        print("  [DNSMON] DNS monitor stopped.")

    # ── Default Handler ──────────────────────────────────────────────────────

    @staticmethod
    def _default_handler(threat: DnsThreat) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS DNSMON — DNS THREAT DETECTED                   ║")
        print(f"  ╠{border}╣")
        print(f"  ║  Type      : {threat.threat_type:<40}║")
        print(f"  ║  Domain    : {threat.domain:<40}║")
        print(f"  ║  Queries   : {threat.query_count:<40}║")
        print(f"  ║  Risk      : {threat.risk_level:<40}║")
        print(f"  ║  Action    : {threat.action_taken:<40}║")
        print(f"  ╚{border}╝")
        print(f"  → {threat.reasoning}\n")


# ─── STANDALONE MODE ──────────────────────────────────────────────────────────
def _run_test_queries(monitor: DnsMonitor) -> None:
    """Feed test DNS queries to demonstrate detection capabilities."""
    import random  # nosec B311
    import string

    print("  [DNSMON] Feeding test queries...\n")

    # Test 1: High entropy (DGA-like domain)
    for _ in range(3):
        rand_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))  # nosec B311
        domain = f"{rand_sub}.dga-test.example.com"
        monitor.feed_query(DnsQuery(
            timestamp=time.time(),
            domain=domain,
            query_type="A",
            source_ip="127.0.0.1",
            query_size=len(domain) + 10,
            response_size=100,
        ))
    time.sleep(0.5)

    # Test 2: DNS tunneling (large responses + high volume)
    for i in range(25):
        sub = f"data{i:04d}.exfil.example.com"
        monitor.feed_query(DnsQuery(
            timestamp=time.time() + (i * 0.5),
            domain=sub,
            query_type="TXT",
            source_ip="127.0.0.1",
            query_size=60 + len(sub),
            response_size=1200 + (i * 50),  # Large responses
        ))
    time.sleep(0.5)

    # Test 3: Beaconing (regular intervals)
    for i in range(15):
        monitor.feed_query(DnsQuery(
            timestamp=time.time() + (i * 2.0),
            domain="beacon.example.com",
            query_type="A",
            source_ip="127.0.0.1",
            query_size=40,
            response_size=80,
        ))
    time.sleep(0.5)

    # Test 4: TXT abuse
    for i in range(8):
        monitor.feed_query(DnsQuery(
            timestamp=time.time() + (i * 0.3),
            domain="txt-tunnel.example.com",
            query_type="TXT",
            source_ip="127.0.0.1",
            query_size=45,
            response_size=800 + (i * 100),
        ))

    print("  [DNSMON] Test queries submitted. Processing...\n")


if __name__ == "__main__":
    print("\n  AEGIS DNS MONITOR — STANDALONE v1.0\n")

    monitor = DnsMonitor()

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true",
                        help="Feed test queries to demonstrate detection")
    args, _ = parser.parse_known_args()

    monitor.start()

    if args.test:
        # Give the monitor a moment to start
        time.sleep(1)
        _run_test_queries(monitor)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
