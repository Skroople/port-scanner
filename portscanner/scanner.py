"""Core scanning logic.

The scanner performs a TCP *connect* scan: for every port it asks the
operating system to complete a full three-way handshake (SYN, SYN-ACK, ACK).

* Handshake completes        -> the port is OPEN (something is listening).
* Connection refused (RST)   -> the port is CLOSED.
* No answer before timeout   -> the port is FILTERED (likely a firewall
                                silently dropping packets).

A connect scan needs no raw sockets or admin rights, which makes it portable,
but it is also the easiest scan type to see in a target's logs because every
open port receives a real, completed connection.
"""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

# Most commonly exposed TCP ports, used by the "top" shortcut.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
    5900, 5985, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
]

# Fallback names for ports the OS service database often does not know.
EXTRA_SERVICES = {
    2375: "docker",
    3000: "dev-http",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp/flask",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Ports where the server speaks first only after receiving a request.
HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 8888, 9000}


@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class ScanReport:
    target: str
    ip: str
    results: List[PortResult] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.state == OPEN]


def parse_ports(spec: str) -> List[int]:
    """Turn a port specification into a sorted list of unique ports.

    Accepts comma-separated single ports and ranges, plus the keyword
    ``top`` for the built-in common-ports list::

        "22,80,443"   -> [22, 80, 443]
        "20-25"       -> [20, 21, 22, 23, 24, 25]
        "top,8081"    -> TOP_PORTS + [8081]
    """
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if part.lower() == "top":
            ports.update(TOP_PORTS)
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = _to_port(start_s), _to_port(end_s)
            if start > end:
                raise ValueError(f"invalid range '{part}': start is after end")
            ports.update(range(start, end + 1))
        else:
            ports.add(_to_port(part))
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _to_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a number") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def resolve(target: str) -> str:
    """Resolve a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve '{target}': {exc}") from None


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return EXTRA_SERVICES.get(port, "unknown")


def grab_banner(sock: socket.socket, port: int, host: str, timeout: float) -> str:
    """Read the first bytes a service sends, to help identify it.

    Many services (SSH, FTP, SMTP) announce themselves as soon as you
    connect. HTTP servers wait for a request, so we send a minimal HEAD.
    """
    sock.settimeout(timeout)
    try:
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(256)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    # Keep the first meaningful line, e.g. "SSH-2.0-OpenSSH_9.6".
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:100]
    return ""


def scan_port(
    ip: str,
    port: int,
    timeout: float = 0.5,
    banner: bool = False,
    host: Optional[str] = None,
) -> PortResult:
    """Scan a single TCP port with a full connect()."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
        except socket.timeout:
            return PortResult(port, FILTERED)
        except OSError:
            return PortResult(port, FILTERED)

        if code == 0:
            result = PortResult(port, OPEN, service_name(port))
            if banner:
                result.banner = grab_banner(sock, port, host or ip, timeout)
            return result

        if code in (errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", -1), 10061):
            return PortResult(port, CLOSED)
        # Timeouts and unreachable networks: no clear answer from the host.
        return PortResult(port, FILTERED)


def scan(
    target: str,
    ports: Iterable[int],
    timeout: float = 0.5,
    workers: int = 200,
    banner: bool = False,
    on_result: Optional[Callable[[PortResult], None]] = None,
) -> ScanReport:
    """Scan many ports concurrently and return a sorted report.

    A connect() spends most of its time waiting on the network, so threads
    give a big speed-up: with 200 workers and a 0.5 s timeout, 1000 filtered
    ports take about 2.5 s instead of more than 8 minutes one by one.
    """
    ip = resolve(target)
    ports = list(ports)
    report = ScanReport(target=target, ip=ip)
    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        futures = [
            pool.submit(scan_port, ip, port, timeout, banner, target) for port in ports
        ]
        for future in as_completed(futures):
            result = future.result()
            report.results.append(result)
            if on_result:
                on_result(result)

    report.results.sort(key=lambda r: r.port)
    report.elapsed = time.perf_counter() - start
    return report
