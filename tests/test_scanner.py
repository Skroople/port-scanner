import json
import socket
import threading

import pytest

from portscanner.cli import main
from portscanner.scanner import CLOSED, OPEN, TOP_PORTS, parse_ports, scan, scan_port


# ---------- parse_ports ----------

def test_single_ports_are_sorted_and_unique():
    assert parse_ports("443,22,80,22") == [22, 80, 443]


def test_range_is_inclusive():
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_mixed_spec_with_spaces():
    assert parse_ports("22, 80-81 ,443") == [22, 80, 81, 443]


def test_top_keyword():
    assert parse_ports("top") == sorted(set(TOP_PORTS))


@pytest.mark.parametrize("spec", ["0", "65536", "abc", "30-20", "", "1-x"])
def test_invalid_specs_raise(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


# ---------- scanning against local sockets ----------

@pytest.fixture
def listener():
    """A local TCP server that sends a banner, like SSH or FTP would."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.sendall(b"SSH-2.0-TestServer_1.0\r\n")
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(1)
    server.close()


def free_port():
    """A port that nothing is listening on."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_open_port_detected_with_banner(listener):
    result = scan_port("127.0.0.1", listener, timeout=1, banner=True)
    assert result.state == OPEN
    assert result.banner == "SSH-2.0-TestServer_1.0"


def test_closed_port_detected():
    assert scan_port("127.0.0.1", free_port(), timeout=1).state == CLOSED


def test_scan_reports_only_listener_as_open(listener):
    closed = free_port()
    report = scan("127.0.0.1", [listener, closed], timeout=1, workers=4)
    assert [r.port for r in report.open_ports] == [listener]
    assert [r.port for r in report.results] == sorted([listener, closed])


def test_cli_writes_json(listener, tmp_path, capsys):
    out = tmp_path / "result.json"
    code = main(["127.0.0.1", "-p", str(listener), "-b", "-o", str(out)])
    assert code == 0
    data = json.loads(out.read_text())
    assert data["summary"]["open"] == 1
    assert data["open_ports"][0]["port"] == listener
    assert "1 open" in capsys.readouterr().out


def test_cli_rejects_bad_ports(capsys):
    assert main(["127.0.0.1", "-p", "99999"]) == 2
    assert "out of range" in capsys.readouterr().err
