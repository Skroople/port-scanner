# port-scanner

A fast, multithreaded **TCP connect port scanner** written in pure Python, with no dependencies beyond the standard library.

I built it to understand what tools like Nmap do under the hood: how a port's state is decided, why scanning is slow without concurrency, and how services can be identified from their banners.

> ⚠️ **Only scan hosts you own or have explicit permission to test.** Scanning networks without authorization may be illegal and is against the terms of most providers. Good legal targets: `127.0.0.1`, your own home lab, a VM, or `scanme.nmap.org`, which the Nmap project provides for testing.

## Features

- Scans single ports, ranges and lists: `22,80,443`, `1-1024`, or `top` for 38 commonly exposed ports
- Concurrent scanning with a configurable thread pool (200 threads by default)
- Classifies every port as **open**, **closed** or **filtered**
- Optional **banner grabbing** to identify services such as SSH, FTP, SMTP and HTTP
- Service-name lookup for open ports
- **JSON export** for use in other tools or reports
- Works on Windows, macOS and Linux, with no admin rights needed

## Usage

Requires Python 3.8+.

```bash
git clone https://github.com/Skroople/port-scanner.git
cd port-scanner

python -m portscanner 127.0.0.1                  # ports 1-1024
python -m portscanner scanme.nmap.org -p top -b  # common ports + banners
python -m portscanner 192.168.1.10 -p 1-65535 -w 500 -t 0.3 -o result.json
```

| Option | Description | Default |
|---|---|---|
| `-p, --ports` | Ports to scan: `22,80`, `1-1024`, `top`, or a mix | `1-1024` |
| `-t, --timeout` | Seconds to wait for each connection | `0.5` |
| `-w, --workers` | Number of concurrent threads | `200` |
| `-b, --banner` | Read a banner from each open port | off |
| `-a, --all` | Also list closed and filtered ports | off |
| `-o, --output` | Save results as JSON | none |

### Example output

```
Scanning 127.0.0.1 (9000 ports, 200 threads)
Only scan hosts you own or have explicit permission to test.

PORT     STATE     SERVICE         BANNER
-----------------------------------------
8000/tcp open      http-alt        HTTP/1.0 200 OK

127.0.0.1 (127.0.0.1): 1 open, 8999 closed, 0 filtered in 1.11s
```

## How it works

### 1. Deciding a port's state

The scanner performs a **TCP connect scan**. For each port it asks the operating system to complete a full three-way handshake:

```
Scanner                Target
   | ------- SYN -------> |
   | <---- SYN/ACK ------ |   port OPEN: something is listening
   | ------- ACK -------> |

   | ------- SYN -------> |
   | <------- RST ------- |   port CLOSED: host is up, nothing listening

   | ------- SYN -------> |
   |      (silence)       |   port FILTERED: a firewall likely dropped the packet
```

In code this is a single `socket.connect_ex()` call. It returns `0` on success, `ECONNREFUSED` when the target answers with a RST, and a timeout when nothing comes back.

**Trade-off:** a connect scan needs no raw sockets or admin rights, so it runs anywhere. But every open port receives a *completed* connection, so it is the easiest scan type to spot in the target's logs. Nmap's default **SYN scan** (`-sS`) avoids this by sending only the SYN and resetting before the handshake completes. That requires crafting raw packets, which is on the roadmap below.

### 2. Why threads matter

A scan is almost entirely *waiting*: on the network, and on timeouts for filtered ports. Scanning 1,000 filtered ports one by one with a 0.5 s timeout takes over 8 minutes. With a `ThreadPoolExecutor` of 200 workers, those waits overlap and the same scan finishes in about 2.5 seconds. Python's GIL is not a bottleneck here, because it is released while a thread is blocked on socket I/O.

### 3. Banner grabbing

Many services introduce themselves the moment you connect, for example SSH sends `SSH-2.0-OpenSSH_9.6`. HTTP servers wait for a request, so for HTTP ports the scanner sends a minimal `HEAD / HTTP/1.0` and reads the status line. Banners often reveal software and version, which is how a tester maps open ports to known vulnerabilities.

## Project structure

```
portscanner/
├── scanner.py   # core logic: port parsing, connect scan, banners, thread pool
├── cli.py       # argument parsing, table and JSON output
└── __main__.py  # entry point for `python -m portscanner`
tests/
└── test_scanner.py  # tests against real local sockets, no network needed
```

## Running the tests

```bash
pip install pytest
python -m pytest
```

The tests spin up a local TCP server that sends an SSH-style banner, then check that the scanner reports it as open with the right banner and that unused ports come back closed.

## Roadmap

- [ ] SYN ("half-open") scanning with raw sockets / Scapy
- [ ] UDP scanning
- [ ] Scanning CIDR ranges (`192.168.1.0/24`) and host discovery
- [ ] Rate limiting to stay gentle on fragile devices
- [ ] Matching banners against known vulnerable versions

## License

[MIT](LICENSE)
