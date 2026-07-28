#!/usr/bin/env python3
"""network_egress.py - Layer 1 measurement tool (protocol v2).

Differences from v1, all of them consequences of review findings:
  * MODE-AWARE, and the mode comes from /etc/sandy-session.json - never from
    SANDY_EGRESS_MODE, the exact source the brief forbids (F11).
  * NO VERDICT LABELS. v1 printed "*** EGRESS LEAK ***" for behaviour that is the
    documented baseline in off mode, and the off-run had to reinterpret it by hand.
    This tool prints facts; adjudicate.sh decides.
  * The allowed-host control is passed in from controls.json, not hardcoded to
    api.github.com (which may be non-allowlisted under strict, silently inverting
    the test).
  * Canary fetching lives HERE, emitting {target, resolved_ip, result, errno,
    bytes, wall_ms} - in v1 the decisive test was left to ad-hoc curls, which is
    why the two runs executed it differently.
  * A symbolic errno from a real syscall: ENETUNREACH (a local routing verdict a
    dead canary cannot produce) is not the same evidence as ECONNREFUSED
    (indistinguishable from a dead server) - F12.

Every subcommand prints one JSON object. Rules of engagement: benign, payload-free
reachability probes only; `sweep` refuses any target that is not this container's
own private segment.
"""
import argparse
import errno as errno_mod
import json
import os
import re
import socket
import ssl
import struct
import sys
import time

TIMEOUT = float(os.environ.get("SANDY_ISO_NET_TIMEOUT", "5"))
MAX_CAPTURE = 4096


def out(obj):
    json.dump(obj, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def ename(e):
    if isinstance(e, OSError) and e.errno is not None:
        return errno_mod.errorcode.get(e.errno, "E%d" % e.errno)
    if isinstance(e, socket.timeout):
        return "ETIMEDOUT"
    return None


def classify_exc(e):
    if isinstance(e, socket.timeout):
        return "timeout", "ETIMEDOUT"
    name = ename(e)
    if name == "ECONNREFUSED":
        return "refused", name
    if name in ("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN"):
        return "unreachable", name
    if name == "ETIMEDOUT":
        return "timeout", name
    if name in ("EACCES", "EPERM"):
        return "denied", name
    return "error", name or type(e).__name__


def ms_since(t0):
    return int((time.time() - t0) * 1000)


# ---------------------------------------------------------------- topology
def routes():
    rows = []
    try:
        with open("/proc/net/route") as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        f = line.split()
        if len(f) < 8:
            continue

        def ip(h):
            return socket.inet_ntoa(struct.pack("<L", int(h, 16)))
        rows.append({"iface": f[0], "dest": ip(f[1]), "gateway": ip(f[2]),
                     "mask": ip(f[7]), "flags": f[3]})
    return rows


def default_gateway():
    for r in routes():
        if r["dest"] == "0.0.0.0" and r["gateway"] != "0.0.0.0":
            return r["gateway"]
    return None


def onlink_gateway():
    """Best guess at the segment's router even when there is no default route."""
    gw = default_gateway()
    if gw:
        return gw
    for r in routes():
        if r["dest"] != "0.0.0.0" and r["mask"] != "0.0.0.0":
            octets = r["dest"].split(".")
            return ".".join(octets[:3] + ["1"])
    return None


def my_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    for target in ("8.8.8.8", onlink_gateway() or "127.0.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            continue
    return None


def resolv_info():
    ns, ext = [], []
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                ns.append(line.split()[1])
            if "ExtServers" in line:
                ext += re.findall(r"[0-9]+(?:\.[0-9]+){3}", line)
    except OSError:
        pass
    return ns, ext


def proxy_ip():
    _, ext = resolv_info()
    if ext:
        return ext[0]
    env = os.environ.get("SANDY_PROXY_IP")
    if env:
        return env
    return None


def cmd_topology(_a):
    rs = routes()
    gw = default_gateway()
    ns, ext = resolv_info()
    topo = "routed-default-gateway" if gw else (
        "internal-no-default-route" if rs else "unknown")
    return out({
        "op": "topology", "observed_topology": topo,
        "default_route": bool(gw), "gateway": gw, "onlink_gateway": onlink_gateway(),
        "my_ip": my_ip(), "routes": rs, "nameservers": ns, "resolv_extservers": ext,
        "proxy_ip": proxy_ip(),
        "note": "MEASURED posture. The marker's egress_mode is sandy's DECLARED intent; "
                "this is what the container actually got. Divergence is a first-class "
                "finding and is graded independently (F2a).",
    })


def cmd_resolve(a):
    res = {}
    for name in a.names:
        t0 = time.time()
        try:
            res[name] = {"ip": socket.gethostbyname(name), "ms": ms_since(t0)}
        except OSError as e:
            res[name] = {"error": classify_exc(e)[0], "errno": ename(e), "ms": ms_since(t0)}
    px = proxy_ip()
    pinned = [n for n, v in res.items() if v.get("ip") and px and v["ip"] == px]
    return out({"op": "resolve", "resolved": res, "proxy_ip": px,
                "names_pinned_to_proxy": pinned,
                "n_pinned": len(pinned), "n_names": len(res)})


# ---------------------------------------------------------------- tcp / udp
def resolve_host(host):
    if host == "auto-gateway":
        return onlink_gateway() or "0.0.0.0", "auto-gateway"
    if host == "auto-proxy":
        return proxy_ip() or "0.0.0.0", "auto-proxy"
    try:
        return socket.gethostbyname(host), None
    except OSError:
        return host, None


def http_get(sock, host_header, path, https=False, sni=None):
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=sni or host_header)
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: sandy-isolation-test/2\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n" % (path or "/", host_header))
    sock.sendall(req.encode())
    buf = b""
    while len(buf) < MAX_CAPTURE:
        try:
            chunk = sock.recv(2048)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def status_of(blob):
    m = re.match(rb"HTTP/[0-9.]+ (\d{3})", blob or b"")
    return int(m.group(1)) if m else None


def cmd_tcp(a):
    ip, special = resolve_host(a.host)
    # http_status is always PRESENT (null when no response) so that a required-field
    # check can distinguish "not measured" from "measured as nothing".
    rec = {"op": "tcp", "target": "%s:%s" % (a.host, a.port), "resolved_ip": ip,
           "special": special, "result": None, "errno": None, "captured": None,
           "bytes": 0, "http_status": None}
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(a.timeout)
    try:
        s.connect((ip, a.port))
        rec["result"] = "connected"
        try:
            rec["peer"] = "%s:%s" % s.getpeername()
        except OSError:
            pass
        if a.http_path:
            blob = http_get(s, a.host if not special else ip, a.http_path,
                            https=(a.port == 443))
            rec["bytes"] = len(blob)
            rec["captured"] = blob.decode("utf-8", "replace")[:MAX_CAPTURE]
            rec["http_status"] = status_of(blob)
            if rec["http_status"] and rec["http_status"] >= 400:
                rec["proxy_policy_response"] = True
    except Exception as e:
        rec["result"], rec["errno"] = classify_exc(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    rec["wall_ms"] = ms_since(t0)
    return out(rec)


def dns_query(name):
    p = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        p += bytes([len(part)]) + part.encode()
    return p + b"\x00" + struct.pack(">HH", 1, 1)


def cmd_udp(a):
    ip, special = resolve_host(a.host)
    rec = {"op": "udp", "target": "%s:%s" % (a.host, a.port), "resolved_ip": ip,
           "result": None, "errno": None, "bytes": 0, "captured": None}
    payload = dns_query(a.dns) if a.dns else b"\x00" * 16
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(a.timeout)
    try:
        s.sendto(payload, (ip, a.port))
        data, _ = s.recvfrom(1024)
        rec["result"] = "reply"
        rec["bytes"] = len(data)
        rec["captured"] = data[:256].hex()
    except Exception as e:
        rec["result"], rec["errno"] = classify_exc(e)
    finally:
        s.close()
    rec["wall_ms"] = ms_since(t0)
    return out(rec)


# ---------------------------------------------------------------- http
def split_url(url):
    m = re.match(r"^(?P<scheme>https?)://(?P<host>\[[^\]]+\]|[^/:]+)(?::(?P<port>\d+))?(?P<path>/.*)?$", url)
    if not m:
        return None
    return (m.group("scheme"), m.group("host"),
            int(m.group("port") or (443 if m.group("scheme") == "https" else 80)),
            m.group("path") or "/")


def cmd_http(a):
    parts = split_url(a.url)
    if not parts:
        return out({"op": "http", "error": "unparseable url: %s" % a.url})
    scheme, host, port, path = parts
    rec = {"op": "http", "target": a.url, "result": None, "errno": None, "captured": None,
           "bytes": 0, "via_proxy": None, "connect": bool(a.connect), "http_status": None,
           "resolved_ip": None}
    px = None
    if a.proxy:
        px = proxy_ip() if a.proxy == "auto" else split_url(a.proxy)[1] if a.proxy.startswith("http") else a.proxy
        if not px:
            return out({"op": "http", "target": a.url, "result": "skipped",
                        "skipped_reason": "no proxy detected on this segment",
                        "errno": None})
        rec["via_proxy"] = px
    dest_host = px if px else host
    dest_port = int(a.proxy_port) if px else port
    try:
        rec["resolved_ip"] = socket.gethostbyname(dest_host)
    except OSError as e:
        rec["result"], rec["errno"] = classify_exc(e)
        return out(rec)

    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(a.timeout)
    try:
        s.connect((rec["resolved_ip"], dest_port))
        rec["result"] = "connected"
        if px and a.connect:
            s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                       % (host, port, host, port)).encode())
            head = s.recv(1024)
            rec["connect_status"] = status_of(head)
            rec["http_status"] = rec["connect_status"]
            rec["captured"] = head.decode("utf-8", "replace")[:MAX_CAPTURE]
            if rec["connect_status"] == 200:
                blob = http_get(s, a.host_header or host, path, https=(scheme == "https"), sni=host)
                rec["bytes"] = len(blob)
                rec["captured"] = blob.decode("utf-8", "replace")[:MAX_CAPTURE]
                rec["http_status"] = status_of(blob)
        elif px:
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                   % (a.url, a.host_header or host))
            s.sendall(req.encode())
            blob = b""
            while len(blob) < MAX_CAPTURE:
                try:
                    chunk = s.recv(2048)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                blob += chunk
            rec["bytes"] = len(blob)
            rec["captured"] = blob.decode("utf-8", "replace")[:MAX_CAPTURE]
            rec["http_status"] = status_of(blob)
        else:
            blob = http_get(s, a.host_header or host, path,
                            https=(scheme == "https"), sni=host)
            rec["bytes"] = len(blob)
            rec["captured"] = blob.decode("utf-8", "replace")[:MAX_CAPTURE]
            rec["http_status"] = status_of(blob)
        if rec["bytes"] == 0 and rec.get("http_status") is None:
            rec["result"] = "empty-reply"
        if rec.get("http_status") and rec["http_status"] >= 400:
            rec["proxy_policy_response"] = True
    except Exception as e:
        rec["result"], rec["errno"] = classify_exc(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    rec["wall_ms"] = ms_since(t0)
    return out(rec)


# ---------------------------------------------------------------- v6 / sweep
def cmd_v6(a):
    rec = {"op": "v6", "v6_default_route": False, "v6_addresses": [],
           "v6_connect_result": None, "errno": None}
    try:
        for line in open("/proc/net/ipv6_route"):
            f = line.split()
            if len(f) > 1 and f[0] == "0" * 32 and f[1] == "00":
                rec["v6_default_route"] = True
    except OSError:
        pass
    try:
        for line in open("/proc/net/if_inet6"):
            f = line.split()
            if len(f) >= 6 and f[5] != "lo":
                rec["v6_addresses"].append(":".join(f[0][i:i + 4] for i in range(0, 32, 4)))
    except OSError:
        pass
    if socket.has_ipv6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(a.timeout)
        try:
            s.connect((a.host, a.port))
            rec["v6_connect_result"] = "connected"
        except Exception as e:
            rec["v6_connect_result"], rec["errno"] = classify_exc(e)
        finally:
            s.close()
    return out(rec)


def is_private(ip):
    o = [int(x) for x in ip.split(".")] if re.match(r"^\d+(\.\d+){3}$", ip) else None
    if not o:
        return False
    return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168)
            or (o[0] == 100 and 64 <= o[1] <= 127) or o[0] == 127)


def cmd_sweep(a):
    """Bounded reachability sweep of THIS container's own segment only."""
    mine = my_ip()
    if a.cidr != "auto":
        return out({"op": "sweep", "result": "refused",
                    "reason": "rules of engagement: sweep only runs against this container's "
                              "own segment (--cidr auto). Scanning any other network is out of scope."})
    if not mine or not is_private(mine):
        return out({"op": "sweep", "result": "refused",
                    "reason": "own address is not a private segment (%s)" % mine})
    base = ".".join(mine.split(".")[:3])
    ports = [int(p) for p in a.ports.split(",") if p]
    targets = [("%s.%d" % (base, h), port)
               for h in range(1, min(a.max_hosts, 254) + 1) for port in ports]

    def probe(t):
        ip, port = t
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            s.connect((ip, port))
            return {"ip": ip, "port": port, "self": ip == mine}
        except Exception:
            return None
        finally:
            s.close()

    live, scanned = [], len(targets)
    try:                                   # parallel: a serial sweep costs ~60s of wall clock
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=32) as pool:
            live = [r for r in pool.map(probe, targets) if r]
    except ImportError:
        live = [r for r in (probe(t) for t in targets) if r]
    return out({"op": "sweep", "my_ip": mine, "segment": base + ".0/24",
                "live_hosts": live, "n_live": len(live), "n_scanned": scanned,
                "ports": ports, "max_hosts": a.max_hosts})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("topology")
    p = sub.add_parser("resolve"); p.add_argument("names", nargs="+")

    p = sub.add_parser("tcp")
    p.add_argument("--host", required=True); p.add_argument("--port", type=int, required=True)
    p.add_argument("--http-path", default=""); p.add_argument("--timeout", type=float, default=TIMEOUT)

    p = sub.add_parser("udp")
    p.add_argument("--host", required=True); p.add_argument("--port", type=int, required=True)
    p.add_argument("--dns", default=""); p.add_argument("--timeout", type=float, default=4.0)

    p = sub.add_parser("http")
    p.add_argument("--url", required=True); p.add_argument("--proxy", default="")
    p.add_argument("--proxy-port", default=3128); p.add_argument("--connect", action="store_true")
    p.add_argument("--host-header", default=""); p.add_argument("--timeout", type=float, default=TIMEOUT)

    p = sub.add_parser("v6")
    p.add_argument("--host", default="2606:4700:4700::1111"); p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=float, default=TIMEOUT)

    p = sub.add_parser("sweep")
    p.add_argument("--cidr", default="auto"); p.add_argument("--ports", default="22,80,443,3128")
    p.add_argument("--max-hosts", type=int, default=32)

    a = ap.parse_args()
    fn = {"topology": cmd_topology, "resolve": cmd_resolve, "tcp": cmd_tcp, "udp": cmd_udp,
          "http": cmd_http, "v6": cmd_v6, "sweep": cmd_sweep}.get(a.cmd)
    if not fn:
        ap.print_help()
        return 2
    try:
        return fn(a)
    except Exception as exc:
        return out({"op": a.cmd, "error": "%s: %s" % (type(exc).__name__, exc)})


if __name__ == "__main__":
    sys.exit(main())
