#!/usr/bin/env python3
"""Non-TCP egress probe for the sandy egress proxy.

Launch the container with SANDY_EGRESS_PROXY=1 (and again =2) on the host; INSIDE
the container the resolved posture shows up as SANDY_EGRESS_MODE (off/permissive/
strict) and, when the proxy is on, SANDY_PROXY_IP. (Older sandy didn't forward the
mode — confirm via the launch banner / resolv ExtServers if SANDY_EGRESS_MODE is
unset.) This answers: does the --internal topology drop UDP/QUIC/ICMP/IPv6 the way
the TCP-only proxy design assumes? The decisive line is the UDP-DNS result.

Expected in =1/=2 (backstop holds): TCP-to-allowed WORKS (via the proxy), every
UDP attempt is BLOCKED, no IPv6 default route. Any "UDP ... -> REPLY" is a real
egress leak (and a DNS-exfil channel) — a genuine finding.
"""
import os, socket, struct, subprocess

def dns_query(name="example.com"):
    p = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        p += bytes([len(part)]) + part.encode()
    return p + b"\x00" + struct.pack(">HH", 1, 1)

print("== environment ==")
print("  SANDY_EGRESS_MODE =", os.environ.get("SANDY_EGRESS_MODE", "(unset)"))
print("  SANDY_PROXY_IP    =", os.environ.get("SANDY_PROXY_IP", "(unset)"))
try:
    rc = open("/etc/resolv.conf").read()
    for line in rc.splitlines():
        if "ExtServers" in line or line.startswith("nameserver"):
            print("  resolv:", line.strip())
except Exception as e:
    print("  resolv: ?", e)

print("== TCP control (an allowed host should work via the proxy) ==")
for host, port in (("api.github.com", 443),):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((host, port))
        print(f"  TCP {host}:{port} -> CONNECTED via {s.getpeername()[0]} "
              f"(proxy IP here = transparent intercept, expected)")
    except Exception as e:
        print(f"  TCP {host}:{port} -> {type(e).__name__}: {e}")
    finally:
        s.close()

print("== UDP egress (THE test — should be BLOCKED in =1/=2) ==")
# (a) raw DNS straight to public resolvers, bypassing the proxy resolver
for ip in ("8.8.8.8", "1.1.1.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    try:
        s.sendto(dns_query(), (ip, 53))
        data, _ = s.recvfrom(128)
        print(f"  UDP {ip}:53  -> REPLY ({len(data)}B) *** EGRESS LEAK ***")
    except Exception as e:
        print(f"  UDP {ip}:53  -> blocked/timeout ({type(e).__name__}) [good]")
    finally:
        s.close()
# (b) raw UDP to a public IP on 443 (the QUIC/HTTP-3 port)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    s.sendto(b"\x00" * 16, ("1.1.1.1", 443))
    data, _ = s.recvfrom(64)
    print(f"  UDP 1.1.1.1:443 -> got {len(data)}B back *** possible QUIC-path LEAK ***")
except Exception as e:
    print(f"  UDP 1.1.1.1:443 -> no reply ({type(e).__name__}) [good — QUIC can't egress]")
finally:
    s.close()

print("== IPv6 ==")
try:
    out = subprocess.run(["sh", "-c", "ip -6 route show default 2>/dev/null"],
                         capture_output=True, text=True, timeout=5).stdout.strip()
    print("  v6 default route:", out if out else "(none) [good]")
except Exception as e:
    print("  v6 route check failed:", e)
print("\nVerdict: all UDP 'blocked' + TCP-allowed 'CONNECTED' + no v6 route "
      "=> --internal is the protocol-agnostic backstop the design assumes.")
