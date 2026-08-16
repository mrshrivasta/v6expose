#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 V6EXPOSE
 IPv6 Exposure Checker - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 THE PROBLEM: THERE IS NO NAT IN IPv6

   On IPv4 most machines sit behind NAT. A service bound to 0.0.0.0 is reachable
   from the local network and nothing else, because the router has no idea where
   to send an unsolicited packet from outside. That protection was never a
   decision anybody made - it is a side effect of running out of addresses - and
   an enormous amount of software has been deployed safely because of it.

   IPv6 has enough addresses that every machine gets a globally routable one.
   There is no NAT, and there is nothing between that service and the internet
   except a firewall somebody has to have written. The same daemon, the same
   config file, the same bind to "all interfaces" - and now it answers the world.

   The second half of the problem is that firewalls are two firewalls. Rules
   written with iptables do not apply to IPv6; ip6tables is a separate table with
   a separate default policy. A machine can be carefully locked down on IPv4 and
   wide open on IPv6, and nothing about it looks wrong.

 WHAT THIS CHECKS
   LISTENERS   Every IPv6 socket accepting connections, and whether it is bound
               to loopback, to a link-local address, or to :: - which means every
               address the machine has, including the globally routable ones.
   ASYMMETRY   IPv4 rules against IPv6 rules. A large gap is the single most
               useful thing in this report.
   REACHABILITY Whether the machine actually holds a globally routable address,
               because a listener on :: is only exposed if there is a global
               address for it to be exposed on.
   TRANSITION  6to4, Teredo and similar tunnels, which carry IPv6 inside IPv4 and
               routinely pass straight through a firewall that only inspects IPv4.
   SETTINGS    Forwarding, router advertisement acceptance, and redirects.

 *** REACHABLE FROM HERE IS NOT REACHABLE FROM THE INTERNET ***
   The caveat that governs the whole tool. This runs ON the machine and looks at
   what the machine is offering. It cannot see what your upstream router, your
   ISP or your cloud provider's security group does with a packet arriving from
   outside - and many of them drop unsolicited IPv6 by default.

   So a finding here means "this machine is offering a service on an address the
   internet can route to". Whether a packet actually arrives is a question only a
   test FROM OUTSIDE can answer, and this tool has no outside vantage point. It
   never claims one, and it never contacts anything to find out.

 *** A LISTENING SOCKET IS NOT A VULNERABILITY ***
   Every useful machine listens for something. This reports attack surface, not
   flaws: a well-patched SSH daemon on a global address is exposed and probably
   fine, while a forgotten debug server on the same address is neither.

 READ-ONLY AND OFFLINE
   It reads /proc and /sys and runs firewall commands in list-only mode. It
   changes no rule, closes no socket and sets no sysctl. It makes no network
   connection of any kind. Where a fix exists, it is printed for you to run.

 LEGAL DISCLAIMER
   Provided "as is" with no warranty; the author accepts no liability for any
   loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import glob
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone

APP_NAME = "V6Expose"
APP_SHORT = "V6EXPOSE"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("V6EXPOSE_DB", "v6expose.db")

NO_NAT = (
    "There is no NAT in IPv6. On IPv4 a service bound to all interfaces is usually protected "
    "by a router that has nowhere to send an unsolicited packet - protection nobody chose, "
    "and which an enormous amount of software has been deployed safely because of. In IPv6 "
    "every machine has a globally routable address and that side effect is gone."
)
NOT_FROM_OUTSIDE = (
    "This runs ON the machine and reports what the machine is offering. It cannot see what "
    "your router, ISP or cloud security group does with a packet arriving from outside, and "
    "many drop unsolicited IPv6 by default. Whether a packet actually arrives is a question "
    "only a test FROM OUTSIDE can answer, and this tool has no outside vantage point."
)
NOT_A_VULNERABILITY = (
    "A listening socket is not a vulnerability. Every useful machine listens for something. "
    "This reports attack surface, not flaws - a patched SSH daemon on a global address is "
    "exposed and probably fine; a forgotten debug server on the same address is not."
)
DISCLAIMER_SHORT = (
    "Read-only and offline. Finds services reachable over IPv6 and compares your IPv4 rules "
    "against your IPv6 rules. Reachable from here is not the same as reachable from the "
    "internet - only a test from outside can tell you that."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    REACHABLE FROM HERE IS NOT REACHABLE FROM THE INTERNET. This runs on the machine and
    reports what the machine offers. It cannot see what your upstream router, your ISP or
    your cloud provider's security group does with a packet arriving from outside, and many
    of them drop unsolicited IPv6 by default. A finding means "this machine is offering a
    service on an address the internet can route to" - whether a packet actually arrives is a
    question only a test from outside can answer, and this tool has no outside vantage point.
    It never claims one and it never contacts anything to find out.

    A LISTENING SOCKET IS NOT A VULNERABILITY. Every useful machine listens for something.
    This reports attack surface, not flaws.

    THERE IS NO NAT IN IPv6. On IPv4 a service bound to all interfaces is usually protected by
    a router with nowhere to send an unsolicited packet. That protection was a side effect of
    address exhaustion rather than a decision, and in IPv6 it is gone.

    FIREWALLS ARE TWO FIREWALLS. Rules written with iptables do not apply to IPv6. A machine
    can be carefully locked down on IPv4 and wide open on IPv6, and nothing about it looks
    wrong from the IPv4 side.

    ABSENCE OF IPv6 IS NOT A CLEAN RESULT. If IPv6 is unavailable or disabled, nothing was
    checked - which is reported as such and not as a pass. The same applies when firewall
    tooling is missing: unknown rules are reported as unknown, never as no rules.

    READ-ONLY AND OFFLINE. It reads /proc and /sys and runs firewall commands in list-only
    mode. It changes no rule, closes no socket and sets no sysctl, and it makes no network
    connection of any kind.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 35.0, "high": 18.0, "medium": 8.0, "low": 3.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}
EXPOSURE_COLOR = {"internet": "#e5484d", "network": "#f76808", "link": "#ffb224",
                  "local": "#30a46c", "unknown": "#8b8f9b"}


def risk_band(score: float, checked: bool = True) -> tuple[str, str]:
    # "not checked" must never render as "nothing exposed". A score of zero
    # because nothing could be examined is a different statement from a score of
    # zero because nothing was found, and this tool exists partly to keep those
    # apart.
    if not checked:
        return "not checked", "#8b8f9b"
    if score >= 35:
        return "exposed to the internet", "#e5484d"
    if score >= 18:
        return "worth closing down", "#f76808"
    if score >= 8:
        return "worth a look", "#ffb224"
    if score > 0:
        return "minor notes", "#3e9dd8"
    return "nothing exposed", "#30a46c"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def shorten(s, n=90) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        delta = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except Exception:
        return "-"
    if delta < 0:
        return "in the future"
    d, r = divmod(int(delta), 86400)
    h, r = divmod(r, 3600)
    m, _s = divmod(r, 60)
    if d:
        return f"{d}d {h}h ago"
    if h:
        return f"{h}h {m}m ago"
    return f"{m}m ago"


def read_file(path: str) -> str | None:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_int(path: str) -> int | None:
    v = read_file(path)
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def F(category, title, severity, description, evidence="", advice="", fix=""):
    """A finding. 'fix' is a command for the person to run - this tool changes
    nothing, so anything actionable is printed rather than applied."""
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:2500],
            "advice": advice, "fix": fix}


class Result:
    def __init__(self, name: str):
        self.name = name
        self.data = None
        self.status = "ok"
        self.detail = ""

    def unavailable(self, detail):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


# =============================================================================
# SECTION 2 - What an address means for exposure
#   Pure arithmetic on the address. No privileges, no IPv6 stack, no network -
#   which is what makes it exactly testable and usable on a value pasted in from
#   another machine.
# =============================================================================

TRANSITION_PREFIXES = [
    ("2002::/16", "6to4",
     "carries IPv6 inside IPv4 protocol 41. It is deprecated by RFC 7526 and it "
     "routinely passes straight through a firewall that only inspects IPv4"),
    ("2001:0000::/32", "Teredo",
     "tunnels IPv6 over UDP specifically to get through NAT, which means it also gets "
     "through a lot of firewalls. It is exactly the sort of connectivity you did not "
     "ask for"),
    ("64:ff9b::/96", "NAT64",
     "a translation prefix, so traffic here is being rewritten to IPv4 somewhere"),
    ("::ffff:0:0/96", "IPv4-mapped",
     "an IPv4 address wearing an IPv6 shape. A socket bound to :: accepts these, which "
     "is how one listener ends up serving both protocols"),
    ("2001:20::/28", "ORCHIDv2", "an experimental identifier range, not ordinary traffic"),
    ("100::/64", "discard-only", "a black hole prefix"),
]


def address_scope(address: str) -> dict:
    """Where an address can be reached from, and what that costs you."""
    out = {"address": address, "valid": False, "scope": "unknown", "reachable": "unknown",
           "why": "", "transition": None, "error": None}
    try:
        addr = ipaddress.IPv6Address(address.split("%")[0].split("/")[0])
    except ValueError as e:
        out["error"] = f"'{address}' is not an IPv6 address: {e}"
        return out
    out["valid"] = True
    out["compressed"] = addr.compressed

    for cidr, name, why in TRANSITION_PREFIXES:
        if addr in ipaddress.IPv6Network(cidr):
            out["transition"] = {"name": name, "prefix": cidr, "why": why}
            break

    if addr.is_unspecified:
        out.update(scope="unspecified", reachable="all",
                   why=("the wildcard address. A socket bound here accepts connections on "
                        "EVERY address this machine has, including globally routable ones"))
    elif addr.is_loopback:
        out.update(scope="loopback", reachable="local",
                   why="this machine only; nothing off the machine can reach it")
    elif addr.is_link_local:
        out.update(scope="link-local", reachable="link",
                   why=("reachable from this network segment only. A router will not "
                        "forward it, so the internet cannot reach it"))
    elif addr in ipaddress.IPv6Network("fc00::/7"):
        out.update(scope="unique-local", reachable="network",
                   why=("private addressing. It routes inside your network but not on the "
                        "internet, which makes it the IPv6 equivalent of an RFC 1918 "
                        "address"))
    elif addr.is_multicast:
        out.update(scope="multicast", reachable="link",
                   why="a group address rather than a host address")
    elif addr in ipaddress.IPv6Network("2000::/3"):
        out.update(scope="global", reachable="internet",
                   why=("globally routable. There is no NAT in front of this - a service "
                        "bound here is offered to the internet"))
        if addr in ipaddress.IPv6Network("2001:db8::/32"):
            out["documentation"] = True
            out["why"] += (". This is the RFC 3849 documentation range, so on a real "
                           "machine it would be an example rather than live")
    else:
        out.update(scope="other", reachable="unknown",
                   why="outside the ranges this tool recognises")
    return out


# Ports worth naming when they appear. Not a threat list - it exists so a finding
# can say "this is a database" rather than "port 5432".
NOTABLE_PORTS = {
    22: ("SSH", "high", "remote shell access - the first thing anything scanning will try"),
    23: ("Telnet", "critical", "unencrypted remote shell; credentials cross the wire in "
                               "clear text"),
    21: ("FTP", "high", "usually unencrypted"),
    25: ("SMTP", "medium", "mail; an open relay is a serious problem"),
    53: ("DNS", "high", "an open resolver is used for amplification attacks"),
    80: ("HTTP", "medium", "unencrypted web"),
    111: ("rpcbind", "high", "used for amplification and it enumerates other services"),
    139: ("NetBIOS", "high", "file sharing; historically a rich source of exposure"),
    445: ("SMB", "critical", "file sharing. Exposing this to the internet is how a great "
                             "deal of ransomware arrives"),
    389: ("LDAP", "high", "directory services, often with credentials behind it"),
    443: ("HTTPS", "low", "encrypted web"),
    1433: ("MS SQL", "critical", "a database"),
    1521: ("Oracle", "critical", "a database"),
    2049: ("NFS", "critical", "file sharing"),
    2375: ("Docker API", "critical", "unauthenticated Docker control is root on the host"),
    2376: ("Docker TLS", "high", "Docker control"),
    3000: ("a development server", "high", "commonly a framework's debug server"),
    3306: ("MySQL", "critical", "a database"),
    3389: ("RDP", "critical", "remote desktop; heavily scanned and brute-forced"),
    4444: ("a port used by exploitation frameworks", "high",
           "commonly a reverse shell listener"),
    5000: ("a development server", "high", "commonly Flask or similar in debug mode"),
    5432: ("PostgreSQL", "critical", "a database"),
    5601: ("Kibana", "high", "a dashboard, often with no authentication"),
    5900: ("VNC", "critical", "remote desktop, often with weak or no authentication"),
    6379: ("Redis", "critical", "a database that historically had no authentication at all"),
    8080: ("HTTP alternative", "medium", "often an admin interface"),
    8000: ("a development server", "high", "often Python's http.server"),
    8443: ("HTTPS alternative", "low", "often an admin interface"),
    9200: ("Elasticsearch", "critical", "a database, historically unauthenticated"),
    9090: ("a dashboard", "medium", "often Prometheus or Cockpit"),
    11211: ("memcached", "critical", "unauthenticated, and a major amplification vector"),
    27017: ("MongoDB", "critical", "a database, historically unauthenticated"),
}

TCP_STATES = {"01": "ESTABLISHED", "0A": "LISTEN", "02": "SYN_SENT", "06": "TIME_WAIT",
              "07": "CLOSE", "08": "CLOSE_WAIT"}


def _decode_v6(hexaddr: str) -> tuple[str, int]:
    """/proc/net/tcp6 stores the address as four little-endian 32-bit words."""
    host, _, port = hexaddr.partition(":")
    port = int(port, 16) if port else 0
    if len(host) != 32:
        return host, port
    parts = [host[i:i + 8] for i in range(0, 32, 8)]
    raw = b"".join(struct.pack("<I", int(p, 16)) for p in parts)
    return socket.inet_ntop(socket.AF_INET6, raw), port


def socket_inode_map() -> tuple[dict, int]:
    """inode -> process, by walking /proc/*/fd. Returns how many were denied so
    the report can say coverage is limited rather than showing fewer sockets."""
    out: dict[int, dict] = {}
    denied = 0
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return out, 0
    for pid in pids:
        fddir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fddir)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        info = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if info is None:
                info = _process_info(int(pid))
            out[inode] = info
    return out, denied


def _process_info(pid: int) -> dict:
    out = {"pid": pid, "name": None, "exe": None, "cmdline": None, "user": None}
    try:
        with open(f"/proc/{pid}/stat") as fh:
            raw = fh.read()
        out["name"] = raw[raw.find("(") + 1:raw.rfind(")")]
    except OSError:
        pass
    try:
        out["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            out["cmdline"] = fh.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip() or None
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    try:
                        import pwd
                        out["user"] = pwd.getpwuid(uid).pw_name
                    except Exception:
                        out["user"] = str(uid)
                    break
    except OSError:
        pass
    return out


def read_v6_listeners() -> Result:
    """Every IPv6 socket accepting connections, with the process that owns it."""
    r = Result("listeners")
    r.data = {"listeners": [], "denied": 0, "owner_coverage": 0.0,
              "sources": [], "v4_listeners": []}
    if not sys.platform.startswith("linux"):
        return r.unavailable(
            f"listeners are read from /proc/net, which is Linux-only; this is "
            f"{sys.platform}. Nothing was checked.")
    if not os.path.exists("/proc/net/tcp6") and not os.path.exists("/proc/net/udp6"):
        return r.unavailable(
            "neither /proc/net/tcp6 nor /proc/net/udp6 exists, so IPv6 is not available on "
            "this machine. Nothing was checked - which is NOT the same as nothing being "
            "exposed.")
    inodes, denied = socket_inode_map()
    r.data["denied"] = denied
    owned = total = 0
    for fname, proto in (("tcp6", "tcp6"), ("udp6", "udp6")):
        path = f"/proc/net/{fname}"
        if not os.path.exists(path):
            continue
        r.data["sources"].append(path)
        try:
            with open(path) as fh:
                next(fh, None)
                for raw in fh:
                    f = raw.split()
                    if len(f) < 10:
                        continue
                    try:
                        local_ip, local_port = _decode_v6(f[1])
                        remote_ip, _remote_port = _decode_v6(f[2])
                        state = TCP_STATES.get(f[3].upper(), f[3])
                        inode = int(f[9])
                    except (ValueError, IndexError):
                        continue
                    listening = (state == "LISTEN" if proto == "tcp6"
                                 else remote_ip in ("::", "0.0.0.0"))
                    if not listening:
                        continue
                    total += 1
                    owner = inodes.get(inode)
                    if owner:
                        owned += 1
                    scope = address_scope(local_ip)
                    port_info = NOTABLE_PORTS.get(local_port)
                    r.data["listeners"].append({
                        "proto": proto, "address": local_ip, "port": local_port,
                        "state": state, "inode": inode,
                        "pid": (owner or {}).get("pid"),
                        "process": (owner or {}).get("name"),
                        "exe": (owner or {}).get("exe"),
                        "cmdline": (owner or {}).get("cmdline"),
                        "user": (owner or {}).get("user"),
                        "scope": scope["scope"], "reachable": scope["reachable"],
                        "scope_why": scope["why"],
                        "transition": scope.get("transition"),
                        "service": port_info[0] if port_info else None,
                        "port_severity": port_info[1] if port_info else None,
                        "port_why": port_info[2] if port_info else None,
                        "key": f"{proto}|{local_ip}|{local_port}",
                    })
        except OSError as e:
            r.partial(f"{path} could not be read: {e}")

    # the same ports on IPv4, so the asymmetry can be shown
    for fname, proto in (("tcp", "tcp"), ("udp", "udp")):
        path = f"/proc/net/{fname}"
        if not os.path.exists(path):
            continue
        try:
            with open(path) as fh:
                next(fh, None)
                for raw in fh:
                    f = raw.split()
                    if len(f) < 4:
                        continue
                    state = TCP_STATES.get(f[3].upper(), f[3])
                    if proto == "tcp" and state != "LISTEN":
                        continue
                    try:
                        port = int(f[1].partition(":")[2], 16)
                    except ValueError:
                        continue
                    r.data["v4_listeners"].append({"proto": proto, "port": port})
        except OSError:
            continue

    r.data["owner_coverage"] = round(100.0 * owned / total, 1) if total else 0.0
    if denied:
        r.partial(f"{denied} process(es) could not be inspected without privileges, so some "
                  f"listeners have no owner shown - a coverage limit, not evidence of "
                  f"hiding")
    return r


def read_v6_addresses() -> Result:
    """Which addresses exist, because a listener on :: is only exposed to the
    internet if a globally routable address exists for it to be exposed on."""
    r = Result("addresses")
    r.data = {"addresses": [], "has_global": False, "has_unique_local": False}
    path = "/proc/net/if_inet6"
    if not os.path.exists(path):
        return r.unavailable(
            f"{path} does not exist, so this machine has no IPv6 addresses and IPv6 is "
            f"effectively off. Nothing was checked - which is NOT the same as nothing "
            f"being exposed.")
    try:
        with open(path) as fh:
            for raw in fh:
                f = raw.split()
                if len(f) < 6:
                    continue
                hexaddr, _idx, plen, _scope_id, flags, device = f[:6]
                try:
                    addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(hexaddr))
                except (ValueError, OSError):
                    continue
                scope = address_scope(addr)
                r.data["addresses"].append({
                    "address": addr, "prefix_length": int(plen, 16),
                    "device": device, "flags": flags,
                    "scope": scope["scope"], "reachable": scope["reachable"],
                    "why": scope["why"], "transition": scope.get("transition"),
                })
                if scope["scope"] == "global":
                    r.data["has_global"] = True
                if scope["scope"] == "unique-local":
                    r.data["has_unique_local"] = True
    except OSError as e:
        return r.unavailable(f"{path} could not be read: {e}")
    if not r.data["addresses"]:
        r.partial("no IPv6 addresses are configured")
    return r


# =============================================================================
# SECTION 3 - The two firewalls
#   Rules written with iptables do not apply to IPv6. This is the single most
#   useful comparison in the tool, and the one most likely to surprise somebody.
#
#   Every command here is LIST-ONLY. Nothing is added, removed or flushed, and
#   when a tool is missing that is reported as "unknown" rather than "no rules" -
#   the difference matters enormously.
# =============================================================================

FIREWALL_PROBES = [
    ("nft", ["nft", "-a", "list", "ruleset"], "nftables"),
    ("ip6tables", ["ip6tables", "-S"], "ip6tables"),
    ("iptables", ["iptables", "-S"], "iptables"),
    ("ufw", ["ufw", "status", "verbose"], "ufw"),
]


def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int | None, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", "not installed"
    except PermissionError:
        return None, "", "permission denied"
    except subprocess.TimeoutExpired:
        return None, "", "timed out"
    except Exception as e:
        return None, "", str(e)


def _count_rules(text: str, kind: str) -> tuple[int, str | None]:
    """Rules and the INPUT policy. The policy is what decides the default."""
    rules = 0
    policy = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if kind in ("iptables", "ip6tables"):
            if s.startswith("-P "):
                parts = s.split()
                if len(parts) >= 3 and parts[1] == "INPUT":
                    policy = parts[2]
                continue
            if s.startswith("-A "):
                rules += 1
        elif kind == "nftables":
            if "policy" in s and "hook input" in s:
                m = re.search(r"policy\s+(\w+)", s)
                if m:
                    policy = m.group(1).upper()
            elif s and not s.startswith(("table", "chain", "}", "{")):
                rules += 1
        elif kind == "ufw":
            if s.lower().startswith("status:"):
                policy = s.split(":", 1)[1].strip()
            elif re.match(r"^\S+\s+(ALLOW|DENY|REJECT|LIMIT)", s):
                rules += 1
    return rules, policy


def read_firewalls() -> Result:
    """What is filtering IPv4, what is filtering IPv6, and whether they agree."""
    r = Result("firewall")
    r.data = {"probes": {}, "v4_rules": None, "v6_rules": None,
              "v4_policy": None, "v6_policy": None, "available": [],
              "missing": [], "asymmetry": None}
    for key, cmd, kind in FIREWALL_PROBES:
        code, out, err = _run(cmd)
        entry = {"command": " ".join(cmd), "kind": kind, "available": code is not None,
                 "returncode": code, "error": err.strip()[:200] or None,
                 "rules": None, "policy": None, "output": out[:4000]}
        if code is None:
            entry["detail"] = f"{key} is {err.strip() or 'unavailable'}"
            r.data["missing"].append(key)
        elif code != 0:
            entry["detail"] = (f"{key} exited {code}: {err.strip()[:120]}"
                               + (" - listing rules usually needs root"
                                  if not is_root() else ""))
            r.data["missing"].append(key)
        else:
            rules, policy = _count_rules(out, kind)
            entry.update(rules=rules, policy=policy,
                         detail=f"{rules} rule(s)"
                                + (f", INPUT policy {policy}" if policy else ""))
            r.data["available"].append(key)
            if key == "ip6tables":
                r.data["v6_rules"], r.data["v6_policy"] = rules, policy
            elif key == "iptables":
                r.data["v4_rules"], r.data["v4_policy"] = rules, policy
        r.data["probes"][key] = entry

    if not r.data["available"]:
        return r.unavailable(
            "no firewall tool could be run (" + ", ".join(r.data["missing"]) + "), so the "
            "rules are UNKNOWN. That is not the same as there being no rules - it means "
            "this check did not happen. Running as root, or installing iptables/nft, would "
            "let it run.")

    v4, v6 = r.data["v4_rules"], r.data["v6_rules"]
    if v4 is not None and v6 is not None:
        r.data["asymmetry"] = v4 - v6
    if "nft" in r.data["available"] and (v4 is None or v6 is None):
        r.partial("nftables is in use, where one ruleset can cover both protocols - the "
                  "iptables/ip6tables comparison may not apply here")
    return r


def read_settings() -> Result:
    """Sysctls that change what this machine accepts or forwards."""
    r = Result("settings")
    r.data = {"settings": {}, "available": False}
    base = "/proc/sys/net/ipv6"
    if not os.path.isdir(base):
        return r.unavailable(
            f"{base} does not exist, so the IPv6 stack is not loaded. Nothing was checked.")
    r.data["available"] = True
    checks = [
        ("conf/all/forwarding", 0, "high",
         "This machine forwards IPv6 between interfaces - it is acting as a router. On a "
         "workstation that is almost never intended, and it turns the machine into a path "
         "into whatever it is connected to."),
        ("conf/all/accept_ra", None, None,
         "Whether router advertisements are accepted. Accepting them means anything on the "
         "segment can set this machine's default route - which is ordinary on a client and "
         "wrong on a router."),
        ("conf/all/accept_redirects", 0, "medium",
         "ICMPv6 redirects let another machine change this one's routing for a destination. "
         "Accepting them is a routine way to divert traffic."),
        ("conf/all/accept_source_route", 0, "medium",
         "Source routing lets the sender choose the path, which is used to reach places "
         "that should not be reachable. It should be off."),
        ("conf/all/disable_ipv6", None, None,
         "Whether IPv6 is switched off entirely on this machine."),
        ("conf/default/accept_ra", None, None,
         "The default for interfaces that appear later."),
        ("bindv6only", None, None,
         "When 0, a socket bound to :: also accepts IPv4 connections as v4-mapped "
         "addresses - so one listener serves both protocols and an IPv4 firewall rule does "
         "not cover the IPv6 half."),
    ]
    for path, want, sev, why in checks:
        full = os.path.join(base, path)
        value = read_int(full)
        r.data["settings"][path] = {
            "path": full, "value": value, "expected": want, "severity": sev,
            "why": why, "present": value is not None,
            "mismatch": (want is not None and value is not None and value != want),
        }
    fwd4 = read_int("/proc/sys/net/ipv4/ip_forward")
    r.data["settings"]["ipv4/ip_forward"] = {
        "path": "/proc/sys/net/ipv4/ip_forward", "value": fwd4, "expected": 0,
        "severity": "low", "present": fwd4 is not None,
        "mismatch": fwd4 is not None and fwd4 != 0,
        "why": "IPv4 forwarding, shown only so the two protocols can be compared."}
    missing = [k for k, v in r.data["settings"].items() if not v["present"]]
    if missing:
        r.partial(f"{len(missing)} setting(s) were not present on this kernel")
    return r


# =============================================================================
# SECTION 4 - Findings
# =============================================================================

def analyse(listeners: Result, addresses: Result, firewall: Result, settings: Result,
            baseline: dict) -> list[dict]:
    out: list[dict] = []
    approved = {k for k, v in baseline.items() if v.get("approved")}

    # ---- is there any IPv6 at all ----
    if listeners.status == "unavailable" and addresses.status == "unavailable":
        out.append(F("IPv6", "IPv6 is not available on this machine", "info",
                     addresses.detail or listeners.detail, "",
                     "Nothing below was checked. That is NOT the same as nothing being "
                     "exposed - it means this tool could not look. If you expected IPv6 to "
                     "be working, that is itself worth knowing."))
        return out

    has_global = (addresses.data or {}).get("has_global", False)
    global_addrs = [a for a in (addresses.data or {}).get("addresses", [])
                    if a["scope"] == "global"]

    if addresses.status == "ok":
        by_scope: dict[str, list] = {}
        for a in addresses.data["addresses"]:
            by_scope.setdefault(a["scope"], []).append(a)
        out.append(F("Addresses", f"{len(addresses.data['addresses'])} IPv6 address(es): "
                     + ", ".join(f"{len(v)} {k}" for k, v in sorted(by_scope.items())),
                     "info",
                     "What this machine can be reached on.",
                     "\n".join(f"  {a['address']}/{a['prefix_length']} on {a['device']} "
                               f"({a['scope']})"
                               for a in addresses.data["addresses"][:10]),
                     ("A globally routable address is present, so anything bound to :: is "
                      "offered to the internet - there is no NAT in the way."
                      if has_global else
                      "No globally routable address, so a listener on :: is reachable from "
                      "this network but not directly from the internet.")))
        for a in addresses.data["addresses"]:
            if a.get("transition"):
                t = a["transition"]
                out.append(F("Transition", f"A {t['name']} address is configured", "high",
                             f"{a['address']} falls in {t['prefix']}.",
                             f"on {a['device']}",
                             f"{t['why'].capitalize()}. Connectivity you did not "
                             f"deliberately configure is worth removing - it is a path in "
                             f"and out that your IPv4 firewall never sees.",
                             fix=(f"# find what configured it, then disable the tunnel\n"
                                  f"ip -6 addr show dev {a['device']}\n"
                                  f"ip link show type sit")))

    # ---- the listeners, which are the point ----
    if listeners.status == "unavailable":
        out.append(F("Listeners", "Listening sockets could not be read", "info",
                     listeners.detail, "",
                     "Nothing was checked here - not the same as nothing listening."))
    else:
        rows = listeners.data["listeners"]
        if not rows:
            out.append(F("Listeners", "Nothing is listening on IPv6", "info",
                         f"Read from {', '.join(listeners.data['sources'])}.", "",
                         "No IPv6 attack surface from this machine's own services. Note "
                         "that a service can start at any time; this is one moment."))
        else:
            wildcard = [x for x in rows if x["scope"] == "unspecified"]
            local = [x for x in rows if x["reachable"] == "local"]
            link = [x for x in rows if x["reachable"] == "link"]
            explicit_global = [x for x in rows if x["scope"] == "global"]

            internet_facing = [x for x in (wildcard if has_global else [])
                               + explicit_global if x["key"] not in approved]
            if internet_facing:
                worst = "critical" if any(
                    x.get("port_severity") == "critical" for x in internet_facing) \
                    else "high"
                out.append(F("Exposure", f"{len(internet_facing)} service(s) are offered on "
                             f"a globally routable address", worst,
                             "These sockets accept connections on an address the internet "
                             "can route to, with no NAT in front of them.",
                             "\n".join(_listener_line(x) for x in internet_facing[:12]),
                             NO_NAT + " " + NOT_FROM_OUTSIDE,
                             fix="# bind a service to loopback instead of all interfaces,\n"
                                 "# or add an ip6tables rule:\n"
                                 "ip6tables -A INPUT -p tcp --dport PORT -j DROP"))
                for x in internet_facing:
                    if x.get("port_severity") in ("critical", "high") \
                            and x["key"] not in approved:
                        out.append(F("Exposure", f"{x['service']} is reachable over IPv6 "
                                     f"on port {x['port']}",
                                     x["port_severity"],
                                     f"{x.get('process') or 'an unidentified process'} is "
                                     f"listening on {x['address']}:{x['port']}.",
                                     _listener_line(x),
                                     f"Port {x['port']} is {x['service']} - "
                                     f"{x['port_why']}. On IPv4 this was probably behind "
                                     f"NAT; on IPv6 it is not."))
            elif wildcard and not has_global:
                out.append(F("Exposure", f"{len(wildcard)} service(s) are bound to :: but "
                             f"there is no global address", "medium",
                             "These accept connections on every address this machine has, "
                             "and none of those is globally routable right now.",
                             "\n".join(_listener_line(x) for x in wildcard[:10]),
                             "They are reachable from this network but not directly from "
                             "the internet. That changes the moment a global address is "
                             "assigned - by a router advertisement, for instance - without "
                             "anything on this machine being reconfigured."))
            if link:
                out.append(F("Listeners", f"{len(link)} service(s) on a link-local address",
                             "low",
                             "Reachable from this network segment only.",
                             "\n".join(_listener_line(x) for x in link[:8]),
                             "A router will not forward these, so the internet cannot reach "
                             "them. Anything on the same segment can."))
            if local:
                out.append(F("Listeners", f"{len(local)} service(s) on loopback only",
                             "info",
                             "Reachable from this machine and nowhere else.",
                             "\n".join(_listener_line(x) for x in local[:8]),
                             "This is the safe way to run a service that only needs to be "
                             "reached locally."))
            approved_rows = [x for x in rows if x["key"] in approved]
            if approved_rows:
                out.append(F("Listeners", f"{len(approved_rows)} approved listener(s)",
                             "info", "You have marked these as intended.",
                             "\n".join(_listener_line(x) for x in approved_rows[:8]),
                             "Listed for completeness."))

            # the same port on both protocols, or only on one
            v4_ports = {x["port"] for x in listeners.data["v4_listeners"]}
            # Only ports that leave this machine matter here. A loopback-only
            # service is unreachable on either protocol, so calling it "IPv6 only"
            # is true but says nothing about exposure.
            reachable_ports = {x["port"] for x in rows if x["reachable"] != "local"}
            v6_only = sorted(reachable_ports - v4_ports)
            if v6_only:
                out.append(F("Asymmetry", f"{len(v6_only)} port(s) listen on IPv6 but not "
                             f"IPv4", "medium",
                             "These services are reachable over IPv6 only.",
                             "ports: " + ", ".join(str(p) for p in v6_only[:20]),
                             "An IPv4-only port scan or firewall audit would not see these "
                             "at all, which is exactly how IPv6 exposure goes unnoticed."))
            if listeners.data["denied"]:
                out.append(F("Listeners", f"{listeners.data['denied']} process(es) could "
                             f"not be inspected", "low",
                             f"Owner coverage is {listeners.data['owner_coverage']}%.",
                             "", "Usually another user's processes. Running as root shows "
                                 "more. This is a coverage limit, not evidence of hiding."))

    # ---- the two firewalls ----
    if firewall.status == "unavailable":
        out.append(F("Firewall", "The firewall rules are UNKNOWN", "medium",
                     firewall.detail, "",
                     "This is deliberately not reported as 'no firewall'. The check could "
                     "not run, so the rules might be anything. Run as root, or install "
                     "iptables or nft, to find out.",
                     fix="sudo ip6tables -S\nsudo nft list ruleset"))
    else:
        v4, v6 = firewall.data["v4_rules"], firewall.data["v6_rules"]
        v4p, v6p = firewall.data["v4_policy"], firewall.data["v6_policy"]
        detail = "\n".join(f"  {k}: {v['detail']}"
                           for k, v in firewall.data["probes"].items() if v.get("detail"))
        if v4 is not None and v6 is not None:
            if v6 == 0 and v4 > 0:
                out.append(F("Firewall", f"IPv4 has {v4} rule(s) and IPv6 has none",
                             "critical",
                             "The machine is filtered on IPv4 and unfiltered on IPv6.",
                             detail,
                             "This is the classic IPv6 exposure: rules written with "
                             "iptables do not apply to IPv6 at all. Everything you "
                             "carefully blocked on IPv4 is open on IPv6, and nothing about "
                             "the IPv4 configuration looks wrong.",
                             fix="# mirror your v4 rules, then persist them\n"
                                 "sudo ip6tables -S\n"
                                 "sudo ip6tables -P INPUT DROP\n"
                                 "sudo ip6tables -A INPUT -m state --state "
                                 "ESTABLISHED,RELATED -j ACCEPT\n"
                                 "sudo ip6tables -A INPUT -i lo -j ACCEPT\n"
                                 "# ICMPv6 must NOT be blocked wholesale - IPv6 needs it\n"
                                 "sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT"))
            elif v4 - v6 >= 5:
                out.append(F("Firewall", f"IPv4 has {v4} rule(s), IPv6 has {v6}", "high",
                             f"A gap of {v4 - v6} rules between the two protocols.",
                             detail,
                             "The two rule sets are separate and this one is thinner. Each "
                             "IPv4 rule with no IPv6 counterpart is something you meant to "
                             "control and are not controlling."))
            else:
                out.append(F("Firewall", f"IPv4 has {v4} rule(s), IPv6 has {v6}", "info",
                             "The two rule sets are comparable in size.", detail,
                             "Similar counts do not prove the rules are equivalent - only "
                             "that neither protocol has obviously been forgotten. Reading "
                             "both is the only way to be sure."))
        if v6p and v6p.upper() == "ACCEPT":
            out.append(F("Firewall", "The IPv6 INPUT policy is ACCEPT", "high",
                         "Anything not explicitly dropped is allowed in.",
                         f"ip6tables INPUT policy: {v6p}"
                         + (f"\niptables INPUT policy: {v4p}" if v4p else ""),
                         "A default-accept policy means the firewall only blocks what it "
                         "was told to block. With IPv6 the list of things to block is "
                         "everything, which is why default-drop is the usual advice.",
                         fix="sudo ip6tables -P INPUT DROP   # after adding accept rules"))
        if v4p and v6p and v4p != v6p:
            out.append(F("Firewall", f"The default policies differ: IPv4 {v4p}, IPv6 {v6p}",
                         "high",
                         "The two protocols treat unmatched traffic differently.",
                         f"iptables INPUT {v4p} / ip6tables INPUT {v6p}",
                         "Whichever is more permissive is the one that decides your "
                         "exposure."))
        for key in firewall.data["missing"]:
            out.append(F("Firewall", f"{key} could not be read", "low",
                         firewall.data["probes"][key].get("detail", ""),
                         "", "Reported so the gap is visible - an unread tool is unknown, "
                             "not empty."))

    # ---- settings ----
    if settings.status == "unavailable":
        out.append(F("Settings", "IPv6 sysctls are not available", "info", settings.detail,
                     "", "The stack is not loaded, so there is nothing to configure."))
    else:
        s = settings.data["settings"]
        for path, info in s.items():
            if info["mismatch"] and info["severity"]:
                name = path.split("/")[-1]
                out.append(F("Settings", f"{name} is {info['value']}", info["severity"],
                             info["why"],
                             f"{info['path']} = {info['value']} (expected "
                             f"{info['expected']})",
                             "Change it if this machine is not meant to behave that way.",
                             fix=f"sudo sysctl -w "
                                 f"{info['path'].replace('/proc/sys/', '').replace('/', '.')}"
                                 f"={info['expected']}"))
        fwd = s.get("conf/all/forwarding", {})
        ra = s.get("conf/all/accept_ra", {})
        if fwd.get("value") == 1 and ra.get("value", 0) in (1, 2):
            out.append(F("Settings", "This machine forwards IPv6 and accepts router "
                         "advertisements", "high",
                         "It is acting as a router while letting other machines tell it "
                         "where to send traffic.",
                         f"forwarding={fwd.get('value')}, accept_ra={ra.get('value')}",
                         "A router should not take its routing from advertisements on the "
                         "segment it serves. This combination lets anything on the network "
                         "redirect traffic passing through this machine."))
        bind = s.get("bindv6only", {})
        if bind.get("value") == 0:
            out.append(F("Settings", "bindv6only is 0, so one socket serves both protocols",
                         "info",
                         "A socket bound to :: also accepts IPv4 connections, which arrive "
                         "as v4-mapped addresses.",
                         f"{bind.get('path')} = 0",
                         "This is the Linux default and usually what you want. It matters "
                         "here because an IPv4 firewall rule does not cover the IPv6 half "
                         "of that same listener - one socket, two ways in, two rule sets."))

    out.append(F("Summary",
                 f"{len((listeners.data or {}).get('listeners', []))} IPv6 listener(s), "
                 f"{len((addresses.data or {}).get('addresses', []))} address(es)",
                 "info",
                 ("a globally routable address is present" if has_global
                  else "no globally routable address is present"),
                 f"firewall: {firewall.status}; settings: {settings.status}",
                 NOT_A_VULNERABILITY + " " + NOT_FROM_OUTSIDE))
    return out


def _listener_line(x: dict) -> str:
    who = x.get("process") or "?"
    if x.get("pid"):
        who += f"({x['pid']})"
    svc = f"  {x['service']}" if x.get("service") else ""
    return f"{x['proto']} [{x['address']}]:{x['port']}  {who}{svc}"


def risk_score(findings: list[dict]) -> float:
    return round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)


# =============================================================================
# SECTION 5 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, ipv6_available INTEGER DEFAULT 0,
    addresses INTEGER DEFAULT 0, has_global INTEGER DEFAULT 0,
    listeners INTEGER DEFAULT 0, internet_facing INTEGER DEFAULT 0,
    v4_rules INTEGER, v6_rules INTEGER, v4_policy TEXT, v6_policy TEXT,
    score REAL DEFAULT 0, band TEXT, status TEXT, detail TEXT,
    elapsed_ms INTEGER, payload TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    kind TEXT, proto TEXT, address TEXT, port INTEGER, scope TEXT, reachable TEXT,
    process TEXT, pid INTEGER, user TEXT, service TEXT, key TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS known (
    key TEXT PRIMARY KEY, proto TEXT, address TEXT, port INTEGER, service TEXT,
    first_seen TEXT, last_seen TEXT, times_seen INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0, approved_at TEXT, label TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    advice TEXT, fix TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs_scan ON observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def baseline_map(conn=None) -> dict:
    out = {}
    for r in q("SELECT * FROM known", (), conn):
        d = dict(r)
        d["approved"] = bool(d["approved"])
        out[d["key"]] = d
    return out


def approve_listener(key_or_port: str, label: str = "", note: str = "") -> tuple[bool, str]:
    conn = connect()
    try:
        init_db(conn)
        row = q1("SELECT * FROM known WHERE key=?", (key_or_port,), conn)
        if not row:
            matches = q("SELECT * FROM known WHERE key LIKE ? OR CAST(port AS TEXT)=?",
                        (f"%{key_or_port}%", key_or_port), conn)
            if len(matches) > 1:
                return False, (f"'{key_or_port}' matches {len(matches)} listeners. Use the "
                               f"full key: " + ", ".join(m["key"] for m in matches[:3]))
            if not matches:
                return False, (f"'{key_or_port}' has not been seen. Run a check first.")
            row = matches[0]
        conn.execute("UPDATE known SET approved=1, approved_at=?, "
                     "label=COALESCE(NULLIF(?,''), label), "
                     "note=COALESCE(NULLIF(?,''), note) WHERE key=?",
                     (now_iso(), label, note, row["key"]))
        conn.commit()
        log_event("INFO", "baseline", f"Approved {row['key']}", None, conn)
        return True, row["key"]
    finally:
        conn.close()


def revoke_listener(key_or_port: str) -> int:
    conn = connect()
    try:
        n = conn.execute("UPDATE known SET approved=0, approved_at=NULL "
                         "WHERE key=? OR key LIKE ? OR CAST(port AS TEXT)=?",
                         (key_or_port, f"%{key_or_port}%", key_or_port)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    if not row:
        return None
    d = dict(row)
    try:
        d["payload"] = json.loads(d["payload"] or "{}")
    except json.JSONDecodeError:
        d["payload"] = {}
    d["band_colour"] = risk_band(d["score"] or 0,
                                 bool(d.get("ipv6_available", 1)))[1]
    return d


def save_scan(listeners: Result, addresses: Result, firewall: Result, settings: Result,
              findings: list[dict], elapsed_ms: int, note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
        rows = (listeners.data or {}).get("listeners", [])
        addrs = (addresses.data or {}).get("addresses", [])
        has_global = (addresses.data or {}).get("has_global", False)
        internet = sum(1 for x in rows
                       if x["scope"] == "global"
                       or (x["scope"] == "unspecified" and has_global))
        fw = firewall.data or {}
        score = risk_score(findings)
        available = not (listeners.status == "unavailable"
                         and addresses.status == "unavailable")
        detail = "; ".join(filter(None, [listeners.detail, addresses.detail,
                                         firewall.detail, settings.detail]))
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, ipv6_available, addresses, has_global,"
            " listeners, internet_facing, v4_rules, v6_rules, v4_policy, v6_policy,"
            " score, band, status, detail, elapsed_ms, payload, critical, high, medium,"
            " low, info, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), socket.gethostname(), int(available), len(addrs),
             int(has_global), len(rows), internet, fw.get("v4_rules"),
             fw.get("v6_rules"), fw.get("v4_policy"), fw.get("v6_policy"),
             score, risk_band(score, available)[0],
             "ok" if not detail else "partial", detail[:600], elapsed_ms,
             json.dumps({"listeners": rows, "addresses": addrs,
                         "firewall": {k: v for k, v in fw.items() if k != "probes"},
                         "probes": {k: {kk: vv for kk, vv in v.items()
                                        if kk != "output"}
                                    for k, v in fw.get("probes", {}).items()},
                         "settings": (settings.data or {}).get("settings", {}),
                         "statuses": {"listeners": listeners.status,
                                      "addresses": addresses.status,
                                      "firewall": firewall.status,
                                      "settings": settings.status}},
                        default=str),
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        sid = cur.lastrowid
        ts = now_iso()
        for x in rows:
            conn.execute(
                "INSERT INTO observations (scan_id, kind, proto, address, port, scope,"
                " reachable, process, pid, user, service, key)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, "listener", x["proto"], x["address"], x["port"], x["scope"],
                 x["reachable"], x.get("process"), x.get("pid"), x.get("user"),
                 x.get("service"), x["key"]))
            conn.execute(
                "INSERT INTO known (key, proto, address, port, service, first_seen,"
                " last_seen, times_seen) VALUES (?,?,?,?,?,?,?,1) "
                "ON CONFLICT(key) DO UPDATE SET last_seen=?, times_seen=times_seen+1",
                (x["key"], x["proto"], x["address"], x["port"], x.get("service"),
                 ts, ts, ts))
        for a in addrs:
            conn.execute(
                "INSERT INTO observations (scan_id, kind, address, scope, reachable)"
                " VALUES (?,?,?,?,?)",
                (sid, "address", a["address"], a["scope"], a["reachable"]))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, advice, fix) VALUES (?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"],
                          f["description"], f["evidence"], f.get("advice", ""),
                          f.get("fix", "")))
        conn.commit()
        log_event("INFO", "scan",
                  f"{len(rows)} listener(s), {internet} internet-facing, score {score}",
                  sid, conn)
        for f in findings:
            if f["severity"] == "critical":
                log_event("WARN", "exposure", f["title"], sid, conn)
        return sid
    finally:
        conn.close()


def run_check(note: str = "") -> dict:
    t0 = time.time()
    init_db()
    listeners = read_v6_listeners()
    addresses = read_v6_addresses()
    firewall = read_firewalls()
    settings = read_settings()
    findings = analyse(listeners, addresses, firewall, settings, baseline_map())
    elapsed = int((time.time() - t0) * 1000)
    sid = save_scan(listeners, addresses, firewall, settings, findings, elapsed, note)
    score = risk_score(findings)
    checked = not (listeners.status == "unavailable"
                   and addresses.status == "unavailable")
    return {"id": sid, "listeners": listeners, "addresses": addresses,
            "firewall": firewall, "settings": settings, "findings": findings,
            "checked": checked,
            "score": score, "band": risk_band(score, checked)[0],
            "band_colour": risk_band(score, checked)[1], "elapsed_ms": elapsed,
            "counts": {s: sum(1 for f in findings if f["severity"] == s)
                       for s in SEVERITIES}}


# =============================================================================
# SECTION 6 - Charts (hand-drawn SVG: no CDN, no JS library, works offline)
# =============================================================================

def svg_exposure(listeners: list[dict], has_global: bool, baseline: dict, width=940,
                 title="How far each listening service can be reached") -> str:
    """The signature visual: services laid out by reach, so 'the internet' is
    visibly a different column from 'this machine'."""
    if not listeners:
        return (f'<div class="chart-empty">{html_escape(title)}: nothing is listening on '
                f'IPv6</div>')
    lanes = [("local", "this machine only", "#30a46c"),
             ("link", "this segment", "#ffb224"),
             ("network", "this network", "#f76808"),
             ("internet", "the internet", "#e5484d")]
    grouped: dict[str, list] = {k: [] for k, _l, _c in lanes}
    for x in listeners:
        reach = x["reachable"]
        if reach == "all":
            reach = "internet" if has_global else "network"
        grouped.setdefault(reach if reach in grouped else "network", []).append(x)
    lane_w = (width - 40) / len(lanes)
    max_rows = max((len(v) for v in grouped.values()), default=0)
    height = 56 + min(max_rows, 10) * 26 + 20
    parts = []
    for i, (key, label, colour) in enumerate(lanes):
        x0 = 20 + i * lane_w
        items = grouped.get(key, [])
        parts.append(f'<rect x="{x0:.0f}" y="14" width="{lane_w - 10:.0f}" '
                     f'height="{height - 30}" rx="8" fill="#1a1e26" '
                     f'stroke="{colour if items else "#262a33"}" stroke-width="1.4"/>')
        parts.append(f'<text x="{x0 + 12:.0f}" y="34" style="fill:{colour};'
                     f'font:700 12px ui-monospace,monospace">'
                     f'{html_escape(label.upper())}</text>')
        parts.append(f'<text x="{x0 + lane_w - 22:.0f}" y="34" text-anchor="end" '
                     f'class="sub">{len(items)}</text>')
        for j, x in enumerate(items[:10]):
            y = 54 + j * 26
            approved = baseline.get(x["key"], {}).get("approved")
            svc = x.get("service") or (x.get("process") or "?")
            txt = f"{x['port']}  {svc}"[:22]
            parts.append(f'<rect x="{x0 + 10:.0f}" y="{y}" width="{lane_w - 30:.0f}" '
                         f'height="20" rx="4" fill="#12161d" '
                         f'stroke="{"#1e5138" if approved else colour}" '
                         f'stroke-opacity="{0.9 if not approved else 0.6}"/>')
            parts.append(f'<text x="{x0 + 18:.0f}" y="{y + 14}" class="cell">'
                         f'{html_escape(txt)}{" ok" if approved else ""}</text>'
                         f'<title>{html_escape(_listener_line(x))}</title>')
        if len(items) > 10:
            parts.append(f'<text x="{x0 + 18:.0f}" y="{54 + 10 * 26 + 12}" class="sub">'
                         f'+{len(items) - 10} more</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'a service bound to :: sits in the rightmost lane it can reach &middot; '
            f'green outline means you approved it</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_firewall(fw: dict, width=430, title="IPv4 rules against IPv6 rules") -> str:
    """The asymmetry, drawn. A gap is the point of the whole chart."""
    v4, v6 = fw.get("v4_rules"), fw.get("v6_rules")
    if v4 is None and v6 is None:
        return (f'<div class="chart-empty">{html_escape(title)}: the rules are UNKNOWN - '
                f'no firewall tool could be run, which is not the same as no rules</div>')
    mx = max(v4 or 0, v6 or 0, 1)
    bw = width - 150
    rows = []
    for i, (label, val, policy, colour) in enumerate(
            [("IPv4", v4, fw.get("v4_policy"), "#5b8def"),
             ("IPv6", v6, fw.get("v6_policy"), "#22b8cf")]):
        y = 14 + i * 46
        rows.append(f'<text x="80" y="{y + 20}" text-anchor="end" class="cell">'
                    f'{label}</text>')
        rows.append(f'<rect x="92" y="{y}" width="{bw}" height="28" rx="5" class="btrack"/>')
        if val is None:
            rows.append(f'<text x="102" y="{y + 19}" class="sub">'
                        f'unknown - the tool could not be run</text>')
        else:
            w = max(3, bw * val / mx)
            rows.append(f'<rect x="92" y="{y}" width="{w:.0f}" height="28" rx="5" '
                        f'fill="{colour}"/>')
            rows.append(f'<text x="{92 + w + 8:.0f}" y="{y + 19}" class="bv">'
                        f'{val} rule(s)</text>')
        if policy:
            pc = "#e5484d" if str(policy).upper() == "ACCEPT" else "#30a46c"
            rows.append(f'<text x="92" y="{y + 42}" style="fill:{pc};'
                        f'font:10.5px ui-monospace,monospace">'
                        f'INPUT policy {html_escape(str(policy))}</text>')
    caption = html_escape(title)
    if v4 is not None and v6 is not None and v4 - v6 >= 5:
        caption += f' &middot; a gap of {v4 - v6} rules'
    return (f'<figure class="chart"><figcaption>{caption} &middot; these are two separate '
            f'rule sets</figcaption>'
            f'<svg viewBox="0 0 {width} 118" width="{width}" height="118" role="img" '
            f'aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 160, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 22 else label[:21] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 7 - Exports
# =============================================================================

def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "there_is_no_nat_in_ipv6": NO_NAT,
            "reachable_here_is_not_reachable_from_the_internet": NOT_FROM_OUTSIDE,
            "a_listening_socket_is_not_a_vulnerability": NOT_A_VULNERABILITY,
            "limitations": [
                "This runs on the machine. It cannot see what an upstream router, ISP or "
                "cloud security group does with a packet from outside - only a test from "
                "outside can tell you that, and this tool has no outside vantage point.",
                "A listening socket is attack surface, not a flaw.",
                "Rules written with iptables do not apply to IPv6 - they are two separate "
                "rule sets with separate default policies.",
                "When a firewall tool cannot be run the rules are reported as UNKNOWN, "
                "never as absent.",
                "If IPv6 is unavailable, nothing was checked - which is reported as 'not "
                "checked' rather than as a clean result.",
                "Socket ownership needs privileges; without them some listeners show no "
                "process, which is a coverage limit and not evidence of hiding.",
                "This is one moment - a service can start listening at any time.",
                "Read-only and offline: no rule, socket or sysctl is changed and no network "
                "connection is made.",
            ],
            "scan": scan,
            "observations": [dict(r) for r in q(
                "SELECT * FROM observations WHERE scan_id=? ORDER BY kind, port",
                (sid,), conn)] if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,advice,fix FROM "
                "findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (sid,), conn)] if sid else [],
            "known": [dict(r) for r in q("SELECT * FROM known ORDER BY port", (), conn)],
            "history": [dict(r) for r in q(
                "SELECT id, ts, score, band, listeners, internet_facing FROM scans "
                "ORDER BY id DESC LIMIT 40", (), conn)][::-1],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# Reachable from here is not reachable from the internet - only a "
                    "test from outside can tell you that."])
        if not scan:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Check"])
        w.writerow(["hostname", "ipv6_available", "addresses", "has_global", "listeners",
                    "internet_facing", "v4_rules", "v6_rules", "v4_policy", "v6_policy",
                    "score", "band"])
        w.writerow([scan["hostname"], scan["ipv6_available"], scan["addresses"],
                    scan["has_global"], scan["listeners"], scan["internet_facing"],
                    scan["v4_rules"], scan["v6_rules"], scan["v4_policy"],
                    scan["v6_policy"], scan["score"], scan["band"]])
        w.writerow([])
        w.writerow(["## Listeners and addresses"])
        w.writerow(["kind", "proto", "address", "port", "scope", "reachable", "process",
                    "pid", "user", "service"])
        for r in q("SELECT * FROM observations WHERE scan_id=? ORDER BY kind, port",
                   (sid,), conn):
            w.writerow([r["kind"], r["proto"], r["address"], r["port"], r["scope"],
                        r["reachable"], r["process"], r["pid"], r["user"], r["service"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["severity", "category", "title", "description", "advice", "fix"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,), conn):
            w.writerow([r["severity"], r["category"], r["title"], r["description"],
                        r["advice"], r["fix"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(sid=None) -> str:
    conn = connect()
    try:
        p = report_payload(sid, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No checks recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        payload = scan.get("payload") or {}
        exposure = svg_exposure(payload.get("listeners") or [],
                                bool(scan["has_global"]), baseline_map(conn))
        fwchart = svg_firewall(payload.get("firewall") or {})
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to make of it:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "")
            + (f'<div class="fix"><b>To change it yourself:</b><pre>{esc(f["fix"])}</pre>'
               f'</div>' if f["fix"] else "")
            + "</td></tr>" for f in p["findings"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.7px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-word}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 .fix{{margin-top:8px;color:#a8d8e8;font-size:12.2px}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4;max-height:300px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .danger{{background:#2a1216;border:1px solid #6b2229;color:#ffc9cd;padding:12px 14px;
        border-radius:10px;font-size:12.8px;margin:14px 0;font-weight:600}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.cell{{fill:#e6e8ee;font:11.5px ui-monospace,monospace}}
 text.sub{{fill:#6f7685;font:10.5px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>IPv6 exposure</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {ts_pretty(scan['ts'])} &middot;
 {scan['elapsed_ms']} ms &middot;
 {'IPv6 is available' if scan['ipv6_available'] else 'IPv6 is NOT available - nothing was checked'}
 </div>
{f'<div class="danger">{scan["internet_facing"]} service(s) are offered on a globally routable '
 f'address, with no NAT in the way.</div>' if scan['internet_facing'] else ''}
<div class="note"><b>There is no NAT in IPv6.</b> {esc(p['there_is_no_nat_in_ipv6'])}
 <ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{scan['band_colour']}">
   {esc(scan['band'] or '')}</div><div class="l">score {scan['score']}</div></div>
 <div class="card"><div class="l">Listeners</div>
  <div class="n">{scan['listeners']}</div></div>
 <div class="card"><div class="l">Internet-facing</div>
  <div class="n" style="color:{'#e5484d' if scan['internet_facing'] else '#30a46c'}">
   {scan['internet_facing']}</div></div>
 <div class="card"><div class="l">Addresses</div>
  <div class="n">{scan['addresses']}</div>
  <div class="l">{'global present' if scan['has_global'] else 'no global'}</div></div>
 <div class="card"><div class="l">Rules v4 / v6</div>
  <div class="n" style="font-size:15px">
   {scan['v4_rules'] if scan['v4_rules'] is not None else '?'} /
   {scan['v6_rules'] if scan['v6_rules'] is not None else '?'}</div></div>
</div>
<h2>Reach</h2><div class="charts">{exposure}</div>
<h2>The two firewalls</h2><div class="charts">{fwchart}{pie}</div>
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Read-only and offline: no rule, socket or sysctl was changed and no network connection was
 made. Reachable from this machine is not the same as reachable from the internet.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 8 - Web application (no CDN, no JS libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#e5484d;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1200px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:11px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
input[type=text],select{font-family:var(--mono);font-size:12px;padding:7px 9px;
 background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);border-radius:7px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.8px;word-break:break-word}
.num{font-family:var(--mono);font-size:11.8px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap;margin-left:4px}
.tag.good{border-color:#1e5138;color:#7fd9ab} .tag.bad{border-color:#5a2326;color:#ff9b9e}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
.fix{margin-top:8px;color:#a8d8e8;font-size:12.2px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:300px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.cell{fill:#e6e8ee;font:11.5px var(--mono)}
text.sub{fill:#6f7685;font:10.5px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1200px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} table{font-size:12px}
 th,td{padding:7px 8px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>V6EXPOSE</b> <small>IPv6 exposure checker</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_listeners') }}" class="{{ 'on' if nav=='listeners' }}">Listeners</a>
  <a href="{{ url_for('page_scans') }}" class="{{ 'on' if nav=='scans' }}">Checks</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner bad"><b>Reachable from here is not reachable from the internet.</b>
  """ + NOT_FROM_OUTSIDE + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Read-only and offline: no rule, socket or sysctl is changed and no network connection is made.
 Fixes are printed for you to run. A listening socket is attack surface, not a flaw.</footer>
</body></html>"""

RUNBAR_TPL = """
<div class="bar">
 <form method="post" action="{{ url_for('do_check') }}">
  <button class="btn primary" type="submit">Check now</button></form>
 {% if scan %}
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</div>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + RUNBAR_TPL + """
<div class="empty"><b>Nothing checked yet</b>
 It finds every service listening on IPv6, works out how far each one can be reached, and
 compares your IPv4 firewall rules against your IPv6 rules - which are two separate rule sets
 that people routinely forget.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 v6expose.py check</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Check #{{ scan.id }} &middot; {{ ts_pretty(scan.ts) }} &middot;
 {{ scan.elapsed_ms }} ms &middot;
 {{ 'IPv6 is available' if scan.ipv6_available else 'IPv6 is NOT available - nothing was checked' }}</div>
""" + RUNBAR_TPL + """
{% if scan.detail %}<div class="banner warn"><b>Partial:</b> {{ scan.detail }}</div>{% endif %}
{% if scan.internet_facing %}
<div class="banner bad"><b>{{ scan.internet_facing }} service(s) are offered on a globally
 routable address.</b> There is no NAT in IPv6 - whatever protection your IPv4 setup got from
 sitting behind a router does not apply here.</div>
{% endif %}
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{{ scan.band_colour }}">{{ scan.band }}</div>
  <div class="l">score {{ scan.score }}</div></div>
 <div class="card"><div class="l">Listeners</div><div class="n">{{ scan.listeners }}</div></div>
 <div class="card"><div class="l">Internet-facing</div>
  <div class="n" style="color:{{ '#e5484d' if scan.internet_facing else '#30a46c' }}">
   {{ scan.internet_facing }}</div></div>
 <div class="card"><div class="l">Addresses</div><div class="n">{{ scan.addresses }}</div>
  <div class="l">{{ 'global present' if scan.has_global else 'no global' }}</div></div>
 <div class="card"><div class="l">Rules v4 / v6</div>
  <div class="n" style="font-size:15px">
   {{ scan.v4_rules if scan.v4_rules is not none else '?' }} /
   {{ scan.v6_rules if scan.v6_rules is not none else '?' }}</div></div>
</div>
<h2>Reach</h2><div class="charts">{{ exposure|safe }}</div>
<h2>The two firewalls</h2><div class="charts">{{ fwchart|safe }}{{ pie|safe }}</div>
<h2>Findings ({{ findings|length }})</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to make of it:</b> {{ f.advice }}</div>
  {% endif %}
  {% if f.fix %}<div class="fix"><b>To change it yourself:</b><pre>{{ f.fix }}</pre></div>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings.</div>{% endif %}
{% endblock %}"""

LISTENERS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Listeners</h1>
<div class="sub">{{ rows|length }} listener(s) seen. Approving one stops it being reported -
 use it for services you deliberately expose.</div>
<div class="banner"><b>A listening socket is not a vulnerability.</b>
 """ + NOT_A_VULNERABILITY + """</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <input type="text" name="qq" value="{{ f_q }}" placeholder="filter by port or address">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_listeners') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Proto</th><th>Address</th><th>Port</th><th>Service</th><th>Seen</th>
 <th>Last</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="sub2">{{ r.proto }}</td>
 <td class="mono">{{ r.address }}{% if r.approved %}<span class="tag good">approved</span>
  {% endif %}{% if r.label %}<div class="sub2">{{ r.label }}</div>{% endif %}</td>
 <td class="num">{{ r.port }}</td>
 <td class="sub2">{{ r.service or '-' }}</td>
 <td class="num">{{ r.times_seen }}</td>
 <td class="mono">{{ ago(r.last_seen) }}</td>
 <td>{% if r.approved %}
   <form method="post" action="{{ url_for('do_revoke') }}" style="display:inline">
    <input type="hidden" name="key" value="{{ r.key }}">
    <button class="btn tiny" type="submit">revoke</button></form>
  {% else %}
   <form method="post" action="{{ url_for('do_approve') }}" style="display:inline">
    <input type="hidden" name="key" value="{{ r.key }}">
    <button class="btn tiny" type="submit">approve</button></form>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty"><b>No listeners recorded</b> Run a check first.</div>{% endif %}
{% endblock %}"""

SCANS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Checks</h1><div class="sub">{{ rows|length }} check(s) stored locally.</div>
{% if rows %}
<table><tr><th>#</th><th>When</th><th>IPv6</th><th>Listeners</th><th>Internet-facing</th>
 <th>v4/v6 rules</th><th>Score</th><th>Verdict</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">#{{ r.id }}</td>
 <td class="mono">{{ r.ts[:19].replace('T',' ') }}</td>
 <td class="sub2">{{ 'yes' if r.ipv6_available else 'no' }}</td>
 <td class="num">{{ r.listeners }}</td>
 <td class="num" style="color:{{ '#e5484d' if r.internet_facing else '#8b8f9b' }}">
  {{ r.internet_facing }}</td>
 <td class="num">{{ r.v4_rules if r.v4_rules is not none else '?' }}/{{ r.v6_rules if r.v6_rules is not none else '?' }}</td>
 <td class="num">{{ r.score }}</td>
 <td class="sub2">{{ r.band }}</td>
 <td><a class="btn" href="{{ url_for('page_overview') }}?scan={{ r.id }}">view</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Why IPv6 exposes things IPv4 did not</h1>
<div class="banner bad"><b>There is no NAT in IPv6.</b> On IPv4 most machines sit behind a
 router that has nowhere to send an unsolicited packet from outside, so a service bound to
 0.0.0.0 is reachable from the local network and nothing else. That protection was never a
 decision anybody made - it is a side effect of running out of addresses - and an enormous
 amount of software has been deployed safely because of it.<br><br>
 IPv6 has enough addresses that every machine gets a globally routable one. The same daemon,
 the same config file, the same bind to "all interfaces" - and now it answers the world.</div>
<h2>Firewalls are two firewalls</h2>
<div class="desc">Rules written with <span class="mono">iptables</span> do not apply to IPv6.
 <span class="mono">ip6tables</span> is a separate table with a separate default policy. A
 machine can be carefully locked down on IPv4 and wide open on IPv6, and nothing about the
 IPv4 side looks wrong.<br><br>
 That comparison is the single most useful number in this report. If your IPv4 rules outnumber
 your IPv6 rules, every missing rule is something you meant to control and are not
 controlling.<br><br>
 One caution when writing IPv6 rules: <b>do not block ICMPv6 wholesale</b>. IPv4 mostly works
 without ICMP; IPv6 does not - neighbour discovery and path MTU discovery both depend on it,
 and dropping it breaks connectivity in ways that are hard to diagnose.</div>
<h2>Binding to :: is not the same as binding to 0.0.0.0</h2>
<div class="desc">On Linux, <span class="mono">bindv6only</span> is normally 0, which means a
 socket bound to <span class="mono">::</span> also accepts IPv4 connections arriving as
 v4-mapped addresses. One socket, two protocols, two separate sets of firewall rules - and an
 IPv4 rule does not cover the IPv6 half.</div>
<h2>Transition tunnels</h2>
<div class="desc">6to4 (<span class="mono">2002::/16</span>) and Teredo
 (<span class="mono">2001:0::/32</span>) carry IPv6 inside IPv4. Teredo exists specifically to
 get through NAT, which means it also gets through a lot of firewalls. Both give a machine
 connectivity nobody deliberately configured, on a path an IPv4 firewall never inspects.</div>
<h2>What this tool cannot tell you</h2>
<div class="banner warn"><b>Whether a packet from the internet actually arrives.</b> This runs
 on the machine and reports what the machine is offering. Your upstream router, your ISP or
 your cloud security group may drop unsolicited IPv6 entirely - many do by default. Finding
 out needs a test from OUTSIDE, and this tool has no outside vantage point. It never claims
 one and it never contacts anything to find out.<br><br>
 It also reports <b>attack surface, not flaws</b>: a patched SSH daemon on a global address is
 exposed and probably fine, while a forgotten debug server on the same address is neither. And
 when a firewall tool cannot be run, the rules are reported as <b>UNKNOWN</b> - never as
 absent, because those are very different statements.</div>
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Stored locally in {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Check</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "listeners.html": LISTENERS_TPL, "scans.html": SCANS_TPL,
             "learn.html": LEARN_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "ago": ago,
                "scan": None, "error": request.args.get("error"),
                "flash": request.args.get("flash")}
        base.update(kw)
        return base

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            init_db(conn)
            try:
                sid = int(request.args.get("scan", "") or 0)
            except ValueError:
                sid = 0
            scan = scan_summary(sid, conn) if sid else None
            if not scan:
                sid = latest_scan_id(conn)
                scan = scan_summary(sid, conn) if sid else None
            if not scan:
                return render_template("empty.html", **ctx("overview"))
            p = report_payload(scan["id"], conn)
            payload = scan.get("payload") or {}
            counts = {s: scan[s] or 0 for s in SEVERITIES}
            return render_template("overview.html", **ctx(
                "overview", scan=scan, findings=p["findings"],
                exposure=svg_exposure(payload.get("listeners") or [],
                                      bool(scan["has_global"]), baseline_map(conn)),
                fwchart=svg_firewall(payload.get("firewall") or {}),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        import urllib.parse as up
        try:
            res = run_check(note="from the web UI")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error=" + up.quote(str(e)))
        return redirect(url_for("page_overview") + f"?scan={res['id']}")

    @app.route("/listeners")
    def page_listeners():
        conn = connect()
        try:
            init_db(conn)
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM known WHERE 1=1", []
            if term:
                sql += " AND (address LIKE ? OR CAST(port AS TEXT) LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY approved DESC, port LIMIT 500"
            rows = [dict(r) for r in q(sql, tuple(args), conn)]
            for r in rows:
                r["approved"] = bool(r["approved"])
            return render_template("listeners.html", **ctx("listeners", rows=rows,
                                                           f_q=term))
        finally:
            conn.close()

    @app.post("/approve")
    def do_approve():
        import urllib.parse as up
        key = (request.form.get("key") or "").strip()
        ok, detail = approve_listener(key)
        return redirect(url_for("page_listeners") + "?flash="
                        + up.quote("Approved." if ok else detail))

    @app.post("/revoke")
    def do_revoke():
        key = (request.form.get("key") or "").strip()
        if key:
            revoke_listener(key)
        return redirect(url_for("page_listeners"))

    @app.route("/scans")
    def page_scans():
        conn = connect()
        try:
            init_db(conn)
            return render_template("scans.html", **ctx(
                "scans", rows=q("SELECT * FROM scans ORDER BY id DESC LIMIT 200",
                                (), conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn"))

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            init_db(conn)
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT 300"
            return render_template("logs.html", **ctx(
                "logs", rows=q(sql, tuple(args), conn), f_level=level, f_q=term,
                dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="v6expose-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no checks yet"}), 404
        s = scan_summary(sid)
        return jsonify({"tool": APP_NAME, "version": VERSION, "read_only": True,
                        "makes_no_network_connection": True,
                        "cannot_test_from_outside": True,
                        "unknown_rules_are_not_absent_rules": True,
                        "disclaimer": DISCLAIMER_SHORT,
                        "scan": {k: v for k, v in s.items() if k != "payload"}})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /listeners /scans /learn "
                        "/logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if not is_root():
        print("  NOTE    : not running as root. Socket ownership and firewall rules will\n"
              "            be limited - reported as unknown rather than hidden.")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI lists every service on this\n"
              "            machine and which are internet-facing. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 9 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False, show_fix=True):
    shown = [f for f in rows if not (quiet and f["severity"] == "info")]
    shown = shown[:limit] if limit else shown
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:10]:
                for w in textwrap.wrap(l, 70) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to make of it: " + f["advice"], 70):
                print(f"      {l}")
        if f.get("fix") and show_fix:
            print("      to change it yourself:")
            for l in str(f["fix"]).splitlines()[:8]:
                print(f"        {l}")


def _report(res, a):
    lst, addrs = res["listeners"], res["addresses"]
    fw = res["firewall"]
    print(f"Host   : {socket.gethostname()}")
    print(f"IPv6   : {'available' if res['checked'] else 'NOT AVAILABLE'}")
    if not is_root():
        print("         (not root - socket ownership and firewall rules are limited)")
    print(f"Time   : {res['elapsed_ms']} ms")
    line("=")
    if not res["checked"]:
        print("  NOT CHECKED - IPv6 is not available on this machine")
        print("  This is NOT the same as nothing being exposed.")
        line("=")
        _print_findings(res["findings"], a.show, a.quiet)
        line()
        return
    rows = (lst.data or {}).get("listeners", [])
    has_global = (addrs.data or {}).get("has_global", False)
    internet = [x for x in rows
                if x["scope"] == "global" or (x["scope"] == "unspecified" and has_global)]
    print(f"  {len(rows)} IPv6 LISTENER(S), {len(internet)} INTERNET-FACING")
    print(f"  {res['band'].upper()}")
    line("=")
    if rows:
        print(f"  {'PROTO':<7} {'ADDRESS':<26} {'PORT':>6}  {'REACH':<10} SERVICE")
        line()
        for x in rows[:30]:
            reach = x["reachable"]
            if reach == "all":
                reach = "internet" if has_global else "network"
            mark = "!" if reach == "internet" else " "
            print(f" {mark}{x['proto']:<7} {x['address'][:25]:<26} {x['port']:>6}  "
                  f"{reach:<10} {x.get('service') or x.get('process') or ''}")
        if len(rows) > 30:
            print(f"  ... and {len(rows) - 30} more")
        line()
        print("  ! is reachable from the internet")
        line()
    v4, v6 = fw.data.get("v4_rules") if fw.data else None, \
        fw.data.get("v6_rules") if fw.data else None
    print(f"  FIREWALL: IPv4 {v4 if v4 is not None else 'unknown'} rule(s), "
          f"IPv6 {v6 if v6 is not None else 'unknown'} rule(s)")
    if fw.status == "unavailable":
        for l in textwrap.wrap(fw.detail, 74):
            print(f"    {l}")
    line()
    _print_findings(res["findings"], a.show, a.quiet, not a.no_fix)
    line()
    print(textwrap.fill("  " + NOT_FROM_OUTSIDE, 78))
    line()


def cmd_check(a):
    banner()
    res = run_check(note=a.note or "")
    _report(res, a)
    return _exit_code(a, res)


def cmd_watch(a):
    banner()
    print(f"Checking every {a.interval:.0f}s"
          + (f", {a.count} times" if a.count else " until Ctrl+C") + ".")
    print("Only new listeners and findings are printed.\n")
    seen: set = set()
    n = 0
    try:
        while True:
            n += 1
            res = run_check(note="watch")
            stamp = datetime.now().strftime("%H:%M:%S")
            rows = (res["listeners"].data or {}).get("listeners", [])
            keys = {x["key"] for x in rows}
            new = keys - seen
            alerts = [f for f in res["findings"]
                      if f["severity"] in ("critical", "high")]
            if new or alerts:
                print(f"  {stamp}  #{res['id']}  {len(rows)} listener(s)")
                for k in sorted(new):
                    x = next(y for y in rows if y["key"] == k)
                    print(f"      new  {x['proto']} [{x['address']}]:{x['port']}  "
                          f"{x.get('service') or x.get('process') or ''}")
                for f in alerts:
                    print(f"   !! [{f['severity'].upper()}] {f['title']}")
            elif not a.quiet:
                print(f"  {stamp}  #{res['id']}  {len(rows)} listener(s), nothing new")
            seen |= keys
            if a.count and n >= a.count:
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    line()
    print(f"  {n} check(s), {len(seen)} distinct listener(s) seen.")
    line()
    return 0


def _exit_code(a, res):
    counts = res["counts"]
    if a.fail_on_internet_facing:
        rows = (res["listeners"].data or {}).get("listeners", [])
        has_global = (res["addresses"].data or {}).get("has_global", False)
        n = sum(1 for x in rows
                if x["scope"] == "global" or (x["scope"] == "unspecified" and has_global))
        if n:
            print(f"  Exiting non-zero: {n} service(s) are internet-facing.")
            return 2
    if a.fail_on_critical and counts["critical"]:
        print(f"  Exiting non-zero: {counts['critical']} critical finding(s).")
        return 2
    if a.fail_over is not None and res["score"] > a.fail_over:
        print(f"  Exiting non-zero: score {res['score']} is above --fail-over "
              f"{a.fail_over}")
        return 2
    return 0


def cmd_scope(a):
    """Classify an address without needing IPv6 on this machine."""
    banner()
    s = address_scope(a.address)
    if not s["valid"]:
        print(f"  {s['error']}")
        return 1
    print(f"  address    : {s['compressed']}")
    print(f"  scope      : {s['scope']}")
    print(f"  reachable  : {s['reachable']}")
    line("=")
    for l in textwrap.wrap(s["why"], 74):
        print(f"  {l}")
    if s.get("transition"):
        t = s["transition"]
        line()
        print(f"  TRANSITION: {t['name']}  ({t['prefix']})")
        for l in textwrap.wrap(t["why"], 74):
            print(f"    {l}")
    line()
    if s["reachable"] == "internet":
        print(textwrap.fill(
            "  A service bound to this address is offered to the internet. There is no NAT "
            "in IPv6 - " + NOT_FROM_OUTSIDE, 78))
    elif s["reachable"] == "all":
        print(textwrap.fill(
            "  A socket bound here accepts connections on EVERY address this machine has. "
            "Whether that reaches the internet depends on whether a global address exists.",
            78))
    line()
    return 0


def cmd_listeners(a):
    rows = q("SELECT * FROM known ORDER BY approved DESC, port LIMIT ?", (a.limit,))
    if not rows:
        print("No listeners recorded yet. Run:  check")
        return 0
    print(f"  {'PROTO':<7} {'ADDRESS':<26} {'PORT':>6} {'SEEN':>5}  {'APPROVED':<9} SERVICE")
    line()
    for r in rows:
        print(f"  {r['proto']:<7} {(r['address'] or '')[:25]:<26} {r['port']:>6} "
              f"{r['times_seen']:>5}  {('yes' if r['approved'] else 'no'):<9} "
              f"{r['service'] or ''}")
    line()
    return 0


def cmd_approve(a):
    ok, detail = approve_listener(a.target, a.label or "", a.note or "")
    if not ok:
        print(detail)
        return 1
    print(f"Approved {detail}")
    print()
    print(textwrap.fill(
        "It will no longer be reported as exposed. Approving records a decision - it does "
        "not close the port, and the service is still reachable by exactly whoever could "
        "reach it before.", 78))
    return 0


def cmd_revoke(a):
    n = revoke_listener(a.target)
    print(f"Revoked {n} approval(s)." if n else f"'{a.target}' was not approved.")
    return 0


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        THERE IS NO NAT IN IPv6

          On IPv4 most machines sit behind a router that has nowhere to send an
          unsolicited packet from outside, so a service bound to 0.0.0.0 is
          reachable from the local network and nothing else.

          That protection was never a decision anybody made. It is a side effect
          of running out of addresses, and an enormous amount of software has been
          deployed safely because of it.

          IPv6 has enough addresses that every machine gets a globally routable
          one. The same daemon, the same config file, the same bind to "all
          interfaces" - and now it answers the world.

        FIREWALLS ARE TWO FIREWALLS

          Rules written with iptables do not apply to IPv6. ip6tables is a
          separate table with a separate default policy. A machine can be
          carefully locked down on IPv4 and wide open on IPv6, and nothing about
          the IPv4 side looks wrong.

          That comparison is the most useful number in this report. If your IPv4
          rules outnumber your IPv6 rules, every missing rule is something you
          meant to control and are not controlling.

          ONE CAUTION: do not block ICMPv6 wholesale. IPv4 mostly works without
          ICMP; IPv6 does not. Neighbour discovery and path MTU discovery both
          depend on it, and dropping it breaks connectivity in ways that are hard
          to diagnose.

        BINDING TO :: IS NOT BINDING TO 0.0.0.0

          On Linux bindv6only is normally 0, so a socket bound to :: also accepts
          IPv4 connections arriving as v4-mapped addresses. One socket, two
          protocols, two separate rule sets - and an IPv4 rule does not cover the
          IPv6 half of that same listener.

        TRANSITION TUNNELS

          6to4 (2002::/16) and Teredo (2001:0::/32) carry IPv6 inside IPv4. Teredo
          exists specifically to get through NAT, which means it also gets through
          a lot of firewalls. Both give a machine connectivity nobody deliberately
          configured, on a path an IPv4 firewall never inspects.

        WHAT THIS TOOL CANNOT TELL YOU

          WHETHER A PACKET FROM THE INTERNET ACTUALLY ARRIVES. This runs on the
          machine and reports what the machine is offering. Your upstream router,
          your ISP or your cloud security group may drop unsolicited IPv6
          entirely - many do by default. Finding out needs a test from OUTSIDE,
          and this tool has no outside vantage point. It never claims one and it
          never contacts anything to find out.

          It reports ATTACK SURFACE, NOT FLAWS. A patched SSH daemon on a global
          address is exposed and probably fine; a forgotten debug server on the
          same address is neither.

          When a firewall tool cannot be run the rules are reported as UNKNOWN,
          never as absent. And if IPv6 is unavailable, the result is "not checked"
          rather than "nothing exposed" - those are very different statements and
          this tool keeps them apart.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'LIS':>4} {'NET':>4} {'V4/V6':>8} {'SCORE':>6}  "
          f"VERDICT")
    line()
    for r in rows:
        v4 = r["v4_rules"] if r["v4_rules"] is not None else "?"
        v6 = r["v6_rules"] if r["v6_rules"] is not None else "?"
        print(f"{r['id']:>4}  {r['ts'][:19].replace('T', ' '):<20} {r['listeners']:>4} "
              f"{r['internet_facing']:>4} {f'{v4}/{v6}':>8} {r['score']:>6}  "
              f"{r['band'] or ''}")
    return 0


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"v6expose-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported check #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("It lists every service on this machine and which are internet-facing - treat it "
          "as sensitive.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<10} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "observations", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.listeners:
                conn.execute("DELETE FROM known")
            conn.commit()
            print("All checks, observations and logs deleted."
                  + (" The listener list was cleared too." if a.listeners
                     else " The listener list and approvals were kept."))
            return 0
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "observations"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    lst = read_v6_listeners()
    addrs = read_v6_addresses()
    fw = read_firewalls()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Privileges : {'root' if is_root() else 'unprivileged - coverage is limited'}")
    print(f"  IPv6       : {'available' if lst.status != 'unavailable' else 'NOT AVAILABLE'}")
    print(f"  Listeners  : {lst.status}, "
          f"{len((lst.data or {}).get('listeners', []))} found")
    print(f"  Addresses  : {addrs.status}, "
          f"{len((addrs.data or {}).get('addresses', []))} found")
    print(f"  Firewall   : {fw.status}")
    for key, probe in (fw.data or {}).get("probes", {}).items():
        print(f"    {key:<11} {probe.get('detail', '-')}")
    print(f"  Ports known: {len(NOTABLE_PORTS)}")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 10 - Self test
#   The exposure logic is tested against fixtures, so it passes or fails without
#   depending on this machine having IPv6 at all - which matters, because the
#   machine this was written on does not.
# =============================================================================

def _listener(address, port, proto="tcp6", process="svc", pid=1, service=None,
              severity=None):
    s = address_scope(address)
    info = NOTABLE_PORTS.get(port)
    return {"proto": proto, "address": address, "port": port, "state": "LISTEN",
            "inode": pid, "pid": pid, "process": process, "exe": None, "cmdline": None,
            "user": "root", "scope": s["scope"], "reachable": s["reachable"],
            "scope_why": s["why"], "transition": s.get("transition"),
            "service": service or (info[0] if info else None),
            "port_severity": severity or (info[1] if info else None),
            "port_why": info[2] if info else None,
            "key": f"{proto}|{address}|{port}"}


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed, skipped = [], [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    def skip(name, why):
        skipped.append(name)
        print(f"  [SKIP] {name}  ({why})")

    banner()
    print("SELF TEST - exposure logic against fixtures, collectors against this machine.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="v6expose-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Address scope - the whole exposure judgement")
        for addr, scope, reach in (
                ("::", "unspecified", "all"), ("::1", "loopback", "local"),
                ("fe80::1", "link-local", "link"), ("fd00::1", "unique-local", "network"),
                ("2a00:1450::200e", "global", "internet"),
                ("2001:db8::1", "global", "internet"),
                ("ff02::1", "multicast", "link")):
            s = address_scope(addr)
            check(f"{addr} is {scope}, reachable from {reach}",
                  s["scope"] == scope and s["reachable"] == reach,
                  (s["scope"], s["reachable"]))
        check("the wildcard explains that it covers every address",
              "EVERY address" in address_scope("::")["why"])
        check("a global address says there is no NAT in front of it",
              "no NAT" in address_scope("2a00:1450::1")["why"])
        check("link-local says a router will not forward it",
              "will not forward" in address_scope("fe80::1")["why"])
        check("an invalid address is rejected with a reason",
              not address_scope("not-an-address")["valid"]
              and address_scope("not-an-address")["error"])
        check("the documentation range is marked as such",
              address_scope("2001:db8::1").get("documentation"))

        print("\n Transition tunnels")
        for addr, name in (("2002:c000:204::1", "6to4"), ("2001:0:53aa::1", "Teredo"),
                           ("64:ff9b::1", "NAT64")):
            s = address_scope(addr)
            check(f"{name} is recognised",
                  s.get("transition") and s["transition"]["name"] == name,
                  s.get("transition"))
        check("an ordinary global address is not called a tunnel",
              not address_scope("2a00:1450::1").get("transition"))
        check("6to4 explains that it passes through IPv4 firewalls",
              "IPv4" in address_scope("2002:c000:204::1")["transition"]["why"])

        print("\n Decoding /proc/net/tcp6")
        check("the wildcard address decodes",
              _decode_v6("00000000000000000000000000000000:0016") == ("::", 22))
        check("loopback decodes",
              _decode_v6("00000000000000000000000001000000:1F90") == ("::1", 8080))
        check("a malformed value is returned rather than crashed on",
              _decode_v6("abc:0016")[1] == 22)

        print("\n Collectors on this machine")
        lst = read_v6_listeners()
        addrs = read_v6_addresses()
        check(f"listeners are read or their absence explained ({lst.status})",
              lst.status in ("ok", "partial", "unavailable"))
        check(f"addresses are read or their absence explained ({addrs.status})",
              addrs.status in ("ok", "partial", "unavailable"))
        if lst.status == "unavailable":
            check("and the absence says it is NOT a clean result",
                  "NOT the same as" in lst.detail, lst.detail)
        fw = read_firewalls()
        check(f"the firewall probe reports a status ({fw.status})",
              fw.status in ("ok", "partial", "unavailable"))
        if fw.status == "unavailable":
            check("missing firewall tools are reported as UNKNOWN, not as no rules",
                  "UNKNOWN" in fw.detail and "not the same as there being no rules"
                  in fw.detail, fw.detail)

        print("\n Counting firewall rules")
        ipt = ("-P INPUT DROP\n-P FORWARD DROP\n-A INPUT -i lo -j ACCEPT\n"
               "-A INPUT -p tcp --dport 22 -j ACCEPT\n")
        rules, policy = _count_rules(ipt, "iptables")
        check("rules are counted", rules == 2, rules)
        check("the INPUT policy is read", policy == "DROP", policy)
        rules, policy = _count_rules("-P INPUT ACCEPT\n", "iptables")
        check("an empty ruleset counts zero and keeps its policy",
              rules == 0 and policy == "ACCEPT", (rules, policy))

        print("\n A machine that is exposed")
        rows = [_listener("::", 5432), _listener("::", 22), _listener("::1", 8080),
                _listener("fe80::1", 5353, proto="udp6")]
        L = Result("listeners")
        L.data = {"listeners": rows, "denied": 0, "owner_coverage": 100.0,
                  "sources": ["/proc/net/tcp6"], "v4_listeners": [{"proto": "tcp",
                                                                  "port": 22}]}
        A = Result("addresses")
        A.data = {"addresses": [{"address": "2a00:1450::5", "prefix_length": 64,
                                 "device": "eth0", "flags": "00", "scope": "global",
                                 "reachable": "internet", "why": "", "transition": None}],
                  "has_global": True, "has_unique_local": False}
        FW = Result("firewall")
        FW.data = {"probes": {"iptables": {"detail": "12 rule(s), INPUT policy DROP"},
                              "ip6tables": {"detail": "0 rule(s), INPUT policy ACCEPT"}},
                   "v4_rules": 12, "v6_rules": 0, "v4_policy": "DROP",
                   "v6_policy": "ACCEPT", "available": ["iptables", "ip6tables"],
                   "missing": [], "asymmetry": 12}
        S = Result("settings")
        S.data = {"settings": {}, "available": True}
        f = analyse(L, A, FW, S, {})
        check("services on a global address are reported",
              any("globally routable" in x["title"] for x in f), [x["title"] for x in f])
        check("PostgreSQL on :: is CRITICAL",
              any(x["severity"] == "critical" and "PostgreSQL" in x["title"] for x in f),
              [x["title"] for x in f])
        check("SSH is named rather than left as a port number",
              any("SSH" in x["title"] for x in f))
        check("the loopback listener is NOT reported as exposed",
              not any("8080" in x.get("evidence", "") and x["severity"] != "info"
                      for x in f))
        check("no IPv6 rules against 12 IPv4 rules is CRITICAL",
              any(x["severity"] == "critical" and "IPv6 has none" in x["title"]
                  for x in f), [x["title"] for x in f])
        check("and the fix warns not to block ICMPv6 wholesale",
              any("ICMPv6 must NOT be blocked" in x.get("fix", "") for x in f))
        check("an ACCEPT policy on IPv6 is reported",
              any("INPUT policy is ACCEPT" in x["title"] for x in f))
        check("differing default policies are reported",
              any("policies differ" in x["title"] for x in f))
        check("a port listening on IPv6 but not IPv4 is reported",
              any("but not IPv4" in x["title"] for x in f), [x["title"] for x in f])
        check("the no-NAT explanation is given",
              any("no NAT" in x.get("advice", "") for x in f))
        check("and so is the from-outside caveat",
              any("outside vantage point" in x.get("advice", "") for x in f))
        check("every finding carries advice",
              all(x.get("advice") for x in f),
              [x["title"] for x in f if not x.get("advice")])

        print("\n Approving what you meant to expose")
        approved = {"tcp6|::|22": {"approved": True}}
        f2 = analyse(L, A, FW, S, approved)
        check("an approved listener stops being reported individually",
              not any("SSH" in x["title"] for x in f2), [x["title"] for x in f2])
        check("but the database is still reported",
              any("PostgreSQL" in x["title"] for x in f2))

        print("\n A machine with no global address")
        A2 = Result("addresses")
        A2.data = {"addresses": [{"address": "fe80::1", "prefix_length": 64,
                                  "device": "eth0", "flags": "20", "scope": "link-local",
                                  "reachable": "link", "why": "", "transition": None}],
                   "has_global": False, "has_unique_local": False}
        f3 = analyse(L, A2, FW, S, {})
        check("services on :: are not called internet-facing without a global address",
              not any("globally routable" in x["title"] for x in f3),
              [x["title"] for x in f3])
        check("but the report warns that assigning one changes it",
              any("without anything on this machine being reconfigured"
                  in x.get("advice", "") for x in f3), [x["title"] for x in f3])

        print("\n A machine with nothing listening")
        L2 = Result("listeners")
        L2.data = {"listeners": [], "denied": 0, "owner_coverage": 0.0,
                   "sources": ["/proc/net/tcp6"], "v4_listeners": []}
        f4 = analyse(L2, A, FW, S, {})
        check("nothing listening is reported as such",
              any("Nothing is listening" in x["title"] for x in f4),
              [x["title"] for x in f4])
        check("and it notes a service can start at any time",
              any("this is one moment" in x.get("advice", "") for x in f4))

        print("\n IPv6 absent is NOT a clean result")
        LU = Result("listeners").unavailable("no /proc/net/tcp6")
        AU = Result("addresses").unavailable("no /proc/net/if_inet6")
        f5 = analyse(LU, AU, FW, S, {})
        check("the report says IPv6 is not available",
              any("not available" in x["title"] for x in f5), [x["title"] for x in f5])
        check("and says explicitly that is not the same as nothing being exposed",
              any("NOT the same as nothing being exposed" in x.get("advice", "")
                  for x in f5))
        check("the band reads 'not checked', not 'nothing exposed'",
              risk_band(0.0, checked=False)[0] == "not checked",
              risk_band(0.0, checked=False))
        check("a genuinely clean machine reads 'nothing exposed'",
              risk_band(0.0, checked=True)[0] == "nothing exposed")

        print("\n Unknown firewall rules are not absent rules")
        FWU = Result("firewall").unavailable(
            "no firewall tool could be run (iptables), so the rules are UNKNOWN. That is "
            "not the same as there being no rules")
        FWU.data = {"probes": {}, "v4_rules": None, "v6_rules": None, "v4_policy": None,
                    "v6_policy": None, "available": [], "missing": ["iptables"],
                    "asymmetry": None}
        f6 = analyse(L, A, FWU, S, {})
        check("unknown rules are reported as UNKNOWN",
              any("UNKNOWN" in x["title"] for x in f6), [x["title"] for x in f6])
        check("and explicitly not as 'no firewall'",
              any("not reported as 'no firewall'" in x.get("advice", "") for x in f6))
        check("the firewall chart says unknown rather than drawing zero",
              "UNKNOWN" in svg_firewall({"v4_rules": None, "v6_rules": None}))

        print("\n Transition addresses on the machine")
        A3 = Result("addresses")
        A3.data = {"addresses": [{"address": "2002:c000:204::1", "prefix_length": 16,
                                  "device": "sit0", "flags": "00", "scope": "global",
                                  "reachable": "internet", "why": "",
                                  "transition": {"name": "6to4", "prefix": "2002::/16",
                                                 "why": "carries IPv6 inside IPv4"}}],
                   "has_global": True, "has_unique_local": False}
        f7 = analyse(L2, A3, FW, S, {})
        check("a 6to4 address is reported",
              any("6to4" in x["title"] for x in f7), [x["title"] for x in f7])
        check("and a command to investigate it is offered",
              any(x.get("fix") for x in f7 if "6to4" in x["title"]))

        print("\n Settings")
        st = read_settings()
        check(f"settings are read or their absence explained ({st.status})",
              st.status in ("ok", "partial", "unavailable"))
        S2 = Result("settings")
        S2.data = {"settings": {
            "conf/all/forwarding": {"path": "/proc/sys/net/ipv6/conf/all/forwarding",
                                    "value": 1, "expected": 0, "severity": "high",
                                    "why": "acting as a router", "present": True,
                                    "mismatch": True},
            "conf/all/accept_ra": {"path": "/proc/sys/net/ipv6/conf/all/accept_ra",
                                   "value": 1, "expected": None, "severity": None,
                                   "why": "accepts advertisements", "present": True,
                                   "mismatch": False},
            "bindv6only": {"path": "/proc/sys/net/ipv6/bindv6only", "value": 0,
                           "expected": None, "severity": None, "why": "dual stack",
                           "present": True, "mismatch": False}},
            "available": True}
        f8 = analyse(L2, A, FW, S2, {})
        check("forwarding being on is reported",
              any("forwarding is 1" in x["title"] for x in f8), [x["title"] for x in f8])
        check("forwarding plus accepting advertisements is called out together",
              any("forwards IPv6 and accepts router advertisements" in x["title"]
                  for x in f8))
        check("a fix command is given as a sysctl",
              any("sysctl -w" in x.get("fix", "") for x in f8))
        check("bindv6only is explained rather than judged",
              any("bindv6only" in x["title"] and x["severity"] == "info" for x in f8))

        print("\n Running for real")
        res = run_check()
        check("a check completes on this machine", res["id"] > 0)
        check("the band matches whether anything was checked",
              (res["band"] == "not checked") == (not res["checked"]),
              (res["band"], res["checked"]))

        print("\n Persistence")
        sid = save_scan(L, A, FW, S, f, 120, "selftest")
        s = scan_summary(sid)
        check("a check is stored", s and s["id"] == sid)
        check("listeners are counted", s["listeners"] == len(rows), s["listeners"])
        check("internet-facing listeners are counted",
              s["internet_facing"] == 2, s["internet_facing"])
        check("the firewall asymmetry is stored",
              s["v4_rules"] == 12 and s["v6_rules"] == 0)
        check("observations are stored for listeners and addresses",
              q1("SELECT COUNT(*) c FROM observations WHERE scan_id=?",
                 (sid,))["c"] == len(rows) + len(A.data["addresses"]))
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                 (sid,))["c"] == len(f))
        save_scan(L, A, FW, S, f, 120)
        check("seeing a listener twice increments rather than duplicating",
              all(r["times_seen"] >= 2 for r in q("SELECT * FROM known", ())),
              [dict(r) for r in q("SELECT key, times_seen FROM known", ())])
        ok, key = approve_listener("5432", "our database")
        check("a listener can be approved by its port", ok, key)
        check("approval is recorded", baseline_map()[key]["approved"])
        check("approval can be revoked",
              revoke_listener("5432") >= 1 and not baseline_map()[key]["approved"])
        ok, why = approve_listener("65535")
        check("approving something never seen is refused with a reason",
              not ok and "has not been seen" in why, why)

        print("\n Charts")
        ex = svg_exposure(rows, True, {})
        check("a lane is drawn per reach", ex.count("<rect") >= 4)
        check("the internet lane is present", "THE INTERNET" in ex)
        check("the exposure chart with nothing says so",
              "nothing is listening" in svg_exposure([], True, {}))
        fwc = svg_firewall(FW.data)
        check("the firewall chart draws both protocols", fwc.count("<rect") >= 4)
        check("and names the gap", "gap of 12" in fwc)
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("charts guard against empty input",
              all("nothing to show" in x or "nothing is listening" in x or "UNKNOWN" in x
                  for x in (svg_pie([]), svg_bar([]), svg_exposure([], True, {}),
                            svg_firewall({}))))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export carries the disclaimer",
              "NO NAT" in j["disclaimer"].upper())
        check("JSON export says there is no NAT in IPv6",
              "no NAT in IPv6" in j["there_is_no_nat_in_ipv6"])
        check("JSON export says it cannot test from outside",
              "outside vantage point"
              in j["reachable_here_is_not_reachable_from_the_internet"])
        check("JSON export says a listener is not a vulnerability",
              "not a vulnerability" in j["a_listening_socket_is_not_a_vulnerability"])
        check("JSON export lists the limitations", len(j["limitations"]) >= 8)
        check("JSON export says unknown rules are not absent rules",
              any("never as absent" in x for x in j["limitations"]))
        c_ = export_csv(sid)
        check("CSV export has sections", c_.count("##") >= 3)
        check("CSV says reachable here is not reachable from the internet",
              any("not reachable from the internet" in l.lower()
                  for l in c_.splitlines()[:6]))
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)
        check("HTML export shows the fix commands", "To change it yourself" in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/listeners", "Listeners"),
                               ("/scans", "Checks"), ("/learn", "no nat"),
                               ("/logs", "Logs")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(),
                      r_.status_code)
            check("every page says reachable here is not reachable from the internet",
                  "not reachable from the internet" in cl.get("/").get_data(as_text=True))
            check("the learn page explains the two firewalls",
                  "two firewalls" in cl.get("/learn").get_data(as_text=True).lower())
            check("the learn page warns about blocking ICMPv6",
                  "ICMPv6" in cl.get("/learn").get_data(as_text=True))
            check("the listeners page says a socket is not a vulnerability",
                  "not a vulnerability" in cl.get("/listeners").get_data(as_text=True))
            r_ = cl.post("/check")
            check("a check runs from the web", r_.status_code == 302)
            approve_listener("5432")
            k = "tcp6|::|5432"
            r_ = cl.post("/revoke", data={"key": k})
            check("revoking from the web works",
                  r_.status_code == 302 and not baseline_map()[k]["approved"])
            r_ = cl.post("/approve", data={"key": k})
            check("approving from the web works",
                  r_.status_code == 302 and baseline_map()[k]["approved"])
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r_ = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200 and ctype in r_.headers["Content-Type"]
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/summary").get_json()
            check("the api declares it is read-only", api["read_only"] is True)
            check("the api declares it makes no network connection",
                  api["makes_no_network_connection"] is True)
            check("the api declares it cannot test from outside",
                  api["cannot_test_from_outside"] is True)

        print("\n It changes nothing and connects to nothing")
        mod = sys.modules[__name__]
        import inspect
        changers = [n for n in dir(mod)
                    if n.startswith(("set_sysctl", "add_rule", "drop_rule", "close_",
                                     "flush_", "block_"))
                    and n != "set_db_path"]
        check("no function exists to change a rule, socket or sysctl", not changers,
              changers)
        for name, cmd, _kind in FIREWALL_PROBES:
            listing = any(w in cmd for w in ("-S", "list", "status"))
            check(f"the {name} command is list-only", listing, cmd)
            check(f"the {name} command has no write verb",
                  not any(w in cmd for w in ("-A", "-D", "-F", "-P", "add", "delete",
                                             "flush", "insert")), cmd)
        # Checked against the collectors themselves, not the whole file: this
        # module necessarily contains the words "connect" and "sendto" in order to
        # assert it does not use them, so grepping its own source could never pass.
        collectors = [read_v6_listeners, read_v6_addresses, read_firewalls,
                      read_settings, address_scope, analyse, run_check]
        joined = "".join(inspect.getsource(fn) for fn in collectors)
        check("no collector opens a socket at all",
              "socket.socket" not in joined, "a checker must not connect to anything")
        check("no collector sends or connects",
              not any(w in joined for w in ("sendto", "sock.connect", ".connect((")),
              "no network connection may be made")
        check("socket is used only for address conversion and the hostname",
              all(w in ("inet_ntop", "inet_pton", "gethostname", "AF_INET6")
                  for w in re.findall(r"socket\.(\w+)", joined)),
              sorted(set(re.findall(r"socket\.(\w+)", joined))))

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, listeners=False))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned observations and findings",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("observations", "findings")))
        cmd_purge(argparse.Namespace(all=True, keep=1, listeners=False))
        check("purge --all clears the checks",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the listener list survives by default",
              q1("SELECT COUNT(*) c FROM known", ())["c"] > 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, listeners=True))
        check("purge --all --listeners clears it too",
              q1("SELECT COUNT(*) c FROM known", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    if failed:
        print("  Failed: " + ", ".join(failed))
    if skipped:
        print("  Skipped: " + ", ".join(skipped))
    if not failed:
        print("  All checks passed. Nothing on this machine was changed, no network\n"
              "  connection was made, and the temporary database has been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 11 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - IPv6 exposure checker, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                why IPv6 exposes things IPv4 did not
              %(prog)s check
              %(prog)s check --quiet --no-fix
              %(prog)s scope 2a00:1450::1   classify any address, no IPv6 needed
              %(prog)s approve 22 --label "our SSH"
              %(prog)s watch --interval 300
              %(prog)s check --fail-on-internet-facing
              %(prog)s serve                http://127.0.0.1:5000

            Read-only and offline. It changes no rule, socket or sysctl and makes
            no network connection. Fixes are printed for you to run.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB})")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def common(s):
        s.add_argument("--quiet", action="store_true", help="hide informational findings")
        s.add_argument("--show", type=int, help="limit how many findings are printed")
        s.add_argument("--no-fix", action="store_true",
                       help="do not print the suggested commands")
        s.add_argument("--fail-on-critical", action="store_true",
                       help="exit non-zero on any critical finding")
        s.add_argument("--fail-on-internet-facing", action="store_true",
                       help="exit non-zero if anything is offered on a global address")
        s.add_argument("--fail-over", type=float,
                       help="exit non-zero if the score exceeds this")
        s.add_argument("--note")
        return s

    s = common(sub.add_parser("check", help="find what is exposed over IPv6"))
    s.set_defaults(func=cmd_check)

    s = common(sub.add_parser("watch", help="check repeatedly, report only what is new"))
    s.add_argument("--interval", type=float, default=300.0)
    s.add_argument("--count", type=int)
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("scope", help="classify any IPv6 address, no IPv6 stack needed")
    s.add_argument("address")
    s.set_defaults(func=cmd_scope)

    s = sub.add_parser("listeners", help="every listener seen")
    s.add_argument("--limit", type=int, default=60)
    s.set_defaults(func=cmd_listeners)

    s = sub.add_parser("approve", help="record that a listener is meant to be there")
    s.add_argument("target", help="a port, or the full key")
    s.add_argument("--label")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="undo an approval")
    s.add_argument("target")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("learn", help="why IPv6 exposes things IPv4 did not")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("scans", help="previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.add_argument("--listeners", action="store_true",
                   help="with --all, also delete the listener list and approvals")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, capabilities and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
