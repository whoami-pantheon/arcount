"""Rootless attack lab: gateway / victim / attacker network namespaces on a bridge.

Must run inside `unshare -Urnm` (see tests/lab/run.sh) or as real root, with a tmpfs on /run.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from arcount import cli
from arcount.store import Store

ROOT = Path(__file__).resolve().parents[2]
GW_IP, GW_MAC = "10.99.0.1", "00:11:22:33:44:01"
VICTIM_IP, VICTIM_MAC = "10.99.0.50", "02:00:00:00:00:50"
EVIL_IP, EVIL_MAC = "10.99.0.66", "00:de:ad:be:ef:66"

FORGE = """
import sys
from scapy.all import Ether, ARP, sendp
iface, smac, dmac, op, psrc, pdst, hwdst, count, inter = sys.argv[1:10]
pkt = Ether(src=smac, dst=dmac) / ARP(op=int(op), hwsrc=smac, psrc=psrc, hwdst=hwdst, pdst=pdst)
sendp(pkt, iface=iface, count=int(count), inter=float(inter), verbose=0)
"""

RESPOND = """
import sys
from scapy.all import Ether, ARP, sendp, sniff
iface, target, mac = sys.argv[1:4]
def cb(p):
    if p.haslayer(ARP) and p[ARP].op == 1 and p[ARP].pdst == target:
        sendp(Ether(src=mac, dst=p[Ether].src) / ARP(op=2, hwsrc=mac, psrc=target,
              hwdst=p[ARP].hwsrc, pdst=p[ARP].psrc), iface=iface, verbose=0)
sniff(iface=iface, filter="arp", prn=cb, store=0)
"""


def sh(*cmd, ns=None, check=True, timeout=30):
    full = ["ip", "netns", "exec", ns, *cmd] if ns else list(cmd)
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(full)} failed: {r.stderr.strip()}")
    return r.stdout


def wait_until(pred, timeout=20.0, interval=0.25, what="condition"):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            last = pred()
            if last:
                return last
        except Exception as e:           # DB not there yet, socket not up yet...
            last = e
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what} (last={last!r})")


class Lab:
    def __init__(self, tmp: Path, config_text: str = ""):
        self.tmp = tmp
        self.state, self.run = tmp / "state", tmp / "run"
        self.state.mkdir()
        self.run.mkdir()
        self.db, self.sock = str(self.state / "arcount.db"), str(self.run / "arcount.sock")
        self.cfg = tmp / "arcount.toml"
        self.cfg.write_text("[detection]\nlearning_seconds = 4\n" + config_text)
        self.log = tmp / "daemon.log"
        self.daemon: subprocess.Popen | None = None
        self.bg: list[subprocess.Popen] = []
        self.nmcli_log = tmp / "nmcli.calls"
        self._build()

    # ---- topology ------------------------------------------------------------------
    def _build(self):
        sh("ip", "link", "set", "lo", "up")
        sh("ip", "link", "add", "br0", "type", "bridge")
        sh("ip", "link", "set", "br0", "up")
        macs = {"gw": GW_MAC, "victim": VICTIM_MAC, "attacker": EVIL_MAC}
        ips = {"gw": GW_IP, "victim": VICTIM_IP, "attacker": EVIL_IP}
        for n in macs:
            sh("ip", "netns", "add", n)
            sh("ip", "link", "add", f"h-{n}", "type", "veth", "peer", "name", "lan0", "netns", n)
            sh("ip", "link", "set", f"h-{n}", "master", "br0", "up")
            sh("ip", "link", "set", "lo", "up", ns=n)
            sh("ip", "link", "set", "lan0", "address", macs[n], ns=n)
            sh("ip", "addr", "add", f"{ips[n]}/24", "dev", "lan0", ns=n)
            sh("ip", "link", "set", "lan0", "up", ns=n)
        sh("ip", "route", "add", "default", "via", GW_IP, ns="victim")
        # a fake nmcli that records its arguments (disconnect response test)
        shim = self.tmp / "nmcli"
        shim.write_text(f'#!/bin/sh\necho "$@" >> {self.nmcli_log}\nexit 0\n')
        shim.chmod(0o755)
        sh("mount", "--bind", str(shim), "/usr/bin/nmcli")
        sh("ping", "-c1", "-W2", GW_IP, ns="victim")        # prime the victim's neighbour entry

    def teardown(self):
        self.stop_daemon()
        for p in self.bg:
            p.kill()
            p.wait()
        for n in ("gw", "victim", "attacker"):
            sh("ip", "netns", "del", n, check=False)
        for n in ("gw", "victim", "attacker"):
            sh("ip", "link", "del", f"h-{n}", check=False)
        sh("ip", "link", "del", "br0", check=False)
        sh("umount", "/usr/bin/nmcli", check=False)

    # ---- daemon --------------------------------------------------------------------------
    def start_daemon(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PATH": os.environ["PATH"]}
        logf = open(self.log, "ab")
        self.daemon = subprocess.Popen(
            ["ip", "netns", "exec", "victim", sys.executable, "-m", "arcount.daemon", "--no-nm",
             "--state-dir", str(self.state), "--run-dir", str(self.run), "--config", str(self.cfg),
             "-v"], env=env, stderr=logf, stdout=logf)
        wait_until(lambda: os.path.exists(self.sock) and self.status(), 15, what="daemon socket")
        return self.daemon

    def stop_daemon(self, sig=signal.SIGTERM):
        if self.daemon and self.daemon.poll() is None:
            self.daemon.send_signal(sig)
            try:
                self.daemon.wait(10)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait()
        self.daemon = None

    def daemon_log(self) -> str:
        return self.log.read_text(errors="replace") if self.log.exists() else ""

    # ---- observation ------------------------------------------------------------------------
    def status(self):
        r = cli.ctl(self.sock, {"cmd": "status"}, timeout=3)
        return r if r.get("ok") else None

    def session(self, iface="lan0"):
        st = self.status()
        return next((s for s in st["sessions"] if s["iface"] == iface), None) if st else None

    def wait_state(self, state, timeout=20):
        return wait_until(lambda: (self.session() or {}).get("state") == state and self.session(),
                          timeout, what=f"session state {state}\n{self.daemon_log()[-1500:]}")

    def events(self, min_severity=0):
        st = Store(self.db, readonly=True)
        try:
            return [{**dict(e), "rules": json.loads(e["rules"]), "macs": json.loads(e["macs"]),
                     "details": json.loads(e["details"])}
                    for e in st.events(min_severity=min_severity, limit=1000)]
        finally:
            st.close()

    def wait_event(self, pred, timeout=20, what="event", min_severity=0):
        return wait_until(lambda: next((e for e in self.events(min_severity) if pred(e)), None),
                          timeout, what=f"{what}\nevents={self.events()}\n{self.daemon_log()[-2000:]}")

    def store(self, readonly=True):
        return Store(self.db, readonly=readonly)

    def neigh(self, ip=GW_IP):
        return sh("ip", "neigh", "show", ip, "dev", "lan0", ns="victim").strip()

    def cli(self, *args):
        r = subprocess.run([sys.executable, "-m", "arcount", "--db", self.db, "--sock", self.sock,
                            *args], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        return r.returncode, r.stdout, r.stderr

    # ---- attacks --------------------------------------------------------------------------------
    def forge(self, op, psrc, pdst, dmac, hwdst, count=1, inter=0.2, smac=EVIL_MAC, ns="attacker"):
        sh(sys.executable, "-c", FORGE, "lan0", smac, dmac, str(op), psrc, pdst, hwdst,
           str(count), str(inter), ns=ns, timeout=60)

    def gateway_announce(self):
        """The real gateway re-asserts itself (unicast reply to the victim)."""
        self.forge(2, GW_IP, VICTIM_IP, VICTIM_MAC, VICTIM_MAC, smac=GW_MAC, ns="gw")

    def poison_gateway(self, count=1, inter=0.2):
        """arpspoof-style: unicast reply to the victim claiming the gateway's IP."""
        self.forge(2, GW_IP, VICTIM_IP, VICTIM_MAC, VICTIM_MAC, count, inter)

    def start_responder(self, target_ip=GW_IP, mac=EVIL_MAC):
        """An attacker NIC that answers 'who-has target_ip' too."""
        p = subprocess.Popen(["ip", "netns", "exec", "attacker", sys.executable, "-c", RESPOND,
                              "lan0", target_ip, mac], stderr=subprocess.DEVNULL)
        self.bg.append(p)
        time.sleep(1.5)                                   # scapy import + sniff start
        return p

    def set_gateway_mac(self, mac):
        sh("ip", "link", "set", "lan0", "down", ns="gw")
        sh("ip", "link", "set", "lan0", "address", mac, ns="gw")
        sh("ip", "link", "set", "lan0", "up", ns="gw")
        sh("ip", "neigh", "flush", "dev", "lan0", ns="victim", check=False)

    def nmcli_calls(self):
        return self.nmcli_log.read_text().splitlines() if self.nmcli_log.exists() else []
