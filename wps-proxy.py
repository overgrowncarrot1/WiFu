#!/usr/bin/env python3

from scapy.all import RadioTap, Dot11, EAPOL, Ether, sendp, sniff
import subprocess, threading, time, sys, os

# ── Config ────────────────────────────────────────────────────────────────────
MON_IFACE    = "wlan14"
CLI_IFACE    = "wlan13"
AP_BSSID     = "02:00:00:00:07:00"
AP_IFACE     = "wlan7"
HOSTAPD_SOCK = "/var/run/hostapd"
WPS_PIN      = "12345670"
WS_DIR       = "/tmp/ws-wps-proxy"
AP_PASS      = "WPSairport123"
AP_FREQ      = "2457"

# ── Logging ───────────────────────────────────────────────────────────────────
def log(m):  print(f"\033[0;32m[proxy]\033[0m {m}", flush=True)
def warn(m): print(f"\033[1;33m[proxy]\033[0m {m}", flush=True)

def run(*cmd):
    return subprocess.run(list(cmd), capture_output=True, text=True)

def get_mac(iface):
    return open(f"/sys/class/net/{iface}/address").read().strip()

# ── Ensure WPS is active ──────────────────────────────────────────────────────
def ensure_wps_ready():
    log("Checking WPS status...")
    out = run("hostapd_cli", "-p", HOSTAPD_SOCK, "-i", AP_IFACE, "wps_get_status").stdout

    if "AP PIN" not in out:
        warn("WPS not ready — forcing PIN activation")
        run("hostapd_cli", "-p", HOSTAPD_SOCK, "-i", AP_IFACE, "wps_pin", "any", WPS_PIN)

    log("WPS ready ✓")

# ── Associate client ──────────────────────────────────────────────────────────
def associate_client():
    reaver_mac = get_mac(MON_IFACE)
    log(f"Spoofing {CLI_IFACE} → {reaver_mac}")

    run("pkill", "-f", f"wpa_supplicant.*{CLI_IFACE}")
    os.makedirs(WS_DIR, mode=0o777, exist_ok=True)

    run("ip", "link", "set", CLI_IFACE, "down")
    run("iw", "dev", CLI_IFACE, "set", "type", "managed")
    run("ip", "link", "set", CLI_IFACE, "address", reaver_mac)
    run("ip", "link", "set", CLI_IFACE, "up")

    conf = f"""
ctrl_interface={WS_DIR}
update_config=1
network={{
    ssid="Airport-WPS"
    psk="{AP_PASS}"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
    scan_freq={AP_FREQ}
    freq_list={AP_FREQ}
}}
"""
    open("/tmp/wps-proxy.conf","w").write(conf)

    subprocess.Popen(
        ["wpa_supplicant","-B","-i",CLI_IFACE,"-c","/tmp/wps-proxy.conf"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for _ in range(30):
        time.sleep(1)
        out = run("wpa_cli","-p",WS_DIR,"-i",CLI_IFACE,"status").stdout
        if "COMPLETED" in out:
            log(f"{CLI_IFACE} associated ✓")
            return True

    warn("Association failed")
    return False

# ── Light WPS keepalive ───────────────────────────────────────────────────────
def wps_keepalive():
    while True:
        time.sleep(120)
        run("hostapd_cli","-p",HOSTAPD_SOCK,"-i",AP_IFACE,"wps_pin","any",WPS_PIN)
        log("WPS window refreshed")

# ── EAPOL Bridge ──────────────────────────────────────────────────────────────
def on_monitor(pkt):
    if not pkt.haslayer(EAPOL):
        return
    eth = Ether(
        src=get_mac(CLI_IFACE),
        dst=AP_BSSID,
        type=0x888e
    ) / bytes(pkt[EAPOL])
    sendp(eth, iface=CLI_IFACE, verbose=False)

def on_managed(pkt):
    if not pkt.haslayer(EAPOL):
        return
    if pkt[Ether].src.lower() != AP_BSSID.lower():
        return

    radio = RadioTap()/Dot11(
        type=2, subtype=8,
        addr1=get_mac(CLI_IFACE),
        addr2=AP_BSSID,
        addr3=AP_BSSID
    ) / bytes(pkt[EAPOL])

    sendp(radio, iface=MON_IFACE, verbose=False)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log("WPS Proxy (fixed version)")

    ensure_wps_ready()

    if not associate_client():
        sys.exit(1)

    threading.Thread(target=wps_keepalive, daemon=True).start()

    threading.Thread(
        target=sniff,
        kwargs=dict(iface=MON_IFACE, prn=on_monitor, store=False),
        daemon=True,
    ).start()

    threading.Thread(
        target=sniff,
        kwargs=dict(iface=CLI_IFACE, filter="ether proto 0x888e",
                    prn=on_managed, store=False),
        daemon=True,
    ).start()

    log("Bridge active — run reaver now")

    while True:
        time.sleep(1)
