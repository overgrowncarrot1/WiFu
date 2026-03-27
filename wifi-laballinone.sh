#!/usr/bin/env bash
# =============================================================================
#  WiFi Challenge Lab — ALL-IN-ONE  (hardened)
#  Tested: Kali Linux 2024+ with mac80211_hwsim
#
#  All known issues fixed:
#    ✓ NetworkManager told to ignore virtual interfaces before anything starts
#    ✓ hwsim0 brought up before APs start (virtual RF medium)
#    ✓ set -e removed — one AP failure won't abort the whole lab
#    ✓ WEP replaced with EasyTarget-WPA2 (WEP unsupported on modern kernels)
#    ✓ WPA/TKIP has ieee80211n removed (TKIP incompatible with HT)
#    ✓ Hidden SSID moved to ch7 (ch13 blocked by regulatory on some systems)
#    ✓ Interfaces explicitly set to managed mode before hostapd claims them
#    ✓ iface.env written with correct socket path for clients.sh
#    ✓ Watchdog gated on .lab_ready sentinel (won't fire during startup)
# =============================================================================
set -uo pipefail      # NOT -e: one failing AP must not abort the whole script

export HOME="${HOME:-/root}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; X='\033[0m'

LAB_DIR="${LAB_DIR:-$HOME/wifi-lab}"
CONF_DIR="$LAB_DIR/conf"
WORDLIST="$LAB_DIR/wordlist.txt"
LOG="$LAB_DIR/lab.log"
PIDS="$LAB_DIR/pids"
PORTAL_DIR="$LAB_DIR/portal"
WS_DIR="/tmp/ws"   # wpa_supplicant socket directory — stable across sessions

mkdir -p "$CONF_DIR" "$PIDS" "$PORTAL_DIR"
> "$LOG"

log()  { echo -e "${G}[+]${X} $*" | tee -a "$LOG"; }
warn() { echo -e "${Y}[!]${X} $*" | tee -a "$LOG"; }
err()  { echo -e "${R}[✗]${X} $*" | tee -a "$LOG"; }
hdr()  { echo -e "\n${C}${B}━━━ $* ━━━${X}" | tee -a "$LOG"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

banner() {
  echo -e "${C}${B}"
  cat << 'ART'
  ██╗    ██╗██╗███████╗██╗      ██████╗██╗  ██╗ █████╗ ██╗
  ██║    ██║██║██╔════╝██║     ██╔════╝██║  ██║██╔══██╗██║
  ██║ █╗ ██║██║█████╗  ██║     ██║     ███████║███████║██║
  ██║███╗██║██║██╔══╝  ██║     ██║     ██╔══██║██╔══██║██║
  ╚███╔███╔╝██║██║     ██║     ╚██████╗██║  ██║██║  ██║███████╗
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                     W I F I   C H A L L E N G E   L A B
ART
  echo -e "${X}"
}

# =============================================================================
# STEP 0 — Tell NetworkManager to ignore ALL virtual lab interfaces
#           Must happen FIRST so NM never grabs wlan0-wlan15
# =============================================================================
configure_networkmanager() {
  hdr "Configuring NetworkManager to ignore lab interfaces"

  # Use wildcard — covers any number of virtual interfaces
  mkdir -p /etc/NetworkManager/conf.d
  cat > /etc/NetworkManager/conf.d/wifi-lab.conf << 'EOF'
[keyfile]
unmanaged-devices=interface-name:wlan*;interface-name:p2p-dev-wlan*
EOF

  # Reload NM config (non-disruptive — doesn't drop your real network)
  if systemctl is-active NetworkManager &>/dev/null; then
    systemctl reload NetworkManager 2>/dev/null || true
    sleep 1
    log "NetworkManager reloaded — all wlan* interfaces set to unmanaged ✓"
  else
    log "NetworkManager not running — no action needed ✓"
  fi
  sysctl net.ipv4.ip_forward
}

# =============================================================================
# STEP 1 — Clean previous state
# =============================================================================
clean_env() {
  hdr "Cleaning previous lab state"

  mkdir -p /var/run/hostapd
  pkill hostapd        2>/dev/null || true
  pkill freeradius     2>/dev/null || true
  pkill wpa_supplicant 2>/dev/null || true
  pkill dhclient       2>/dev/null || true
  sleep 1

  if lsmod | grep -q mac80211_hwsim; then
    rmmod mac80211_hwsim 2>/dev/null || true
    sleep 1
  fi

  rm -f "$PIDS"/*.pid "$PIDS"/*.pids "$LAB_DIR/.lab_ready" 2>/dev/null || true
  rfkill unblock all 2>/dev/null || true

  log "Environment clean ✓"
}

# =============================================================================
# STEP 2 — Install packages
# =============================================================================
install_packages() {
  hdr "Installing packages"
  apt-get update -qq 2>&1 | tee -a "$LOG"

  PKGS=(
    aircrack-ng hostapd iw wireless-tools rfkill
    net-tools iproute2 macchanger
    hcxtools hcxdumptool
    hashcat
    reaver bully pixiewps
    freeradius freeradius-utils
    python3 python3-pip
    curl wget tcpdump tshark wireshark-common
    mdk4 cowpatty arping
  )

  AVAILABLE=()
  for p in "${PKGS[@]}"; do
    apt-cache show "$p" &>/dev/null 2>&1 && AVAILABLE+=("$p") || warn "Package not found, skipping: $p"
  done

  DEBIAN_FRONTEND=noninteractive apt-get install -y "${AVAILABLE[@]}" \
    2>&1 | tee -a "$LOG"

  pip3 install --quiet --break-system-packages scapy 2>/dev/null || true
  log "Packages done ✓"
}

# =============================================================================
# STEP 3 — Load virtual radios
# =============================================================================
load_radios() {
  hdr "Loading virtual 802.11 radios"

  modinfo mac80211_hwsim &>/dev/null || {
    err "mac80211_hwsim not found. Install: apt-get install linux-modules-extra-$(uname -r)"
    exit 1
  }

  # Unload cleanly
  if lsmod | grep -q mac80211_hwsim; then
    mkdir -p /var/run/hostapd
  pkill hostapd        2>/dev/null || true
    pkill wpa_supplicant 2>/dev/null || true
    sleep 1
    rmmod mac80211_hwsim 2>/dev/null || true
    sleep 1
  fi

  # Load — try decreasing counts until one works
  LOADED=0
  for try_n in 18 16 12 10 8; do
    if modprobe mac80211_hwsim radios=$try_n 2>/dev/null; then
      log "Loaded mac80211_hwsim with radios=$try_n"
      LOADED=$try_n
      break
    fi
  done

  if [[ $LOADED -eq 0 ]]; then
    err "Failed to load mac80211_hwsim"
    exit 1
  fi

  sleep 2
  rfkill unblock all 2>/dev/null || true

  # ── CRITICAL: bring up hwsim0 (the virtual RF medium) ─────────────────────
  # Without this, virtual radios cannot hear each other — clients will scan
  # forever and never find any AP.
  ip link set hwsim0 up 2>/dev/null || true
  sleep 1
  log "hwsim0 (virtual RF medium): $(ip link show hwsim0 2>/dev/null | grep -o 'state [A-Z]*' || echo 'unknown')"

  # Collect interfaces
  mapfile -t IFACES < <(iw dev 2>/dev/null | awk '/Interface/{print $2}' | sort -V)
  N=${#IFACES[@]}
  log "Detected $N virtual interfaces: ${IFACES[*]}"

  if [[ $N -lt 9 ]]; then
    err "Only $N interfaces — need at least 9. Try: modprobe mac80211_hwsim radios=12"
    exit 1
  fi

  # ── Interface layout ───────────────────────────────────────────────────────
  # Index  Role
  #  0-3   Core APs  (Open, EasyWPA2, WPA, WPA2)  — always available
  #  4-8   Extra APs (WPA3, Enterprise, Hidden, WPS, DupSSID) — if N≥9
  #  9-12  Clients   (one per core AP)
  #  13    Client for WPA3 (if N≥14)
  #  14    Attacker interface #0
  #  15    Attacker interface #1

  IF_OPEN="${IFACES[0]}"    # AP: CoffeeShop-FreeWiFi  ch6
  IF_WEP="${IFACES[1]}"     # AP: EasyTarget-WPA2      ch1  (WEP dead on modern kernels)
  IF_WPA="${IFACES[2]}"     # AP: WPA-PSK-Lab          ch3
  IF_WPA2="${IFACES[3]}"    # AP: ChallengeNet-WPA2    ch11
  IF_WPA3="${IFACES[4]:-}"  # AP: SecureNet-WPA3       ch9
  IF_ENT="${IFACES[5]:-}"   # AP: CorpNet-8021X        ch8
  IF_HIDDEN="${IFACES[6]:-}"# AP: [hidden]             ch7
  IF_WPS="${IFACES[7]:-}"   # AP: Airport-WPS          ch10
  IF_DUP1="${IFACES[8]:-}"  # AP: Airport-WiFi (dup)   ch6

  IF_CLI_OPEN="${IFACES[9]}"   # client → Open
  IF_CLI_WEP="${IFACES[10]}"   # client → EasyTarget-WPA2
  IF_CLI_WPA="${IFACES[11]}"   # client → WPA
  IF_CLI_WPA2="${IFACES[12]}"  # client → WPA2
  IF_CLI_WPA3="${IFACES[13]:-}"# client → WPA3

  IF_ATK0="${IFACES[14]:-${IFACES[9]}}"  # attacker/monitor
  IF_ATK1="${IFACES[15]:-}"

  [[ -n "${IF_WPA3:-}" ]]  && HAVE_WPA3=1 || HAVE_WPA3=0

  log "APs: 0-8  Clients: 9-13  Attackers: 14-15  WPA3: $HAVE_WPA3"

  # ── Write iface.env ────────────────────────────────────────────────────────
  cat > "$LAB_DIR/iface.env" << EOF
# Auto-generated — do not edit manually
IF_OPEN=$IF_OPEN
IF_WEP=$IF_WEP
IF_WPA=$IF_WPA
IF_WPA2=$IF_WPA2
IF_WPA3=${IF_WPA3:-}
IF_ENT=${IF_ENT:-}
IF_HIDDEN=${IF_HIDDEN:-}
IF_WPS=${IF_WPS:-}
IF_DUP1=${IF_DUP1:-}
IF_CLI_OPEN=$IF_CLI_OPEN
IF_CLI_WEP=$IF_CLI_WEP
IF_CLI_WPA=$IF_CLI_WPA
IF_CLI_WPA2=$IF_CLI_WPA2
IF_CLI_WPA3=${IF_CLI_WPA3:-}
IF_ATK0=$IF_ATK0
IF_ATK1=${IF_ATK1:-}
HAVE_WPA3=$HAVE_WPA3
HAVE_5G=0
LAB_DIR=$LAB_DIR
WORDLIST=$LAB_DIR/wordlist.txt
WS_DIR=$WS_DIR
GW_OPEN=10.0.0.1
GW_WEP=10.0.1.1
GW_WPA=10.0.2.1
GW_WPA2=10.0.3.1
GW_WPA3=10.0.4.1
GW_ENT=10.0.5.1
GW_HIDDEN=10.0.6.1
GW_WPS=10.0.7.1
GW_DUP1=10.0.8.1
EOF
  log "iface.env written → $LAB_DIR/iface.env"
}

# =============================================================================
# STEP 4 — Wordlist
# =============================================================================
build_wordlist() {
  hdr "Building wordlist"
  cat > "$WORDLIST" << 'EOF'
password
password123
12345678
letmein
wifi@2024
WPA2SecretKey
WPA3TopSecret
labpassword
ChallengePassword
airport123
WPSairport123
CorpPassword!
abc12345
EasyTarget
EOF

  for base in wifi admin password corp airport lab net guest; do
    printf '%s\n%s123\n%s@2024\n%s2024\n' \
      "$base" "$base" "$base" "$base"
  done >> "$WORDLIST"

  for i in $(seq 0 499); do echo "pass$i"; done >> "$WORDLIST"

  sort -u "$WORDLIST" -o "$WORDLIST"
  log "Wordlist: $(wc -l < "$WORDLIST") entries"
}

# =============================================================================
# STEP 5 — Certificates (WPA2-Enterprise)
# =============================================================================
build_certs() {
  hdr "Generating WPA2-Enterprise certificates"
  CERT="$LAB_DIR/certs"
  mkdir -p "$CERT"
  [[ -f "$CERT/ca.pem" ]] && { log "Certs already exist ✓"; return; }

  openssl req -new -x509 -days 3650 -nodes \
    -out "$CERT/ca.pem" -keyout "$CERT/ca.key" \
    -subj "/C=US/ST=Lab/O=WiFiLab/CN=CA" 2>/dev/null

  openssl req -new -nodes \
    -out "$CERT/server.csr" -keyout "$CERT/server.key" \
    -subj "/C=US/ST=Lab/O=WiFiLab/CN=radius.lab" 2>/dev/null

  openssl x509 -req -days 3650 \
    -in "$CERT/server.csr" \
    -CA "$CERT/ca.pem" -CAkey "$CERT/ca.key" \
    -CAcreateserial -out "$CERT/server.pem" 2>/dev/null

  openssl dhparam -out "$CERT/dh" 1024 2>/dev/null
  log "Certificates created ✓"
}

# =============================================================================
# STEP 6 — FreeRADIUS
# =============================================================================
configure_radius() {
  hdr "Configuring FreeRADIUS"
  RDDIR=/etc/freeradius/3.0
  [[ -d $RDDIR ]] || { warn "FreeRADIUS not installed — Enterprise AP will still broadcast but auth will fail"; return; }

  cat > "$RDDIR/users" << 'EOF'
alice   Cleartext-Password := "password123"
bob     Cleartext-Password := "letmein"
charlie Cleartext-Password := "abc123"
EOF

  CERT="$LAB_DIR/certs"
  if [[ -f "$CERT/server.pem" ]]; then
    cp "$CERT/ca.pem"     "$RDDIR/certs/ca.pem"     2>/dev/null || true
    cp "$CERT/server.pem" "$RDDIR/certs/server.pem"  2>/dev/null || true
    cp "$CERT/server.key" "$RDDIR/certs/server.key"  2>/dev/null || true
    cp "$CERT/dh"         "$RDDIR/certs/dh"          2>/dev/null || true
    chown -R freerad:freerad "$RDDIR/certs"           2>/dev/null || true
  fi

  systemctl stop freeradius 2>/dev/null || true
  sleep 0.5
  freeradius -X >> "$LOG" 2>&1 &
  echo $! > "$PIDS/freeradius.pid"
  sleep 1
  pgrep freeradius &>/dev/null && log "FreeRADIUS started ✓" || warn "FreeRADIUS failed to start — check $LOG"
}

# =============================================================================
# STEP 7 — Build hostapd configs
# =============================================================================
build_configs() {
  hdr "Building hostapd configs"

  # Helper: reset an interface to managed before hostapd claims it
  prep_iface() {
    local iface=$1
    [[ -z "$iface" ]] && return
    ip link set "$iface" down    2>/dev/null || true
    iw dev "$iface" set type managed 2>/dev/null || true
    ip link set "$iface" up       2>/dev/null || true
  }

  # 01 — Open (ch6)
  prep_iface "$IF_OPEN"
  cat > "$CONF_DIR/01-open.conf" << EOF
interface=$IF_OPEN
driver=nl80211
ssid=CoffeeShop-FreeWiFi
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

  # 02 — EasyTarget-WPA2 (ch1)
  # NOTE: WEP is removed — unsupported on kernels ≥5.18 with modern cfg80211.
  # This slot teaches the same lesson (weak password = crackable) via WPA2.
  prep_iface "$IF_WEP"
  cat > "$CONF_DIR/02-wep.conf" << EOF
interface=$IF_WEP
driver=nl80211
ssid=EasyTarget-WPA2
hw_mode=g
channel=1
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

  # 03 — WPA/TKIP (ch3)
  # NOTE: ieee80211n MUST be omitted with TKIP — kernel rejects the combination
  prep_iface "$IF_WPA"
  cat > "$CONF_DIR/03-wpa.conf" << EOF
interface=$IF_WPA
driver=nl80211
ssid=WPA-PSK-Lab
hw_mode=g
channel=3
macaddr_acl=0
auth_algs=1
wpa=1
wpa_passphrase=wifi@2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
EOF

  # 04 — WPA2/CCMP (ch11)
  prep_iface "$IF_WPA2"
  cat > "$CONF_DIR/04-wpa2.conf" << EOF
interface=$IF_WPA2
driver=nl80211
ssid=ChallengeNet-WPA2
hw_mode=g
channel=11
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=WPA2SecretKey
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

  # 05 — WPA3 transition mode (ch9)
  # ieee80211w=1 = PMF optional, not required
  # wpa_key_mgmt=SAE WPA-PSK = accepts both WPA3 and WPA2 clients
  # This is the common real-world misconfiguration that allows a downgrade attack:
  # a WPA2 client can connect and produce a crackable 4-way handshake
  # despite the AP advertising WPA3. The fix is ieee80211w=2 (PMF mandatory).
  if [[ -n "${IF_WPA3:-}" ]]; then
    prep_iface "$IF_WPA3"
    cat > "$CONF_DIR/05-wpa3.conf" << EOF
interface=$IF_WPA3
driver=nl80211
ssid=SecureNet-WPA3
hw_mode=g
channel=9
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_key_mgmt=SAE WPA-PSK
rsn_pairwise=CCMP
sae_password=WPA3TopSecret
wpa_passphrase=WPA3TopSecret
ieee80211w=1
EOF
  fi

  # 06 — Enterprise (ch8)
  if [[ -n "${IF_ENT:-}" ]]; then
    prep_iface "$IF_ENT"
    cat > "$CONF_DIR/06-enterprise.conf" << EOF
interface=$IF_ENT
driver=nl80211
ssid=CorpNet-8021X
hw_mode=g
channel=8
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eapol_version=2
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=radiussecret
EOF
  fi

  # 07 — Hidden SSID (ch7)
  if [[ -n "${IF_HIDDEN:-}" ]]; then
    prep_iface "$IF_HIDDEN"
    cat > "$CONF_DIR/07-hidden.conf" << EOF
ctrl_interface=/tmp/ws
ctrl_interface_group=0
update_config=1

network={
    ssid="HiddenLab"
    psk="SuperSecret123"

    scan_ssid=1   #  REQUIRED

    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP

    scan_freq=2442
    freq_list=2442

    priority=10
}
EOF
  fi

  # 08 — WPS (ch10)
  if [[ -n "${IF_WPS:-}" ]]; then
    prep_iface "$IF_WPS"
    cat > "$CONF_DIR/08-wps.conf" << EOF
interface=wlan7
driver=nl80211
ssid=Airport-WPS
hw_mode=g
channel=10

ieee80211n=1
wmm_enabled=1

macaddr_acl=0
auth_algs=1

wpa=2
wpa_passphrase=WPSairport123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP

# WPS CORE
eap_server=1
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
eapol_version=2

ap_pin=12345670

wps_state=2
ap_setup_locked=0
wps_independent=1
wps_cred_processing=1

config_methods=label display push_button keypad

# REQUIRED identity fields
device_name=LabRouter
friendly_name=LabRouter
manufacturer=LabVendor
model_name=LabRouter
model_number=1
serial_number=12345
device_type=6-0050F204-1

uuid=12345678-1234-1234-1234-123456789012
wps_rf_bands=g
EOF
  fi

  # 09 — Duplicate SSID (ch6)
  if [[ -n "${IF_DUP1:-}" ]]; then
    prep_iface "$IF_DUP1"
    cat > "$CONF_DIR/09-dup.conf" << EOF
interface=$IF_DUP1
driver=nl80211
ssid=Airport-WiFi
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=airport123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
  fi

  log "All hostapd configs created ✓"
}

# =============================================================================
# STEP 8 — Start APs
# =============================================================================
start_aps() {
  hdr "Starting access points"

  pkill hostapd 2>/dev/null || true
  sleep 0.5

  started=0
  for conf in "$CONF_DIR"/[0-9]*.conf; do
    [[ -f "$conf" ]] || continue
    label=$(basename "$conf" .conf)
    iface=$(grep "^interface=" "$conf" | cut -d= -f2)

    # Ensure interface is in clean managed state before hostapd starts
    ip link set "$iface" down    2>/dev/null || true
    iw dev "$iface" set type managed 2>/dev/null || true
    ip link set "$iface" up       2>/dev/null || true
    sleep 0.2

    if hostapd -B -P "$PIDS/${label}.pid" "$conf" >> "$LOG" 2>&1; then
      sleep 0.5
      mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
      if [[ "$mode" == "AP" ]]; then
        log "  ✓ $label ($iface)"
        (( started++ )) || true
      else
        warn "  ✗ $label — started but interface not in AP mode"
      fi
    else
      warn "  ✗ $label FAILED"
      # Show the actual error without aborting
      hostapd "$conf" 2>&1 | grep -m2 "Could not\|not allowed\|error\|failed" \
        | sed 's/^/        /' || true
    fi
    sleep 0.3
  done

  log "$started APs started"
}

# =============================================================================
# STEP 9 — Static IPs (no DHCP needed)
# =============================================================================
assign_static_ips() {
  hdr "Assigning static IPs"

  set_ip() {
    local iface=$1 addr=$2
    [[ -z "$iface" ]] && return
    ip addr flush dev "$iface" 2>/dev/null || true
    ip addr add "$addr" dev "$iface" 2>/dev/null || true
    log "  $iface → $addr"
  }

  # AP gateways
  set_ip "$IF_OPEN"  "10.0.0.1/24"
  set_ip "$IF_WEP"   "10.0.1.1/24"
  set_ip "$IF_WPA"   "10.0.2.1/24"
  set_ip "$IF_WPA2"  "10.0.3.1/24"
  [[ -n "${IF_WPA3:-}" ]]   && set_ip "$IF_WPA3"   "10.0.4.1/24"
  [[ -n "${IF_ENT:-}" ]]    && set_ip "$IF_ENT"    "10.0.5.1/24"
  [[ -n "${IF_HIDDEN:-}" ]] && set_ip "$IF_HIDDEN" "10.0.6.1/24"
  [[ -n "${IF_WPS:-}" ]]    && set_ip "$IF_WPS"    "10.0.7.1/24"
  [[ -n "${IF_DUP1:-}" ]]   && set_ip "$IF_DUP1"   "10.0.8.1/24"

  # Client IPs (set here AND in clients.sh — belt and braces)
  set_ip "$IF_CLI_OPEN" "10.0.0.10/24"
  set_ip "$IF_CLI_WEP"  "10.0.1.10/24"
  set_ip "$IF_CLI_WPA"  "10.0.2.10/24"
  set_ip "$IF_CLI_WPA2" "10.0.3.10/24"
  [[ -n "${IF_CLI_WPA3:-}" ]] && set_ip "$IF_CLI_WPA3" "10.0.4.10/24"

  log "Static IPs assigned ✓"
}

# =============================================================================
# STEP 10 — Captive portal (for Evil Twin challenge)
# =============================================================================
build_captive_portal() {
  hdr "Building captive portal"

  cat > "$PORTAL_DIR/index.html" << 'EOF'
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WiFi Login</title>
<style>
  body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:20px}
  h2{color:#2c3e50}
  input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
  button{background:#3498db;color:#fff;padding:12px;border:none;border-radius:4px;width:100%;cursor:pointer}
</style></head><body>
<h2>✈ Airport-WiFi — Sign in</h2>
<form method="POST" action="/login">
  <input type="text"     name="username" placeholder="Email" required>
  <input type="password" name="password" placeholder="Password" required>
  <br><br><button type="submit">Connect</button>
</form>
</body></html>
EOF

  cat > "$PORTAL_DIR/server.py" << 'PYEOF'
#!/usr/bin/env python3
"""Captive portal credential logger — lab use only"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus
import datetime, pathlib

BASE     = pathlib.Path(__file__).parent
CREDLOG  = BASE / "portal_creds.log"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        data = (BASE / "index.html").read_bytes()
        self.send_response(200); self.send_header("Content-Type","text/html")
        self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length",0))).decode()
        p    = parse_qs(body)
        u    = unquote_plus(p.get("username",[""])[0])
        pw   = unquote_plus(p.get("password",[""])[0])
        line = f"[{datetime.datetime.now().isoformat()}] {self.client_address[0]}  {u!r}:{pw!r}\n"
        with open(CREDLOG, "a") as f: f.write(line)
        print(f"\033[91m[CAPTURED]\033[0m {line.strip()}")
        self.send_response(302); self.send_header("Location","http://example.com"); self.end_headers()

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
PYEOF

  log "Captive portal ready — run: python3 $PORTAL_DIR/server.py"
}

# =============================================================================
# STEP 11 — Watchdog
# =============================================================================
self_heal() {
  hdr "Starting self-heal watchdog"

  # Kill any stale watchdog from a previous run
  if [[ -f "$PIDS/watchdog.pid" ]]; then
    kill "$(cat "$PIDS/watchdog.pid")" 2>/dev/null || true
    rm -f "$PIDS/watchdog.pid"
  fi

  READY_FILE="$LAB_DIR/.lab_ready"
  rm -f "$READY_FILE"

  (
    # Wait for print_map to write the sentinel before doing anything
    waited=0
    while [[ ! -f "$READY_FILE" ]]; do
      sleep 1
      (( waited++ )) || true
      [[ $waited -gt 180 ]] && exit 0
    done

    while true; do
      sleep 30

      if ! pgrep hostapd >/dev/null 2>&1; then
        echo "[heal $(date +%T)] hostapd died — restarting" >> "$LOG"
        for conf in "$CONF_DIR"/[0-9]*.conf; do
          [[ -f "$conf" ]] || continue
          label=$(basename "$conf" .conf)
          iface=$(grep "^interface=" "$conf" | cut -d= -f2)
          ip link set "$iface" down    2>/dev/null || true
          iw dev "$iface" set type managed 2>/dev/null || true
          ip link set "$iface" up       2>/dev/null || true
          hostapd -B -P "$PIDS/${label}_heal.pid" "$conf" >> "$LOG" 2>&1 || true
          sleep 0.4
        done
      fi

      if [[ -n "${IF_ENT:-}" ]] && ! pgrep freeradius >/dev/null 2>&1; then
        echo "[heal $(date +%T)] freeradius died — restarting" >> "$LOG"
        freeradius -X >> "$LOG" 2>&1 &
      fi
    done
  ) &
  echo $! > "$PIDS/watchdog.pid"
  log "Watchdog started (PID $(cat "$PIDS/watchdog.pid"))"
}

# =============================================================================
# STEP 12 — Print lab map and write .lab_ready sentinel
# =============================================================================
print_map() {
  echo ""
  echo -e "${C}${B}╔══════════════════════════════════════════════════════════════════════╗${X}"
  echo -e "${C}${B}║                    WIFI CHALLENGE LAB — READY                      ║${X}"
  echo -e "${C}${B}╠══════╦══════════════════════╦════════════╦═══════╦════════════════╣${X}"
  printf  "${C}${B}║${X} %-4s ${C}${B}║${X} %-22s ${C}${B}║${X} %-10s ${C}${B}║${X} %-5s ${C}${B}║${X} %-14s ${C}${B}║${X}\n" \
    "#" "SSID" "Security" "Ch" "Interface"
  echo -e "${C}${B}╠══════╬══════════════════════╬════════════╬═══════╬════════════════╣${X}"

  pr() {
    printf "${C}${B}║${X} %-4s ${C}${B}║${X} %-22s ${C}${B}║${X} %-10s ${C}${B}║${X} %-5s ${C}${B}║${X} %-14s ${C}${B}║${X}\n" \
      "$1" "$2" "$3" "$4" "${5:-(unavail)}"
  }

  pr "01" "CoffeeShop-FreeWiFi"  "Open"      "6"  "$IF_OPEN"
  pr "02" "EasyTarget-WPA2"      "WPA2"      "1"  "$IF_WEP"
  pr "03" "WPA-PSK-Lab"          "WPA/TKIP"  "3"  "$IF_WPA"
  pr "04" "ChallengeNet-WPA2"    "WPA2/CCMP" "11" "$IF_WPA2"
  pr "05" "SecureNet-WPA3"       "WPA3→WPA2" "9"  "${IF_WPA3:-}"
  pr "06" "CorpNet-8021X"        "WPA2-EAP"  "8"  "${IF_ENT:-}"
  pr "07" "[hidden SSID]"        "WPA2"      "7"  "${IF_HIDDEN:-}"
  pr "08" "Airport-WPS"          "WPA2+WPS"  "10" "${IF_WPS:-}"
  pr "09" "Airport-WiFi (dup)"   "WPA2"      "6"  "${IF_DUP1:-}"

  echo -e "${C}${B}╚══════╩══════════════════════╩════════════╩═══════╩════════════════╝${X}"
  echo ""
  echo -e "  ${B}Clients:${X}  $IF_CLI_OPEN $IF_CLI_WEP $IF_CLI_WPA $IF_CLI_WPA2 ${IF_CLI_WPA3:-}"
  echo -e "  ${B}Attacker:${X} $IF_ATK0  ${IF_ATK1:-(none)}"
  echo ""
  echo -e "  ${B}Next steps:${X}"
  echo -e "    sudo bash clients.sh                 # start client traffic"
  echo -e "    ip link set $IF_ATK0 down"
  echo -e "    iw dev $IF_ATK0 set type monitor"
  echo -e "    ip link set $IF_ATK0 up"
  echo -e "    airodump-ng $IF_ATK0                 # scan all APs"
  echo ""
  echo -e "  ${G}${B}Lab is running. Stop: sudo bash $(basename "$0") stop${X}"
  echo ""

  touch "$LAB_DIR/.lab_ready"
}

# =============================================================================
# STOP / STATUS / MAIN
# =============================================================================
stop_lab() {
  echo -e "${Y}[!]${X} Stopping WiFi Challenge Lab..."
  [[ -f "$PIDS/watchdog.pid" ]] && kill "$(cat "$PIDS/watchdog.pid")" 2>/dev/null || true
  pkill hostapd freeradius wpa_supplicant 2>/dev/null || true
  for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
    iw dev "$iface" set type managed 2>/dev/null || true
  done
  rm -f "$PIDS"/*.pid "$PIDS"/*.pids "$LAB_DIR/.lab_ready" 2>/dev/null || true
  echo -e "${G}[+]${X} Lab stopped."
}

status_lab() {
  source "$LAB_DIR/iface.env" 2>/dev/null || true
  echo -e "${C}${B}━━━ Lab Status ━━━${X}"
  pgrep hostapd    &>/dev/null && echo -e "  hostapd:    ${G}running${X} ($(pgrep -c hostapd) instances)" || echo -e "  hostapd:    ${R}stopped${X}"
  pgrep freeradius &>/dev/null && echo -e "  freeradius: ${G}running${X}" || echo -e "  freeradius: ${R}stopped${X}"
  pgrep wpa_supplicant &>/dev/null && echo -e "  clients:    ${G}running${X}" || echo -e "  clients:    ${R}stopped${X}"
  echo ""
  echo -e "  APs:"
  iw dev 2>/dev/null | awk '/Interface/{i=$2} /type AP/{print "    "i}' || echo "    (none)"
  echo ""
  echo -e "  Last 3 log lines:"
  tail -3 "$LOG" 2>/dev/null | sed 's/^/    /' || true
}

run_all() {
  banner
  configure_networkmanager
  clean_env
  install_packages
  load_radios
  build_wordlist
  build_certs
  configure_radius
  build_configs
  start_aps
  assign_static_ips
  build_captive_portal
  self_heal
  print_map
}

case "${1:-all}" in
  all|start)  run_all ;;
  stop)       stop_lab ;;
  status)     status_lab ;;
  clients)
    source "$LAB_DIR/iface.env" 2>/dev/null || { echo "Run '$0 all' first"; exit 1; }
    bash "$(dirname "$0")/clients.sh"
    ;;
  help|-h|--help)
    echo "Usage: sudo bash $0 [all|stop|status|clients|help]"
    echo "  all      — start the full lab (default)"
    echo "  stop     — tear down everything"
    echo "  status   — show what's running"
    echo "  clients  — (re)start clients only"
    ;;
  *) echo "Unknown: $1. Try: sudo bash $0 help"; exit 1 ;;
esac
