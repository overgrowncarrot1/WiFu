#!/usr/bin/env bash
# =============================================================================
#  WiFi Challenge Lab — Client Simulator  (hardened v2)
#
#  Fixes applied from session:
#    ✓ Hidden client uses IF_CLI_HIDDEN (wlan16) not wlan13
#    ✓ Enterprise client uses IF_CLI_ENT (wlan17)
#    ✓ start_traffic calls all have correct 7 args (iface gw conf label ip src_mac dst_mac)
#    ✓ client-hidden.conf and client-enterprise.conf read from conf dir
#    ✓ scapy injection for HTTP/DNS (bypasses kernel loopback)
#    ✓ Reauth loop keeps fresh handshakes available every 60s
#    ✓ Captive portal loop on open network client
# =============================================================================
set -uo pipefail

export HOME="${HOME:-/root}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; X='\033[0m'

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

ENV_FILE="${LAB_DIR:-$HOME/wifi-lab}/iface.env"
[[ -f "$ENV_FILE" ]] || {
  echo -e "${R}[✗]${X} $ENV_FILE not found. Run wifi-laballinone.sh all first."
  exit 1
}
source "$ENV_FILE"

PIDS="$LAB_DIR/pids"
LOG="$LAB_DIR/clients.log"
WS_DIR="${WS_DIR:-/tmp/ws}"

mkdir -p "$PIDS"
> "$LOG"

log()  { echo -e "${G}[+]${X} $*" | tee -a "$LOG"; }
warn() { echo -e "${Y}[!]${X} $*" | tee -a "$LOG"; }
hdr()  { echo -e "\n${C}${B}━━━ $* ━━━${X}" | tee -a "$LOG"; }

install -d -m 0777 "$WS_DIR"
log "Socket dir: $WS_DIR"

# =============================================================================
# HELPERS
# =============================================================================
prep() {
  local iface=$1
  [[ -z "$iface" ]] && return 1
  pkill -f "wpa_supplicant.*-i $iface" 2>/dev/null || true
  sleep 0.3
  ip link set "$iface" down        2>/dev/null || true
  iw dev "$iface" set type managed 2>/dev/null || true
  ip addr flush dev "$iface"       2>/dev/null || true
  ip link set "$iface" up
}

start_wpa() {
  local iface=$1 conf=$2 label=$3
  [[ -z "$iface" ]] && { warn "start_wpa: empty iface for $label"; return 1; }
  wpa_supplicant -B -i "$iface" -c "$conf" \
    -P "$PIDS/wpa_${label}.pid" >> "$LOG" 2>&1 \
    && log "  wpa_supplicant started: $label ($iface)" \
    || { warn "  wpa_supplicant FAILED: $label — check $LOG"; return 1; }
}

wait_for_assoc() {
  local iface=$1 label=$2 timeout=${3:-20}
  local sock_wait=0
  while [[ ! -S "$WS_DIR/$iface" && $sock_wait -lt 10 ]]; do
    sleep 0.5; (( sock_wait++ )) || true
  done
  if [[ ! -S "$WS_DIR/$iface" ]]; then
    warn "  Socket never appeared for $label"
    return 0
  fi
  local i=0 state=""
  while (( i < timeout )); do
    state=$(wpa_cli -p "$WS_DIR" -i "$iface" status 2>/dev/null \
            | awk -F= '/^wpa_state/{print $2}')
    if [[ "$state" == "COMPLETED" ]]; then
      local ssid bssid
      ssid=$(wpa_cli  -p "$WS_DIR" -i "$iface" status 2>/dev/null | awk -F= '/^ssid/{print $2}')
      bssid=$(wpa_cli -p "$WS_DIR" -i "$iface" status 2>/dev/null | awk -F= '/^bssid/{print $2}')
      log "  Associated: $label → '$ssid'  BSSID=$bssid"
      return 0
    fi
    sleep 1; (( i++ )) || true
  done
  warn "  Timeout (${timeout}s) for $label — last state: $state"
  return 0
}

set_ip() {
  local iface=$1 addr=$2 gw=$3
  ip addr flush dev "$iface"       2>/dev/null || true
  ip addr add "$addr" dev "$iface" 2>/dev/null || true
  ip route add default via "$gw"  dev "$iface" 2>/dev/null || true
  local got
  got=$(ip addr show "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
  [[ -n "$got" ]] && log "  IP: $iface → $got" || warn "  IP failed on $iface"
}

# =============================================================================
# TRAFFIC LOOPS
# =============================================================================
loop_arp() {
  local iface=$1 gw=$2
  while true; do
    arping -c 1 -I "$iface" "$gw" >> "$LOG" 2>&1 || true
    sleep 8
  done
}

loop_ping() {
  local iface=$1 gw=$2
  while true; do
    ping -c 2 -W 2 -I "$iface" "$gw" >> "$LOG" 2>&1 || true
    sleep 12
  done
}

loop_http_scapy() {
  local iface=$1 src_mac=$2 dst_mac=$3 src_ip=$4 dst_ip=$5
  python3 - "$iface" "$src_mac" "$dst_mac" "$src_ip" "$dst_ip" << 'PYEOF'
import sys, time, random
from urllib.parse import urlencode
from scapy.all import Ether, IP, TCP, Raw, sendp

iface, src_mac, dst_mac, src_ip, dst_ip = sys.argv[1:]

uagents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

fake_creds = [
    ("admin","admin"),("admin","password"),("john.smith","password123"),
    ("alice","alice123"),("bob","qwerty"),("dave","123456"),
    ("j.doe","Welcome1"),("guest","guest"),
]

fake_cards = [
    ("4111111111111111","Visa","John Smith","12/26","123"),
    ("5500005555555559","Mastercard","Bob Williams","03/27","789"),
]

get_pages = [
    ("mail.corp-internal.com","/inbox"),("shop.local-store.net","/cart"),
    ("intranet.office.local","/dashboard"),("neverssl.com","/"),
    ("httpforever.com","/"),
]

login_targets = [
    ("mail.corp-internal.com","/login","username","password"),
    ("intranet.office.local","/login","user","pass"),
    ("shop.local-store.net","/account/login","email","passwd"),
    ("admin.router.local","/login","username","password"),
]

def send_pkt(payload, sport=None):
    sport = sport or random.randint(1024,65535)
    pkt = (Ether(src=src_mac,dst=dst_mac)/IP(src=src_ip,dst=dst_ip)/
           TCP(sport=sport,dport=80,flags="PA",seq=random.randint(1000,9999999))/
           Raw(load=payload))
    sendp(pkt, iface=iface, verbose=False)

def make_get(host, path, ua):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: text/html\r\nConnection: keep-alive\r\n\r\n").encode()

def make_post_login(host, path, uf, pf, user, passwd, ua):
    body = urlencode({uf:user, pf:passwd, "submit":"Login"})
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()

def make_post_checkout(host, ua):
    num,ct,name,exp,cvv = random.choice(fake_cards)
    body = urlencode({"card_number":num,"cardholder":name,"expiry":exp,
                      "cvv":cvv,"submit":"Place Order"})
    return (f"POST /checkout/payment HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()

actions = ["get"]*5 + ["login"]*3 + ["checkout"]*2
while True:
    ua = random.choice(uagents)
    action = random.choice(actions)
    if action == "get":
        host, path = random.choice(get_pages)
        send_pkt(make_get(host, path, ua))
    elif action == "login":
        host, path, uf, pf = random.choice(login_targets)
        user, passwd = random.choice(fake_creds)
        send_pkt(make_post_login(host, path, uf, pf, user, passwd, ua))
    elif action == "checkout":
        send_pkt(make_post_checkout("shop.local-store.net", ua))
    time.sleep(random.uniform(6, 18))
PYEOF
}

loop_dns_scapy() {
  local iface=$1 src_mac=$2 dst_mac=$3 src_ip=$4 dst_ip=$5
  python3 - "$iface" "$src_mac" "$dst_mac" "$src_ip" "$dst_ip" << 'PYEOF'
import sys, time, random
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp

iface, src_mac, dst_mac, src_ip, dst_ip = sys.argv[1:]
domains = ["example.com","github.com","google.com","neverssl.com",
           "httpforever.com","apple.com","microsoft.com","cloudflare.com"]
while True:
    pkt = (Ether(src=src_mac,dst=dst_mac)/IP(src=src_ip,dst=dst_ip)/
           UDP(sport=random.randint(1024,65535),dport=53)/
           DNS(rd=1,qd=DNSQR(qname=random.choice(domains))))
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(random.uniform(5,15))
PYEOF
}

loop_captive_portal_scapy() {
  local iface=$1 src_mac=$2 dst_mac=$3 src_ip=$4 portal_ip=$5
  python3 - "$iface" "$src_mac" "$dst_mac" "$src_ip" "$portal_ip" << 'PYEOF'
import sys, time, random
from urllib.parse import urlencode
from scapy.all import Ether, IP, TCP, Raw, sendp

iface, src_mac, dst_mac, src_ip, portal_ip = sys.argv[1:]

uagents = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "CaptiveNetworkSupport/1.0 wispr",
]

fake_creds = [
    ("alice@example.com","password"),("bob@company.com","letmein"),
    ("john.doe@gmail.com","password123"),("guest","guest"),
    ("admin","admin"),("traveler@yahoo.com","Travel2024"),
]

def send_http(payload, sport=None):
    sport = sport or random.randint(1024,65535)
    pkt = (Ether(src=src_mac,dst=dst_mac)/IP(src=src_ip,dst=portal_ip)/
           TCP(sport=sport,dport=8080,flags="PA",seq=random.randint(10000,9999999))/
           Raw(load=payload))
    sendp(pkt, iface=iface, verbose=False)

def make_get(ua):
    return (f"GET / HTTP/1.1\r\nHost: {portal_ip}:8080\r\nUser-Agent: {ua}\r\n"
            f"Accept: text/html\r\nConnection: close\r\n\r\n").encode()

def make_post(ua, user, pw):
    body = urlencode({"username":user,"password":pw,"submit":"Connect"})
    return (f"POST /login HTTP/1.1\r\nHost: {portal_ip}:8080\r\nUser-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode()

while True:
    ua = random.choice(uagents)
    user, pw = random.choice(fake_creds)
    send_http(make_get(ua))
    time.sleep(random.uniform(2,6))
    send_http(make_post(ua, user, pw))
    time.sleep(random.uniform(15,45))
PYEOF
}

loop_reauth() {
  local iface=$1 conf=$2 label=$3 ip=$4 gw=$5
  while true; do
    sleep 60
    log "  [reauth] $label — reconnecting"
    wpa_cli -p "$WS_DIR" -i "$iface" disconnect >> "$LOG" 2>&1 || true
    sleep 2
    wpa_cli -p "$WS_DIR" -i "$iface" reconnect  >> "$LOG" 2>&1 || true
    sleep 4
    local state
    state=$(wpa_cli -p "$WS_DIR" -i "$iface" status 2>/dev/null \
            | awk -F= '/^wpa_state/{print $2}')
    if [[ "$state" != "COMPLETED" ]]; then
      pkill -f "wpa_supplicant.*-i $iface" 2>/dev/null || true
      sleep 1
      wpa_supplicant -B -i "$iface" -c "$conf" \
        -P "$PIDS/wpa_${label}.pid" >> "$LOG" 2>&1 || true
      wait_for_assoc "$iface" "$label" 15
    fi
    set_ip "$iface" "$ip" "$gw"
  done
}

# Args: iface gw conf label ip src_mac dst_mac [portal_ip]
start_traffic() {
  local iface=$1 gw=$2 conf=$3 label=$4 ip=$5 src_mac=$6 dst_mac=$7
  local portal_ip="${8:-}"
  local src_ip="${ip%%/*}"
  rm -f "$PIDS/traffic_${label}.pids"

  loop_arp        "$iface" "$gw"                                      >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_ping       "$iface" "$gw"                                      >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_http_scapy "$iface" "$src_mac" "$dst_mac" "$src_ip" "$gw"     >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_dns_scapy  "$iface" "$src_mac" "$dst_mac" "$src_ip" "$gw"     >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"

  if [[ -n "$portal_ip" ]]; then
    loop_captive_portal_scapy "$iface" "$src_mac" "$dst_mac" "$src_ip" "$portal_ip" >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  fi

  if [[ -n "$conf" ]]; then
    loop_reauth "$iface" "$conf" "$label" "$ip" "$gw" >> "$LOG" 2>&1 \
      & echo $! >> "$PIDS/traffic_${label}.pids"
  fi

  local extras=""
  [[ -n "$portal_ip" ]] && extras+=" CAPTIVE-PORTAL"
  [[ -n "$conf" ]] && extras+=" REAUTH/1m"
  log "  Traffic: $label ($iface) — ARP PING HTTP DNS${extras}"
}

# =============================================================================
# STOP EXISTING CLIENTS
# =============================================================================
hdr "Stopping existing clients"
pkill wpa_supplicant 2>/dev/null || true
for f in "$PIDS"/traffic_*.pids; do
  [[ -f "$f" ]] || continue
  while read -r pid; do kill "$pid" 2>/dev/null || true; done < "$f"
  rm -f "$f"
done
sleep 1

# =============================================================================
# CONNECT: Open
# =============================================================================
hdr "Client: Open → $IF_CLI_OPEN"
prep "$IF_CLI_OPEN"
cat > "$LAB_DIR/conf/client-open.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="CoffeeShop-FreeWiFi"
    key_mgmt=NONE
    scan_freq=2437
    freq_list=2437
    priority=10
}
EOF
start_wpa "$IF_CLI_OPEN" "$LAB_DIR/conf/client-open.conf" "open"
wait_for_assoc "$IF_CLI_OPEN" "open" 20
set_ip "$IF_CLI_OPEN" "10.0.0.10/24" "10.0.0.1"
log "Open client ready"

# =============================================================================
# CONNECT: EasyTarget-WPA2
# =============================================================================
hdr "Client: EasyTarget-WPA2 → $IF_CLI_WEP"
prep "$IF_CLI_WEP"
cat > "$LAB_DIR/conf/client-easy.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="EasyTarget-WPA2"
    psk="password"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    scan_freq=2412
    freq_list=2412
    priority=10
}
EOF
start_wpa "$IF_CLI_WEP" "$LAB_DIR/conf/client-easy.conf" "easy"
wait_for_assoc "$IF_CLI_WEP" "easy" 20
set_ip "$IF_CLI_WEP" "10.0.1.10/24" "10.0.1.1"
log "EasyTarget-WPA2 client ready"

# =============================================================================
# CONNECT: WPA/TKIP
# =============================================================================
hdr "Client: WPA/TKIP → $IF_CLI_WPA"
prep "$IF_CLI_WPA"
cat > "$LAB_DIR/conf/client-wpa.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="WPA-PSK-Lab"
    psk="wifi@2024"
    proto=WPA
    key_mgmt=WPA-PSK
    pairwise=TKIP
    group=TKIP
    scan_freq=2422
    freq_list=2422
    priority=10
}
EOF
start_wpa "$IF_CLI_WPA" "$LAB_DIR/conf/client-wpa.conf" "wpa"
wait_for_assoc "$IF_CLI_WPA" "wpa" 25
set_ip "$IF_CLI_WPA" "10.0.2.10/24" "10.0.2.1"
log "WPA client ready"

# =============================================================================
# CONNECT: WPA2/CCMP
# =============================================================================
hdr "Client: WPA2 → $IF_CLI_WPA2"
prep "$IF_CLI_WPA2"
cat > "$LAB_DIR/conf/client-wpa2.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="ChallengeNet-WPA2"
    psk="WPA2SecretKey"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    scan_freq=2462
    freq_list=2462
    priority=10
}
EOF
start_wpa "$IF_CLI_WPA2" "$LAB_DIR/conf/client-wpa2.conf" "wpa2"
wait_for_assoc "$IF_CLI_WPA2" "wpa2" 25
set_ip "$IF_CLI_WPA2" "10.0.3.10/24" "10.0.3.1"
log "WPA2 client ready"

# =============================================================================
# CONNECT: WPA3 downgrade
# =============================================================================
if [[ -n "${IF_CLI_WPA3:-}" && -n "${IF_WPA3:-}" ]]; then
  hdr "Client: WPA3-downgrade → $IF_CLI_WPA3"
  prep "$IF_CLI_WPA3"
  cat > "$LAB_DIR/conf/client-wpa3.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="SecureNet-WPA3"
    psk="WPA3TopSecret"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    ieee80211w=0
    scan_freq=2452
    freq_list=2452
    priority=10
}
EOF
  start_wpa "$IF_CLI_WPA3" "$LAB_DIR/conf/client-wpa3.conf" "wpa3"
  wait_for_assoc "$IF_CLI_WPA3" "wpa3" 25
  set_ip "$IF_CLI_WPA3" "10.0.4.10/24" "10.0.4.1"
  log "WPA3 downgrade client ready"
else
  log "WPA3 client: skipped"
fi

# =============================================================================
# CONNECT: Hidden SSID
# =============================================================================
if [[ -n "${IF_CLI_HIDDEN:-}" && -n "${IF_HIDDEN:-}" ]]; then
  hdr "Client: Hidden → $IF_CLI_HIDDEN"
  prep "$IF_CLI_HIDDEN"

  # Ensure config exists
  [[ -f "$LAB_DIR/conf/client-hidden.conf" ]] || \
  cat > "$LAB_DIR/conf/client-hidden.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
network={
    ssid="SecretLabNetwork"
    psk="ChallengePassword"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    scan_ssid=1
    scan_freq=2442
    freq_list=2442
    priority=10
}
EOF

  start_wpa "$IF_CLI_HIDDEN" "$LAB_DIR/conf/client-hidden.conf" "hidden"
  wait_for_assoc "$IF_CLI_HIDDEN" "hidden" 25
  set_ip "$IF_CLI_HIDDEN" "10.0.6.10/24" "10.0.6.1"
  log "Hidden client ready"
else
  log "Hidden client: skipped (need 18 radios)"
fi

# =============================================================================
# CONNECT: Enterprise
# =============================================================================
if [[ -n "${IF_CLI_ENT:-}" && -n "${IF_ENT:-}" ]]; then
  hdr "Client: Enterprise → $IF_CLI_ENT"

  # Reset MAC to correct hwsim value
  local_idx=$(echo "$IF_CLI_ENT" | grep -o '[0-9]*$')
  printf -v ent_mac "02:00:00:00:%02x:00" "$local_idx"

  ip link set "$IF_CLI_ENT" down
  iw dev "$IF_CLI_ENT" set type managed
  ip link set "$IF_CLI_ENT" address "$ent_mac" 2>/dev/null || true
  ip link set "$IF_CLI_ENT" up

  pkill -f "wpa_supplicant.*$IF_CLI_ENT" 2>/dev/null || true
  rm -f "$WS_DIR/$IF_CLI_ENT" 2>/dev/null || true
  sleep 1

  # Ensure config exists
  [[ -f "$LAB_DIR/conf/client-enterprise.conf" ]] || \
  cat > "$LAB_DIR/conf/client-enterprise.conf" << EOF
ctrl_interface=$WS_DIR
ctrl_interface_group=0
update_config=1
p2p_disabled=1
network={
    ssid="CorpNet-8021X"
    key_mgmt=WPA-EAP
    eap=TTLS
    identity="alice"
    password="password123"
    phase2="auth=PAP"
    ca_cert="$LAB_DIR/certs/ca.pem"
    scan_ssid=1
    proto=RSN
    pairwise=CCMP
    group=CCMP
    scan_freq=2447
    freq_list=2447
    priority=10
}
EOF

  wpa_supplicant -B -i "$IF_CLI_ENT" \
    -c "$LAB_DIR/conf/client-enterprise.conf" \
    -P "$PIDS/wpa_enterprise.pid" >> "$LOG" 2>&1
  wait_for_assoc "$IF_CLI_ENT" "enterprise" 25
  log "Enterprise client ready ($IF_CLI_ENT / $ent_mac)"
else
  log "Enterprise client: skipped (need 18 radios — IF_CLI_ENT=${IF_CLI_ENT:-unset})"
fi

# =============================================================================
# START TRAFFIC GENERATORS
# hwsim MAC pattern: wlanN → 02:00:00:00:NN:00
# =============================================================================
hdr "Starting traffic generators"

start_traffic "$IF_CLI_OPEN" "10.0.0.1" ""                                "open"  "10.0.0.10/24"  "02:00:00:00:09:00" "02:00:00:00:00:00" "10.0.0.1"
start_traffic "$IF_CLI_WEP"  "10.0.1.1" "$LAB_DIR/conf/client-easy.conf"  "easy"  "10.0.1.10/24"  "02:00:00:00:0a:00" "02:00:00:00:01:00"
start_traffic "$IF_CLI_WPA"  "10.0.2.1" "$LAB_DIR/conf/client-wpa.conf"   "wpa"   "10.0.2.10/24"  "02:00:00:00:0b:00" "02:00:00:00:02:00"
start_traffic "$IF_CLI_WPA2" "10.0.3.1" "$LAB_DIR/conf/client-wpa2.conf"  "wpa2"  "10.0.3.10/24"  "02:00:00:00:0c:00" "02:00:00:00:03:00"

if [[ -n "${IF_CLI_WPA3:-}" && -n "${IF_WPA3:-}" ]]; then
  start_traffic "$IF_CLI_WPA3" "10.0.4.1" "$LAB_DIR/conf/client-wpa3.conf" "wpa3" "10.0.4.10/24" "02:00:00:00:0d:00" "02:00:00:00:04:00"
fi

if [[ -n "${IF_CLI_HIDDEN:-}" && -n "${IF_HIDDEN:-}" ]]; then
  start_traffic "$IF_CLI_HIDDEN" "10.0.6.1" "$LAB_DIR/conf/client-hidden.conf" "hidden" "10.0.6.10/24" "02:00:00:00:10:00" "02:00:00:00:06:00"
fi

# =============================================================================
# STATUS
# =============================================================================
echo ""
echo -e "${C}${B}╔══════════════════════════════════════════════════════════════════════╗${X}"
echo -e "${C}${B}║                      ACTIVE CLIENT MAP                             ║${X}"
echo -e "${C}${B}╠════════╦═════════════╦════════════════╦═══════════════════════════╣${X}"
printf  "${C}${B}║${X} %-6s ${C}${B}║${X} %-11s ${C}${B}║${X} %-14s ${C}${B}║${X} %-25s ${C}${B}║${X}\n" \
  "Client" "Interface" "IP" "AP / Traffic"
echo -e "${C}${B}╠════════╬═════════════╬════════════════╬═══════════════════════════╣${X}"

pr() {
  printf "${C}${B}║${X} %-6s ${C}${B}║${X} %-11s ${C}${B}║${X} %-14s ${C}${B}║${X} %-25s ${C}${B}║${X}\n" \
    "$1" "$2" "$3" "$4"
}

pr "Open"   "$IF_CLI_OPEN"   "10.0.0.10/24" "CoffeeShop-FreeWiFi + portal"
pr "Easy"   "$IF_CLI_WEP"    "10.0.1.10/24" "EasyTarget-WPA2 / REAUTH"
pr "WPA"    "$IF_CLI_WPA"    "10.0.2.10/24" "WPA-PSK-Lab / REAUTH/1m"
pr "WPA2"   "$IF_CLI_WPA2"   "10.0.3.10/24" "ChallengeNet-WPA2 / REAUTH/1m"
[[ -n "${IF_CLI_WPA3:-}" && -n "${IF_WPA3:-}" ]] && \
  pr "WPA3" "$IF_CLI_WPA3"   "10.0.4.10/24" "SecureNet-WPA3 (downgrade!)"
[[ -n "${IF_CLI_HIDDEN:-}" && -n "${IF_HIDDEN:-}" ]] && \
  pr "Hidden" "$IF_CLI_HIDDEN" "10.0.6.10/24" "SecretLabNetwork"
[[ -n "${IF_CLI_ENT:-}" && -n "${IF_ENT:-}" ]] && \
  pr "Ent"  "$IF_CLI_ENT"    "—"            "CorpNet-8021X (TTLS/PAP)"

echo -e "${C}${B}╚════════╩═════════════╩════════════════╩═══════════════════════════╝${X}"
echo ""
echo -e "${B}  Capture commands:${X}"
echo -e "  ${G}✓${X} Open HTTP     → tshark -i \$IF_ATK0 -Y 'http.request'"
echo -e "  ${G}✓${X} Open DNS      → tshark -i \$IF_ATK0 -Y 'dns.flags.response==0'"
echo -e "  ${G}✓${X} Portal creds  → python3 $LAB_DIR/portal/server.py"
echo -e "  ${G}✓${X} WPA handshake → airodump-ng -c 3  $IF_ATK0  (fresh every 1m)"
echo -e "  ${G}✓${X} WPA2 handshake→ airodump-ng -c 11 $IF_ATK0  (fresh every 1m)"
echo -e "  ${G}✓${X} WPA3 downgrade→ airodump-ng -c 9  $IF_ATK0"
echo -e "  ${G}✓${X} Enterprise    → tail -f $LAB_DIR/lab.log | grep 'pap: User'"
echo ""
echo -e "  ${B}WPS PIN attack:${X}"
echo -e "    python3 ~/wifi/wps-proxy.py   # terminal 1"
echo ""
echo -e "  ${B}Rogue Enterprise AP:${X}"
echo -e "    hostapd /tmp/rogue-enterprise.conf   # uses ${IF_CLI_ENT:-wlan17}"
echo -e "    aireplay-ng -0 3 -a 02:00:00:00:05:00 -c \$(cat /sys/class/net/${IF_CLI_ENT:-wlan17}/address) $IF_ATK0"
echo ""
echo -e "  ${B}Log:${X} $LOG"
echo ""
