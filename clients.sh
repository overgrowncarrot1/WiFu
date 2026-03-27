#!/usr/bin/env bash
# =============================================================================
#  WiFi Challenge Lab — Client Simulator  (hardened + scapy injection)
#
#  All known issues fixed:
#    ✓ /tmp/ws socket dir created before wpa_supplicant starts
#    ✓ scan_freq/freq_list added — clients find APs instantly, no scan timeout
#    ✓ Each client has its own dedicated interface (no sharing)
#    ✓ Static IP set after association (no DHCP)
#    ✓ Re-auth every 1 min — fresh handshake always available
#    ✓ WEP slot replaced with EasyTarget-WPA2
#    ✓ wpa_cli uses correct socket path (/tmp/ws)
#    ✓ HTTP/DNS traffic uses scapy raw injection — bypasses kernel routing
#      loop-back issue that occurs when AP and client share the same host.
#      curl/nslookup cannot work because the kernel short-circuits packets
#      destined for a local IP; scapy bypasses the kernel stack entirely.
# =============================================================================
set -uo pipefail

export HOME="${HOME:-/root}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; X='\033[0m'

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

# Load interface assignments from allinone.sh
ENV_FILE="${LAB_DIR:-$HOME/wifi-lab}/iface.env"
[[ -f "$ENV_FILE" ]] || {
  echo -e "${R}[✗]${X} $ENV_FILE not found. Run wifi-lab-allinone.sh all first."
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

# =============================================================================
# CRITICAL: create the wpa_supplicant socket directory
# /run/wpa_supplicant is managed by systemd-tmpfiles and gets wiped.
# /tmp/ws is stable for the full session.
# =============================================================================
install -d -m 0777 "$WS_DIR"
log "Socket dir: $WS_DIR"

# =============================================================================
# HELPERS
# =============================================================================

# Reset interface to clean managed state
prep() {
  local iface=$1
  [[ -z "$iface" ]] && return 1
  pkill -f "wpa_supplicant.*-i $iface" 2>/dev/null || true
  sleep 0.3
  ip link set "$iface" down         2>/dev/null || true
  iw dev "$iface" set type managed  2>/dev/null || true
  ip addr flush dev "$iface"        2>/dev/null || true
  ip link set "$iface" up
}

# Start wpa_supplicant
start_wpa() {
  local iface=$1 conf=$2 label=$3
  [[ -z "$iface" ]] && { warn "start_wpa: empty iface for $label"; return 1; }
  wpa_supplicant -B -i "$iface" -c "$conf" \
    -P "$PIDS/wpa_${label}.pid" >> "$LOG" 2>&1 \
    && log "  wpa_supplicant started: $label ($iface)" \
    || { warn "  wpa_supplicant FAILED: $label — check $LOG"; return 1; }
}

# Wait for wpa_supplicant to associate — polls socket, then state
wait_for_assoc() {
  local iface=$1 label=$2 timeout=${3:-20}

  local sock_wait=0
  while [[ ! -S "$WS_DIR/$iface" && $sock_wait -lt 10 ]]; do
    sleep 0.5; (( sock_wait++ )) || true
  done

  if [[ ! -S "$WS_DIR/$iface" ]]; then
    warn "  Socket never appeared for $label — wpa_supplicant crashed"
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
  warn "  Timeout ($timeout s) for $label — last state: $state"
  return 0
}

# Set static IP after association
set_ip() {
  local iface=$1 addr=$2 gw=$3
  ip addr flush dev "$iface"       2>/dev/null || true
  ip addr add "$addr" dev "$iface" 2>/dev/null || true
  ip route add default via "$gw"  dev "$iface" 2>/dev/null || true
  local got
  got=$(ip addr show "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
  [[ -n "$got" ]] && log "  IP: $iface → $got" || warn "  IP assignment failed on $iface"
}

# =============================================================================
# TRAFFIC LOOPS
# All HTTP and DNS use scapy raw injection to bypass the kernel routing
# short-circuit that occurs when AP and client are on the same Linux host.
# loop_arp and loop_ping still use arping/ping — ARP works fine at L2 and
# ping is useful for handshake generation even without replies.
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

# Inject realistic HTTP traffic via scapy — bypasses kernel stack entirely.
# Generates a mix of GET browsing, POST logins, and POST form submissions
# (fake shopping checkouts, webmail, forum posts) so captures look like
# real user activity. All credentials and card numbers are fictitious.
loop_http_scapy() {
  local iface=$1 src_mac=$2 dst_mac=$3 src_ip=$4 dst_ip=$5
  python3 - "$iface" "$src_mac" "$dst_mac" "$src_ip" "$dst_ip" << 'PYEOF'
import sys, time, random
from urllib.parse import urlencode
from scapy.all import Ether, IP, TCP, Raw, sendp

iface, src_mac, dst_mac, src_ip, dst_ip = sys.argv[1:]

uagents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Fake usernames and passwords — visibly weak, realistic for a lab
fake_creds = [
    ("admin",        "admin"),
    ("admin",        "password"),
    ("admin",        "letmein"),
    ("john.smith",   "password123"),
    ("alice",        "alice123"),
    ("bob",          "qwerty"),
    ("carol",        "iloveyou"),
    ("dave",         "123456"),
    ("j.doe",        "Welcome1"),
    ("info",         "company123"),
    ("test",         "test"),
    ("guest",        "guest"),
]

# Fake Visa/MC numbers (Luhn-valid test numbers, not real)
fake_cards = [
    ("4111111111111111", "Visa",       "John Smith",   "12/26", "123"),
    ("4012888888881881", "Visa",       "Alice Johnson","09/25", "456"),
    ("5500005555555559", "Mastercard", "Bob Williams", "03/27", "789"),
    ("5105105105105100", "Mastercard", "Carol Davis",  "11/26", "321"),
]

# GET browsing targets
get_pages = [
    ("mail.corp-internal.com",   "/inbox"),
    ("mail.corp-internal.com",   "/compose"),
    ("shop.local-store.net",     "/cart"),
    ("shop.local-store.net",     "/checkout"),
    ("intranet.office.local",    "/dashboard"),
    ("intranet.office.local",    "/employees"),
    ("forum.community-site.org", "/latest"),
    ("neverssl.com",             "/"),
    ("httpforever.com",          "/"),
    ("detectportal.firefox.com", "/success.txt"),
]

# POST login targets
login_targets = [
    ("mail.corp-internal.com",   "/login",          "username", "password"),
    ("intranet.office.local",    "/login",          "user",     "pass"),
    ("shop.local-store.net",     "/account/login",  "email",    "passwd"),
    ("forum.community-site.org", "/login.php",      "username", "password"),
    ("admin.router.local",       "/login",          "username", "password"),
]

def send_pkt(payload_bytes, sport=None):
    sport = sport or random.randint(1024, 65535)
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=80, flags="PA", seq=random.randint(1000, 9999999)) /
        Raw(load=payload_bytes)
    )
    sendp(pkt, iface=iface, verbose=False)

def make_get(host, path, ua, referer=None):
    hdrs = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Language: en-US,en;q=0.5\r\n"
        f"Connection: keep-alive\r\n"
    )
    if referer:
        hdrs += f"Referer: http://{referer}/\r\n"
    hdrs += "\r\n"
    return hdrs.encode()

def make_post_login(host, path, user_field, pass_field, user, passwd, ua):
    body = urlencode({user_field: user, pass_field: passwd, "submit": "Login"})
    hdrs = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Referer: http://{host}/login\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return hdrs.encode()

def make_post_checkout(host, ua):
    card_num, card_type, name, exp, cvv = random.choice(fake_cards)
    addr = random.choice([
        "123 Main St, Springfield, IL 62701",
        "456 Oak Ave, Portland, OR 97201",
        "789 Pine Rd, Austin, TX 73301",
    ])
    body = urlencode({
        "card_number":   card_num,
        "card_type":     card_type,
        "cardholder":    name,
        "expiry":        exp,
        "cvv":           cvv,
        "billing_addr":  addr,
        "amount":        f"{random.randint(10,299)}.{random.randint(0,99):02d}",
        "submit":        "Place Order",
    })
    hdrs = (
        f"POST /checkout/payment HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Referer: http://{host}/checkout\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return hdrs.encode()

# Traffic mix weights: GET 50%, login POST 30%, checkout POST 20%
actions = ["get"] * 5 + ["login"] * 3 + ["checkout"] * 2

while True:
    ua     = random.choice(uagents)
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

# Inject raw DNS queries via scapy
loop_dns_scapy() {
  local iface=$1 src_mac=$2 dst_mac=$3 src_ip=$4 dst_ip=$5
  python3 - "$iface" "$src_mac" "$dst_mac" "$src_ip" "$dst_ip" << 'PYEOF'
import sys, time, random
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp

iface, src_mac, dst_mac, src_ip, dst_ip = sys.argv[1:]

domains = [
    "example.com", "github.com", "google.com",
    "neverssl.com", "httpforever.com", "apple.com",
    "microsoft.com", "cloudflare.com",
]

while True:
    domain = random.choice(domains)
    sport  = random.randint(1024, 65535)
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=sport, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain))
    )
    sendp(pkt, iface=iface, verbose=False)
    time.sleep(random.uniform(5, 15))
PYEOF
}

# Re-auth loop: disconnect+reconnect to generate fresh 4-way handshake
loop_reauth() {
  local iface=$1 conf=$2 label=$3 ip=$4 gw=$5
  local interval=60
  while true; do
    sleep "$interval"
    log "  [reauth] $label — reconnecting for fresh handshake"
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

# Start all traffic loops for one client
# Args: iface gw conf label ip src_mac dst_mac
start_traffic() {
  local iface=$1 gw=$2 conf=$3 label=$4 ip=$5 src_mac=$6 dst_mac=$7
  local src_ip="${ip%%/*}"   # strip /24

  rm -f "$PIDS/traffic_${label}.pids"

  loop_arp        "$iface" "$gw"                                >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_ping       "$iface" "$gw"                                >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_http_scapy "$iface" "$src_mac" "$dst_mac" "$src_ip" "$gw" >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"
  loop_dns_scapy  "$iface" "$src_mac" "$dst_mac" "$src_ip" "$gw" >> "$LOG" 2>&1 & echo $! >> "$PIDS/traffic_${label}.pids"

  if [[ -n "$conf" ]]; then
    loop_reauth "$iface" "$conf" "$label" "$ip" "$gw" >> "$LOG" 2>&1 \
      & echo $! >> "$PIDS/traffic_${label}.pids"
  fi

  log "  Traffic: $label ($iface) — ARP PING HTTP(scapy) DNS(scapy)$([ -n "$conf" ] && echo ' REAUTH/1m')"
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
# CONNECT: Open  → 10.0.0.10
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
# CONNECT: EasyTarget-WPA2  → 10.0.1.10
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
# CONNECT: WPA/TKIP  → 10.0.2.10
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
# CONNECT: WPA2/CCMP  → 10.0.3.10   (primary handshake target)
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
# CONNECT: WPA3 downgrade → 10.0.4.10
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
  log "WPA3 downgrade client ready (connected as WPA2-PSK)"
else
  log "WPA3 client: skipped (not enough radios — need 16)"
fi

# =============================================================================
# START TRAFFIC GENERATORS
# MACs follow the hwsim pattern: 02:00:00:00:NN:00
#   wlan9  = 09 → 02:00:00:00:09:00   AP wlan0 = 00 → 02:00:00:00:00:00
#   wlan10 = 0a → 02:00:00:00:0a:00   AP wlan1 = 01 → 02:00:00:00:01:00
#   wlan11 = 0b → 02:00:00:00:0b:00   AP wlan2 = 02 → 02:00:00:00:02:00
#   wlan12 = 0c → 02:00:00:00:0c:00   AP wlan3 = 03 → 02:00:00:00:03:00
# =============================================================================

IF_CLI_HIDDEN=wlan13
IF_HIDDEN=wlan6

# =============================================================================
# CONNECT: Hidden → 10.0.6.10
# =============================================================================
if [[ -n "${IF_CLI_HIDDEN:-}" ]]; then
  hdr "Client: Hidden → $IF_CLI_HIDDEN"
  prep "$IF_CLI_HIDDEN"

  HIDDEN_CONF="$LAB_DIR/conf/client-hidden.conf"

  if [[ ! -f "$HIDDEN_CONF" ]]; then
    warn "Missing config: $HIDDEN_CONF"
  else
    start_wpa "$IF_CLI_HIDDEN" "$LAB_DIR/conf/client-hidden.conf" "hidden"
    wait_for_assoc "$IF_CLI_HIDDEN" "hidden" 25

    set_ip "$IF_CLI_HIDDEN" "10.0.6.10/24" "10.0.6.1"

    log "Hidden client ready (active probe + reauth enabled)"
  fi
else
  log "Hidden client: skipped (no interface assigned)"
fi

if [[ -n "${IF_CLI_HIDDEN:-}" ]]; then
  start_traffic "$IF_CLI_HIDDEN" "10.0.6.1" "$LAB_DIR/conf/client-hidden.conf" "hidden" "10.0.6.10/24" "02:00:00:00:11:00" "02:00:00:00:06:00"
fi

# =============================================================================
# CONNECT: Rouge AP Client
# =============================================================================

# wlan16 = enterprise client, wlan17 = rogue AP
ip link set wlan16 down
iw dev wlan16 set type managed
ip link set wlan16 address 02:00:00:00:10:00
ip link set wlan16 up

pkill -f "wpa_supplicant.*wlan16" 2>/dev/null
rm -f /tmp/ws/wlan16 && sleep 1

wpa_supplicant -B -i wlan16 \
  -c ~/wifi-lab/conf/client-enterprise.conf
sleep 5
wpa_cli -p /tmp/ws -i wlan16 status | grep -E "wpa_state|bssid"

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

pr "Open"  "$IF_CLI_OPEN" "10.0.0.10/24" "CoffeeShop-FreeWiFi"
pr "Easy"  "$IF_CLI_WEP"  "10.0.1.10/24" "EasyTarget-WPA2 / REAUTH"
pr "WPA"   "$IF_CLI_WPA"  "10.0.2.10/24" "WPA-PSK-Lab / REAUTH/1m"
pr "WPA2"  "$IF_CLI_WPA2" "10.0.3.10/24" "ChallengeNet-WPA2 / REAUTH/1m"
[[ -n "${IF_CLI_WPA3:-}" && -n "${IF_WPA3:-}" ]] && \
  pr "WPA3" "$IF_CLI_WPA3" "10.0.4.10/24" "SecureNet-WPA3 (WPA2 downgrade!)"

echo -e "${C}${B}╚════════╩═════════════╩════════════════╩═══════════════════════════╝${X}"
echo ""
echo -e "${B}  What you can capture right now:${X}"
echo -e "  ${G}✓${X} Open plaintext HTTP  → tshark -i \$IF_ATK0 -Y 'http.request'"
echo -e "  ${G}✓${X} Open DNS queries     → tshark -i \$IF_ATK0 -Y 'dns.flags.response==0'"
echo -e "  ${G}✓${X} WPA handshake        → airodump-ng -c 3  $IF_ATK0  (fresh every 1m)"
echo -e "  ${G}✓${X} WPA2 handshake       → airodump-ng -c 11 $IF_ATK0  (fresh every 1m)"
echo -e "  ${G}✓${X} WPA3 downgrade HS    → airodump-ng -c 9  $IF_ATK0  (crackable!)"
echo ""
echo -e "  ${B}tshark one-liner (open network sniffing challenge):${X}"
echo -e "    iw dev $IF_ATK0 set channel 6"
echo -e "    tshark -i $IF_ATK0 -Y 'http.request' -T fields \\"
echo -e "      -e ip.src -e http.host -e http.request.method -e http.request.uri"
echo ""
echo -e "  ${B}Force instant handshake:${X}"
echo -e "    aireplay-ng -0 1 -a <AP_BSSID> -c <CLIENT_MAC> $IF_ATK0"
echo ""
echo -e "  ${B}Set up monitor mode:${X}"
echo -e "    ip link set $IF_ATK0 down"
echo -e "    iw dev $IF_ATK0 set type monitor"
echo -e "    ip link set $IF_ATK0 up"
echo ""
echo -e "  ${B}Stop:${X} sudo bash stop-clients.sh   ${B}Log:${X} $LOG"
echo ""
