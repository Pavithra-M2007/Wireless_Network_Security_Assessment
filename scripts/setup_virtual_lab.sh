#!/usr/bin/env bash
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$ROOT_DIR/.wsa-runtime"
mkdir -p "$STATE_DIR"
if ! lsmod 2>/dev/null | grep -q '^mac80211_hwsim'; then
  modprobe mac80211_hwsim radios=3 || { echo "mac80211_hwsim could not be loaded"; exit 1; }
fi
mapfile -t WLAN_IFACES < <(iw dev 2>/dev/null | awk '$1 == "Interface" {print $2}')
if [ "${#WLAN_IFACES[@]}" -lt 2 ]; then echo "Need at least two virtual wireless interfaces; found ${#WLAN_IFACES[@]}."; exit 1; fi
AP_IFACE="${WLAN_IFACES[0]}"; CLIENT_IFACE="${WLAN_IFACES[1]}"
cat >"$STATE_DIR/hostapd.conf" <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=WSA_OPEN_LAB
hw_mode=g
channel=1
auth_algs=1
ignore_broadcast_ssid=0
EOF
ip link set "$AP_IFACE" up; ip link set "$CLIENT_IFACE" up
if [ ! -f "$STATE_DIR/hostapd.pid" ] || ! kill -0 "$(cat "$STATE_DIR/hostapd.pid" 2>/dev/null)" 2>/dev/null; then
  hostapd -B -P "$STATE_DIR/hostapd.pid" "$STATE_DIR/hostapd.conf" >"$STATE_DIR/hostapd.log" 2>&1 || { echo "hostapd failed; see $STATE_DIR/hostapd.log"; exit 1; }
fi
cat >"$STATE_DIR/wpa_supplicant.conf" <<EOF
ctrl_interface=$STATE_DIR/wpa_ctrl
update_config=0
network={
    ssid="WSA_OPEN_LAB"
    key_mgmt=NONE
}
EOF
if [ ! -f "$STATE_DIR/wpa.pid" ] || ! kill -0 "$(cat "$STATE_DIR/wpa.pid" 2>/dev/null)" 2>/dev/null; then
  wpa_supplicant -B -P "$STATE_DIR/wpa.pid" -i "$CLIENT_IFACE" -c "$STATE_DIR/wpa_supplicant.conf" >"$STATE_DIR/wpa.log" 2>&1 || echo "wpa_supplicant failed; see $STATE_DIR/wpa.log"
fi
echo "Virtual lab AP=$AP_IFACE CLIENT=$CLIENT_IFACE SSID=WSA_OPEN_LAB"
