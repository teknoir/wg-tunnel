#!/usr/bin/env bash
# NAT lab for the plane-B hole-punching tests (test/natlab/natlab_test.go).
#
# It builds, with network namespaces and veth pairs, this topology:
#
#   wgt-ha (client host)  10.77.1.2 ---- 10.77.1.1  wgt-nata  203.0.113.2 ---\
#                                                                               wgt-pub (203.0.113.1 and .5, STUN)
#   wgt-hb (device host)  10.77.2.2 ---- 10.77.2.1  wgt-natb  203.0.113.6 ---/
#
# Each NAT masquerades its inside network behind its outer address:
#
#   eim  iptables MASQUERADE            Linux keeps the source port when it can, so the
#                                       mapping is endpoint-independent (EIM); the
#                                       conntrack filtering is address-and-port
#                                       dependent, like a port-restricted cone NAT.
#   edm  iptables MASQUERADE --random   a random source port per connection, so the
#                                       mapping depends on the destination (EDM, a
#                                       "hard" or symmetric NAT).
#
# Everything lives in namespaces named wgt-* with interfaces named wgt-*; the root
# namespace and every other namespace (docker, k3d ...) are never touched.
# Needs root. Usage:
#
#   sudo natlab.sh up            create the lab (both NATs EIM)
#   sudo natlab.sh mode a|b eim|edm   change the NAT of the client (a) or device (b) side
#   sudo natlab.sh status
#   sudo natlab.sh down          remove the lab (idempotent)
set -euo pipefail

NAMESPACES=(wgt-pub wgt-nata wgt-natb wgt-ha wgt-hb)
IPT=${IPTABLES:-iptables}

need_root() { [[ $EUID -eq 0 ]] || { echo "natlab.sh: needs root" >&2; exit 1; }; }

ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

pair() { # pair <ifA> <nsA> <addrA> <ifB> <nsB> <addrB>
  ip link add "$1" type veth peer name "$4"
  ip link set "$1" netns "$2"
  ip link set "$4" netns "$5"
  ns "$2" ip addr add "$3" dev "$1"
  ns "$5" ip addr add "$6" dev "$4"
  ns "$2" ip link set "$1" up
  ns "$5" ip link set "$4" up
}

nat_mode() { # nat_mode <side a|b> <eim|edm>
  local side=$1 mode=$2 nsn out
  case $side in a) nsn=wgt-nata; out=wgt-na0 ;; b) nsn=wgt-natb; out=wgt-nb0 ;; *) echo "side must be a or b" >&2; exit 2 ;; esac
  ns "$nsn" "$IPT" -t nat -F POSTROUTING
  case $mode in
    eim) ns "$nsn" "$IPT" -t nat -A POSTROUTING -o "$out" -j MASQUERADE ;;
    edm) ns "$nsn" "$IPT" -t nat -A POSTROUTING -o "$out" -j MASQUERADE --random ;;
    *) echo "mode must be eim or edm" >&2; exit 2 ;;
  esac
}

up() {
  down
  for n in "${NAMESPACES[@]}"; do
    ip netns add "$n"
    ns "$n" ip link set lo up
  done
  pair wgt-ha0 wgt-ha 10.77.1.2/24 wgt-na1 wgt-nata 10.77.1.1/24
  pair wgt-na0 wgt-nata 203.0.113.2/30 wgt-pa0 wgt-pub 203.0.113.1/30
  pair wgt-hb0 wgt-hb 10.77.2.2/24 wgt-nb1 wgt-natb 10.77.2.1/24
  pair wgt-nb0 wgt-natb 203.0.113.6/30 wgt-pb0 wgt-pub 203.0.113.5/30
  ns wgt-ha ip route add default via 10.77.1.1
  ns wgt-hb ip route add default via 10.77.2.1
  ns wgt-nata ip route add default via 203.0.113.1
  ns wgt-natb ip route add default via 203.0.113.5
  for n in wgt-pub wgt-nata wgt-natb; do ns "$n" sysctl -qw net.ipv4.ip_forward=1; done
  # A NAT box does not answer, and keeps no state for, unsolicited packets from
  # outside. Without this, a peer's probe that arrives before our own first
  # packet gets confirmed as a conntrack entry of its own and steals the
  # source port our outbound flow would have kept (Linux then picks another
  # port: an artefact of the lab, not of a "hard" NAT).
  ns wgt-nata "$IPT" -A INPUT -i wgt-na0 -j DROP
  ns wgt-natb "$IPT" -A INPUT -i wgt-nb0 -j DROP
  nat_mode a eim
  nat_mode b eim
  echo "natlab up"
}

down() {
  for n in "${NAMESPACES[@]}"; do
    ip netns del "$n" 2>/dev/null || true
  done
}

status() {
  ip netns list | grep '^wgt-' || echo "no lab"
  for side in nata natb; do
    echo "--- wgt-$side"
    ns "wgt-$side" "$IPT" -t nat -S POSTROUTING 2>/dev/null || true
  done
}

need_root
case ${1:-} in
  up) up ;;
  down) down ;;
  mode) nat_mode "${2:?side}" "${3:?mode}" ;;
  status) status ;;
  *) echo "usage: natlab.sh up|down|mode a|b eim|edm|status" >&2; exit 2 ;;
esac
