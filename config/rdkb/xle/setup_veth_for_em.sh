#!/bin/sh
# =============================================================================
# setup_veth_br_home.sh
# Creates veth pair, adds one end to br-home, assigns derived MAC to other end
# =============================================================================

VETH_BR="agent_virt_end"       # end that goes into br-home
VETH_AGT="agent_virt_peer"      # end for ieee1905 agent
MAC_OFFSET=0x20
MTU=1500

# =============================================================================
# Derive AL MAC
# =============================================================================
get_derived_mac() {
    offset=$1
    if [ -e "/sys/class/net/eth0/address" ]; then
        base_addr="$(cat /sys/class/net/br-home/address)"
        echo "Reading base MAC: $base_addr from br-home" >&2
    elif [ -e "/sys/class/net/br-home/address" ]; then
        base_addr="$(cat /sys/class/net/eth0/address)"
        echo "Reading base MAC: $base_addr from eth0" >&2
    elif [ -e "/sys/class/net/bhaul-sta-u50/address" ]; then
        base_addr="$(cat /sys/class/net/bhaul-sta-u50/address)"
        echo "Reading base MAC: $base_addr from bhaul-sta-u50" >&2
    else
        base_addr="$(cat /sys/class/ieee80211/phy0/macaddress)"
        echo "Reading base MAC: $base_addr from phy0" >&2
    fi

    # Extract first 5 bytes and last byte separately
    prefix=$(echo "$base_addr" | cut -d: -f1-5)
    last=$(echo "$base_addr" | cut -d: -f6)

    # Add offset to last byte only, cap at 0xff
    new_last=$(printf "%02x" $(( (0x$last + $offset) & 0xff )))

    echo "${prefix}:${new_last}"
}
# =============================================================================
# Cleanup
# =============================================================================
echo "=== Cleanup ==="
ovs-vsctl --if-exists del-port br-home "$VETH_BR"
ip link del "$VETH_BR" 2>/dev/null && echo "Deleted $VETH_BR (and peer)"
echo ""

# =============================================================================
# Create veth pair
# =============================================================================
echo "=== Creating veth pair ==="
ip link add name "$VETH_BR"  type veth peer name "$VETH_AGT"
ip link set dev "$VETH_BR"  mtu $MTU
ip link set dev "$VETH_AGT" mtu $MTU
ip link set dev "$VETH_BR"  up
ip link set dev "$VETH_AGT" up
echo "Created $VETH_BR <-> $VETH_AGT"
echo ""

# =============================================================================
# Add to br-home
# =============================================================================
echo "=== Adding $VETH_BR to br-home ==="
ovs-vsctl add-port br-home "$VETH_BR"
echo "$VETH_BR added to br-home"
echo ""

# =============================================================================
# Assign derived MAC to agent end
# =============================================================================
echo "=== Assigning AL MAC ==="
al_mac=$(get_derived_mac $MAC_OFFSET)
ip link set dev "$VETH_AGT" address "$al_mac"
echo "AL MAC $al_mac assigned to $VETH_AGT"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=== Setup Complete ==="
echo ""
echo "  br-home (OVS)"
echo "      └── $VETH_BR"
echo "              └── $VETH_AGT  (AL MAC: $al_mac)"
echo ""
echo "To start agent:"
echo "  ieee1905 -f off -i $VETH_AGT >> /tmp/ieee1905_agent_log.txt &"
