#!/bin/sh
# =============================================================================
# setup_veth_for_em_gw.sh
#
# Sets up veth pairs for IEEE 1905 EasyMesh Controller and Agent
# on a Gateway using OVS (Open vSwitch) bridges.
#
# What this script does:
#   1. Creates a master 1905 OVS bridge (br-1905)
#   2. Taps into brlan0, brlan112, brlan113 via veth pairs → feeds into br-1905
#   3. Creates controller veth pair (eth0_virt_end <-> eth0_virt_peer)
#   4. Creates agent veth pair     (eth1_virt_end <-> eth1_virt_peer)
#   5. Assigns unique AL MACs:
#        Controller: base_mac + 0x10
#        Agent:      base_mac + 0x20
#
# Usage:
#   setup_veth_for_em_gw.sh
#   (no arguments needed — bridges and MACs are auto-detected)
#
# Result:
#   ieee1905 controller → -i ctrl_virt_peer
#   ieee1905 agent      → -i agent_virt_peer
# =============================================================================

MASTER_BRIDGE="br-1905"

# Existing OVS bridges to tap into
BRIDGES="brlan0 brlan112 brlan113 br403"

# Controller veth pair
CTRL_END="ctrl_virt_end"
CTRL_PEER="ctrl_virt_peer"
CTRL_MAC_OFFSET=0x10

# Agent veth pair
AGT_END="agent_virt_end"
AGT_PEER="agent_virt_peer"
AGT_MAC_OFFSET=0x20

# =============================================================================
# Helper: derive a unique MAC from base MAC + offset
# =============================================================================
get_derived_mac() {
    offset=$1
    if [ -e "/sys/class/net/erouter0/address" ]; then
        base_addr="$(cat /sys/class/net/erouter0/address)"
        echo "Reading base MAC: $base_addr from erouter0" >&2
    elif [ -e "/sys/class/net/lan0/address" ]; then
        base_addr="$(cat /sys/class/net/lan0/address)"
        echo "Reading base MAC: $base_addr from lan0" >&2
    elif [ -e "/sys/class/net/brlan0/address" ]; then
        base_addr="$(cat /sys/class/net/brlan0/address)"
        echo "Reading base MAC: $base_addr from brlan0" >&2
    else
        base_addr="$(cat /sys/class/ieee80211/phy0/macaddress)"
        echo "Reading base MAC: $base_addr from phy0" >&2
    fi

    hex=$(echo "$base_addr" | tr -d ':')
    derived=$(printf "%012x" $(( 0x$hex + $offset )))
    echo "$derived" | sed 's/../&:/g;s/:$//'
}

# =============================================================================
# Helper: add a port to OVS bridge
# =============================================================================
ovs_add_port() {
    bridge=$1
    port=$2
    ovs-vsctl --may-exist add-port "$bridge" "$port"
}

# =============================================================================
# Helper: delete a port from OVS bridge (ignore error if not present)
# =============================================================================
ovs_del_port() {
    bridge=$1
    port=$2
    ovs-vsctl --if-exists del-port "$bridge" "$port" 2>/dev/null
}

# =============================================================================
# Step 1: Cleanup previous setup
# =============================================================================
echo "=== Cleaning up previous virtual network devices ==="

# Remove tap veth pairs — first remove from OVS, then delete interface
for br in $BRIDGES; do
    veth_tap="veth-${br}-0"
    veth_feed="veth-${br}-1"
    ovs_del_port "$br"            "$veth_tap"
    ovs_del_port "$MASTER_BRIDGE" "$veth_feed"
    ip link del "$veth_tap" 2>/dev/null && echo "Deleted $veth_tap (and peer $veth_feed)"
done

# Remove controller veth pair
ovs_del_port "$MASTER_BRIDGE" "$CTRL_END"
ip link del "$CTRL_END" 2>/dev/null && echo "Deleted $CTRL_END (and peer $CTRL_PEER)"

# Remove agent veth pair
ovs_del_port "$MASTER_BRIDGE" "$AGT_END"
ip link del "$AGT_END" 2>/dev/null && echo "Deleted $AGT_END (and peer $AGT_PEER)"

# Remove master 1905 OVS bridge
ovs-vsctl --if-exists del-br "$MASTER_BRIDGE" 2>/dev/null && echo "Deleted OVS bridge $MASTER_BRIDGE"

echo "Cleanup complete."
echo ""

# =============================================================================
# Step 2: Create master 1905 OVS bridge
# =============================================================================
echo "=== Creating master 1905 OVS bridge: $MASTER_BRIDGE ==="
ovs-vsctl add-br "$MASTER_BRIDGE"
ip link set dev "$MASTER_BRIDGE" up
echo "$MASTER_BRIDGE created and brought up."
echo ""

# =============================================================================
# Step 3: Tap into each existing OVS bridge via a veth pair
#
#   veth-<bridge>-0  →  added as port to existing OVS bridge (sees real traffic)
#   veth-<bridge>-1  →  added as port to br-1905             (feeds 1905 daemon)
# =============================================================================
echo "=== Tapping into existing OVS bridges ==="
for br in $BRIDGES; do
    veth_tap="veth-${br}-0"
    veth_feed="veth-${br}-1"

    # Check bridge exists in OVS
    if ! ovs-vsctl br-exists "$br"; then
        echo "WARNING: OVS bridge $br not found, skipping..."
        continue
    fi

    echo "Tapping into $br ($veth_tap <-> $veth_feed)..."
    ip link add name "$veth_tap"  type veth peer name "$veth_feed"
    ip link set dev "$veth_tap"  up
    ip link set dev "$veth_feed" up

    ovs_add_port "$br"            "$veth_tap"   # tap end  → existing OVS bridge
    ovs_add_port "$MASTER_BRIDGE" "$veth_feed"  # feed end → br-1905

    echo "  $veth_tap  → $br"
    echo "  $veth_feed → $MASTER_BRIDGE"
done
echo ""

# =============================================================================
# Step 4: Create Controller veth pair
#
#   eth0_virt_end  → added as port to br-1905
#   eth0_virt_peer → ieee1905 controller daemon attaches here
#   AL MAC         → base_mac + 0x10
# =============================================================================
echo "=== Creating Controller veth pair ==="
ip link add name "$CTRL_END" type veth peer name "$CTRL_PEER"
ip link set dev "$CTRL_END"  up
ip link set dev "$CTRL_PEER" up

ovs_add_port "$MASTER_BRIDGE" "$CTRL_END"

ctrl_mac=$(get_derived_mac $CTRL_MAC_OFFSET)
ip link set dev "$CTRL_PEER" address "$ctrl_mac"
echo "Controller veth pair: $CTRL_END <-> $CTRL_PEER"
echo "Controller AL MAC: $ctrl_mac (base + 0x10)"
echo ""

# =============================================================================
# Step 5: Create Agent veth pair
#
#   eth1_virt_end  → added as port to br-1905
#   eth1_virt_peer → ieee1905 agent daemon attaches here
#   AL MAC         → base_mac + 0x20
# =============================================================================
echo "=== Creating Agent veth pair ==="
ip link add name "$AGT_END" type veth peer name "$AGT_PEER"
ip link set dev "$AGT_END"  up
ip link set dev "$AGT_PEER" up

ovs_add_port "$MASTER_BRIDGE" "$AGT_END"

agt_mac=$(get_derived_mac $AGT_MAC_OFFSET)
ip link set dev "$AGT_PEER" address "$agt_mac"
echo "Agent veth pair: $AGT_END <-> $AGT_PEER"
echo "Agent AL MAC: $agt_mac (base + 0x20)"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=== Setup Complete ==="
echo ""
echo "Network topology:"
echo ""
echo "  Controller daemon  →  -i $CTRL_PEER  (AL MAC: $ctrl_mac)"
echo "  Agent daemon       →  -i $AGT_PEER   (AL MAC: $agt_mac)"
echo ""
echo "  $CTRL_END and $AGT_END are both ports on OVS $MASTER_BRIDGE"
echo ""
echo "  $MASTER_BRIDGE aggregates traffic from:"
for br in $BRIDGES; do
    echo "    - $br  (via veth-${br}-0 <-> veth-${br}-1)"
done
echo ""
echo "OVS bridge ports of $MASTER_BRIDGE:"
ovs-vsctl list-ports "$MASTER_BRIDGE"
echo ""
echo "To start daemons:"
echo "  ieee1905 -f off -i $CTRL_PEER --sap-data-path /tmp/al_em_ctrl_data_socket --sap-control-path /tmp/al_em_ctrl_control_socket"
echo "  ieee1905 -f off -i $AGT_PEER"
echo ""
echo "To clean up, run this script again (cleanup runs at start) or manually:"
echo "  ovs-vsctl del-br $MASTER_BRIDGE"
for br in $BRIDGES; do
    echo "  ip link del veth-${br}-0"
    echo "  ovs-vsctl --if-exists del-port ${br} veth-${br}-0"
done
echo "  ip link del $CTRL_END"
echo "  ip link del $AGT_END"
