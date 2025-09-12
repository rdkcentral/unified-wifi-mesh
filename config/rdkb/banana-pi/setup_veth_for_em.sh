#!/bin/sh
# --- Configuration ---
BRIDGE_NAME=$1
VETH_BASE_IFACE=$2 # e.g., eth0, eth1
DO_OBTAIN_MAC=${3:-false} # Optional, default false
PREV_VETH_PEER_MACADDR=/nvram/veth_peer_macaddr.txt
if [ -z "$BRIDGE_NAME" ] || [ -z "$VETH_BASE_IFACE" ]; then
    echo "Usage: $0 <bridge_name> <base_iface> [true|false]"
    exit 1
fi

VETH_END="${VETH_BASE_IFACE}_virt_end"
VETH_PEER="${VETH_BASE_IFACE}_virt_peer"
VETH_OUTPUT="/tmp/${VETH_BASE_IFACE}_virt_output.$$"

# --- Cleanup previous setup (important for fresh runs) ---
echo "Cleaning up earlier virtual network devices..."
ip link del $VETH_END 2>/dev/null
echo "Cleanup complete."

# --- Create the Bridge ---
echo "Creating bridge $BRIDGE_NAME..."
ip link add name $BRIDGE_NAME type bridge
ip link set dev $BRIDGE_NAME up
echo "Bridge $BRIDGE_NAME created and brought up."

# --- Create veth pair and add one end to the bridge ---
echo "Creating veth pair ($VETH_END <-> $VETH_PEER)..."
ip link add name $VETH_END type veth peer name $VETH_PEER
ip link set $VETH_END master $BRIDGE_NAME
ip link set dev $VETH_END up
ip link set dev $VETH_PEER up

if [ "$DO_OBTAIN_MAC" = true ]; then
    # Set the mac address of VETH_PEER to be a fixed offset of erouter0/eth0/wlan0 address
    if [ -e "/sys/class/net/erouter0/address" ]; then
            primary_addr="$(cat /sys/class/net/erouter0/address)"
            echo "Reading mac:$primary_addr from erouter0"
            #Convert the mac address into hex and increment by 1
            primary_veth0_mac=$(echo $primary_addr | tr -d ':')
            primary_veth0_mac=$((0x$primary_veth0_mac + 0x10))
    elif [ -e "/sys/class/net/eth0/address" ]; then
            primary_addr="$(cat /sys/class/net/eth0/address)"
            echo "Reading mac:$primary_addr from eth0"
            primary_veth0_mac=$(echo $primary_addr | tr -d ':')
            primary_veth0_mac=$((0x$primary_veth0_mac + 0x10))
    else
            primary_addr="$(cat /sys/class/ieee80211/phy0/macaddress)"
            echo "Reading mac:$primary_addr from phy0"
            primary_veth0_mac=$(echo $primary_addr | tr -d ':')
            primary_veth0_mac=$((0x$primary_veth0_mac + 0x30))
    fi
    #Obtain the VETH_PEER mac address by converting to str format
    veth0_mac=$(printf "%012x" $primary_veth0_mac | sed 's/../&:/g;s/:$//')
    echo "$VETH_PEER macaddress: $veth0_mac"
    ip link set dev $VETH_PEER address $veth0_mac
fi

echo "veth pair created, $VETH_END added to $BRIDGE_NAME, both ends up."

# --- Verify setup ---
echo "\n--- Network Setup Summary ---"
echo "Bridge members:"
brctl show $BRIDGE_NAME
echo "\nInterface IPs:"
ip a show $VETH_PEER

echo "To clean up, run 'ip link del $BRIDGE_NAME'."

# ----------- 🔍 TEST: Broadcast from VETH_PEER -----------

echo "Testing broadcast connectivity..."

TEST_PORT=9999
TEST_MSG="hello_broadcast_test_$$"
RESULT=""

# Start listener in background
timeout 3 socat -u UDP4-RECVFROM:$TEST_PORT,broadcast - > $VETH_OUTPUT &
LISTENER_PID=$!
sleep 1

# Send broadcast from veth peer
echo "$TEST_MSG" | socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH_PEER"

# Wait and read result
sleep 1
if [ -f "$VETH_OUTPUT" ]; then
    RESULT=$(cat $VETH_OUTPUT)
    rm -f $VETH_OUTPUT
fi

if [ "$DO_OBTAIN_MAC" = false ]; then
    if [ -e "/sys/class/net/erouter0/address" ]; then
       base_addr="$(cat /sys/class/net/erouter0/address)"
    elif [ -e "/sys/class/net/lan0/address" ]; then
       base_addr="$(cat /sys/class/net/lan0/address)"
    else
       base_addr="$(cat /sys/class/ieee80211/phy0/macaddress)"
    fi
    echo "Reading mac:$base_addr from lan0/erouter0/phy0"
    #Convert the mac address into hex and increment by 1
    VETH1_MACADDR=$(echo $base_addr | tr -d ':')
    VETH1_MACADDR=$((0x$VETH1_MACADDR + 0x20))
    #Obtain the VETH_PEER mac address by converting to str format
    veth1_mac=$(printf "%012x" $VETH1_MACADDR | sed 's/../&:/g;s/:$//')
    echo "$VETH_PEER macaddress: $veth1_mac"
    ip link set dev $VETH_PEER address $veth1_mac
fi

if [ "$RESULT" = "$TEST_MSG" ]; then
    echo "✅ Broadcast test successful: Message received in "$VETH_PEER""
else
    echo "❌ Broadcast test failed: Message not received"
    echo "You can run manually:"
    echo "  ip socat -u UDP4-RECVFROM:$TEST_PORT,broadcast"
    echo "  echo \"$TEST_MSG\" | socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH_PEER""
    exit 1
fi
