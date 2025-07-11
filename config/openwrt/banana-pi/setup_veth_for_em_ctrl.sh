#!/bin/sh
# --- Configuration ---
BRIDGE_NAME=$1
VETH_CTRL_END="eth0_virt_end"
VETH_CTRL_PEER="eth0_virt_peer"


# --- Cleanup previous setup (important for fresh runs) ---
echo "Cleaning up any existing virtual network devices..."
sudo ip link del $VETH_CTRL_END 2>/dev/null
echo "Cleanup complete."

# --- Create the Bridge ---
echo "Creating bridge $BRIDGE_NAME..."
sudo ip link add name $BRIDGE_NAME type bridge
sudo ip link set dev $BRIDGE_NAME up
echo "Bridge $BRIDGE_NAME created and brought up."

# --- Create veth pair 0 and add one end to the bridge ---
echo "Creating veth pair ($VETH_CTRL_END <-> $VETH_CTRL_PEER)..."
sudo ip link add name $VETH_CTRL_END type veth peer name $VETH_CTRL_PEER
sudo ip link set $VETH_CTRL_END master $BRIDGE_NAME
sudo ip link set dev $VETH_CTRL_END up
sudo ip link set dev $VETH_CTRL_PEER up
# Set the mac address of VETH_CTRL_PEER to be a fixed offset of erouter0/eth0/wlan0 address
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
#Obtain the VETH_CTRL_PEER mac address by converting to str format
veth0_mac=$(printf "%012x" $primary_veth0_mac | sed 's/../&:/g;s/:$//')
echo "$VETH_CTRL_PEER macaddress: $veth0_mac"
ip link set dev $VETH_CTRL_PEER address $veth0_mac
echo "veth pair 0 created, $VETH_CTRL_END added to $BRIDGE_NAME, both ends up."

# --- Verify setup ---
echo -e "\n--- Network Setup Summary ---"
echo "Bridge members:"
sudo brctl show $BRIDGE_NAME
echo -e "\nInterface IPs:"
ip a show $VETH_CTRL_PEER

echo "To clean up, run 'sudo ip link del $BRIDGE_NAME'."

# ----------- 🔍 TEST: Broadcast from veth_ctrl_peer -----------

echo "Testing broadcast connectivity..."

TEST_PORT=9999
TEST_MSG="hello_broadcast_test_$$"
RESULT=""

# Start listener in background
sudo timeout 3 socat -u UDP4-RECVFROM:$TEST_PORT,broadcast - > /tmp/eth0_virt_output.$$ &
LISTENER_PID=$!
sleep 1

# Send broadcast from veth_ctrl_peer
echo "$TEST_MSG" | sudo socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH_CTRL_PEER"

# Wait and read result
sleep 1
if [ -f /tmp/eth0_virt_output.$$ ]; then
    RESULT=$(cat /tmp/eth0_virt_output.$$)
    rm -f /tmp/eth0_virt_output.$$
fi

if [[ "$RESULT" == "$TEST_MSG" ]]; then
    echo "✅ Broadcast test successful: Message received in "$VETH_CTRL_PEER""
else
    echo "❌ Broadcast test failed: Message not received"
    echo "You can run manually:"
    echo "  ip socat -u UDP4-RECVFROM:$TEST_PORT,broadcast"
    echo "  echo \"$TEST_MSG\" | socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH1_PEER""
    exit 1
fi
