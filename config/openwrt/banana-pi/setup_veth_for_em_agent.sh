#!/bin/sh
# --- Configuration ---
BRIDGE_NAME=$1
VETH_AGENT_END="eth1_virt_end"
VETH_AGENT_PEER="eth1_virt_peer"

# --- Cleanup previous setup (important for fresh runs) ---
echo "Cleaning up earlier virtual network devices..."
sudo ip link del $VETH_AGENT_END 2>/dev/null
echo "Cleanup complete."

# --- Create the Bridge ---
echo "Creating bridge $BRIDGE_NAME..."
sudo ip link add name $BRIDGE_NAME type bridge
sudo ip link set dev $BRIDGE_NAME up
echo "Bridge $BRIDGE_NAME created and brought up."

# --- Create veth pair 1 and add one end to the bridge ---
echo "Creating veth pair ($VETH_AGENT_END <-> $VETH_AGENT_PEER)..."
sudo ip link add name $VETH_AGENT_END type veth peer name $VETH_AGENT_PEER
sudo ip link set $VETH_AGENT_END master $BRIDGE_NAME
sudo ip link set dev $VETH_AGENT_END up
sudo ip link set dev $VETH_AGENT_PEER up
echo "veth pair 1 created, $VETH_AGENT_END added to $BRIDGE_NAME, both ends up."

# --- Verify setup ---
echo -e "\n--- Network Setup Summary ---"
echo "Bridge members:"
sudo brctl show $BRIDGE_NAME
echo -e "\nInterface IPs:"
ip a show $VETH_AGENT_PEER

echo "To clean up, run 'sudo ip link del $BRIDGE_NAME'."

# ----------- 🔍 TEST: Broadcast from VETH_AGENT_PEER -----------

echo "Testing broadcast connectivity..."

TEST_PORT=9999
TEST_MSG="hello_broadcast_test_$$"
RESULT=""

# Start listener in background
sudo timeout 3 socat -u UDP4-RECVFROM:$TEST_PORT,broadcast - > /tmp/eth1_virt_output.$$ &
LISTENER_PID=$!
sleep 1

# Send broadcast from veth_agent_peer
echo "$TEST_MSG" | sudo socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH_AGENT_PEER"

# Wait and read result
sleep 1
if [ -f /tmp/eth1_virt_output.$$ ]; then
    RESULT=$(cat /tmp/eth1_virt_output.$$)
    rm -f /tmp/eth1_virt_output.$$
fi

if [[ "$RESULT" == "$TEST_MSG" ]]; then
    echo "✅ Broadcast test successful: Message received"
else
    echo "❌ Broadcast test failed: Message not received"
    echo "You can run manually:"
    echo "  ip socat -u UDP4-RECVFROM:$TEST_PORT,broadcast"
    echo "  echo \"$TEST_MSG\" | socat - UDP4-DATAGRAM:255.255.255.255:$TEST_PORT,broadcast,bindtodevice="$VETH_AGENT_PEER""
    exit 1
fi
