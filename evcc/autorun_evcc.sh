#!/bin/bash

# Port number to listen for synchronization packet
sync_port=12356

trap ctrl_c INT

function ctrl_c() {
    echo "INT received. Killing processes..."
    pkill -P $$
    exit 1
}

# Function to listen for synchronization packet
function listen_sync_packet() {
    echo "Waiting for synchronization packet on port $sync_port..."
    # Listen for synchronization packet
    sudo tcpdump -q -i any udp port 12356 -c 1
    echo "Received synchronization packet"
}

# Infinite loop
while true; do
    sleep 10
    konsole -e "python start_ev.py" &
    listen_sync_packet
    pkill -P $$
done

