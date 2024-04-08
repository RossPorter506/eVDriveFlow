cd secc

num=100

trap ctrl_c INT
function ctrl_c() {
        echo "Received INT. Killing processes..."
        pkill -P $$
        exit 1
}

device_ip=192.168.1.4
sync_port=12356
send_sync_packet() {
    echo "Sync" > /dev/udp/$device_ip/$sync_port
}

for ((i=0; i<$num; i++)); do
	python -B start_evse.py &
	pid=$!
	sleep 40
	kill $pid
	send_sync_packet
done
