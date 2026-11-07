#!/usr/bin/env bash
set -e

# Remove old namespaces if they exist
for ns in pc1 device1 device2 pc2; do
    ip netns del "$ns" 2>/dev/null || true
done

# Create namespaces
for ns in pc1 device1 device2 pc2; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

# Create veth pairs
ip link add pc1-d1 type veth peer name d1-pc1
ip link add d1-d2 type veth peer name d2-d1
ip link add d2-pc2 type veth peer name pc2-d2

# Move interfaces into namespaces
ip link set pc1-d1 netns pc1
ip link set d1-pc1 netns device1
ip link set d1-d2 netns device1
ip link set d2-d1 netns device2
ip link set d2-pc2 netns device2
ip link set pc2-d2 netns pc2

# Configure PC1
ip -n pc1 addr add 10.0.1.2/24 dev pc1-d1
ip -n pc1 link set pc1-d1 up
ip -n pc1 route add default via 10.0.1.1

# Configure Device1
ip -n device1 addr add 10.0.1.1/24 dev d1-pc1
ip -n device1 link set d1-pc1 up
ip -n device1 addr add 10.0.12.1/24 dev d1-d2
ip -n device1 link set d1-d2 up
ip -n device1 route add 10.0.2.0/24 via 10.0.12.2

# Configure Device2
ip -n device2 addr add 10.0.12.2/24 dev d2-d1
ip -n device2 link set d2-d1 up
ip -n device2 addr add 10.0.2.1/24 dev d2-pc2
ip -n device2 link set d2-pc2 up
ip -n device2 route add 10.0.1.0/24 via 10.0.12.1

# Configure PC2
ip -n pc2 addr add 10.0.2.2/24 dev pc2-d2
ip -n pc2 link set pc2-d2 up
ip -n pc2 route add default via 10.0.2.1

# Enable forwarding
ip netns exec device1 sysctl -w net.ipv4.ip_forward=1
ip netns exec device2 sysctl -w net.ipv4.ip_forward=1

echo "Network topology created successfully."
