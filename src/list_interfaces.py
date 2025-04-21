from scapy.all import get_working_ifaces

# Get all working network interfaces
interfaces = get_working_ifaces()

# Print each interface
for iface in interfaces:
    print(f"Interface: {iface.name}")