from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Callback function to process each captured packet
def analyze_packet(packet):
    print("=" * 80)
    
    # Check for IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] Source IP: {ip_layer.src}")
        print(f"[+] Destination IP: {ip_layer.dst}")
        print(f"[+] Protocol: {ip_layer.proto}")

        # Check for protocol type
        if packet.haslayer(TCP):
            print("[*] Protocol: TCP")
            tcp_layer = packet[TCP]
            print(f"    - Source Port: {tcp_layer.sport}")
            print(f"    - Destination Port: {tcp_layer.dport}")
        
        elif packet.haslayer(UDP):
            print("[*] Protocol: UDP")
            udp_layer = packet[UDP]
            print(f"    - Source Port: {udp_layer.sport}")
            print(f"    - Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            print("[*] Protocol: ICMP")
        
        # Display payload if any
        if packet.haslayer(Raw):
            print("[*] Payload:")
            print(packet[Raw].load[:100])  # Print first 100 bytes of payload (optional limit)
    else:
        print("[!] Non-IP packet captured")

# Start sniffing packets
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=0)
