from scapy.all import sniff, Ether, IP

def process_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        print('\nEthernet Frame:')
        print(f'\t - Destination: {eth.dst}, Source: {eth.src}, Type: {eth.type}')

        if IP in packet:
            ip = packet[IP]
            print(f'\t - IPv4 Packet:')
            print(f'\t\t - Version: {ip.version}, Header Length: {ip.ihl}, TTL: {ip.ttl}')
            print(f'\t\t - Protocol: {ip.proto}, Source: {ip.src}, Target: {ip.dst}')
            print(f'\t\t - IPv4 Data:')
            print(f'\t\t\t - {bytes(ip.payload)}')

def main():
    print("Starting network sniffer...")
    sniff(prn=process_packet, store=0)

if __name__ == '__main__':
    main()