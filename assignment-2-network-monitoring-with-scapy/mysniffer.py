import argparse
import sys
from scapy.all import *
import datetime
import http.client

load_layer("tls")

TLS_VERSIONS = {
    0x301: "TLS v1.0",
    0x302: "TLS v1.1",
    0x303: "TLS v1.2",
    0x304: "TLS v1.3",
}

# Reference: https://stackoverflow.com/a/21926971
def get_server_name_from_payload(bytes_data):
    
    start = 1 + 32 + 10

    session_id_length = bytes_data[start]

    start += 1 + session_id_length

    cipher_suites_length = (bytes_data[start] << 8) | bytes_data[start + 1]

    start += 2 + cipher_suites_length

    compresssion_methods_length = bytes_data[start]

    start += 1 + compresssion_methods_length

    extensions_length = (bytes_data[start] << 8) | bytes_data[start + 1]
    
    start += 2

    while start < extensions_length:

        extension_type = (bytes_data[start] << 8) | bytes_data[start + 1]
        start += 2

        extensions_length = (bytes_data[start] << 8) | bytes_data[start + 1]
        start += 2

        if extension_type == 0:  # SNI Extension
            server_name_length = (bytes_data[start] << 8) | bytes_data[start + 1]   
            start += 2
            # don't know what this field?
#            print(bytes_data[start : start + 3])
            return bytes_data[start + 3 : start + server_name_length].decode('utf-8')
        else:
            start += extensions_length

def process_packet(packet):
    """Processes a network packet, extracting relevant information for HTTP/TLS analysis.

    Args:
        packet: The Scapy packet to process.
    """
    try:
        pkt_timestamp = datetime.datetime.fromtimestamp(int(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')

        pkt_src_ip = None
        pkt_src_port = None
        pkt_dst_ip = None
        pkt_dst_port = None
        pkt_hostname = None
        pkt_request_uri = None
        pkt_method = None

        tls_version = None
        pkt_dst_hostname = None

        processed_as_http = False
        # IP Layer Processing
        if packet.haslayer(IP):
            pkt_src_ip = packet[IP].src
            pkt_dst_ip = packet[IP].dst

            if packet.haslayer(TCP):
                pkt_src_port = packet[TCP].sport
                pkt_dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                pkt_src_port = packet[UDP].sport
                pkt_dst_port = packet[UDP].dport
        # TCP and TLS Layer Processing
        if packet.haslayer(TCP):
            if packet.haslayer(TLSClientHello):
                tls_version = packet[TLSClientHello].version
                tls_version_str = TLS_VERSIONS.get(tls_version, "Unknown")  # Convert TLS version to string

                if hasattr(packet[TLSClientHello], 'ext'):
                    for ext in packet[TLSClientHello].ext:
                        if isinstance(ext, TLS_Ext_ServerName):
                            for server_name in ext.servernames:
                                if server_name.nametype == 0:
                                    pkt_dst_hostname = server_name.servername.decode('utf-8')
                                    print(f"{pkt_timestamp.strip()} {tls_version_str.strip()} "
                                        f"{pkt_src_ip.strip()}:{pkt_src_port} -> "
                                        f"{pkt_dst_ip.strip()}:{pkt_dst_port} {pkt_dst_hostname.strip()}")

            # HTTP Layer Processing
            elif packet.haslayer(Raw):
                try:
                    lines = packet[Raw].load.decode('utf-8').split('\n')
                      # Skip if decoding fails

                    request_line = lines[0]
                    http_methods = ['GET', 'POST']

                    if request_line.split()[0] in http_methods:
                        pkt_method, pkt_request_uri, _ = request_line.split(' ', 2)

                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                if pkt_dst_port == 80:
                                    pkt_hostname = line.split(': ')[1]
                                else:
                                    pkt_hostname_and_port = line.split(': ')[1]
                                    pkt_hostname = pkt_hostname_and_port.split(':')[0]
                                break
                        processed_as_http = True
                        print(f"{pkt_timestamp.strip()} HTTP {pkt_src_ip.strip()}:{pkt_src_port} -> "
                            f"{pkt_dst_ip.strip()}:{pkt_dst_port} {pkt_hostname.strip()} "
                            f"{pkt_method.strip()} {pkt_request_uri.strip()}")
                    
                except UnicodeDecodeError:
                    pass    
            if processed_as_http == False:
                tcp_layer = packet.getlayer(TCP)  
                payload_bytes = bytes(tcp_layer.payload)  # Get payload as bytes
                # print(payload_bytes)
                if payload_bytes.startswith(b'\x16'):  # Content type for Handshake 
                    record_type = payload_bytes[0]
                    version = payload_bytes[1:3]
                    length = int.from_bytes(payload_bytes[3:5], 'big')
                    if payload_bytes[5] == 1:
                        tls_version = int.from_bytes(payload_bytes[9:11], "big")
                        tls_version_str = TLS_VERSIONS.get(tls_version, "Unknown")
                        pkt_dst_hostname = get_server_name_from_payload(payload_bytes)
                        print(f"{pkt_timestamp.strip()} {tls_version_str.strip()} " f"{pkt_src_ip.strip()}:{pkt_src_port} -> " f"{pkt_dst_ip.strip()}:{pkt_dst_port} {pkt_dst_hostname.strip()}")
                    
    except Exception as e:
        print(f"Error processing packet: {e}")

def parse_args():
    """Parses command-line arguments for the packet sniffer.

    Returns:
        An argparse.Namespace object containing the parsed arguments.
    """

    parser = argparse.ArgumentParser(description='HTTP/TLS Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to capture packets from', default=None)
    parser.add_argument('-r', '--tracefile', help='Trace file to read packet captures from', default=None)
    parser.add_argument('expression', nargs='?', help='BPF filter expression', default='')
    return parser.parse_args()


def main():
    """Main entry point for the packet sniffer."""

    args = parse_args()

    if args.tracefile:
        sniff(offline=args.tracefile, filter=args.expression, prn=process_packet)
    else:
        interface = args.interface if args.interface else conf.iface
        sniff(iface=interface, filter=args.expression, prn=process_packet)


if __name__ == '__main__':
    main()