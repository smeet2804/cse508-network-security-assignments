import sys
import socket
import ssl
from scapy.all import *
import logging
import string


def parse_ports(port_range):
    """ Parse port range string into a list of ports """
    ports = []
    if "-" in port_range:
        start, end = port_range.split("-")
        ports = range(int(start), int(end) + 1)
    else:
        ports.append(int(port_range))
    return ports

def syn_scan(target, ports):
    """ Perform a SYN scan on the target """
    open_ports = []
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=3, verbose=0)
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags == 'SA':
                    open_ports.append(port)
                    send(IP(dst=target)/TCP(sport=src_port, dport=port, flags="R"), verbose=0)
                else:
                    logging.debug(f"Port {port} is closed (received TCP flags: {response.getlayer(TCP).flags})")
            else:
                logging.debug(f"Port {port} is closed (received packet: {response.summary()})")
        else:
            logging.debug(f"Port {port} is filtered")
            logging.debug("Trying to establish connection and check whether port is open")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            res = s.connect_ex((target, port))
            if res == 0:
                logging.debug(f"Port {port} is open")
                open_ports.append(port)
            else:
                logging.debug(f"Port {port} is closed")
            s.close()
    return open_ports

def tls_probe_port(target, port):
    """ Probe a port for TLS support """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    # context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certificate.pem")
    # context.check_hostname = False  # Don't validate the hostname

    context = ssl.create_default_context()
    s = context.wrap_socket(s, server_hostname=target)
    try:
        res = s.connect_ex((target, port))
        if (res != 0):
            logging.debug(f"Port {port} does not support TLS")
            return False


        logging.debug(f"Port {port} [TLS]: Connected")
        # Check for server initiated TLS
        try:
            data = s.recv(1024)
            if data:
                print(f"Port {port} [TLS server-initiated]: {format_data(data).decode()}")
                return True
        except socket.timeout:
            pass
        except Exception as e:
            pass
        
        try:

            # Probing with HTTP GET request over TLS
            probe = probe="GET / HTTP/1.0\r\n\r\n"
            s.send(probe.encode())
            data = s.recv(1024)
            if data:
                if format_data(data).decode().startswith("HTTP"):
                    print(f"Port {port} [HTTPS Server]: {format_data(data).decode()}")
                    return True
                else:
                    print(f"Port {port} [Generic TLS Server]: {format_data(data).decode()}")
                    return True
        except socket.timeout:
            pass
        except Exception as e:
            pass
        try:
        # Probing with generic lines over TLS
            probe = "\r\n\r\n\r\n\r\n"
            s.send(probe.encode())
            data = s.recv(1024)
            print(f"Port {port} [Generic TLS Server]: {format_data(data).decode()}")
            return True
        except socket.timeout:
            print(f"Port {port} [Generic TLS Server]:")
            return True
        except Exception as e:
            pass
    except ssl.SSLError as e:
        logging.debug(f"Port {port} does not support TLS (error: {e.strerror})")
        return False

    except Exception as e:
        logging.debug(f"Received error while TLS probing port {port}: {e}")
        return False
    finally:
        logging.debug(f"Closing connection to port {port}")
        s.close()

def tcp_probe_port(target, port):
    """ Probe a port for TCP support """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((target, port))
        res = s.connect_ex((target, port))
        
        if res != 0:
            logging.debug(f"Port {port} does not support TCP")
            return False
        
        logging.debug(f"Port {port} [TCP]: Connected")

        # Check if the socket type is TCP or UDP
        try:
        # Check for server initiated TCP
            logging.debug(f"Probing port {port} with server initiated data")
            data = s.recv(1024)
            if data:
                print(f"Port {port} [TCP server-initiated]: {format_data(data).decode()}")
                return True
        except socket.timeout:
            pass 
        except Exception as e:
            pass
        try:       
            # Probing with HTTP GET request over TCP
            logging.debug(f"Probing port {port} with HTTP GET request")
            probe = probe="GET / HTTP/1.0\r\n\r\n"
            s.send(probe.encode())
            data = s.recv(1024)
            if data:
                if format_data(data).decode().startswith("HTTP"):
                    print(f"Port {port} [HTTP Server]: {format_data(data).decode()}")
                    return True
                else:
                    print(f"Port {port} [Generic TCP Server]: {format_data(data).decode()}")
                    return True
        except socket.timeout:
            pass
        except Exception as e:
            pass

        # Probing with generic lines over TCP
        try:
            logging.debug(f"Probing port {port} with generic lines")
            probe = "\r\n\r\n\r\n\r\n"
            s.send(probe.encode())
            data = s.recv(1024)
            print(f"Port {port} [Generic TCP Server]: {format_data(data).decode()}")
            return True
        except socket.timeout:
            print(f"Port {port} [Generic TCP Server]:")
            return True
        except Exception as e:
            print(f"Port {port} [Generic TCP Server]:")
            return True
    except Exception as e:
        logging.debug(f"Port {port} does not support TCP (error: {e})")
        return False
    finally:
        logging.debug(f"Closing connection to port {port}")
        s.close()

def format_data(data):
    # return bytes(46 if not (byte in (9, 10) or 32 <= byte <= 126) else byte for byte in data)
    # return bytes(46 if not (32 <= byte <= 126) else byte for byte in data)
    return bytes(46 if chr(byte) not in string.printable else byte for byte in data)


def main():
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]  # Default ports
    target = None

    # Parse command line arguments
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '-p' and i + 1 < len(args):
            port_range = args[i + 1]
            ports = parse_ports(port_range)
            i += 2  # Skip next argument since it's the port range
        else:
            # If not processing a port range, it could be the target
            if target is None:  # First non-flag argument is assumed to be the target
                target = args[i]
            i += 1

    # Validate target
    if not target:
        print("Usage: synprobe [-p port_range] target")
        sys.exit(1)

    if "--log" in args:
        logging.basicConfig(level=logging.DEBUG)

    open_ports = syn_scan(target, ports)
    for port in open_ports:
        if tls_probe_port(target, port):
            continue
        tcp_probe_port(target, port)

if __name__ == "__main__":
    main()
