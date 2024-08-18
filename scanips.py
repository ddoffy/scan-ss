from scapy.all import ARP, Ether, srp
import socket
import webbrowser
import time

def get_local_ip():
    # get the local ip addresses
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # hostname = socket.gethostname()
        # ipAddr = socket.gethostbyname(hostname)
        s.connect(('192.168.100.1', 1))
        socket_name = s.getsockname()
        print(socket_name)
        local_ip = socket_name[0]
    except:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    return local_ip

def scan_network(ip_range):
    # create arp request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices;

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
    except socket.timeout:
        return False
    except socket.error:
        return False
    else:
        return True
    finally:
        sock.close()

def health_check(ip, port, path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
        response = sock.recv(1024)
        print(response)
    except socket.timeout:
        return False
    except socket.error:
        return False
    else:
        return True
    finally:
        sock.close()

def main():
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")

    # Assuming a typical /24 network mask
    ip_base = '.'.join(local_ip.split('.')[:-1]) + '.'
    ip_range = ip_base + '1/24'
    print(f"Scanning IP range: {ip_range}")

    devices = scan_network(ip_range)
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

    print("\nChecking for open ports on devices:")
    port = 5000
    for device in devices:
        print(f"Checking {device['ip']}...")
        if check_port(device['ip'], port):
            print(f"Port {port} is open on {device['ip']}")
            webbrowser.open(f"http://{device['ip']}:{port}/stream")
            while True:
                if health_check(device['ip'], port, "/health"):
                    print(f"Device {device['ip']} is healthy")
                    time.sleep(1)
                else:
                    print(f"Device {device['ip']} is not healthy")
                    break

if __name__ == "__main__":
    while True:
        main()
        time.sleep(15)
