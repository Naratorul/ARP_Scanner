import ipaddress
import subprocess
import netifaces
import re
import time
import sys
import threading

def get_network_range():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip_address = ip_info['addr']
            netmask = ip_info['netmask']
            network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
            return str(network)
    raise Exception("Cannot determine network range")

def get_device_type(mac):
    oui = mac[:8].upper()
    device_types = {
        "B8:27:EB": "Pc",
        "00:1A:2B": "Phone",
    }
    return device_types.get(oui, "Unknown Device")

def get_mac_address(ip):
    output = subprocess.Popen(['arp', '-a', ip], stdout=subprocess.PIPE).communicate()[0]
    match = re.search(r"(([a-f0-9]{2}[:-]){5}[a-f0-9]{2})", output.decode('utf-8').lower())
    if match:
        return match.group(0).upper()
    return "N/A"

def scan_network(networkAddr):
    network = ipaddress.ip_network(networkAddr)
    spinfo = subprocess.STARTUPINFO()
    spinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    spinfo.wShowWindow = subprocess.SW_HIDE

    devices = []
    for host in network.hosts():
        host = str(host)
        output = subprocess.Popen(['ping', '-n', '1', '-w', '100', host], stdout=subprocess.PIPE, startupinfo=spinfo).communicate()[0]
        status = "Offline"
        if 'Received = 1' in output.decode('utf-8'):
            mac = get_mac_address(host)
            device_type = get_device_type(mac)
            status = "Online"
            devices.append({"ip": host, "mac": mac, "type": device_type, "status": status})
    
    return devices

def show_spinner():
    spinner_chars = ['/', '-', '\\', '|']
    while not stop_event.is_set():
        for char in spinner_chars:
            if stop_event.is_set():
                return
            sys.stdout.write(f'\r{char} ')
            time.sleep(0.1)

if __name__ == '__main__':
    try:
        network_range = get_network_range()
        print(f"    Scanning network: {network_range}", end='', flush=True)
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=show_spinner)
        spinner_thread.start()
        start_time = time.time()
        devices = scan_network(network_range)
        end_time = time.time()
        stop_event.set()
        spinner_thread.join()

        elapsed_time = end_time - start_time
        sys.stdout.write('\r' + ' ' * 4 + '\r')
        sys.stdout.flush()
        
        if devices:
            print("\nIP Address              MAC Address           Device Type        Status")
            print("-----------------------------------------------------------------------")
            for device in devices:
                print(f"{device['ip']:<22} {device['mac']:<20} {device['type']:<20} {device['status']}")
        else:
            print("\nNo devices found")
        
        print(f"\nScan completed in {elapsed_time:.2f} seconds.")
        
    except Exception as e:
        print(f"Error: {e}")
