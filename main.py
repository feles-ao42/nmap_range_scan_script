import subprocess
import sys

def run_nmap_scan(ip_range, ports):
    # Construct the NMap command
    command = ["nmap", "-p", ports, ip_range]

    # Execute the command asynchronously and capture the output in real-time
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Display progress updates in real-time
    while True:
        output_line = process.stdout.readline()
        if output_line == '' and process.poll() is not None:
            break
        if output_line:
            print(output_line.strip())

    # If any post-scan processing is needed, it can be added here

if __name__ == "__main__":
    # Specify the IP range and ports to scan
    ip_range = "133.27.186.64/26"  # Example: From 192.168.1.0 to 192.168.1.255
    #ports = "22,80,443"  # Example: Scan ports 22, 80 and 443
    ports = "1-65535" #Example: Scan all ports

    run_nmap_scan(ip_range, ports)
