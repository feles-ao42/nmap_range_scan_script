import os
import subprocess
import xml.etree.ElementTree as ET
import csv
from dotenv import load_dotenv
from datetime import datetime

def run_nmap_scan(ip_range, ports):
    # Ensure the /result directory exists
    result_dir = "./result"
    os.makedirs(result_dir, exist_ok=True)
    
    # Generate file name based on current date and time
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(result_dir, f"nmap_scan_results_{timestamp}.xml")
    csv_file = os.path.join(result_dir, f"scan_results_{timestamp}.csv")
    
    # Execute NMap scan in XML format and save to a temporary file
    command = ["nmap", "-p", ports, ip_range, "-oX", output_file]
    subprocess.run(command)
    
    # Parse the XML file and save the results to a CSV file
    parse_nmap_xml_to_csv(output_file, csv_file)
    
    # Remove the temporary XML file after parsing
    os.remove(output_file)

def parse_nmap_xml_to_csv(xml_file, csv_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "Domain", "Open Ports", "Closed Ports"])
        
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            try:
                domain = host.find('hostnames/hostname').get('name')
            except AttributeError:
                domain = ""
            
            open_ports = []
            closed_ports = []
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                if state == "open":
                    open_ports.append(port_id)
                elif state == "closed":
                    closed_ports.append(port_id)
            
            writer.writerow([ip, domain, ", ".join(open_ports), ", ".join(closed_ports)])

if __name__ == "__main__":
    load_dotenv()  # Load environment variables from .env file
    ip_range = os.getenv("IP_RANGE")  # Read the IP range from .env file
    ports = os.getenv("PORTS")  # Read the ports from .env file
    run_nmap_scan(ip_range, ports)

