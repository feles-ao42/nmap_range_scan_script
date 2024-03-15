import subprocess
import xml.etree.ElementTree as ET
import csv

def run_nmap_scan(ip_range, ports):
    # XML形式でNMapスキャンを実行し、一時ファイルに出力
    output_file = "nmap_scan_results.xml"
    command = ["nmap", "-p", ports, ip_range, "-oX", output_file]
    subprocess.run(command)
    
    # XMLファイルを解析して結果をCSVに保存
    parse_nmap_xml_to_csv(output_file, "scan_results.csv")

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
    ip_range = "192.168.1.0/24"  # Specify the IP range
    ports = "22,80,443"  # Specify the ports
    #ports = "1-65535"
    run_nmap_scan(ip_range, ports)

