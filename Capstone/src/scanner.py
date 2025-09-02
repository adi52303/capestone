import socket
import requests
import whois
import dns.resolver
import random
import string
from datetime import datetime
import os
import json


# BASIC FUNCTIONS


def basic_port_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306]
    print(f"\n[+] Scanning {target}...\n")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        else:
            print(f"[CLOSED] Port {port}")
        sock.close()
    return open_ports


def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return {
            "domain_name": data.domain_name if isinstance(data.domain_name, str) else (data.domain_name[0] if data.domain_name else "N/A"),
            "registrar": data.registrar or "N/A",
            "registrar_url": getattr(data, "registrar_url", "N/A"),
            "creation_date": str(data.creation_date) if data.creation_date else "N/A",
            "expiration_date": str(data.expiration_date) if data.expiration_date else "N/A",
            "updated_date": str(data.updated_date) if data.updated_date else "N/A",
            "name_servers": list(data.name_servers) if data.name_servers else [],
            "emails": data.emails if data.emails else "N/A",
            "country": getattr(data, "country", "N/A")
        }
    except Exception:
        return {
            "domain_name": "Error",
            "registrar": "Error",
            "registrar_url": "Error",
            "creation_date": "Error",
            "expiration_date": "Error",
            "updated_date": "Error",
            "name_servers": [],
            "emails": "Error",
            "country": "Error"
        }



def dns_lookup(domain):
    dns_data = {"A": [], "MX": [], "NS": []}

    try:
        # A records
        try:
            for rdata in dns.resolver.resolve(domain, 'A'):
                dns_data["A"].append(rdata.address)
        except:
            pass

        # MX records
        try:
            for rdata in dns.resolver.resolve(domain, 'MX'):
                dns_data["MX"].append(str(rdata.exchange))
        except:
            pass

        # NS records
        try:
            for rdata in dns.resolver.resolve(domain, 'NS'):
                dns_data["NS"].append(str(rdata.target))
        except:
            pass

    except Exception as e:
        pass

    return dns_data



# WILDCARD DETECTION


def detect_wildcard(domain):
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test_domain = f"{random_sub}.{domain}"
    try:
        answers = dns.resolver.resolve(test_domain, "A")
        ips = [str(rdata) for rdata in answers]
        print(f"[!] Wildcard DNS detected → {ips}")
        return ips
    except:
        print("[+] No wildcard DNS detected.")
        return []



# SUBDOMAIN BRUTE FORCE


def subdomain_bruteforce(domain, wildcard_ips, wordlist_path="wordlists/subdomains.txt"):
    print(f"\n[+] Starting subdomain brute force for {domain}...\n")
    found_subdomains = []

    try:
        with open(wordlist_path, "r") as file:
            subdomains = file.read().splitlines()

        for sub in subdomains:
            full_sub = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(full_sub, "A")
                ips = [str(rdata) for rdata in answers]

                # If wildcard present, skip if IP matches wildcard IP
                if wildcard_ips and set(ips) == set(wildcard_ips):
                    continue

                print(f"[FOUND] {full_sub} → {', '.join(ips)}")
                found_subdomains.append((full_sub, ips))
            except:
                pass
    except FileNotFoundError:
        print("[!] Wordlist not found. Please create wordlists/subdomains.txt")
    
    return found_subdomains

def load_vuln_db(path="vuln_db.json"):
    """Load vulnerability database from JSON file."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Could not load vuln_db.json: {e}")
        return {}

def check_iot_ports(open_ports, vuln_db):
    """Match open ports against IoT vuln database."""
    findings = []
    for port in open_ports:
        if str(port) in vuln_db:
            findings.append({
                "port": port,
                "description": vuln_db[str(port)]["description"],
                "severity": vuln_db[str(port)]["severity"]
            })
    return findings


def check_rtsp(ip):
    """Basic check if RTSP port 554 responds."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 554))
        sock.close()
        if result == 0:
            print(f"[!] RTSP port (554) open on {ip} → potential camera stream")
            return True
    except Exception:
        pass
    return False


def grab_http_banner(ip):
    """Try grabbing HTTP/HTTPS headers from device."""
    headers_info = {}
    try:
        for scheme, port in [("http", 80), ("https", 443)]:
            url = f"{scheme}://{ip}:{port}"
            try:
                resp = requests.get(url, timeout=3, verify=False)
                headers_info[scheme] = dict(resp.headers)
                print(f"[+] Grabbed {scheme.upper()} headers from {ip}:{port}")
            except Exception:
                pass
    except Exception:
        pass
    return headers_info


# SAVE REPORT

def save_report(domain, whois_data, dns_data, subdomains_data, port_data, iot_findings):
    """
    Save scan results into TXT and JSON reports (Recon + IoT).
    """

    os.makedirs("outputs/reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    txt_filename = f"outputs/reports/scan_report_{domain}_{timestamp}.txt"
    json_filename = f"outputs/reports/scan_report_{domain}_{timestamp}.json"

    def clean_date(date_value):
        if isinstance(date_value, list):
            return [str(d) for d in date_value]
        return str(date_value) if date_value else "N/A"

    total_open_ports = sum(len(ports) for ports in port_data.values())
    total_subdomains = len(subdomains_data) if subdomains_data else 0
    total_dns_records = sum(len(v) for v in dns_data.values()) if isinstance(dns_data, dict) else 0

    # ----------------------
    # TXT REPORT
    # ----------------------
    with open(txt_filename, "w", encoding="utf-8") as f:

        f.write("========================================\n")
        f.write(" IoT Vulnerability Scanner Report\n")
        f.write(f" Target: {domain}\n")
        f.write(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("========================================\n\n")

        # Summary
        f.write("[Summary]\n")
        f.write(f"- Target: {domain}\n")
        f.write(f"- Total Open Ports: {total_open_ports}\n")
        f.write(f"- DNS Records Found: {total_dns_records}\n")
        f.write(f"- Subdomains Found: {total_subdomains}\n\n")

        # WHOIS
        f.write("[1] WHOIS Information\n")
        f.write("---------------------\n")
        if isinstance(whois_data, dict):
            f.write(f"Domain Name: {whois_data.get('domain_name', 'N/A')}\n")
            f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
            f.write(f"Registrar URL: {whois_data.get('registrar_url', 'N/A')}\n")
            f.write(f"Creation Date: {clean_date(whois_data.get('creation_date'))}\n")
            f.write(f"Expiration Date: {clean_date(whois_data.get('expiration_date'))}\n")
            f.write(f"Updated Date: {clean_date(whois_data.get('updated_date'))}\n")
            f.write("Name Servers:\n")
            for ns in whois_data.get("name_servers", []):
                f.write(f"  - {ns}\n")
            f.write(f"Contact Email: {whois_data.get('emails', 'N/A')}\n")
            f.write(f"Country: {whois_data.get('country', 'N/A')}\n\n")
        else:
            f.write(str(whois_data) + "\n\n")

        # DNS
        f.write("[2] DNS Records\n")
        f.write("---------------\n")
        if isinstance(dns_data, dict):
            for record in dns_data.get("A", []):
                f.write(f"A Record: {record}\n")
            for mx in dns_data.get("MX", []):
                f.write(f"MX Record: {mx}\n")
            for ns in dns_data.get("NS", []):
                f.write(f"NS Record: {ns}\n")
        f.write("\n")

        # Subdomains
        f.write("[3] Subdomain Enumeration\n")
        f.write("-------------------------\n")
        if subdomains_data:
            for sub, ip in subdomains_data:
                f.write(f"{sub} -> {ip}\n")
        else:
            f.write("No subdomains found from current wordlist.\n")
        f.write("\n")

        # Open Ports
        f.write("[4] Open Ports\n")
        f.write("--------------\n")
        for host, ports in port_data.items():
            f.write(f"Target: {host}\n")
            for port in ports:
                f.write(f"  - {port}\n")
        f.write("\n")

        # IoT Findings
        f.write("[5] IoT Vulnerability Findings\n")
        f.write("------------------------------\n")
        if iot_findings:
            for host, findings in iot_findings.items():
                f.write(f"Target: {host}\n")
                for fnd in findings:
                    f.write(f"  - Port {fnd['port']} | {fnd['severity']} | {fnd['description']}\n")
        else:
            f.write("No IoT-specific findings detected.\n")
        f.write("\n")

        f.write("========================================\n")
        f.write("End of Report\n")
        f.write("Generated by: IoT Vulnerability Scanner\n")

    # ----------------------
    # JSON REPORT
    # ----------------------
    json_data = {
        "target": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_open_ports": total_open_ports,
            "dns_records_found": total_dns_records,
            "subdomains_found": total_subdomains
        },
        "whois": whois_data if isinstance(whois_data, dict) else {"raw": str(whois_data)},
        "dns_records": dns_data if isinstance(dns_data, dict) else {"raw": str(dns_data)},
        "subdomains": subdomains_data or {},
        "open_ports": port_data,
        "iot_findings": iot_findings
    }

    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(json_data, jf, indent=4)

    print(f"\n[+] Report saved as: {txt_filename}")
    print(f"[+] JSON data saved as: {json_filename}")

if __name__ == "__main__":
    target = input("Enter target IP or domain: ")

    whois_data = whois_lookup(target)
    dns_data = dns_lookup(target)

    wildcard_ips = detect_wildcard(target)
    subdomains_data = subdomain_bruteforce(target, wildcard_ips)

    port_scan_results = {}
    try:
        main_ip = socket.gethostbyname(target)
        port_scan_results[target] = basic_port_scan(main_ip)
    except:
        pass

    for sub, ips in subdomains_data:
        for ip in ips:
            port_scan_results[sub] = basic_port_scan(ip)

    # IoT checks
    vuln_db = load_vuln_db()
    iot_findings = {}
    for host, ports in port_scan_results.items():
        iot_findings[host] = check_iot_ports(ports, vuln_db)
        if check_rtsp(host):
            iot_findings[host].append({
                "port": 554,
                "description": "RTSP open on IoT device.",
                "severity": "Critical"
            })
        http_info = grab_http_banner(host)
        if http_info:
            iot_findings[host].append({
                "port": 80,
                "description": f"HTTP headers: {list(http_info.get('http', {}).keys())}",
                "severity": "Info"
            })

    save_report(target, whois_data, dns_data, subdomains_data, port_scan_results, iot_findings)
