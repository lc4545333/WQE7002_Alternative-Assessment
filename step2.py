import nmap
import json
import datetime
import step1
import step3
import step4

scanner = step1.NetworkScanner()
result = scanner.scan('192.168.61.0/24',scan_type='arp')
result.discard('192.168.61.1')
result.discard('192.168.61.254')

def parse_vulners_output(script_output):
    vulnerabilities = []
    lines = script_output.strip().split('\n')
    current_cpe = None

    for line in lines:
        line = line.strip()
        if line.startswith('cpe:/'):
            current_cpe = line.strip(': ')
            continue
        if '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 3:
                vuln = {
                    'cpe': current_cpe,
                    'id': parts[0].strip(),
                    'severity': float(parts[1].strip()),
                    'url': parts[2].strip(),
                    'is_exploit': '*EXPLOIT*' in line
                }
                vulnerabilities.append(vuln)

    return sorted(vulnerabilities, key=lambda x: x['severity'], reverse=True)


# init
path = [r'C:.\Program Files (x86)\Nmap\nmap.exe']
scanner = nmap.PortScanner(nmap_search_path=path)
a = scanner.scan()
print(a)
# 目标配置
ip_list = result
ports = '22,80,443'

scan_results = {}

for ip in ip_list:
    scanner.scan(ip, ports=ports, arguments='-sV --script vulners')
    results = {
            'host': ip,
            'timestamp': datetime.datetime.now().isoformat(),
            'ports': {}
        }
    try:
        for port in scanner[ip].all_tcp():
            port_info = scanner[ip]['tcp'][port]
            results['ports'][port] = {
                    'state': port_info['state'],
                    'service': port_info['name'],
                    'version': port_info.get('version', ''),
                    'vulnerabilities': []
                }

            if 'script' in port_info and 'vulners' in port_info['script']:
                vulns = parse_vulners_output(port_info['script']['vulners'])
                results['ports'][port]['vulnerabilities'] = vulns

                print(f"\nfind vuln: {ip}:{port}:")
                for vuln in vulns[:5]:  # 只显示最严重的5个
                    exploit_mark = "[exploit available]" if vuln['is_exploit'] else ""
                    print(f"  {vuln['id']} - severity: {vuln['severity']} {exploit_mark}")

    except KeyError:
        results['error'] = f'Failed to scan host {ip}'

    scan_results[ip] = results

with open('scan_results.json', 'w') as f:
    json.dump(scan_results, f, indent=4, ensure_ascii=False)

print("\nfinished! visit scan_results.json")

json_file = "scan_results.json"
print(step3.process_scan_results(json_file))
print(step3.process_scan_results_for_email(json_file))
print(step4.send_report_email())
