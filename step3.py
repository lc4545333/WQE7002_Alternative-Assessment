import json
import datetime
from collections import defaultdict
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
import base64
from io import BytesIO


def get_severity_level(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def get_severity_class(score):
    """返回对应的CSS类名"""
    if score >= 9.0:
        return "risk-critical"
    elif score >= 7.0:
        return "risk-high"
    elif score >= 4.0:
        return "risk-medium"
    else:
        return "risk-low"


def analyze_vulnerabilities(vulns):

    severity_counts = defaultdict(int)
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    low_vulns = []

    for vuln in vulns: #迭代列表里的每个漏洞 漏洞是用字典包着的{'cpe': 'cpe:/a:apache:http_server:2.2.8',
        # 'id': 'SSV:69341', 'severity': 10.0,
        # 'url': 'https://vulners.com/seebug/SSV:69341', 'is_exploit': True}
        score = float(vuln['severity'])
        severity_counts[get_severity_level(score)] += 1  #计算不同危险程度漏洞的数量

        # 收集高危漏洞详情
        if score >= 9.0:
            critical_vulns.append(vuln)
        elif score >= 7.0:
            high_vulns.append(vuln)
        elif score >= 4.0:
            medium_vulns.append(vuln)
        else:
            low_vulns.append(vuln)

        critical_vulns = sorted(critical_vulns, key=lambda x: float(x['severity']), reverse=True)
        high_vulns = sorted(high_vulns, key=lambda x: float(x['severity']), reverse=True)
        medium_vulns = sorted(medium_vulns, key=lambda x: float(x['severity']), reverse=True)
        low_vulns = sorted(low_vulns, key=lambda x: float(x['severity']), reverse=True)

    return dict(severity_counts), {
        'critical': critical_vulns,
        'high': high_vulns,
        'medium': medium_vulns,
        'low': low_vulns
    }

def generate_chart_image(severity_counts: Dict[str, int], host: str):
    """生成漏洞统计图并返回Base64编码的图像"""
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())

    plt.figure(figsize=(6, 4))
    plt.bar(labels, sizes, color=["#ff6b6b", "#ff9f43", "#feca57", "#1dd1a1"])
    plt.title(f'Vulnerability Distribution for {host}')
    plt.xlabel('Risk Level')
    plt.ylabel('Count')

    # 将图表保存为Base64编码的图像
    buf = BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    return image_base64

def generate_html_report(scan_results: Dict) -> str:
  #html里的{}要重复一遍以转义，但是包裹变量的{}不需要转义哦！
    HTML_TEMPLATE = """  
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .header {{
                background: #2c3e50;
                color: white;
                padding: 20px;
                border-radius: 5px 5px 0 0;
                margin: -20px -20px 20px;
            }}
            .summary-box {{
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 15px;
                margin-bottom: 20px;
            }}
            .risk-tag {{
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: bold;
            }}
            .risk-critical {{ background: #dc3545; color: white; }}
            .risk-high {{ background: #fd7e14; color: white; }}
            .risk-medium {{ background: #ffc107; }}
            .risk-low {{ background: #28a745; color: white; }}
            .host-section {{
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 15px;
                margin: 10px 0;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }}
            th {{ background: #f8f9fa; }}
            .exploit-tag {{
                background: #dc3545;
                color: white;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
            }}
            .tab-container {{
                display: flex;
                border: 1px solid #ccc;
                border-radius: 4px;
                overflow: hidden;
                margin: 15px 0;
            }}
            .tab-button {{
                flex: 1;
                background-color: #f1f1f1;
                border: none;
                outline: none;
                cursor: pointer;
                padding: 10px 16px;
                transition: 0.3s;
                text-align: center;
            }}
            .tab-button:hover {{
                background-color: #ddd;
            }}
            .tab-button.active {{
                background-color: #ccc;
            }}
            .tab-content {{
                display: none;
                padding: 15px;
                border-top: 1px solid #ccc;
            }}
            .tab-content.active {{
                display: block;
            }}
                .scrollable-table {{
                max-height: 300px;
                overflow-y: auto;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                margin: 15px 0;
            }}
            .scrollable-table table {{
                margin: 0;
            }}
            .chart-container {{
                margin: 20px 0;
                text-align: center;
            }}
            .chart-container img {{
                max-width: 100%;
                height: auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Vulnerabilities Scan Report</h1>
                <p>Scan Time: {timestamp}</p>
            </div>

            <div class="summary-box">
                <h2>Overview</h2>
                <ul>
                    <li>Hosts Scanned: {host_count}</li>
                    <li>Total Ports Checked: {total_ports}</li>
                    <li>Open Ports Found: {open_ports}</li>
                    <li>Total Vulnerabilities Found: {total_vulns}</li>
                </ul>
            </div>

            {host_sections}

            <div class="summary-box">
                <h2>Security Recommendations</h2>
                <ol>
                    <li>Upgrade Apache HTTP Server to the latest stable version</li>
                    <li>Prioritize fixing high-risk vulnerabilities with known exploits</li>
                    <li>For systems that cannot be upgraded immediately:
                        <ul>
                            <li>Configure WAF rules to block known attacks</li>
                            <li>Restrict access to unnecessary ports</li>
                            <li>Strengthen access controls and monitoring</li>
                        </ul>
                    </li>
                    <li>Perform regular security scans and vulnerability assessments</li>
                    <li>Establish an incident response plan</li>
                </ol>
            </div>
        </div>
        <script>
        // 选项卡切换逻辑
            function openTab(evt, tabName) {{
                var tabContent = document.getElementById(tabName);
                var tabButton = evt.currentTarget;

            // 切换选项卡内容的显示状态
                if (tabContent.style.display === "block") {{
                    tabContent.style.display = "none";
                    tabButton.classList.remove("active");
                }} else {{
                    tabContent.style.display = "block";
                    tabButton.classList.add("active");
                }}
            }}
        </script>   
    </body>
    </html>
        """


    HOST_SECTION_TEMPLATE = """
    <meta charset="UTF-8">
    <div class="host-section">
        <h3>Host: {host}</h3>
        <p>Open Ports:</p>
        {port_sections}
        <div class="chart-container">
            <img src="data:image/png;base64,{chart_image}" alt="Vulnerability Distribution Chart">
        </div>   
        {vuln_tabs}
    </div>
    """

    def generate_host_section(host_data: Dict) -> str:  #在每个主机的每个端口层面总结
        port_sections = []
        all_vulns = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        for port, port_data in host_data['ports'].items():
            if port_data['state'] == 'open':
                vulns = port_data.get('vulnerabilities', [])
                severity_counts, classified_vulns = analyze_vulnerabilities(vulns)

                # 合并漏洞到总列表
                for level, vuln_list in classified_vulns.items():
                    all_vulns[level].extend(vuln_list)

                port_sections.append(f"""
                    <li><strong>{port}/tcp</strong> - {port_data['service']} {port_data.get('version', '')}
                        <ul>
                            <li class="high-risk">Critical Vulnerabilities(CVSS ≥ 9.0): {severity_counts.get('Critical', 0)}</li>
                            <li class="medium-risk">High-risk Vulnerabilities(CVSS 7.0-8.9): {severity_counts.get('High', 0)}</li>
                            <li>Medium-risk Vulnerabilities(CVSS 4.0-6.9): {severity_counts.get('Medium', 0)}</li>
                            <li>Low-risk Vulnerabilities(CVSS < 4.0): {severity_counts.get('Low', 0)}</li>
                        </ul>
                    </li>
                """)

        # 生成漏洞选项卡
        vuln_tabs = []
        for level, vulns in all_vulns.items():
            if vulns:
                vuln_rows = []
                for vuln in vulns:
                    vuln_rows.append(f"""
                        <tr>
                            <td>{vuln['id']}</td>
                            <td><span class="risk-tag {get_severity_class(float(vuln['severity']))}">{get_severity_level(float(vuln['severity']))} ({vuln['severity']})</span></td>
                            <td>{'<span class="exploit-tag">Exploit Available</span>' if vuln['is_exploit'] else 'No'}</td>
                            <td><a href="{vuln['url']}" target="_blank">Detail</a></td>
                        </tr>
                    """)

                # 使用主机 IP 和漏洞等级生成唯一 ID
                tab_id = f"{host_data['host']}-{level}"
                vuln_tabs.append(f"""
                    <div class="tab-container">
                        <button class="tab-button" onclick="openTab(event, '{tab_id}')">{get_severity_level(9.0 if level == 'critical' else 7.0 if level == 'high' else 4.0 if level == 'medium' else 0)}Vulnerabilities</button>
                    </div>
                    <div id="{tab_id}" class="tab-content">
                        <div class="scrollable-table">
                            <table>
                                <tr>
                                    <th>Vulnerability ID</th>
                                    <th>Risk Level</th>
                                    <th>Exploit Available</th>
                                    <th>Details</th>
                                </tr>
                                {''.join(vuln_rows)}
                            </table>
                        </div>
                    </div>
                """)


        severity_counts, _ = analyze_vulnerabilities([vuln for port_data in host_data['ports'].values() for vuln in port_data.get('vulnerabilities', [])])
        chart_image = generate_chart_image(severity_counts, host_data['host'])

        return HOST_SECTION_TEMPLATE.format(
            host=host_data['host'],
            port_sections='<ul>' + ''.join(port_sections) + '</ul>',
            vuln_tabs=''.join(vuln_tabs),
            chart_image=chart_image
        )



    # 生成报告数据
    host_sections = []
    total_vulns = 0
    open_ports = 0

    for host_data in scan_results.values():  #host_data对应每一个IP内部的扫描结果。scan_results.keys()是两个IP地址
        host_sections.append(generate_host_section(host_data)) #对每个IP的扫描结果进行处理，结果按照端口进行分析
        for port_data in host_data['ports'].values():
            if port_data['state'] == 'open':
                open_ports += 1
                total_vulns += len(port_data.get('vulnerabilities', []))
    output_file1 = '11.html'
    with open(output_file1, 'w', encoding='utf-8') as f:
        f.write(''.join(host_sections))

    report_html = HTML_TEMPLATE.format(
        timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        host_count=len(scan_results),
        total_ports=sum(len(host['ports']) for host in scan_results.values()),
        open_ports=open_ports,
        total_vulns=total_vulns,
        host_sections=''.join(host_sections)
    )

    return report_html


def process_scan_results(json_file_path):
    """处理扫描结果并生成报告"""
    # 读取JSON文件
    with open(json_file_path, 'r', encoding='utf-8') as f:
        scan_results = json.load(f)

    # 生成HTML报告
    report_html = generate_html_report(scan_results)

    # 保存HTML报告
    output_file = 'vulnerability_report.html'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_html)

    print(f"Report generated:: {output_file}")
    return True

def generate_email_html_report(scan_results: Dict) -> str:
    """生成适合邮件发送的简化版HTML报告（去掉安全建议）"""
    EMAIL_HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
        <div style="background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
            <div style="background: #2c3e50; color: white; padding: 20px; border-radius: 5px 5px 0 0; margin: -20px -20px 20px;">
                <h1>Vulnerabilities Scan Report</h1>
                <p>Scan time: {timestamp}</p>
            </div>

            <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin-bottom: 20px;">
                <h2>Overview</h2>
                <ul>
                    <li>Hosts Scanned: {host_count}</li>
                    <li>Total Ports Checked: {total_ports}</li>
                    <li>Open Ports Found: {open_ports}</li>
                    <li>Total Vulnerabilities Found: {total_vulns}</li>
                </ul>
            </div>

            <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin-bottom: 20px;">
                <h2>Vulnerability Statistics</h2>
                <ul>
                    <li>Critical Vulnerabilities(CVSS ≥ 9.0): {critical_count}</li>
                    <li>High-risk Vulnerabilities(CVSS 7.0-8.9): {high_count}</li>
                    <li>Medium-risk Vulnerabilities(CVSS 4.0-6.9): {medium_count}</li>
                    <li>Low-risk Vulnerabilities(CVSS < 4.0): {low_count}</li>
                </ul>
            </div>

            <p style="text-align: center; margin-top: 20px;">
                <a href="http://localhost:63342/final/milestone_DongXinyu_23099506_wqe7002_project/vulnerability_report.html?_ijt=6072h02lmoda8ronjggi9gnu4n&_ij_reload=RELOAD_ON_SAVE.html?_ijt=eb2gkn4vnge58dk86ifdmi9dcq&_ij_reload=RELOAD_ON_SAVE" style="color: #007bff; text-decoration: none;">
                    For More Information, Please Visit the page.
                </a>
            </p>
        </div>
    </body>
    </html>
    """

    # 统计漏洞数量
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    total_vulns = 0
    open_ports = 0

    for host_data in scan_results.values():
        for port_data in host_data['ports'].values():
            if port_data['state'] == 'open':
                open_ports += 1
                vulns = port_data.get('vulnerabilities', [])
                total_vulns += len(vulns)
                for vuln in vulns:
                    score = float(vuln['severity'])
                    if score >= 9.0:
                        critical_count += 1
                    elif score >= 7.0:
                        high_count += 1
                    elif score >= 4.0:
                        medium_count += 1
                    else:
                        low_count += 1

    report_html = EMAIL_HTML_TEMPLATE.format(
        timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        host_count=len(scan_results),
        total_ports=sum(len(host['ports']) for host in scan_results.values()),
        open_ports=open_ports,
        total_vulns=total_vulns,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )

    return report_html

def process_scan_results_for_email(json_file_path):
    with open(json_file_path, 'r', encoding='utf-8') as f:
        scan_results = json.load(f)

    report_html = generate_email_html_report(scan_results)

    output_file = 'vulnerability_report_email.html'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_html)

    print(f"report generated: {output_file}")
    return True
