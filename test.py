import nmap
import requests
import webbrowser
import datetime
import os

# إعدادات السكربت
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
HTML_REPORT_PATH = "vuln_report.html"

# دالة فحص الهدف
def scan_target(target_ip):
    scanner = nmap.PortScanner()
    print(f"\n🔍 بدء الفحص على: {target_ip}...\n")
    scanner.scan(target_ip, arguments="-T4 -sV")

    results = []

    for host in scanner.all_hosts():
        print(f"🎯 الهدف: {host}")
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in lport:
                service = scanner[host][proto][port]['name']
                print(f"🛡️ منفذ {port}/{proto} - الخدمة: {service}")

                cves = search_cve(service)
                results.append({
                    'host': host,
                    'port': port,
                    'protocol': proto,
                    'service': service,
                    'cves': cves
                })
    return results

# دالة البحث عن الثغرات
def search_cve(service_name):
    try:
        response = requests.get(NVD_API_URL + service_name)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            cve_list = []
            for vuln in vulnerabilities[:3]:  # نأخذ أول ٣ فقط
                cve_id = vuln['cve']['id']
                cve_list.append(cve_id)
            return cve_list
        else:
            print(f"❗ فشل في جلب CVE لـ {service_name}")
            return []
    except Exception as e:
        print(f"❗ خطأ أثناء الاتصال: {e}")
        return []

# دالة إنشاء تقرير HTML
def generate_html_report(results):
    html = f"""
    <html>
    <head><title>تقرير المسح الأمني</title></head>
    <body style="font-family: Arial; direction: rtl;">
    <h1>📋 تقرير المسح الأمني</h1>
    <p><b>تاريخ الإنشاء:</b> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <hr>
    """

    for result in results:
        html += f"""
        <h2>🎯 الهدف: {result['host']}</h2>
        <p><b>المنفذ:</b> {result['port']}/{result['protocol']}</p>
        <p><b>الخدمة:</b> {result['service']}</p>
        <ul>
        """
        if result['cves']:
            for cve in result['cves']:
                html += f"<li><a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank'>{cve}</a></li>"
        else:
            html += "<li>✅ لا توجد ثغرات معروفة</li>"
        html += "</ul><hr>"

    html += "</body></html>"

    with open(HTML_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ تم إنشاء تقرير: {HTML_REPORT_PATH}")
    webbrowser.open(f"file://{os.path.abspath(HTML_REPORT_PATH)}")

# البرنامج الرئيسي
if __name__ == "__main__":
    target = input("🌐 أدخل عنوان IP الهدف لفحصه: ")
    results = scan_target(target)
    generate_html_report(results)
