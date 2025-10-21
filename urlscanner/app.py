import os
import requests
import time
import base64
import socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

# --- API Keys Configuration ---
GOOGLE_API_KEY = "YOUR API KEY"
VT_API_KEY = "YOUR API KEY"
URLHAUS_API_KEY = "YOUR API KEY"
ABUSEIPDB_API_KEY = "YOUR API KEY"

# --- Endpoint Configuration ---
GSB_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
VT_API_URL = "https://www.virustotal.com/api/v3/urls"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

app = Flask(__name__)

# --- VENDOR Exception Functions ---
# Google Safe Browsing
def check_google_safebrowsing(url_to_check):
    payload = {
        "client": {"clientId": "url-checker-pribadi", "clientVersion": "3.0"},
        "threatInfo": {
            "threatTypes":  ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    try:
        response = requests.post(GSB_API_URL, json=payload, timeout=10)
        if response.status_code == 200 and 'matches' in response.json():
            details = {"Jenis Ancaman": response.json()['matches'][0]['threatType']}
            return {"status": "malicious", "vendor": "Google Safe Browsing", "details": details}
        return {"status": "clean", "vendor": "Google Safe Browsing", "details": {}}
    except requests.exceptions.RequestException:
        return {"status": "error", "vendor": "Google Safe Browsing", "details": {"Error": "Koneksi ke API gagal."}}

# VirusTotal
def check_virustotal(url_to_check):
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    report_url = f"{VT_API_URL}/{url_id}"
    try:
        response = requests.get(report_url, headers=headers, timeout=10)
        if response.status_code == 404:
            scan_payload = {"url": url_to_check}
            requests.post(VT_API_URL, headers=headers, data=scan_payload, timeout=10)
            return {"status": "pending_analysis", "vendor": "VirusTotal", "details": {"Info": "URL baru dikirim untuk analisis."}}
        elif response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            details = {"Ringkasan": f"{malicious_count} malicious, {suspicious_count} suspicious"}

            if malicious_count > 0 or suspicious_count > 0:
                malicious_scanners = []
                # Get scanner name
                for scanner, scan_result in attributes.get("last_analysis_results", {}).items():
                    category = scan_result.get("category")
                    if category == "malicious":
                        # Add spesific result
                        scanner_detail = f"{scanner} ({scan_result.get('result', 'N/A')})"
                        malicious_scanners.append(scanner_detail)

                if malicious_scanners:
                    details["Deteksi Berbahaya"] = ", ".join(malicious_scanners)

                return {"status": "malicious", "vendor": "VirusTotal", "details": details}
            else:
                return {"status": "clean", "vendor": "VirusTotal", "details": {}}
        else:
            return {"status": "error", "vendor": "VirusTotal", "details": {"Error": f"HTTP Status {response.status_code}"}}
    except requests.exceptions.RequestException:
        return {"status": "error", "vendor": "VirusTotal", "details": {"Error": "Koneksi ke API gagal."}}

# URLhaus
def check_urlhaus(url_to_check):
    headers = {'Auth-Key': URLHAUS_API_KEY}
    data = {'url': url_to_check}
    try:
        response = requests.post(URLHAUS_API_URL, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get('query_status') == 'ok':
                details = {
                    "Jenis Ancaman": json_response.get('threat'),
                    "Tags": ", ".join(json_response.get('tags', [])),
                    "Status URL": json_response.get('url_status'),
                    "Pelapor": json_response.get('reporter')
                }
                return {"status": "malicious", "vendor": "URLhaus", "details": details}
            elif json_response.get('query_status') == 'no_results':
                return {"status": "clean", "vendor": "URLhaus", "details": {}}
        return {"status": "error", "vendor": "URLhaus", "details": {"Error": f"HTTP Status {response.status_code}"}}
    except requests.exceptions.RequestException:
        return {"status": "error", "vendor": "URLhaus", "details": {"Error": "Koneksi ke API gagal."}}

# AbuseIPDB
def check_abuseipdb(url_to_check):
    try:
        hostname = urlparse(url_to_check).hostname
        if not hostname:
            return {"status": "error", "vendor": "AbuseIPDB", "details": {"Error": "Hostname tidak valid"}}
        ip_address = socket.gethostbyname(hostname)

        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''}

        response = requests.get(url=ABUSEIPDB_API_URL, headers=headers, params=querystring, timeout=10)

        if response.status_code == 200:
            data = response.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            details = {
                "Skor IP": f"{score}/100",
                "Total Laporan": data.get('totalReports', 0),
                "Negara": data.get('countryName', 'N/A'),
                "ISP": data.get('isp', 'N/A'),
                "Tipe Penggunaan": data.get('usageType', 'N/A')
            }
            if score >= 75:
                return {"status": "malicious", "vendor": "AbuseIPDB", "details": details}
            else:
                return {"status": "clean", "vendor": "AbuseIPDB", "details": details}
        else:
            return {"status": "error", "vendor": "AbuseIPDB", "details": {"Error": f"HTTP Status {response.status_code}"}}
    except socket.gaierror:
        return {"status": "error", "vendor": "AbuseIPDB", "details": {"Error": "Domain tidak ditemukan"}}
    except requests.exceptions.RequestException:
        return {"status": "error", "vendor": "AbuseIPDB", "details": {"Error": "Koneksi ke API gagal."}}

# --- Main Endpoint ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-url', methods=['POST'])
def check_url():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "URL tidak ditemukan dalam permintaan"}), 400

    api_functions = [
        check_google_safebrowsing,
        check_virustotal,
       check_urlhaus
    ]
    if ABUSEIPDB_API_KEY and ABUSEIPDB_API_KEY != "PASTE_ABUSEIPDB_API_KEY_ANDA_DI_SINI":
        api_functions.append(check_abuseipdb)

    results = [func(url) for func in api_functions]
    
    score = sum(1 for res in results if res.get("status") == "malicious")

    return jsonify({
        "url": url,
        "score": score,
        "total_vendors": len(results),
        "details": results
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
