<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
 
</head>
<body>
    <h1>Advanced PCAP Analysis Tool</h1>
    
        
    
   <p>An advanced network traffic analysis tool for SOC analysts that examines PCAP files for malicious activity, with interactive configuration and comprehensive reporting.</p>

   <h2 id="table-of-contents">📌 Table of Contents</h2>
    <ul>
        <li><a href="#overview">Overview</a></li>
        <li><a href="#key-features">Key Features</a></li>
        <li><a href="#installation-guide">Installation Guide</a></li>
        <li><a href="#usage-instructions">Usage Instructions</a></li>
        <li><a href="#configuration--customization">Configuration & Customization</a></li>
        <li><a href="#sample-reports--output-formats">Sample Reports & Output Formats</a></li>
        <li><a href="#dependencies--requirements">Dependencies & Requirements</a></li>
        <li><a href="#project-structure">Project Structure</a></li>
        <li><a href="#contributing-guidelines">Contributing Guidelines</a></li>
        <li><a href="#troubleshooting--support">Troubleshooting & Support</a></li>
        <li><a href="#license">License</a></li>
    </ul>

   <h2 id="overview">🔍 Overview</h2>
    <p>This <strong>PCAP Analysis Tool</strong> is designed for <strong>SOC Analysts, Threat Hunters, and Network Security Professionals</strong> to analyze network traffic captures (<code>.pcap</code> files) for malicious activity.</p>
    
  <ul>
        <li><strong>Detects</strong> malware C2 communications, port scans, DDoS attempts, data exfiltration, and more.</li>
        <li><strong>Supports</strong> interactive and command-line modes for flexibility.</li>
        <li><strong>Generates</strong> detailed reports in <strong>JSON</strong> and <strong>CSV</strong> formats.</li>
        <li><strong>Integrates</strong> with threat intelligence feeds (custom IP/domain blacklists, GeoIP).</li>
    </ul>

   <h2 id="key-features">✨ Key Features</h2>
    
  <h3>1. Malicious Traffic Detection</h3>
    <p>✅ <strong>Malicious IPs & Domains</strong> – Checks against custom threat lists.<br>
    ✅ <strong>Port Scans & DDoS Attempts</strong> – Identifies suspicious connection patterns.<br>
    ✅ <strong>C2 Communication</strong> – Detects beaconing and command-and-control traffic.<br>
    ✅ <strong>Data Exfiltration</strong> – Flags large, unusual data transfers.</p>
    
   <h3>2. Interactive & Automated Modes</h3>
    <p>🖥 <strong>Interactive CLI</strong> – Guided analysis with menus and prompts.<br>
    ⚡ <strong>Command-Line Mode</strong> – Scriptable for automation.</p>
    
  <h3>3. Threat Intelligence Integration</h3>
    <p>🌍 <strong>GeoIP Lookups</strong> – Maps IPs to countries (requires MaxMind DB).<br>
    📜 <strong>Custom Blacklists</strong> – Load known malicious IPs/domains from files.</p>
    
   <h3>4. Reporting & Output</h3>
    <p>📊 <strong>JSON Reports</strong> – Structured data for further analysis.<br>
    📋 <strong>CSV Export</strong> – Compatible with SIEMs and spreadsheets.</p>

  <h2 id="installation-guide">📥 Installation Guide</h2>
    
   <h3>1. Clone the Repository</h3>
    <pre><code>https://github.com/7yr4nT/pcap-analyst.git
cd pcap-analyst</code></pre>
    
   <h3>2. Install Dependencies</h3>
    <pre><code>pip install -r requirements.txt</code></pre>
    
  <h3>3. Set Up GeoIP Database</h3>
    <ol>
        <li>Download <strong>GeoLite2-Country.mmdb</strong> from <a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data">MaxMind</a>.</li>
        <li>Place it in the <code>data/</code> directory.</li>
    </ol>
    
   <h3>4. Configure Threat Intel Feeds (Optional)</h3>
    <ul>
        <li>Edit <code>data/malicious_ips.txt</code> and <code>data/malicious_domains.txt</code> to add known bad IPs/domains.</li>
    </ul>

  <h2 id="usage-instructions">🚀 Usage Instructions</h2>
    
   <h3>1. Interactive Mode (Recommended for Beginners)</h3>
    <pre><code>python pcap_analyzer.py -i</code></pre>
    <p>Follow the on-screen prompts to configure and run the analysis.</p>
    
  <h3>2. Command-Line Mode (For Automation)</h3>
    <pre><code>python pcap_analyzer.py samples/suspicious_traffic.pcap -o json -v</code></pre>
    
   <h4>Arguments:</h4>
    <table>
        <thead>
            <tr>
                <th>Flag</th>
                <th>Description</th>
                <th>Example</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><code>-i</code></td>
                <td>Interactive mode</td>
                <td><code>python pcap_analyzer.py -i</code></td>
            </tr>
            <tr>
                <td><code>-o</code></td>
                <td>Output format (<code>json</code>/<code>csv</code>)</td>
                <td><code>-o csv</code></td>
            </tr>
            <tr>
                <td><code>-v</code></td>
                <td>Verbose logging (debug mode)</td>
                <td><code>-v</code></td>
            </tr>
        </tbody>
    </table>

  <h2 id="configuration--customization">⚙️ Configuration & Customization</h2>
    
  <h3>1. Custom Detection Thresholds</h3>
    <p>You can adjust sensitivity in the <strong>interactive mode</strong> or modify the code:</p>
    <pre><code class="language-python"># Example: Changing port scan threshold
self.config['PORT_SCAN_THRESHOLD'] = 15  # Default: 10</code></pre>
    
  <h3>2. Adding Custom Threat Intel Sources</h3>
    <p>Edit:</p>
    <ul>
        <li><code>data/malicious_ips.txt</code> (One IP per line)</li>
        <li><code>data/malicious_domains.txt</code> (One domain per line)</li>
    </ul>
    
  <h3>3. Enabling/Disabling Modules</h3>
    <p>In <strong>interactive mode</strong>, you can select which detections to run.</p>

  <h2 id="sample-reports--output-formats">📊 Sample Reports & Output Formats</h2>
    
  <h3>JSON Report Example</h3>
    <pre><code class="language-json">{
  "summary": {
    "total_packets": 12456,
    "malicious_ip_count": 3,
    "port_scan_attempts": 12,
    "ddos_attempts": 5
  },
  "malicious_ips": ["192.168.1.100", "10.0.0.15"],
  "geoip_info": {
    "192.168.1.100": {
      "country": "United States",
      "iso_code": "US"
    }
  }
}</code></pre>
    
  <h3>CSV Export Example</h3>
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>Count</th>
                <th>Country</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>192.168.1.100</td>
                <td>15</td>
                <td>US</td>
            </tr>
            <tr>
                <td>10.0.0.15</td>
                <td>8</td>
                <td>RU</td>
            </tr>
        </tbody>
    </table>

   <h2 id="dependencies--requirements">📦 Dependencies & Requirements</h2>
    
  <h3>Python 3.6+</h3>
    <p>Check your Python version:</p>
    <pre><code>python --version</code></pre>
    
  <h3>Required Libraries (<code>requirements.txt</code>)</h3>
    <pre><code>dpkt==1.9.7.2        # PCAP parsing
geoip2==4.6.0        # IP geolocation
pandas==1.3.5        # CSV export
tqdm==4.64.1         # Progress bars
python-dateutil==2.8.2  # Time handling
argcomplete==2.1.1   # CLI autocomplete
pyfiglet==0.8.post1  # Fancy banners (optional)</code></pre>
    
  <p>Install them with:</p>
    <pre><code>pip install -r requirements.txt</code></pre>

  <h2 id="project-structure">🗂 Project Structure</h2>
    <pre><code>pcap-analyzer/
│
├── pcap_analyzer.py       # Main script
├── README.md              # This guide
├── requirements.txt       # Dependencies
├── LICENSE                # MIT License
│
├── data/                  # Threat intel & GeoIP DB
│   ├── malicious_ips.txt
│   ├── malicious_domains.txt
│   └── GeoLite2-Country.mmdb
│
├── samples/               # Example PCAPs
│   ├── normal_traffic.pcap
│   └── malware_c2.pcap
│
└── tests/                 # Unit tests (optional)
    └── test_analysis.py</code></pre>

  <h2 id="contributing-guidelines">🤝 Contributing Guidelines</h2>
    <ol>
        <li><strong>Fork</strong> the repository.</li>
        <li><strong>Create a branch</strong> (<code>git checkout -b feature/new-detection</code>).</li>
        <li><strong>Commit changes</strong> (<code>git commit -m "Add XYZ feature"</code>).</li>
        <li><strong>Push</strong> (<code>git push origin feature/new-detection</code>).</li>
        <li><strong>Open a Pull Request</strong>.</li>
    </ol>

  <h2 id="troubleshooting--support">🛠 Troubleshooting & Support</h2>
    
   <h3>Common Issues</h3>
    <p>❌ <strong>"GeoIP database not found"</strong> → Download <code>GeoLite2-Country.mmdb</code> and place in <code>data/</code>.<br>
    ❌ <strong>"Missing dependencies"</strong> → Run <code>pip install -r requirements.txt</code>.</p>
    
 
   <h2>🚀 Ready to Analyze PCAPs?</h2>
    <pre><code>python pcap_analyzer.py -i</code></pre>
    <p>Happy hunting! 🕵️‍♂️🔍</p>
</body>
</html>
