#!/usr/bin/env python3
import dpkt
import socket
import argparse
import os
import time
from collections import defaultdict
import geoip2.database
import pandas as pd
import warnings
import multiprocessing
from tqdm import tqdm
import logging
import zlib
import hashlib
import re
import json
from datetime import datetime
import math
import sys
import readline  # For better input handling

# Suppress warnings
warnings.filterwarnings("ignore")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pcap_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PCAPAnalyzer:
    def __init__(self, config=None):
        self.config = config or self.get_default_config()
        self.results = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'port_scans': defaultdict(int),
            'ddos_attempts': defaultdict(int),
            'suspicious_tls': [],
            'data_exfiltration': [],
            'malware_c2': [],
            'geoip_info': defaultdict(dict),
            'protocol_stats': defaultdict(int),
            'connection_stats': defaultdict(int),
            'dns_queries': defaultdict(int),
            'http_requests': defaultdict(int),
            'anomalies': [],
            'user_settings': {}
        }
        self.load_threat_intel()
        self.geoip_reader = self.init_geoip()
        self.file_stats = {}
        
    def get_default_config(self):
        """Get default configuration with user input"""
        config = {
            'MAX_FILE_SIZE': self.get_user_input(
                "Enter maximum file size to analyze (in GB)", 
                default=20,
                input_type=float) * 1024 * 1024 * 1024,
            'KNOWN_MALICIOUS_IPS': self.get_user_input(
                "Path to malicious IPs file",
                default='data/malicious_ips.txt'),
            'KNOWN_MALICIOUS_DOMAINS': self.get_user_input(
                "Path to malicious domains file",
                default='data/malicious_domains.txt'),
            'SUSPICIOUS_PORTS': self.get_user_input(
                "Enter suspicious ports (comma separated)",
                default="22,23,80,443,445,3389,5900,8080",
                process_func=lambda x: [int(p.strip()) for p in x.split(',')]),
            'GEOIP_DATABASE': self.get_user_input(
                "Path to GeoIP database",
                default='data/GeoLite2-Country.mmdb'),
            'THREAT_INTEL_API': self.get_user_input(
                "Threat intelligence API endpoint",
                default='https://api.threatintelplatform.com/v1/check'),
            'API_KEY': self.get_user_input(
                "API key for threat intelligence",
                default='your_api_key_here',
                sensitive=True),
            'WORKER_PROCESSES': self.get_user_input(
                "Number of worker processes to use",
                default=max(1, multiprocessing.cpu_count() - 1),
                input_type=int),
            'OUTPUT_FORMAT': self.get_user_input(
                "Output format (json/csv)",
                default='json',
                options=['json', 'csv']),
            'VERBOSE_LOGGING': self.get_user_input(
                "Enable verbose logging? (y/n)",
                default='n',
                options=['y', 'n'],
                process_func=lambda x: x.lower() == 'y')
        }
        return config

    def get_user_input(self, prompt, default=None, input_type=str, options=None, process_func=None, sensitive=False):
        """Get interactive user input with validation"""
        while True:
            try:
                # Build the prompt
                full_prompt = prompt
                if default is not None:
                    if sensitive and default != '':
                        full_prompt += f" [default: *******]: "
                    else:
                        full_prompt += f" [default: {default}]: "
                else:
                    full_prompt += ": "
                
                # Get input
                user_input = input(full_prompt).strip()
                
                # Use default if input is empty
                if not user_input and default is not None:
                    user_input = default
                
                # Validate against options if provided
                if options and user_input not in options:
                    print(f"Invalid option. Must be one of: {', '.join(options)}")
                    continue
                
                # Convert type if needed
                if input_type and not isinstance(user_input, input_type):
                    try:
                        user_input = input_type(user_input)
                    except ValueError:
                        print(f"Invalid input. Must be of type {input_type.__name__}.")
                        continue
                
                # Apply processing function if provided
                if process_func:
                    user_input = process_func(user_input)
                
                return user_input
            
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
                sys.exit(0)
            except Exception as e:
                print(f"Error: {e}. Please try again.")

    def configure_analysis(self):
        """Allow user to configure analysis parameters"""
        print("\nAnalysis Configuration")
        print("=====================")
        
        # Configure detection thresholds
        self.config['PORT_SCAN_THRESHOLD'] = self.get_user_input(
            "Port scan detection threshold (connections per IP)",
            default=10,
            input_type=int)
        
        self.config['DDoS_THRESHOLD'] = self.get_user_input(
            "DDoS detection threshold (SYN packets per IP)",
            default=50,
            input_type=int)
        
        self.config['DATA_EXFIL_THRESHOLD'] = self.get_user_input(
            "Data exfiltration size threshold (bytes)",
            default=1024,
            input_type=int)
        
        self.config['C2_CONNECTION_THRESHOLD'] = self.get_user_input(
            "C2 server connection threshold",
            default=50,
            input_type=int)
        
        # Enable/disable specific detection modules
        self.config['ENABLE_GEOIP'] = self.get_user_input(
            "Enable GeoIP lookups? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['ENABLE_THREAT_INTEL'] = self.get_user_input(
            "Enable threat intelligence lookups? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['ENABLE_DGA_DETECTION'] = self.get_user_input(
            "Enable DGA domain detection? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        # Store user settings in results
        self.results['user_settings'] = {
            'port_scan_threshold': self.config['PORT_SCAN_THRESHOLD'],
            'ddos_threshold': self.config['DDoS_THRESHOLD'],
            'data_exfil_threshold': self.config['DATA_EXFIL_THRESHOLD'],
            'c2_threshold': self.config['C2_CONNECTION_THRESHOLD'],
            'geoip_enabled': self.config['ENABLE_GEOIP'],
            'threat_intel_enabled': self.config['ENABLE_THREAT_INTEL'],
            'dga_detection_enabled': self.config['ENABLE_DGA_DETECTION']
        }

    def load_threat_intel(self):
        """Load threat intelligence data from files"""
        if not self.config.get('ENABLE_THREAT_INTEL', True):
            self.malicious_ips = set()
            self.malicious_domains = set()
            return
            
        try:
            # Load malicious IPs
            ip_file = self.config['KNOWN_MALICIOUS_IPS']
            if os.path.exists(ip_file):
                with open(ip_file, 'r') as f:
                    self.malicious_ips = set(line.strip() for line in f if line.strip())
            else:
                logger.warning(f"Malicious IPs file not found: {ip_file}")
                self.malicious_ips = set()
            
            # Load malicious domains
            domain_file = self.config['KNOWN_MALICIOUS_DOMAINS']
            if os.path.exists(domain_file):
                with open(domain_file, 'r') as f:
                    self.malicious_domains = set(line.strip().lower() for line in f if line.strip())
            else:
                logger.warning(f"Malicious domains file not found: {domain_file}")
                self.malicious_domains = set()
        except Exception as e:
            logger.error(f"Error loading threat intelligence: {e}")
            self.malicious_ips = set()
            self.malicious_domains = set()

    def init_geoip(self):
        """Initialize GeoIP database"""
        if not self.config.get('ENABLE_GEOIP', True):
            return None
            
        try:
            geoip_db = self.config['GEOIP_DATABASE']
            if os.path.exists(geoip_db):
                return geoip2.database.Reader(geoip_db)
            else:
                logger.warning(f"GeoIP database not found: {geoip_db}")
                return None
        except Exception as e:
            logger.error(f"Error initializing GeoIP database: {e}")
            return None

    def get_file_stats(self, pcap_file):
        """Get PCAP file statistics"""
        stats = {
            'file_size': os.path.getsize(pcap_file),
            'file_hash': self.calculate_file_hash(pcap_file),
            'modified_time': datetime.fromtimestamp(os.path.getmtime(pcap_file)).strftime('%Y-%m-%d %H:%M:%S')
        }
        return stats

    def calculate_file_hash(self, file_path):
        """Calculate file hash (SHA256)"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def analyze(self, pcap_file):
        """Main analysis function"""
        self.pcap_file = pcap_file
        self.file_stats = self.get_file_stats(pcap_file)
        
        try:
            if self.file_stats['file_size'] > self.config['MAX_FILE_SIZE']:
                size_gb = self.file_stats['file_size']/1024/1024/1024
                max_gb = self.config['MAX_FILE_SIZE']/1024/1024/1024
                logger.warning(f"File size {size_gb:.2f}GB exceeds maximum limit of {max_gb:.2f}GB")
                return False

            logger.info(f"Starting analysis of {pcap_file} (Size: {self.file_stats['file_size']/1024/1024:.2f}MB)")
            
            # Ask user which analysis modules to run
            self.select_analysis_modules()
            
            # Use multiprocessing for large files
            if self.file_stats['file_size'] > 100 * 1024 * 1024:  # 100MB
                self.analyze_large_pcap()
            else:
                self.analyze_small_pcap()
            
            self.post_analysis()
            return True
        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
            return False

    def select_analysis_modules(self):
        """Let user select which analysis modules to run"""
        print("\nSelect Analysis Modules")
        print("======================")
        
        self.config['RUN_PORT_SCAN_ANALYSIS'] = self.get_user_input(
            "Run port scan analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['RUN_DDoS_ANALYSIS'] = self.get_user_input(
            "Run DDoS analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['RUN_DATA_EXFIL_ANALYSIS'] = self.get_user_input(
            "Run data exfiltration analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['RUN_C2_ANALYSIS'] = self.get_user_input(
            "Run C2 server analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['RUN_DNS_ANALYSIS'] = self.get_user_input(
            "Run DNS analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')
        
        self.config['RUN_HTTP_ANALYSIS'] = self.get_user_input(
            "Run HTTP analysis? (y/n)",
            default='y',
            options=['y', 'n'],
            process_func=lambda x: x.lower() == 'y')

    def analyze_small_pcap(self):
        """Analyze small PCAP files (<= 100MB)"""
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                self.process_packet(ts, buf)

    def analyze_large_pcap(self):
        """Analyze large PCAP files using multiprocessing"""
        logger.info("Using multiprocessing for large file analysis")
        
        # Split the pcap into chunks
        chunks = self.split_pcap()
        
        # Process chunks in parallel
        with multiprocessing.Pool(processes=self.config['WORKER_PROCESSES']) as pool:
            results = list(tqdm(pool.imap(self.process_chunk, chunks), total=len(chunks), desc="Processing PCAP chunks"))
        
        # Merge results
        for result in results:
            self.merge_results(result)

    def split_pcap(self):
        """Split PCAP file into chunks for parallel processing"""
        chunk_size = 100 * 1024 * 1024  # 100MB chunks
        chunks = []
        with open(self.pcap_file, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
        return chunks

    def process_chunk(self, chunk):
        """Process a chunk of PCAP data"""
        chunk_results = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'port_scans': defaultdict(int),
            'ddos_attempts': defaultdict(int),
            'suspicious_tls': [],
            'data_exfiltration': [],
            'malware_c2': [],
            'geoip_info': defaultdict(dict),
            'protocol_stats': defaultdict(int),
            'connection_stats': defaultdict(int),
            'dns_queries': defaultdict(int),
            'http_requests': defaultdict(int),
            'anomalies': []
        }
        
        try:
            pcap = dpkt.pcap.Reader(chunk)
            for ts, buf in pcap:
                self.process_packet(ts, buf, chunk_results)
        except Exception as e:
            logger.error(f"Error processing chunk: {e}")
        
        return chunk_results

    def merge_results(self, chunk_results):
        """Merge results from chunk processing"""
        for key in chunk_results:
            if isinstance(chunk_results[key], (set, list)):
                self.results[key].update(chunk_results[key])
            elif isinstance(chunk_results[key], defaultdict):
                for k, v in chunk_results[key].items():
                    self.results[key][k] += v

    def process_packet(self, ts, buf, results=None):
        """Process individual packet"""
        if results is None:
            results = self.results
        
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                return
            
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            
            # Check for malicious IPs
            if self.config.get('ENABLE_THREAT_INTEL', True):
                self.check_malicious_ips(src_ip, dst_ip, results)
            
            # Get GeoIP information
            if self.config.get('ENABLE_GEOIP', True):
                self.get_geoip_info(src_ip, dst_ip, results)
            
            # Protocol statistics
            protocol = ip.p
            results['protocol_stats'][protocol] += 1
            
            # Check for port scans and suspicious ports
            if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                transport = ip.data
                src_port = transport.sport
                dst_port = transport.dport
                
                if dst_port in self.config['SUSPICIOUS_PORTS']:
                    results['connection_stats'][(src_ip, src_port, dst_ip, dst_port)] += 1
                
                # Check for port scans
                if self.config.get('RUN_PORT_SCAN_ANALYSIS', True):
                    if transport.sport > 32768 and transport.dport < 1024:
                        results['port_scans'][src_ip] += 1
                
                # Process TCP-specific features
                if isinstance(transport, dpkt.tcp.TCP):
                    self.process_tcp(ts, ip, transport, results)
                
                # Process UDP-specific features
                elif isinstance(transport, dpkt.udp.UDP):
                    self.process_udp(ip, transport, results)
            
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def process_tcp(self, ts, ip, tcp, results):
        """Process TCP packet"""
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        # Check for SYN flood (DDoS)
        if self.config.get('RUN_DDoS_ANALYSIS', True):
            if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
                results['ddos_attempts'][src_ip] += 1
        
        # Check for data exfiltration
        if self.config.get('RUN_DATA_EXFIL_ANALYSIS', True):
            if len(tcp.data) > self.config.get('DATA_EXFIL_THRESHOLD', 1024):
                results['data_exfiltration'].append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'size': len(tcp.data),
                    'sport': tcp.sport,
                    'dport': tcp.dport
                })
        
        # Process HTTP traffic
        if self.config.get('RUN_HTTP_ANALYSIS', True):
            if tcp.dport == 80 or tcp.sport == 80:
                self.process_http(tcp.data, results)
        
        # Process HTTPS/TLS traffic
        if tcp.dport == 443 or tcp.sport == 443:
            self.process_tls(tcp.data, results)

    def process_udp(self, ip, udp, results):
        """Process UDP packet"""
        # Process DNS traffic
        if self.config.get('RUN_DNS_ANALYSIS', True):
            if udp.dport == 53 or udp.sport == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q:
                        for q in dns.qd:
                            domain = q.name.lower()
                            results['dns_queries'][domain] += 1
                            
                            # Check for malicious domains
                            if domain in self.malicious_domains:
                                results['malicious_domains'].add(domain)
                            
                            # Check for DGA-like domains
                            if self.config.get('ENABLE_DGA_DETECTION', True):
                                if self.is_dga_domain(domain):
                                    results['anomalies'].append({
                                        'type': 'DGA-like domain',
                                        'domain': domain,
                                        'src_ip': socket.inet_ntoa(ip.src)
                                    })
                except:
                    pass

    def process_http(self, data, results):
        """Process HTTP traffic"""
        try:
            http = dpkt.http.Request(data)
            results['http_requests'][http.uri] += 1
            
            # Check for suspicious URIs
            if self.is_malicious_uri(http.uri):
                results['anomalies'].append({
                    'type': 'Suspicious HTTP URI',
                    'uri': http.uri,
                    'headers': dict(http.headers)
                })
        except:
            pass

    def process_tls(self, data, results):
        """Process TLS/SSL traffic"""
        try:
            # Check for self-signed certificates or suspicious TLS patterns
            if b'\x00\x00\x00\x00' in data:  # Simple heuristic for suspicious TLS
                results['suspicious_tls'].append({
                    'data': data[:100].hex()  # Store first 100 bytes as hex
                })
        except:
            pass

    def check_malicious_ips(self, src_ip, dst_ip, results):
        """Check if IPs are in malicious IP list"""
        if src_ip in self.malicious_ips:
            results['malicious_ips'].add(src_ip)
        if dst_ip in self.malicious_ips:
            results['malicious_ips'].add(dst_ip)

    def get_geoip_info(self, src_ip, dst_ip, results):
        """Get GeoIP information for IP addresses"""
        if self.geoip_reader:
            try:
                if src_ip not in results['geoip_info']:
                    response = self.geoip_reader.country(src_ip)
                    results['geoip_info'][src_ip] = {
                        'country': response.country.name,
                        'iso_code': response.country.iso_code
                    }
                
                if dst_ip not in results['geoip_info']:
                    response = self.geoip_reader.country(dst_ip)
                    results['geoip_info'][dst_ip] = {
                        'country': response.country.name,
                        'iso_code': response.country.iso_code
                    }
            except:
                pass

    def is_dga_domain(self, domain):
        """Check if domain appears to be DGA-generated"""
        # Simple heuristic for DGA detection
        if len(domain) > 30:
            return True
        
        # Check for high entropy
        if self.calculate_entropy(domain) > 3.5:
            return True
        
        # Check for numeric domains
        if re.match(r'^[a-z0-9]{16,}\.(com|net|org)$', domain):
            return True
        
        return False

    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def is_malicious_uri(self, uri):
        """Check if URI appears malicious"""
        suspicious_patterns = [
            r'\.exe$', r'\.dll$', r'\.bat$', r'\.ps1$', 
            r'cmd\.exe', r'powershell', r'/admin/', r'/wp-content/',
            r'\.php\?', r'\.asp\?', r'select%20', r'union%20select',
            r'exec%20', r'xss', r'sql', r'javascript:'
        ]
        
        uri_lower = uri.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, uri_lower):
                return True
        return False

    def post_analysis(self):
        """Perform post-analysis tasks"""
        # Identify potential C2 servers
        if self.config.get('RUN_C2_ANALYSIS', True):
            self.identify_c2_servers()
        
        # Generate summary statistics
        self.generate_summary()
        
        # Check for beaconing behavior
        self.check_beaconing()

    def identify_c2_servers(self):
        """Identify potential C2 servers based on traffic patterns"""
        # Look for periodic connections to the same IP/port
        threshold = self.config.get('C2_CONNECTION_THRESHOLD', 50)
        for (src_ip, src_port, dst_ip, dst_port), count in self.results['connection_stats'].items():
            if count > threshold:
                self.results['malware_c2'].append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'connection_count': count,
                    'type': 'Potential C2 Communication'
                })

    def check_beaconing(self):
        """Check for beaconing behavior (regular intervals)"""
        # This would require more sophisticated time series analysis
        pass

    def generate_summary(self):
        """Generate summary statistics"""
        self.results['summary'] = {
            'total_packets': sum(self.results['protocol_stats'].values()),
            'malicious_ip_count': len(self.results['malicious_ips']),
            'malicious_domain_count': len(self.results['malicious_domains']),
            'port_scan_attempts': sum(self.results['port_scans'].values()),
            'ddos_attempts': sum(self.results['ddos_attempts'].values()),
            'data_exfiltration_attempts': len(self.results['data_exfiltration']),
            'suspicious_tls_count': len(self.results['suspicious_tls']),
            'c2_servers': len(self.results['malware_c2']),
            'anomalies': len(self.results['anomalies']),
            'analysis_settings': self.results['user_settings']
        }

    def save_results(self, output_format=None):
        """Save analysis results to file"""
        try:
            if output_format is None:
                output_format = self.config['OUTPUT_FORMAT']
                
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(self.pcap_file))[0]
            output_file = f"pcap_analysis_{base_name}_{timestamp}"
            
            if output_format == 'json':
                with open(f"{output_file}.json", 'w') as f:
                    json.dump(self.results, f, indent=2)
            elif output_format == 'csv':
                # Convert relevant results to DataFrames and save as CSV
                self.save_results_as_csv(output_file)
            else:
                logger.error(f"Unsupported output format: {output_format}")
                return False
            
            logger.info(f"Results saved to {output_file}.{output_format}")
            return True
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            return False

    def save_results_as_csv(self, output_file):
        """Save results as multiple CSV files"""
        # Save malicious IPs
        if self.results['malicious_ips']:
            pd.DataFrame(list(self.results['malicious_ips']), columns=['ip']).to_csv(f"{output_file}_malicious_ips.csv", index=False)
        
        # Save port scans
        if self.results['port_scans']:
            pd.DataFrame(self.results['port_scans'].items(), columns=['ip', 'count']).to_csv(f"{output_file}_port_scans.csv", index=False)
        
        # Save DNS queries
        if self.results['dns_queries']:
            pd.DataFrame(self.results['dns_queries'].items(), columns=['domain', 'count']).to_csv(f"{output_file}_dns_queries.csv", index=False)
        
        # Save HTTP requests
        if self.results['http_requests']:
            pd.DataFrame(self.results['http_requests'].items(), columns=['uri', 'count']).to_csv(f"{output_file}_http_requests.csv", index=False)
        
        # Save anomalies
        if self.results['anomalies']:
            pd.DataFrame(self.results['anomalies']).to_csv(f"{output_file}_anomalies.csv", index=False)

    def print_summary(self):
        """Print summary of findings to console"""
        print("\nPCAP Analysis Summary")
        print("====================")
        print(f"File: {self.pcap_file}")
        print(f"Size: {self.file_stats['file_size']/1024/1024:.2f} MB")
        print(f"Hash: {self.file_stats['file_hash']}")
        print(f"Modified: {self.file_stats['modified_time']}")
        
        summary = self.results.get('summary', {})
        print("\nKey Findings:")
        print(f"- Malicious IPs detected: {summary.get('malicious_ip_count', 0)}")
        print(f"- Malicious domains detected: {summary.get('malicious_domain_count', 0)}")
        print(f"- Port scan attempts: {summary.get('port_scan_attempts', 0)}")
        print(f"- DDoS attempts: {summary.get('ddos_attempts', 0)}")
        print(f"- Data exfiltration attempts: {summary.get('data_exfiltration_attempts', 0)}")
        print(f"- Suspicious TLS connections: {summary.get('suspicious_tls_count', 0)}")
        print(f"- Potential C2 servers: {summary.get('c2_servers', 0)}")
        print(f"- Anomalies detected: {summary.get('anomalies', 0)}")
        
        # Print user settings
        if 'analysis_settings' in summary:
            print("\nAnalysis Settings:")
            for k, v in summary['analysis_settings'].items():
                print(f"- {k.replace('_', ' ').title()}: {v}")

def interactive_mode():
    """Run in interactive mode with menus"""
    print("PCAP Analysis Tool - Interactive Mode")
    print("====================================")
    
    # Get PCAP file
    while True:
        pcap_file = input("Enter path to PCAP file: ").strip()
        if os.path.exists(pcap_file):
            break
        print("File not found. Please try again.")
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer()
    
    # Main menu
    while True:
        print("\nMain Menu")
        print("---------")
        print("1. Configure analysis parameters")
        print("2. Select analysis modules")
        print("3. Run analysis")
        print("4. View results")
        print("5. Save results")
        print("6. Exit")
        
        choice = input("Select an option (1-6): ").strip()
        
        if choice == '1':
            analyzer.configure_analysis()
        elif choice == '2':
            analyzer.select_analysis_modules()
        elif choice == '3':
            start_time = time.time()
            if analyzer.analyze(pcap_file):
                elapsed = time.time() - start_time
                print(f"\nAnalysis completed in {elapsed:.2f} seconds")
            else:
                print("\nAnalysis failed")
        elif choice == '4':
            if 'summary' in analyzer.results:
                analyzer.print_summary()
            else:
                print("No results available. Please run analysis first.")
        elif choice == '5':
            if 'summary' in analyzer.results:
                output_format = input("Enter output format (json/csv) [default: json]: ").strip().lower()
                if output_format not in ['json', 'csv']:
                    output_format = 'json'
                analyzer.save_results(output_format)
            else:
                print("No results available to save. Please run analysis first.")
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    parser = argparse.ArgumentParser(description="Advanced PCAP Malicious Event Analysis Tool")
    parser.add_argument("pcap_file", nargs='?', help="Path to the PCAP file to analyze")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], help="Output format (json/csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if args.interactive:
        interactive_mode()
        return
    
    if not args.pcap_file:
        print("Error: PCAP file path required in non-interactive mode")
        parser.print_help()
        return
    
    if not os.path.exists(args.pcap_file):
        logger.error(f"File not found: {args.pcap_file}")
        return
    
    start_time = time.time()
    analyzer = PCAPAnalyzer()
    
    if analyzer.analyze(args.pcap_file):
        analyzer.print_summary()
        analyzer.save_results(args.output)
        
        elapsed = time.time() - start_time
        logger.info(f"Analysis completed in {elapsed:.2f} seconds")
    else:
        logger.error("Analysis failed")

if __name__ == "__main__":
    main()
