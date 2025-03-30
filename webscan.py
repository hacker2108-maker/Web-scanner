#!/usr/bin/env python3

import os
import sys
import json
import socket
import argparse
import datetime
import subprocess
import dns.resolver
import requests
import whois
import concurrent.futures
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WebAnalyzer:
    def __init__(self, target, threads=10, output=None, timeout=10, verbose=False):
        self.target = self._format_target(target)
        self.domain = self._extract_domain(self.target)
        self.threads = threads
        self.output = output
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "domain": self.domain,
            "ip_addresses": [],
            "dns_records": {},
            "whois": {},
            "headers": {},
            "technologies": [],
            "subdomains": [],
            "open_ports": [],
            "vulnerabilities": []
        }
        
        # Ensure Termux DNS resolution works
        self._fix_resolv_conf()

    def _format_target(self, target):
        """Format the target URL properly"""
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        return target

    def _extract_domain(self, url):
        """Extract the domain name from the URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def _fix_resolv_conf(self):
        """Fix DNS resolution in Termux"""
        if not os.path.exists('/etc/resolv.conf'):
            try:
                # Check if we're in Termux
                if os.path.exists('/data/data/com.termux'):
                    print(f"{Fore.YELLOW}[*] Detected Termux environment, fixing DNS resolution...")
                    
                    # Create a resolv.conf file with Google DNS
                    with open('/data/data/com.termux/files/usr/tmp/resolv.conf', 'w') as f:
                        f.write("nameserver 8.8.8.8\n")
                        f.write("nameserver 8.8.4.4\n")
                    
                    # Set environment variable to use our custom resolv.conf
                    os.environ['RESOLV_CONF'] = '/data/data/com.termux/files/usr/tmp/resolv.conf'
                    
                    print(f"{Fore.GREEN}[+] DNS resolution fixed")
            except Exception as e:
                print(f"{Fore.RED}[-] Error fixing DNS resolution: {str(e)}")

    def run_scan(self):
        """Run the complete website analysis"""
        print(f"{Fore.CYAN}[*] Starting analysis of {self.target}")
        
        try:
            self._get_basic_info()
            self._get_dns_records()
            self._get_whois_info()
            self._get_headers()
            self._detect_technologies()
            self._find_subdomains()
            self._scan_ports()
            self._check_vulnerabilities()
            
            if self.output:
                self._save_report()
                
            self._print_summary()
            return self.results
            
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[!] Scan interrupted by user")
            if self.output:
                self._save_report()
            return self.results

    def _get_basic_info(self):
        """Get basic information about the target"""
        print(f"{Fore.BLUE}[*] Getting basic information...")
        
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["ip_addresses"].append(ip)
            print(f"{Fore.GREEN}[+] IP Address: {ip}")
        except socket.gaierror:
            print(f"{Fore.RED}[-] Error resolving hostname")

    def _get_dns_records(self):
        """Get DNS records for the domain"""
        print(f"{Fore.BLUE}[*] Getting DNS records...")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                # Use Google DNS servers
                resolver.nameservers = ['8.8.8.8', '8.8.4.4']
                answers = resolver.resolve(self.domain, record_type)
                
                if record_type not in self.results["dns_records"]:
                    self.results["dns_records"][record_type] = []
                
                for answer in answers:
                    if record_type == 'SOA':
                        data = str(answer.mname)
                    elif record_type == 'MX':
                        data = f"{answer.preference} {answer.exchange}"
                    else:
                        data = str(answer)
                    
                    self.results["dns_records"][record_type].append(data)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] {record_type} record: {data}")
            
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error getting {record_type} records: {str(e)}")

    def _get_whois_info(self):
        """Get WHOIS information for the domain"""
        print(f"{Fore.BLUE}[*] Getting WHOIS information...")
        
        try:
            w = whois.whois(self.domain)
            
            # Convert datetime objects to strings to make it JSON serializable
            whois_data = {}
            for key, value in w.items():
                if isinstance(value, datetime.datetime):
                    whois_data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(value, list) and value and isinstance(value[0], datetime.datetime):
                    whois_data[key] = [dt.strftime("%Y-%m-%d %H:%M:%S") for dt in value]
                else:
                    whois_data[key] = value
            
            self.results["whois"] = whois_data
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] WHOIS data retrieved successfully")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error getting WHOIS information: {str(e)}")

    def _get_headers(self):
        """Get HTTP headers of the target website"""
        print(f"{Fore.BLUE}[*] Getting HTTP headers...")
        
        try:
            response = requests.get(self.target, timeout=self.timeout)
            self.results["headers"] = dict(response.headers)
            
            if self.verbose:
                for header, value in response.headers.items():
                    print(f"{Fore.GREEN}[+] {header}: {value}")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error getting HTTP headers: {str(e)}")

    def _detect_technologies(self):
        """Detect technologies used by the website"""
        print(f"{Fore.BLUE}[*] Detecting technologies...")
        
        try:
            response = requests.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for common technologies
            tech_signatures = {
                'WordPress': [
                    {'type': 'meta', 'attribute': 'generator', 'value': 'WordPress'},
                    {'type': 'link', 'attribute': 'href', 'value': 'wp-content'},
                    {'type': 'script', 'attribute': 'src', 'value': 'wp-includes'},
                ],
                'Joomla': [
                    {'type': 'meta', 'attribute': 'generator', 'value': 'Joomla'},
                    {'type': 'script', 'attribute': 'src', 'value': 'media/jui'},
                ],
                'Drupal': [
                    {'type': 'meta', 'attribute': 'generator', 'value': 'Drupal'},
                    {'type': 'link', 'attribute': 'href', 'value': 'sites/all'},
                ],
                'Bootstrap': [
                    {'type': 'link', 'attribute': 'href', 'value': 'bootstrap'},
                    {'type': 'script', 'attribute': 'src', 'value': 'bootstrap'},
                ],
                'jQuery': [
                    {'type': 'script', 'attribute': 'src', 'value': 'jquery'},
                ],
                'React': [
                    {'type': 'script', 'attribute': 'src', 'value': 'react'},
                ],
                'Angular': [
                    {'type': 'script', 'attribute': 'src', 'value': 'angular'},
                    {'type': 'attribute', 'attribute': 'ng-app', 'value': ''},
                ],
                'Google Analytics': [
                    {'type': 'script', 'attribute': 'src', 'value': 'google-analytics.com'},
                    {'type': 'script', 'attribute': 'src', 'value': 'ga.js'},
                    {'type': 'script', 'attribute': 'src', 'value': 'analytics.js'},
                ],
                'Cloudflare': [
                    {'type': 'header', 'attribute': 'server', 'value': 'cloudflare'},
                ],
                'Nginx': [
                    {'type': 'header', 'attribute': 'server', 'value': 'nginx'},
                ],
                'Apache': [
                    {'type': 'header', 'attribute': 'server', 'value': 'apache'},
                ],
                'PHP': [
                    {'type': 'header', 'attribute': 'x-powered-by', 'value': 'php'},
                ],
            }
            
            for tech, signatures in tech_signatures.items():
                detected = False
                
                for sig in signatures:
                    if sig['type'] == 'meta':
                        metas = soup.find_all('meta', attrs={sig['attribute']: True})
                        for meta in metas:
                            if sig['value'].lower() in str(meta.get(sig['attribute'], '')).lower():
                                detected = True
                                break
                                
                    elif sig['type'] == 'link':
                        links = soup.find_all('link', attrs={sig['attribute']: True})
                        for link in links:
                            if sig['value'].lower() in str(link.get(sig['attribute'], '')).lower():
                                detected = True
                                break
                                
                    elif sig['type'] == 'script':
                        scripts = soup.find_all('script', attrs={sig['attribute']: True})
                        for script in scripts:
                            if sig['value'].lower() in str(script.get(sig['attribute'], '')).lower():
                                detected = True
                                break
                                
                    elif sig['type'] == 'attribute':
                        elements = soup.find_all(attrs={sig['attribute']: True})
                        if elements:
                            detected = True
                            
                    elif sig['type'] == 'header':
                        if sig['attribute'] in self.results["headers"] and \
                           sig['value'].lower() in str(self.results["headers"][sig['attribute']]).lower():
                            detected = True
                
                if detected and tech not in self.results["technologies"]:
                    self.results["technologies"].append(tech)
                    print(f"{Fore.GREEN}[+] Detected: {tech}")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error detecting technologies: {str(e)}")

    def _find_subdomains(self):
        """Find subdomains using DNS and brute force"""
        print(f"{Fore.BLUE}[*] Finding subdomains...")
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
            'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'portal',
            'm', 'support', 'admin', 'mx', 'email', 'cloud', 'login', 'shop',
            'ftp', 'cdn', 'app', 'wiki', 'docs', 'store', 'cms', 'cp'
        ]
        
        discovered = set()
        
        # Check if the TXT records contain any subdomains
        if 'TXT' in self.results["dns_records"]:
            for record in self.results["dns_records"]["TXT"]:
                for word in str(record).split():
                    if self.domain in word and word.startswith(('*.', '_')):
                        subdomain = word.lstrip('*.').strip('.')
                        if subdomain != self.domain and '.' + self.domain in subdomain:
                            discovered.add(subdomain)
        
        # Check DNS records for subdomains
        for record_type in ['NS', 'MX', 'CNAME']:
            if record_type in self.results["dns_records"]:
                for record in self.results["dns_records"][record_type]:
                    if self.domain in str(record):
                        parts = str(record).split()
                        for part in parts:
                            if self.domain in part and part != self.domain:
                                subdomain = part.rstrip('.')
                                if subdomain.endswith(self.domain) and subdomain != self.domain:
                                    discovered.add(subdomain)
        
        # Brute force common subdomains
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(self._check_subdomain, f"{sub}.{self.domain}"): sub for sub in common_subdomains}
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        discovered.add(f"{subdomain}.{self.domain}")
                except Exception:
                    pass
        
        # Add discovered subdomains to results
        for subdomain in discovered:
            if subdomain not in self.results["subdomains"]:
                self.results["subdomains"].append(subdomain)
                print(f"{Fore.GREEN}[+] Discovered subdomain: {subdomain}")
        
        print(f"{Fore.GREEN}[+] Found {len(self.results['subdomains'])} subdomains")

    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False

    def _scan_ports(self):
        """Scan for open ports on the target"""
        print(f"{Fore.BLUE}[*] Scanning common ports...")
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        # Get the IP addresses to scan
        targets = self.results["ip_addresses"]
        if not targets:
            print(f"{Fore.RED}[-] No IP addresses to scan")
            return
        
        for ip in targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {executor.submit(self._check_port, ip, port): port for port in common_ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                        if is_open:
                            service = self._get_service_name(port)
                            self.results["open_ports"].append({
                                "ip": ip,
                                "port": port,
                                "service": service
                            })
                            print(f"{Fore.GREEN}[+] Open port: {ip}:{port} ({service})")
                    except Exception:
                        pass
        
        print(f"{Fore.GREEN}[+] Found {len(self.results['open_ports'])} open ports")

    def _check_port(self, ip, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def _get_service_name(self, port):
        """Get the service name for a port number"""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        return common_services.get(port, "Unknown")

    def _check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        print(f"{Fore.BLUE}[*] Checking for vulnerabilities...")
        
        try:
            response = requests.get(self.target, timeout=self.timeout)
            
            # Check for server information disclosure
            if 'Server' in response.headers:
                server = response.headers['Server']
                if not server.startswith(('cloudflare', 'Cloudflare')):
                    self.results["vulnerabilities"].append({
                        "name": "Server Information Disclosure",
                        "description": f"Server header reveals: {server}",
                        "severity": "Low"
                    })
                    print(f"{Fore.YELLOW}[!] Server Information Disclosure: {server}")
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in response.headers:
                tech = response.headers['X-Powered-By']
                self.results["vulnerabilities"].append({
                    "name": "Technology Information Disclosure",
                    "description": f"X-Powered-By header reveals: {tech}",
                    "severity": "Low"
                })
                print(f"{Fore.YELLOW}[!] Technology Information Disclosure: {tech}")
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS not implemented',
                'Content-Security-Policy': 'CSP not implemented',
                'X-Frame-Options': 'X-Frame-Options not implemented (clickjacking risk)',
                'X-XSS-Protection': 'XSS Protection not implemented',
                'X-Content-Type-Options': 'X-Content-Type-Options not implemented'
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.results["vulnerabilities"].append({
                        "name": f"Missing {header}",
                        "description": message,
                        "severity": "Medium"
                    })
                    print(f"{Fore.YELLOW}[!] {message}")
            
            # Check for WordPress vulnerabilities
            if 'WordPress' in self.results["technologies"]:
                try:
                    wp_version = None
                    generator = BeautifulSoup(response.text, 'html.parser').find('meta', attrs={'name': 'generator'})
                    if generator:
                        content = generator.get('content', '')
                        if 'WordPress' in content:
                            wp_version = content.split('WordPress')[1].strip()
                    
                    if wp_version:
                        self.results["vulnerabilities"].append({
                            "name": "WordPress Version Disclosure",
                            "description": f"WordPress version {wp_version} detected",
                            "severity": "Medium"
                        })
                        print(f"{Fore.YELLOW}[!] WordPress version {wp_version} detected")
                    
                    # Check for wp-json API
                    wp_json = requests.get(f"{self.target}/wp-json/", timeout=self.timeout)
                    if wp_json.status_code == 200:
                        self.results["vulnerabilities"].append({
                            "name": "WordPress REST API Exposed",
                            "description": "WordPress REST API (wp-json) is accessible",
                            "severity": "Low"
                        })
                        print(f"{Fore.YELLOW}[!] WordPress REST API exposed")
                except Exception:
                    pass
            
            # Check for open directories
            common_dirs = ['backup', 'wp-content', 'wp-admin', 'admin', 'login', 'wp-includes', 
                          'uploads', 'tmp', 'old', 'config', 'images', 'includes']
            
            for directory in common_dirs:
                try:
                    dir_url = f"{self.target}/{directory}/"
                    dir_response = requests.get(dir_url, timeout=2)
                    
                    if dir_response.status_code == 200:
                        # Check if it looks like a directory listing
                        if 'Index of' in dir_response.text or 'Directory Listing' in dir_response.text:
                            self.results["vulnerabilities"].append({
                                "name": "Directory Listing Enabled",
                                "description": f"Directory listing is enabled at {dir_url}",
                                "severity": "Medium"
                            })
                            print(f"{Fore.YELLOW}[!] Directory listing enabled at {dir_url}")
                except Exception:
                    pass
            
            # Check for robots.txt
            try:
                robots = requests.get(f"{self.target}/robots.txt", timeout=2)
                if robots.status_code == 200:
                    self.results["vulnerabilities"].append({
                        "name": "Robots.txt Found",
                        "description": "robots.txt file may disclose sensitive directories",
                        "severity": "Info"
                    })
                    print(f"{Fore.BLUE}[i] robots.txt found")
            except Exception:
                pass
            
            print(f"{Fore.GREEN}[+] Found {len(self.results['vulnerabilities'])} potential vulnerabilities")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking vulnerabilities: {str(e)}")

    def _save_report(self):
        """Save the scan results to a file"""
        print(f"{Fore.BLUE}[*] Saving report to {self.output}...")
        
        try:
            with open(self.output, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"{Fore.GREEN}[+] Report saved successfully")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving report: {str(e)}")

    def _print_summary(self):
        """Print a summary of the scan results"""
        print(f"\n{Fore.CYAN}========== SCAN SUMMARY ==========")
        print(f"{Fore.CYAN}Target: {self.target}")
        print(f"{Fore.CYAN}Domain: {self.domain}")
        print(f"{Fore.CYAN}IP Address(es): {', '.join(self.results['ip_addresses'])}")
        print(f"{Fore.CYAN}Technologies: {', '.join(self.results['technologies'])}")
        print(f"{Fore.CYAN}Subdomains: {len(self.results['subdomains'])}")
        print(f"{Fore.CYAN}Open Ports: {len(self.results['open_ports'])}")
        print(f"{Fore.CYAN}Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        # Print top vulnerabilities by severity
        if self.results["vulnerabilities"]:
            print(f"\n{Fore.YELLOW}Top vulnerabilities:")
            
            for severity in ['High', 'Medium', 'Low', 'Info']:
                for vuln in self.results["vulnerabilities"]:
                    if vuln["severity"] == severity:
                        print(f"{Fore.YELLOW}[{vuln['severity']}] {vuln['name']}: {vuln['description']}")
        
        print(f"{Fore.CYAN}================================\n")


def main():
    parser = argparse.ArgumentParser(description='Termux Web Analyzer & Vulnerability Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target URL/domain to scan')
    parser.add_argument('-o', '--output', help='Output file to save the report (JSON format)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    try:
        analyzer = WebAnalyzer(
            target=args.target,
            threads=args.threads,
            output=args.output,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        analyzer.run_scan()
        
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] An error occurred: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()


