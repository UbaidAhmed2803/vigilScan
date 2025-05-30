#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Color coding for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configure logging
def setup_logging(log_file: str = 'scanner.log') -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

# Input validation
def validate_ip(ip: str) -> bool:
    """Validate an IP address (v4 or v6)"""
    ipv4_pattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    return re.match(ipv4_pattern, ip) is not None or re.match(ipv6_pattern, ip) is not None

def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation"""
    try:
        ip, prefix = cidr.split('/')
        if not validate_ip(ip):
            return False
        prefix = int(prefix)
        return 0 <= prefix <= 32  # For IPv4
    except ValueError:
        return False

def sanitize_input(input_str: str) -> str:
    """Allow command-line flags (e.g., --rate) and IPs/CIDR."""
    if not re.match(r'^[a-zA-Z0-9\.\/\-\_\: \=\-\-]+$', input_str):  # Added \= and \-\-
        raise ValueError(f"Potential malicious input: {input_str}")
    return input_str

# Configuration management
class ConfigManager:
    def __init__(self, config_file: str = 'config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        self.config.read(self.config_file)

    def create_default_config(self) -> None:
        """Create default configuration file"""
        self.config['DEFAULT'] = {
            'nmap_path': '/usr/bin/nmap',
            'masscan_path': '/usr/bin/masscan',
            'shodan_api_key': '',
            'nmap_args': '-sV -T4',
            'masscan_args': '--rate=1000 -p1-65535',
            'threads': '10',
            'timeout': '300'
        }
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        logging.info(f"Created default config file at {self.config_file}")

    def get(self, section: str, key: str, default: Optional[str] = None) -> str:
        """Get a configuration value"""
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            if default is not None:
                return default
            raise

# Scanner base class
class Scanner:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.progress = {
            'total': 0,
            'completed': 0,
            'start_time': None,
            'current_task': None
        }
        self.lock = threading.Lock()

    def update_progress(self, task: Optional[str] = None) -> None:
        """Update progress information"""
        with self.lock:
            if task:
                self.progress['current_task'] = task
            if self.progress['completed'] == 0:
                self.progress['start_time'] = datetime.now()
            self.progress['completed'] += 1

    def get_progress(self) -> Dict[str, Union[int, str, None]]:
        """Get current progress information"""
        with self.lock:
            elapsed = (datetime.now() - self.progress['start_time']).total_seconds() if self.progress['start_time'] else 0
            remaining = (self.progress['total'] - self.progress['completed']) * (elapsed / max(1, self.progress['completed'])) if self.progress['completed'] > 0 else 0
            return {
                'completed': self.progress['completed'],
                'total': self.progress['total'],
                'percent': (self.progress['completed'] / self.progress['total']) * 100 if self.progress['total'] > 0 else 0,
                'elapsed': str(timedelta(seconds=int(elapsed))),
                'eta': str(timedelta(seconds=int(remaining))) if remaining > 0 else 'Calculating...',
                'current_task': self.progress['current_task']
            }

    def run_command(self, command: List[str], timeout: int = 600):  # Increased default
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False
            )
            return (result.returncode, result.stdout.decode('utf-8'), result.stderr.decode('utf-8'))
        except subprocess.TimeoutExpired as e:
            # Return partial output if available
            return (-1, e.stdout.decode('utf-8') if e.stdout else '', 'Command timed out')

    def print_status(self) -> None:
        """Print current status to console"""
        progress = self.get_progress()
        print(f"\r{Colors.OKBLUE}[STATUS]{Colors.ENDC} {progress['current_task']} | "
              f"Progress: {progress['completed']}/{progress['total']} ({progress['percent']:.1f}%) | "
              f"Elapsed: {progress['elapsed']} | ETA: {progress['eta']}", end='', flush=True)

# Nmap scanner implementation
class NmapScanner(Scanner):
    def scan(self, target: str) -> Dict[str, Union[str, Dict]]:
        """Run Nmap scan on target"""
        self.update_progress(f"Nmap scanning {target}")
        nmap_path = self.config.get('DEFAULT', 'nmap_path')
        nmap_args = self.config.get('DEFAULT', 'nmap_args').split()
        
        command = [nmap_path, *nmap_args, target]
        returncode, stdout, stderr = self.run_command(command, int(self.config.get('DEFAULT', 'timeout')))
        
        if returncode != 0:
            logging.error(f"Nmap scan failed for {target}: {stderr}")
            return {'target': target, 'error': stderr}
        
        return self.parse_nmap_output(stdout, target)

    def parse_nmap_output(self, output: str, target: str) -> Dict[str, Union[str, Dict]]:
        """Parse Nmap output into structured data"""
        result = {
            'target': target,
            'services': [],
            'os': None,
            'hostname': None
        }
        
        # Simple parsing - in a real implementation you'd want more robust parsing
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    port_proto = parts[0].split('/')
                    service = {
                        'port': port_proto[0],
                        'protocol': port_proto[1],
                        'state': parts[1],
                        'service': parts[2],
                        'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                    }
                    result['services'].append(service)
            elif 'OS details:' in line:
                result['os'] = line.split('OS details:')[1].strip()
            elif 'Nmap scan report for' in line:
                hostname = line.split('Nmap scan report for ')[1].split()[0]
                if hostname != target:
                    result['hostname'] = hostname
        
        return result

# Masscan scanner implementation
class MasscanScanner(Scanner):
    def scan(self, target: str) -> Dict[str, Union[str, Dict]]:
        """Run Masscan on target"""
        self.update_progress(f"Masscan scanning {target}")
        masscan_path = self.config.get('DEFAULT', 'masscan_path')
        masscan_args = self.config.get('DEFAULT', 'masscan_args')
        
        # Use shlex.split() to handle arguments safely
        command = [masscan_path] + shlex.split(masscan_args) + [target]
        returncode, stdout, stderr = self.run_command(command, int(self.config.get('DEFAULT', 'timeout')))
        
        if returncode != 0:
            logging.error(f"Masscan scan failed for {target}: {stderr}")
            return {'target': target, 'error': stderr}
        
        return self.parse_masscan_output(stdout, target)

    def parse_masscan_output(self, output: str, target: str) -> Dict[str, Union[str, List]]:
        """Parse Masscan output into structured data"""
        result = {
            'target': target,
            'open_ports': []
        }
        
        for line in output.split('\n'):
            if 'Discovered open port' in line:
                parts = line.split()
                port_proto = parts[3].split('/')
                result['open_ports'].append({
                    'port': port_proto[0],
                    'protocol': port_proto[1]
                })
        
        return result

# Shodan scanner implementation
class ShodanScanner(Scanner):
    def __init__(self, config: ConfigManager):
        super().__init__(config)
        self.api_key = self.config.get('DEFAULT', 'shodan_api_key')
        if not self.api_key:
            raise ValueError("Shodan API key not configured")

    def scan(self, target: str) -> Dict:
        if target.startswith(('10.', '192.168.', '172.')):
            return {'target': target, 'error': 'Private IP (not queryable via Shodan)'}
        """Query Shodan for target information"""
        self.update_progress(f"Querying Shodan for {target}")
        try:
            import shodan
        except ImportError:
            logging.error("Shodan library not installed. Run 'pip install shodan'")
            return {'target': target, 'error': 'Shodan library not installed'}
        
        try:
            api = shodan.Shodan(self.api_key)
            result = api.host(target)
            return {
                'target': target,
                'data': {
                    'ports': result.get('ports', []),
                    'vulns': result.get('vulns', []),
                    'hostnames': result.get('hostnames', []),
                    'os': result.get('os', None),
                    'isp': result.get('isp', None)
                }
            }
        except shodan.APIError as e:
            logging.error(f"Shodan API error for {target}: {str(e)}")
            return {'target': target, 'error': str(e)}
        except Exception as e:
            logging.error(f"Error querying Shodan for {target}: {str(e)}")
            return {'target': target, 'error': str(e)}

# Main scanner class
class NetworkScanner:
    def __init__(self, config_file: str = 'config.ini'):
        self.config = ConfigManager(config_file)
        self.scanners = {
            'nmap': NmapScanner(self.config),
            'masscan': MasscanScanner(self.config),
            'shodan': ShodanScanner(self.config)
        }
        self.results = []
        self.progress_thread = None
        self.stop_progress = False

    def display_progress(self) -> None:
        """Display progress in a separate thread"""
        while not self.stop_progress:
            for scanner in self.scanners.values():
                scanner.print_status()
            time.sleep(1)

    def scan_target(self, target: str) -> Dict[str, Union[str, Dict]]:
        """Scan a single target with all scanners"""
        result = {'target': target, 'scans': {}}
        
        for name, scanner in self.scanners.items():
            try:
                result['scans'][name] = scanner.scan(target)
            except Exception as e:
                logging.error(f"Error running {name} scan on {target}: {str(e)}")
                result['scans'][name] = {'error': str(e)}
        
        self.results.append(result)
        return result

    def scan_targets(self, targets: List[str]) -> None:
        """Scan multiple targets with multithreading"""
        total_targets = len(targets)
        for scanner in self.scanners.values():
            scanner.progress['total'] = total_targets
        
        # Start progress display thread
        self.progress_thread = threading.Thread(target=self.display_progress)
        self.progress_thread.daemon = True
        self.progress_thread.start()
        
        # Process targets with thread pool
        try:
            with ThreadPoolExecutor(max_workers=int(self.config.get('DEFAULT', 'threads'))) as executor:
                futures = {executor.submit(self.scan_target, target): target for target in targets}
                
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error processing target {target}: {str(e)}")
        finally:
            self.stop_progress = True
            if self.progress_thread:
                self.progress_thread.join()
            print()  # New line after progress display

    def print_results(self) -> None:
        """Print results to console with color coding"""
        for result in self.results:
            print(f"\n{Colors.HEADER}Results for {result['target']}:{Colors.ENDC}")
            
            for scanner_name, scan_result in result['scans'].items():
                print(f"\n{Colors.BOLD}{scanner_name.upper()} Results:{Colors.ENDC}")
                
                if 'error' in scan_result:
                    print(f"{Colors.FAIL}Error: {scan_result['error']}{Colors.ENDC}")
                    continue
                
                if scanner_name == 'nmap':
                    if scan_result.get('services'):
                        print(f"{Colors.OKGREEN}Discovered services:{Colors.ENDC}")
                        for service in scan_result['services']:
                            print(f"  {service['port']}/{service['protocol']} - {service['state']} - {service['service']} {service['version']}")
                    if scan_result.get('os'):
                        print(f"{Colors.OKGREEN}OS: {scan_result['os']}{Colors.ENDC}")
                    if scan_result.get('hostname'):
                        print(f"{Colors.OKGREEN}Hostname: {scan_result['hostname']}{Colors.ENDC}")
                
                elif scanner_name == 'masscan':
                    if scan_result.get('open_ports'):
                        print(f"{Colors.OKGREEN}Open ports:{Colors.ENDC}")
                        for port in scan_result['open_ports']:
                            print(f"  {port['port']}/{port['protocol']}")
                
                elif scanner_name == 'shodan':
                    if scan_result.get('data'):
                        data = scan_result['data']
                        if data.get('ports'):
                            print(f"{Colors.OKGREEN}Ports: {', '.join(map(str, data['ports']))}{Colors.ENDC}")
                        if data.get('hostnames'):
                            print(f"{Colors.OKGREEN}Hostnames: {', '.join(data['hostnames'])}{Colors.ENDC}")
                        if data.get('os'):
                            print(f"{Colors.OKGREEN}OS: {data['os']}{Colors.ENDC}")
                        if data.get('vulns'):
                            print(f"{Colors.WARNING}Vulnerabilities:{Colors.ENDC}")
                            for vuln in data['vulns']:
                                print(f"  {vuln}")

    def save_results(self, output_file: str) -> None:
        """Save results to a file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logging.info(f"Results saved to {output_file}")
        except Exception as e:
            logging.error(f"Error saving results to {output_file}: {str(e)}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Professional Network Scanner')
    parser.add_argument('targets', nargs='*', help='IP addresses or CIDR ranges to scan')
    parser.add_argument('-f', '--file', help='File containing IP addresses (one per line)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-c', '--config', default='config.ini', help='Configuration file')
    args = parser.parse_args()

    # Setup logging
    setup_logging()

    # Validate inputs
    targets = []
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            logging.error(f"Error reading input file: {str(e)}")
            sys.exit(1)
    
    targets.extend(args.targets)
    
    if not targets:
        logging.error("No targets specified. Provide IPs as arguments or via file.")
        sys.exit(1)

    # Validate all targets
    valid_targets = []
    for target in targets:
        if validate_ip(target) or validate_cidr(target):
            valid_targets.append(target)
        else:
            logging.warning(f"Invalid target format: {target}")
    
    if not valid_targets:
        logging.error("No valid targets to scan")
        sys.exit(1)

    try:
        # Initialize and run scanner
        scanner = NetworkScanner(args.config)
        scanner.scan_targets(valid_targets)
        scanner.print_results()
        
        if args.output:
            scanner.save_results(args.output)
    except Exception as e:
        logging.error(f"Scanner error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
