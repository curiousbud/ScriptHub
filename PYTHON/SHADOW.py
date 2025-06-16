import os
import yaml
import requests
from ipaddress import ip_network, ip_address
import dns.resolver
import asyncio
import aiohttp
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def print_banner():
    banner = """
    
     █████████  █████   █████   █████████   ██████████      ███████    █████   ███   █████
 ███░░░░░███░░███   ░░███   ███░░░░░███ ░░███░░░░███   ███░░░░░███ ░░███   ░███  ░░███ 
░███    ░░░  ░███    ░███  ░███    ░███  ░███   ░░███ ███     ░░███ ░███   ░███   ░███ 
░░█████████  ░███████████  ░███████████  ░███    ░███░███      ░███ ░███   ░███   ░███ 
 ░░░░░░░░███ ░███░░░░░███  ░███░░░░░███  ░███    ░███░███      ░███ ░░███  █████  ███  
 ███    ░███ ░███    ░███  ░███    ░███  ░███    ███ ░░███     ███   ░░░█████░█████░   
░░█████████  █████   █████ █████   █████ ██████████   ░░░███████░      ░░███ ░░███     
 ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░      ░░░░░░░         ░░░   ░░░      
                                                                                                                                                                      
    """
    print(banner)

def load_templates(directory):
    templates = []
    for filename in os.listdir(directory):
        if filename.endswith(".yaml"):
            with open(os.path.join(directory, filename), 'r') as file:
                templates.append(yaml.safe_load(file))
    return templates

def add_scheme(url):
    if not url.startswith(('http://', 'https://')):
        return ['http://' + url, 'https://'+ url]
    return [url]

async def run_template(template, target):
    results = []

    # Handle HTTP requests
    if 'requests' in template:
        results.extend(await run_http_requests(template['requests'], target))

    # Handle JavaScript execution
    if 'javascript' in template:
        results.extend(run_javascript(template['javascript'], target))

    # Handle DNS checks
    if 'dns' in template:
        results.extend(run_dns_checks(template['dns'], target))

    return results

async def run_http_requests(requests_section, target):
    results = []
    urls = add_scheme(target)  # Ensure target URL has a scheme or try both

    async with aiohttp.ClientSession() as session:
        for url in urls:
            for request in requests_section:
                full_url = url + request['path']
                headers = request.get('headers', {})
                try:
                    async with session.request(request['method'], full_url, headers=headers) as response:
                        result = await process_response(response, request)
                        results.append(result)
                except aiohttp.ClientError as e:
                    logger.error(f"Request to {full_url} failed: {e}")
    return results

async def process_response(response, request):
    expected = request.get('expected', [{}])[0]
    result = {
        'status': 'Not Vulnerable',
        'response_status': response.status,
        'body': await response.text()
    }

    if response.status == expected.get('status') and \
            expected.get('body_contains', '') in result['body']:
        result['status'] = 'Vulnerable'

    return result

def run_javascript(javascript_section, target):
    # Example of handling JavaScript execution (simulated)
    logger.info(f"Executing JavaScript on {target}")
    results = []
    for script in javascript_section:
        logger.info(f"Running script: {script}")
        # Simulate running JavaScript - in practice, you'd need a JS engine
        result = {
            'status': 'Executed',
            'script': script
        }
        results.append(result)
    return results

def run_dns_checks(dns_section, target):
    logger.info(f"Running DNS checks on {target}")
    results = []
    for check in dns_section:
        try:
            answers = dns.resolver.resolve(target, check['type'])
            for rdata in answers:
                logger.info(f"Found DNS record: {rdata}")
                result = {
                    'status': 'Found',
                    'record': str(rdata)
                }
                results.append(result)
        except dns.resolver.NoAnswer:
            logger.info(f"No DNS answer for {target}")
            result = {
                'status': 'NoAnswer',
                'type': check['type']
            }
            results.append(result)
        except dns.resolver.NXDOMAIN:
            logger.info(f"Domain {target} does not exist")
            result = {
                'status': 'NXDOMAIN',
                'type': check['type']
            }
            results.append(result)
    return results

def generate_report(results):
    report = []
    report.append("Vulnerability Scan Report")
    report.append("==========================\n")
    
    for result in results:
        report.append(f"Status: {result.get('status', 'Unknown')}")
        if 'response_status' in result:
            report.append(f"HTTP Status: {result['response_status']}")
        if 'body' in result:
            report.append(f"Response Body: {result['body'][:100]}\n")
        if 'script' in result:
            report.append(f"Executed Script: {result['script']}")
        if 'record' in result:
            report.append(f"DNS Record: {result['record']}")
        report.append("\n")
    
    return "\n".join(report)

def save_report(report, target):
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    filename = os.path.join('reports', f"{target.replace('http://', '').replace('https://', '').replace('/', '_')}_report.txt")
    with open(filename, 'w') as file:
        file.write(report)

def is_valid_ip(target):
    try:
        ip_address(target)
        return True
    except ValueError:
        return False

def is_valid_ip_range(target):
    try:
        ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def expand_wildcard(domain):
    subdomains = []
    try:
        answers = dns.resolver.resolve(domain.replace('*.', ''), 'A')
        for rdata in answers:
            subdomains.append(f"{domain.replace('*', 'www')}")
    except dns.resolver.NoAnswer:
        subdomains.append(f"{domain.replace('*', 'www')}")
    return subdomains

def parse_targets(targets):
    expanded_targets = []
    for target in targets:
        if '*' in target:
            expanded_targets.extend(expand_wildcard(target))
        elif is_valid_ip_range(target):
            expanded_targets.extend([str(ip) for ip in ip_network(target, strict=False)])
        else:
            expanded_targets.append(target)
    return expanded_targets

def load_targets_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

async def main():
    print_banner()
    print("Choose the type of target input:")
    print("1. Single IP address")
    print("2. IP range (CIDR notation)")
    print("3. Single domain")
    print("4. Subdomains (wildcard)")
    print("5. List of targets from a text file")
    print("6. List of targets from a YAML file")
    choice = input("Enter your choice (1-6): ")
    
    targets = []
    if choice == '1':
        target = input("Enter the IP address: ").strip()
        targets.append(target)
    elif choice == '2':
        target = input("Enter the IP range (CIDR notation): ").strip()
        targets.append(target)
    elif choice == '3':
        target = input("Enter the domain: ").strip()
        targets.append(target)
    elif choice == '4':
        target = input("Enter the wildcard domain (e.g., *.example.com): ").strip()
        targets.append(target)
    elif choice == '5':
        file_path = input("Enter the path to the text file: ").strip()
        targets = load_targets_from_file(file_path)
    elif choice == '6':
        file_path = input("Enter the path to the YAML file: ").strip()
        with open(file_path, 'r') as file:
            targets = yaml.safe_load(file)
    else:
        print("Invalid choice")
        return
    
    targets = parse_targets(targets)
    templates_directory = "./templates"  # Directory where YAML templates are stored
    templates = load_templates(templates_directory)
    
    all_results = []
    
    for target in targets:
        for template in templates:
            results = await run_template(template, target)
            all_results.extend(results)
    
    report = generate_report(all_results)
    print(report)
    save_report(report, "_".join(targets))

# Call the main function
if __name__ == "__main__":
    asyncio.run(main())