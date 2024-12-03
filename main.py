import re
from collections import Counter, defaultdict
import csv


def parse_log(file_path):
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<endpoint>[^\s]+) [^"]+" (?P<status>\d+) (?P<size>\d+)'
    )
    ip_addresses = Counter()
    endpoints = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status")
                
                # IP requests counts
                ip_addresses[ip] += 1
                
                #  endpoint requests counts
                endpoints[endpoint] += 1
                
                # Detect failed login attempts
                if status == "401" or "Invalid credentials" in line:
                    failed_logins[ip] += 1

    return ip_addresses, endpoints, failed_logins


def analyze_logs(ip_addresses, endpoints, failed_logins):
    # Sorting IPs
    sorted_ips = ip_addresses.most_common()

    most_accessed_endpoint, access_count = endpoints.most_common(1)[0]

    suspicious_ips = [
        (ip, count) for ip, count in failed_logins.items() if count >= FAILED_LOGIN_THRESHOLD
    ]

    return sorted_ips, (most_accessed_endpoint, access_count), suspicious_ips


def output_results(sorted_ips, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ips)
        writer.writerow([])

        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips)

    print("Results saved to", output_file)


def display_results(sorted_ips, most_accessed_endpoint, suspicious_ips):
    print("\nRequests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted_ips:
        print(f"{ip:<20}{count:<15}")
    
    print("\nMost Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
        for ip, count in suspicious_ips:
            print(f"{ip:<20}{count:<15}")
    else:
        print("No suspicious activity detected.")

def main():
    ip_addresses, endpoints, failed_logins = parse_log(LOG_FILE)
    sorted_ips, most_accessed_endpoint, suspicious_ips = analyze_logs(ip_addresses, endpoints, failed_logins)
    display_results(sorted_ips, most_accessed_endpoint, suspicious_ips)
    output_results(sorted_ips, most_accessed_endpoint, suspicious_ips, CSV_FILE)

if __name__ == "__main__":
    LOG_FILE = "sample.log"
    CSV_FILE = "log_analysis_results.csv"
    FAILED_LOGIN_THRESHOLD = 10 
    main()
