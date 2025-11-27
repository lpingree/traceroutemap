
import logging
import sqlite3
import subprocess
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
from rich.table import Table
from rich.console import Console
from rich import box

# Set up logging for informational output
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# List of top 10 websites for traceroutes
TOP_WEBSITES = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'wikipedia.org', 'amazon.com',
    'yahoo.com', 'netflix.com'
]

# Connect to SQLite database or create the database schema
def setup_or_connect_database():
    conn = sqlite3.connect('network_monitor.db')
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS results (
                      site TEXT,
                      hop_count INTEGER,
                      avg_latency REAL,
                      unique_path_count INTEGER,
                      geo_ip_data TEXT,
                      fqdn TEXT)""")
    return conn, cursor

# Execute traceroute and handle potential sandbox restrictions
def perform_traceroute(site):
    last_responded_ip = None
    fqdn = None
    try:
        logging.info(f'Starting traceroute for {site}')
        # Execute the traceroute command. Ensure the environment is correctly set up to allow network utility execution.
        result = subprocess.run(
            ['traceroute', '-n', site],
            capture_output=True,
            timeout=30,
            check=True,  # Ensures any subprocess error is raised
            text=True    # Provides readable text output
        )
        lines = result.stdout.splitlines()
        path = []
        total_latency = 0

        for line in lines[1:]:
            fields = line.split()
            if len(fields) > 1 and fields[1] != '*':
                ip = fields[1]
                if all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split('.')):
                    latencies = [float(lat) for lat in fields[2:] if lat.replace('.', '', 1).isdigit()]
                    path.append(ip)
                    total_latency += sum(latencies)
                    last_responded_ip = ip

        hop_count = len(path)
        avg_latency = total_latency / hop_count if hop_count > 0 else 0
        unique_path_count = len(set(path))
        geo_ip_data = "; ".join(path)

        if last_responded_ip:
            try:
                fqdn = socket.gethostbyaddr(last_responded_ip)[0]
            except socket.herror:
                fqdn = last_responded_ip

        # Enhanced detection logic
        detect_anomalies_and_threats(last_responded_ip, avg_latency, fqdn)

        return (site, hop_count, avg_latency, unique_path_count, geo_ip_data, fqdn)

    except subprocess.CalledProcessError as e:
        logging.error(f"Traceroute command failed: {e}")
        return None  # Handle execution failure gracefully by returning None

# Detect anomalies and threats
def detect_anomalies_and_threats(last_ip, latency, resolved_name):
    logging.info(f'Monitoring Anomalies: IP: {last_ip}, Latency: {latency}, Hostname: {resolved_name}')
    location_info = get_geolocation(last_ip)
    if location_info:
        country = location_info.get('country', '')
        if country in ["China", "Russia"]:
            logging.warning(f"Security alert! Traffic through {country}. Reconsider your VPN or connection setup.")

    if check_ip_threat_level(last_ip):
        logging.warning(f"Security threat detected! IP {last_ip} has a high threat score.")

def get_geolocation(ip):
    # Public API for IP geolocation - no key needed
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json() if response.status_code == 200 else {}
    except requests.RequestException as e:
        logging.error(f"Geolocation lookup failed for IP {ip}: {e}")
        return {}

def check_ip_threat_level(ip):
    # Mock returning threat status - replace with a real check
    return False

# Update the database with traceroute results
def update_database(results):
    conn, cursor = setup_or_connect_database()
    cursor.executemany("""INSERT INTO results (site, hop_count, avg_latency, unique_path_count, geo_ip_data, fqdn)
                          VALUES (?, ?, ?, ?, ?, ?)""", results)
    conn.commit()
    conn.close()

# Generate summary reports with Rich
def generate_reports():
    conn, cursor = setup_or_connect_database()
    cursor.execute("SELECT site, hop_count, avg_latency, unique_path_count, geo_ip_data, fqdn FROM results")
    results = cursor.fetchall()
    conn.close()

    console = Console()
    
    # Create a summary table
    table = Table(title="Traceroute Summary", box=box.ROUNDED, highlight=True)
    table.add_column("Site", style="cyan", no_wrap=True)
    table.add_column("Hop Count", justify="right", style="magenta")
    table.add_column("Avg Latency (ms)", justify="right", style="green")
    table.add_column("Unique Paths", justify="right", style="magenta")
    table.add_column("FQDN", style="yellow")

    # Add data to the table
    for row in results:
        table.add_row(
            row[0],
            str(row[1]),
            f"{row[2]:.2f}",
            str(row[3]),
            row[5] or "Unknown"
        )

    console.print(table)

# Main execution logic
def main():
    with ThreadPoolExecutor(max_workers=len(TOP_WEBSITES)) as executor:
        futures = {executor.submit(perform_traceroute, site): site for site in TOP_WEBSITES}
        all_results = []
        for future in futures:
            result = future.result()
            if result:
                all_results.append(result)
                update_database([result])  # Pass a list of results to executemany
    generate_reports()

if __name__ == "__main__":
    main()
    logging.info('Traceroutes completed and database updated.')
