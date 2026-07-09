import datetime
import requests

# URL for open-source botnet IP threat feed
INTEL_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def fetch_threat_intel():
    print("Fetching latest threat indicators...")
    try:
        response = requests.get(INTEL_URL, timeout=15)
        if response.status_code == 200:
            return response.text
        print(f"Failed to fetch data. Status code: {response.status_code}")
        return None
    except Exception as e:
        print(f"Error occurred during fetch: {e}")
        return None


def parse_and_save(raw_data):
    if not raw_data:
        return

    # Filter out comments and extract the top malicious IPs
    lines = raw_data.splitlines()
    ip_list = []

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        # The CSV format: first column is the IP address
        parts = line.split(",")
        if parts:
            ip_list.append(parts[0].strip('"'))

    # Limit to top 50 active threats for clean visualization
    top_threats = ip_list[:50]
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    # Format the data into a clean Markdown file
    markdown_content = f"# Automated Daily Threat Intelligence Feed\n"
    markdown_content += f"*Last Updated: {current_time}*\n\n"
    markdown_content += (
        "This repository automatically tracks active botnet command-and-control "
        "malicious IP addresses using GitHub Actions cloud pipelines.\n\n"
    )
    markdown_content += "### Active Malicious IP Addresses (Top 50)\n"
    markdown_content += "| IP Address | Threat Type |\n|---|---|\n"

    for ip in top_threats:
        markdown_content += f"| `{ip}` | Botnet C&C |\n"

    # Write to a file named LATEST_THREATS.md
    with open("LATEST_THREATS.md", "w") as f:
        f.write(markdown_content)

    print(
        f"Successfully recorded {len(top_threats)} malicious indicators at {current_time}"
    )


if __name__ == "__main__":
    raw_intel = fetch_threat_intel()
    parse_and_save(raw_intel)
