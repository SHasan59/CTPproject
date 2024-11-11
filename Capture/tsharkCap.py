import subprocess
import os
import time
import re

# Configuration
capture_duration = 10  # Duration for each file segment in seconds
max_files = 6          # Number of files in the rotation
output_dir = "/Users/estebanm/Desktop/Capture"  # Directory to store files

# Ensure output directory exists
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def get_active_interface():
    """Detect the active interface for capturing."""
    # List all interfaces and filter out only those with "Wi-Fi" or "en0"
    interfaces = subprocess.check_output(["tshark", "-D"]).decode("utf-8").splitlines()
    for interface in interfaces:
        # Extract the interface number and name
        match = re.match(r"^(\d+)\.\s+([^\s]+)", interface)
        if match:
            interface_id, interface_name = match.groups()
            # Check if the interface is the expected one (like en0 for Wi-Fi)
            if "en0" in interface_name or "Wi-Fi" in interface_name:
                return interface_id  # Return only the interface ID (e.g., "2")

    return None

def continuous_capture():
    """Capture traffic continuously, saving every 10 seconds to rotating files."""
    active_interface = get_active_interface()
    if not active_interface:
        print("No active interface detected.")
        return

    file_index = 0
    while True:
        # Determine the filename for the current segment
        pcap_filename = os.path.join(output_dir, f"capture_{file_index}.pcap")
        print(f"Capturing traffic on interface {active_interface} to file {pcap_filename}")

        # Start tshark for 10 seconds, saving to a pcap file
        subprocess.run([
            "tshark", "-i", active_interface, "-a", f"duration:{capture_duration}", "-w", pcap_filename
        ], check=True)

        # Convert the pcap file to CSV immediately after each capture segment
        convert_pcap_to_csv(pcap_filename, file_index)
        print(f"Saved capture to {pcap_filename} and converted to CSV.")

        # Rotate file index to overwrite oldest file when max_files is reached
        file_index = (file_index + 1) % max_files

        # Brief pause to prepare for the next capture
        time.sleep(1)

def convert_pcap_to_csv(pcap_filename, file_index):
    """Convert pcap file to csv using tshark."""
    csv_filename = os.path.join(output_dir, f"capture_{file_index}.csv")
    fields = [
        "-e", "frame.number",            # Packet number
        "-e", "frame.time",              # Timestamp
        "-e", "ip.src",                  # Source IP address
        "-e", "ip.dst",                  # Destination IP address
        "-e", "frame.protocols",         # Protocols in the frame
        "-e", "frame.len",               # Length of the frame
        "-e", "tcp.srcport",             # Source port (for TCP)
        "-e", "tcp.dstport",             # Destination port (for TCP)
        "-e", "udp.srcport",             # Source port (for UDP)
        "-e", "udp.dstport",             # Destination port (for UDP)
        "-e", "tcp.flags"                # TCP flags
    ]

    # Run tshark to convert pcap to csv
    with open(csv_filename, "w") as csv_file:
        subprocess.run(["tshark", "-r", pcap_filename, "-T", "fields", "-E", "separator=,", "-E", "header=y"] + fields, stdout=csv_file, check=True)
    print(f"Converted {pcap_filename} to {csv_filename}")

if __name__ == "__main__":
    continuous_capture()
