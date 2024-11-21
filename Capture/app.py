import pyshark
import threading
import time
import numpy as np
import pandas as pd
from collections import deque
import netifaces as net
import os

class Flow:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """
        Initialize a network flow with key identifiers and metrics.
        
        Args:
            src_ip (str): Source IP address
            src_port (int): Source port number
            dst_ip (str): Destination IP address
            dst_port (int): Destination port number
            protocol (str): Network protocol
        """
        # Flow identifiers
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol

        # Packet tracking
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_length_fwd_packets = 0
        self.total_length_bwd_packets = 0

        # Packet lengths
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []

        # Inter-arrival times
        self.fwd_iat = []
        self.last_fwd_packet_time = None

        # Other features
        self.fwd_header_length = 0
        self.init_win_bytes_forward = None
        self.act_data_pkt_fwd = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0

        # Timestamps
        self.start_time = time.time()
        self.last_packet_time = self.start_time

    def add_packet(self, packet, direction):
        """
        Add a packet to the flow and update flow metrics.
        
        Args:
            packet (pyshark.Packet): Captured network packet
            direction (str): 'forward' or 'backward'
        """
        try:
            current_time = float(packet.sniff_timestamp)
            self.last_packet_time = current_time

            # Packet length
            packet_length = int(packet.length)

            if direction == 'forward':
                self.total_fwd_packets += 1
                self.total_length_fwd_packets += packet_length
                self.fwd_packet_lengths.append(packet_length)

                # Inter-arrival times
                if self.last_fwd_packet_time is not None:
                    iat = current_time - self.last_fwd_packet_time
                    self.fwd_iat.append(iat)
                self.last_fwd_packet_time = current_time

                # Header length calculation
                header_length = 14  # Ethernet header
                if hasattr(packet, 'ip'):
                    header_length += int(packet.ip.hdr_len or 0)
                
                if hasattr(packet, 'tcp'):
                    header_length += int(packet.tcp.hdr_len or 0)
                    
                    # TCP flag tracking
                    if hasattr(packet.tcp, 'flags'):
                        flags = int(packet.tcp.flags, 16)
                        self.fin_flag_count += bool(flags & 0x01)  # FIN flag
                        self.syn_flag_count += bool(flags & 0x02)  # SYN flag

                    # Initial window size
                    if self.init_win_bytes_forward is None:
                        self.init_win_bytes_forward = int(packet.tcp.window_size or 0)
                
                elif hasattr(packet, 'udp'):
                    header_length += 8  # UDP header length
                
                self.fwd_header_length += header_length
                self.act_data_pkt_fwd += 1
            else:
                self.total_bwd_packets += 1
                self.total_length_bwd_packets += packet_length
                self.bwd_packet_lengths.append(packet_length)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def is_expired(self, timeout=60):
        """
        Check if the flow is inactive.
        
        Args:
            timeout (int): Inactivity timeout in seconds
        
        Returns:
            bool: Whether the flow is expired
        """
        return (time.time() - self.last_packet_time) > timeout

    def compute_features(self):
        """
        Compute comprehensive features for the flow.
        
        Returns:
            dict: Extracted flow features
        """
        features = {
            'Destination Port': self.dst_port,
            'Total Fwd Packets': self.total_fwd_packets,
            'Total Backward Packets': self.total_bwd_packets,
            'Total Length of Fwd Packets': self.total_length_fwd_packets,
            'Total Length of Bwd Packets': self.total_length_bwd_packets,
            'Fwd Packet Length Max': max(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Fwd Packet Length Mean': np.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Bwd Packet Length Min': min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'Fwd IAT Total': sum(self.fwd_iat) if self.fwd_iat else 0,
            'Fwd IAT Mean': np.mean(self.fwd_iat) if self.fwd_iat else 0,
            'Fwd IAT Std': np.std(self.fwd_iat) if self.fwd_iat else 0,
            'Fwd IAT Max': max(self.fwd_iat) if self.fwd_iat else 0,
            'Fwd Header Length': self.fwd_header_length,
            'Avg Fwd Segment Size': np.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'Subflow Fwd Packets': self.total_fwd_packets,
            'Subflow Fwd Bytes': self.total_length_fwd_packets,
            'Subflow Bwd Packets': self.total_bwd_packets,
            'Subflow Bwd Bytes': self.total_length_bwd_packets,
            'Init_Win_bytes_forward': self.init_win_bytes_forward or 0,
            'Act_Data_Pkt_Fwd': self.act_data_pkt_fwd,
            'FIN_Flag_Count': self.fin_flag_count,
            'SYN_Flag_Count': self.syn_flag_count
        }
        return features

def get_all_interfaces():
    """
    Get all available network interfaces with their IP addresses.
    
    Returns:
        list: Available network interfaces with IP addresses
    """
    try:
        interfaces = net.interfaces()
        excluded_interfaces = ['lo', 'lo0', 'bridge', 'docker', 'vmnet']
        available_interfaces = []

        for iface in interfaces:
            if any(excluded in iface for excluded in excluded_interfaces):
                continue
            
            try:
                addrs = net.ifaddresses(iface)
                ip_info = addrs.get(net.AF_INET)
                if ip_info:
                    ip_addr = ip_info[0].get('addr', 'N/A')
                    available_interfaces.append((iface, ip_addr))
                else:
                    available_interfaces.append((iface, 'N/A'))
            except ValueError:
                continue
        
        return available_interfaces
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return []

def process_packets(packet_queue, flow_dict):
    """
    Process captured packets and extract flow features.
    
    Args:
        packet_queue (deque): Queue of captured packets
        flow_dict (dict): Dictionary of active network flows
    """
    while packet_queue:
        try:
            packet = packet_queue.popleft()
            
            # Check for valid IP packet
            if not hasattr(packet, 'ip'):
                continue

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Determine protocol
            if hasattr(packet, 'tcp'):
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                protocol = 'TCP'
            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                protocol = 'UDP'
            else:
                continue

            # Create unique flow key
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            
            # Create or update flow
            if flow_key not in flow_dict:
                flow_dict[flow_key] = Flow(*flow_key)
            
            # Determine packet direction
            direction = 'forward'
            flow = flow_dict[flow_key]
            flow.add_packet(packet, direction)

        except Exception as e:
            print(f"Error processing packet: {e}")

def capture_packets(interface_name, packet_queue, stop_event):
    """
    Capture packets from a specified network interface.
    
    Args:
        interface_name (str): Name of network interface
        packet_queue (deque): Queue to store captured packets
        stop_event (threading.Event): Event to stop packet capture
    """
    try:
        capture = pyshark.LiveCapture(interface=interface_name, only_summaries=False)
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                break
            packet_queue.append(packet)
    except Exception as e:
        print(f"Packet capture error: {e}")

def main():
    # Configure logging or error handling
    print("Network Traffic Feature Extractor")
    
    # Packet and flow tracking
    packet_queue = deque(maxlen=1000)  # Limit queue size
    flow_dict = {}

    # Get network interfaces with active IPs
    interfaces = [(iface, ip) for iface, ip in get_all_interfaces() if ip != 'N/A']
    if not interfaces:
        print("No active network interfaces found. Ensure you're connected to the internet.")
        return

    if len(interfaces) == 1:
        # If only one active interface, automatically select it
        interface_name = interfaces[0][0]
        print(f"Automatically selected the active interface: {interface_name} (IP: {interfaces[0][1]})")
    else:
        # Display multiple active interfaces and let the user select
        print("\nAvailable Active Network Interfaces:")
        for idx, (iface, ip_addr) in enumerate(interfaces):
            print(f"{idx}: {iface} (IP: {ip_addr})")
        
        # Interface selection
        while True:
            try:
                selected_idx = int(input("\nSelect interface index for packet capture: "))
                if 0 <= selected_idx < len(interfaces):
                    break
                print("Invalid selection. Try again.")
            except ValueError:
                print("Please enter a valid number.")

        interface_name = interfaces[selected_idx][0]
        print(f"\nStarting packet capture on: {interface_name}")

    # Capture configuration
    stop_event = threading.Event()
    capture_thread = threading.Thread(target=capture_packets, 
                                      args=(interface_name, packet_queue, stop_event),
                                      daemon=True)
    capture_thread.start()

    # Capture and process for 30 seconds
    capture_duration = 30
    start_time = time.time()
    try:
        while time.time() - start_time < capture_duration:
            process_packets(packet_queue, flow_dict)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    finally:
        stop_event.set()
        capture_thread.join(timeout=5)

    # Feature extraction
    print("\nProcessing captured network flows...")
    features_list = []
    for flow in flow_dict.values():
        features = flow.compute_features()
        features_list.append(features)

    # Save to CSV
    if features_list:
        df = pd.DataFrame(features_list)
        output_file = 'network_traffic_features.csv'
        df.to_csv(output_file, index=False)
        print(f"\nFeatures saved to {output_file}")
        print(f"Total flows captured: {len(features_list)}")
    else:
        print("No network flows were captured.")

if __name__ == '__main__':
    main()
