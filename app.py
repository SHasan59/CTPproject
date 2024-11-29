import streamlit as st
import pandas as pd
import time
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import pygeoip
from collections import deque, OrderedDict
import datetime
import plotly.graph_objs as go
from plotly.subplots import make_subplots

# Function to get geolocation
def get_geolocation(ip):
    gi = pygeoip.GeoIP('GeoLiteCity.dat')
    try:
        return gi.record_by_addr(ip)
    except:
        return None

# Set up the Streamlit app
st.title("Real-Time Network Traffic DDoS Monitor")

# Create a single stop button at the top of the app
stop_button = st.button('Stop', key='stop_button')

# Statistics section
st.header("Statistics")
col1, col2, col3 = st.columns(3)
with col1:
    total_packets = st.empty()
with col2:
    ddos_flows = st.empty()
with col3:
    benign_flows = st.empty()

# Divider line
st.markdown("---")

# Active Flows section
st.header("Active Flows")

# Create placeholders for the tables, graphs, and map
active_flows_placeholder = st.empty()
malicious_ips_placeholder = st.empty()
graphs_placeholder = st.empty()
map_placeholder = st.empty()

# Initialize map in session state if it doesn't exist
if 'map' not in st.session_state:
    st.session_state.map = folium.Map(location=[0, 0], zoom_start=2)
    st.session_state.marker_cluster = MarkerCluster().add_to(st.session_state.map)
    st.session_state.map_counter = 0

m = st.session_state.map
marker_cluster = st.session_state.marker_cluster

# Display the initial map
st_folium(m, width=700, height=500, key="initial_map")

# Load data in chunks
chunk_size = 1000  # Adjust this value based on your needs
data_iterator = pd.read_csv('SSDP_Flood_output_copy.csv', chunksize=chunk_size)

# Initialize data structures
ip_packet_counts = {}
time_series_data = []
ip_packet_time_series = {}
recent_rows = deque(maxlen=10)
malicious_ips = OrderedDict()

# Initialize counters
total_packet_count = 0
ddos_flow_count = 0
benign_flow_count = 0

# Flag to track if the map needs updating
map_updated = False

# Process data in chunks
for chunk_index, chunk in enumerate(data_iterator):
    for row_index, row in chunk.iterrows():
        if stop_button:
            st.write('Stopped by user')
            break

        # Update counters
        total_packet_count += row['packets']
        if row['label'] == 1:
            ddos_flow_count += 1
        else:
            benign_flow_count += 1

        # Update statistics
        total_packets.metric("Total Packets", total_packet_count)
        ddos_flows.metric("DDoS Flows", ddos_flow_count)
        benign_flows.metric("Benign Flows", benign_flow_count)

        # Update the time column with current time
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        row['time'] = current_time

        # Update active flows table
        recent_rows.appendleft(row)
        active_flows_df = pd.DataFrame(list(recent_rows))
        
        active_flows_placeholder.dataframe(
            active_flows_df[['time', 'src', 'sport', 'dst', 'dport', 'protocol', 'packets']], 
            height=300, 
            use_container_width=True,
            hide_index=True
        )

        # Update the malicious IPs list if the IP is malicious
        if row['label'] == 1:
            if row['src'] not in malicious_ips:
                malicious_ips[row['src']] = True
                if len(malicious_ips) > 10:
                    malicious_ips.popitem(last=False)
                
                # Add new malicious IP to the map
                geo_info = get_geolocation(row['src'])
                if geo_info:
                    folium.Marker(
                        location=[geo_info['latitude'], geo_info['longitude']],
                        popup=row['src'],
                        icon=folium.Icon(color='red', icon='info-sign')
                    ).add_to(marker_cluster)
                
                # Set flag to update map
                map_updated = True
            
            # Format malicious IPs as a numbered list
            malicious_ips_text = "**Recent Malicious IPs:**\n"
            for i, ip in enumerate(malicious_ips.keys(), 1):
                malicious_ips_text += f"{i}. <span style='color: red;'>{ip}</span>\n"
            malicious_ips_placeholder.markdown(malicious_ips_text, unsafe_allow_html=True)
        
        # Update packet counts for the source IP
        src_ip = row['src']
        packets = row['packets']
        
        if src_ip not in ip_packet_counts:
            ip_packet_counts[src_ip] = 0
            ip_packet_time_series[src_ip] = []
        
        ip_packet_counts[src_ip] += packets
        ip_packet_time_series[src_ip].append((current_time, ip_packet_counts[src_ip]))

        # Add current total packet count to time series data
        time_series_data.append((current_time, total_packet_count))

        # Create and update the graphs
        if len(ip_packet_counts) > 0:
            fig = make_subplots(rows=3, cols=1, 
                                subplot_titles=("Top 10 Source IPs by Packet Count", 
                                                "Total Packet Count Over Time",
                                                "Packet Count per Source IP Over Time"))

            top_ips = sorted(ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ips, counts = zip(*top_ips)

            fig.add_trace(go.Bar(x=ips, y=counts), row=1, col=1)

            times, packet_counts = zip(*time_series_data[-100:])
            fig.add_trace(go.Scatter(x=times, y=packet_counts, mode='lines'), row=2, col=1)

            for ip in ips:
                ip_times, ip_counts = zip(*ip_packet_time_series[ip][-100:])
                fig.add_trace(go.Scatter(x=ip_times, y=ip_counts, mode='lines', name=ip), row=3, col=1)

            fig.update_layout(height=1200, showlegend=True)
            fig.update_xaxes(title_text="Source IP", row=1, col=1)
            fig.update_xaxes(title_text="Time", row=2, col=1)
            fig.update_xaxes(title_text="Time", row=3, col=1)
            fig.update_yaxes(title_text="Packet Count", row=1, col=1)
            fig.update_yaxes(title_text="Total Packet Count", row=2, col=1)
            fig.update_yaxes(title_text="Packet Count", row=3, col=1)

            graphs_placeholder.plotly_chart(fig, use_container_width=True)

        # Update the map if new points were added
        if map_updated:
            map_placeholder.empty()
            st.session_state.map_counter += 1
            st_folium(m, width=700, height=500, key=f"map_{st.session_state.map_counter}")
            map_updated = False
        
        time.sleep(0.1)
    
    if stop_button:
        break

st.write("Data processing complete")
