# dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import json
from pathlib import Path

# Set page config
st.set_page_config(
    page_title="DDoS Detection Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'last_processed_time' not in st.session_state:
    st.session_state.last_processed_time = time.time()
if 'flow_history' not in st.session_state:
    st.session_state.flow_history = []

def load_latest_data():
    """Load the latest network traffic predictions"""
    try:
        df = pd.read_csv('network_traffic_predictions.csv')
        return df
    except Exception as e:
        return None

def update_metrics(df):
    """Update dashboard metrics"""
    total_flows = len(df) if df is not None else 0
    ddos_flows = df['Prediction'].sum() if df is not None else 0
    benign_flows = total_flows - ddos_flows if df is not None else 0
    
    return total_flows, ddos_flows, benign_flows

def create_protocol_chart(df):
    """Create protocol distribution chart"""
    if df is not None and not df.empty:
        protocol_counts = df['Protocol'].value_counts()
        fig = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title='Protocol Distribution'
        )
        return fig
    return None

def create_time_series(flow_history):
    """Create time series of flow counts"""
    df = pd.DataFrame(flow_history)
    if not df.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['ddos_flows'],
            name='DDoS Flows',
            line=dict(color='red')
        ))
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['benign_flows'],
            name='Benign Flows',
            line=dict(color='green')
        ))
        fig.update_layout(
            title='Flow Detection Over Time',
            xaxis_title='Time',
            yaxis_title='Number of Flows'
        )
        return fig
    return None

def main():
    # Header
    st.title("🛡️ Real-time DDoS Detection Monitor")
    st.markdown("---")
    
    # Create layout
    col1, col2, col3 = st.columns(3)
    
    # Initialize metrics placeholders
    total_metric = col1.metric("Total Flows", "0")
    ddos_metric = col2.metric("DDoS Flows", "0")
    benign_metric = col3.metric("Benign Flows", "0")
    
    # Create charts placeholders
    protocol_chart = st.empty()
    time_series_chart = st.empty()
    
    # Create table placeholder
    flow_table = st.empty()
    
    # Main loop for updating dashboard
    while True:
        # Load latest data
        df = load_latest_data()
        
        if df is not None and not df.empty:
            # Update metrics
            total_flows, ddos_flows, benign_flows = update_metrics(df)
            
            # Update session state
            st.session_state.flow_history.append({
                'timestamp': datetime.now(),
                'total_flows': total_flows,
                'ddos_flows': ddos_flows,
                'benign_flows': benign_flows
            })
            
            # Keep only last 100 points
            if len(st.session_state.flow_history) > 100:
                st.session_state.flow_history.pop(0)
            
            # Update metrics display
            total_metric.metric("Total Flows", total_flows)
            ddos_metric.metric("DDoS Flows", ddos_flows)
            benign_metric.metric("Benign Flows", benign_flows)
            
            # Update charts
            protocol_chart.plotly_chart(create_protocol_chart(df))
            time_series_chart.plotly_chart(create_time_series(st.session_state.flow_history))
            
            # Update table
            flow_table.dataframe(df.tail(10))
        
        # Wait before next update
        time.sleep(1)

if __name__ == "__main__":
    main()