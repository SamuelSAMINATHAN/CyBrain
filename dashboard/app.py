#!/usr/bin/env python3
"""
CyBrain SOC Dashboard
Real-time monitoring dashboard using Streamlit
"""

import json
import time
from pathlib import Path
import streamlit as st
import pandas as pd
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="CyBrain SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
    }
    .alert-card {
        background-color: #fff3cd;
        padding: 15px;
        border-radius: 5px;
        border-left: 5px solid #ffc107;
        margin: 10px 0;
    }
    .blocked-card {
        background-color: #f8d7da;
        padding: 15px;
        border-radius: 5px;
        border-left: 5px solid #dc3545;
        margin: 10px 0;
    }
    .normal-card {
        background-color: #d1ecf1;
        padding: 15px;
        border-radius: 5px;
        border-left: 5px solid #17a2b8;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

class CyBrainDashboard:
    def __init__(self):
        self.workspace = Path(__file__).parent.parent
        self.alerts_file = self.workspace / "data" / "alerts.json"
        self.last_update = None

    def load_alerts(self) -> list:
        """Load alerts from JSON file"""
        try:
            if not self.alerts_file.exists():
                return []

            with open(self.alerts_file, "r") as f:
                alerts = json.load(f)

            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return alerts
        except Exception as e:
            st.error(f"Failed to load alerts: {e}")
            return []

    def get_kpis(self, alerts: list) -> dict:
        """Calculate KPIs from alerts"""
        total_logs = len(alerts)
        blocked_alerts = sum(1 for alert in alerts if alert.get("action") == "blocked")
        false_positives = sum(1 for alert in alerts
                            if alert.get("action") == "blocked" and
                            alert.get("mitre", {}).get("technique") == "Anomalie Inconnue")

        return {
            "total_logs": total_logs,
            "blocked_alerts": blocked_alerts,
            "false_positives": false_positives
        }

    def display_header(self):
        """Display dashboard header"""
        st.title("🛡️ CyBrain SOC Dashboard")
        st.markdown("*Real-time Endpoint Detection & Response*")

        col1, col2, col3 = st.columns(3)

        alerts = self.load_alerts()
        kpis = self.get_kpis(alerts)

        with col1:
            st.metric("Total Logs Analyzed", kpis["total_logs"])

        with col2:
            st.metric("Blocked Alerts", kpis["blocked_alerts"])

        with col3:
            st.metric("False Positives", kpis["false_positives"])

    def display_alerts_table(self, alerts: list):
        """Display table of all flagged alerts"""
        st.header("🚨 Alert Overview")

        if not alerts:
            st.info("No alerts detected yet. The system is monitoring...")
            return

        # Filter alerts with MSE > 0.05 (flagged by auto-encoder)
        flagged_alerts = [alert for alert in alerts if alert.get("mse", 0) > 0.05]

        if not flagged_alerts:
            st.info("No anomalies detected yet.")
            return

        # Prepare data for table
        table_data = []
        for alert in flagged_alerts:
            mitre = alert.get("mitre", {})
            process = alert.get("event", {}).get("process", {})

            table_data.append({
                "Timestamp": alert.get("timestamp", ""),
                "PID": process.get("pid", "N/A"),
                "Process": process.get("binary", "N/A"),
                "MSE Score": f"{alert.get('mse', 0):.4f}",
                "Technique": mitre.get("technique", "Unknown"),
                "Confidence": f"{mitre.get('confidence', 0):.2%}",
                "Action": alert.get("action", "monitored")
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)

    def display_mitre_details(self, alerts: list):
        """Display MITRE ATT&CK details for detected techniques"""
        st.header("🎯 MITRE ATT&CK Analysis")

        # Filter alerts with GNN detections (not "Normal" or "Anomalie Inconnue")
        mitre_alerts = [alert for alert in alerts
                       if alert.get("mitre", {}).get("technique", "").startswith("T")
                       and alert.get("mitre", {}).get("technique") != "Anomalie Inconnue"]

        if not mitre_alerts:
            st.info("No MITRE techniques detected yet.")
            return

        for alert in mitre_alerts[:10]:  # Show last 10
            mitre = alert.get("mitre", {})
            process = alert.get("event", {}).get("process", {})

            with st.container():
                st.markdown(f"""
                <div class="alert-card">
                    <h4>{mitre.get('technique', 'Unknown')} - {mitre.get('tactic', 'Unknown')}</h4>
                    <p><strong>Process:</strong> {process.get('binary', 'N/A')} (PID: {process.get('pid', 'N/A')})</p>
                    <p><strong>Confidence:</strong> {mitre.get('confidence', 0):.2%}</p>
                    <p><strong>Description:</strong> {mitre.get('description', 'No description available')}</p>
                    <p><strong>Timestamp:</strong> {alert.get('timestamp', '')}</p>
                </div>
                """, unsafe_allow_html=True)

    def display_false_positives(self, alerts: list):
        """Display false positives (unmatched anomalies)"""
        st.header("❓ False Positives")

        false_positives = [alert for alert in alerts
                          if alert.get("mitre", {}).get("technique") == "Anomalie Inconnue"]

        if not false_positives:
            st.success("No false positives detected!")
            return

        st.warning(f"Found {len(false_positives)} potential false positives that need investigation.")

        for alert in false_positives[:5]:  # Show last 5
            process = alert.get("event", {}).get("process", {})

            with st.container():
                st.markdown(f"""
                <div class="blocked-card">
                    <h4>Unmatched Anomaly</h4>
                    <p><strong>Process:</strong> {process.get('binary', 'N/A')} (PID: {process.get('pid', 'N/A')})</p>
                    <p><strong>MSE Score:</strong> {alert.get('mse', 0):.4f}</p>
                    <p><strong>Timestamp:</strong> {alert.get('timestamp', '')}</p>
                    <p><em>This anomaly was not matched to any known MITRE technique and may be a false positive.</em></p>
                </div>
                """, unsafe_allow_html=True)

    def run(self):
        """Main dashboard loop"""
        self.display_header()

        # Load data
        alerts = self.load_alerts()

        # Create tabs
        tab1, tab2, tab3 = st.tabs(["📊 Overview", "🎯 MITRE Details", "❓ False Positives"])

        with tab1:
            self.display_alerts_table(alerts)

        with tab2:
            self.display_mitre_details(alerts)

        with tab3:
            self.display_false_positives(alerts)

        # Auto-refresh every 5 seconds
        time.sleep(5)
        st.rerun()

if __name__ == "__main__":
    dashboard = CyBrainDashboard()
    dashboard.run()
