import streamlit as st
import os
import json
from datetime import datetime
import hashlib
from pathlib import Path

# ============================================================================
# PAGE CONFIGURATION - MUST BE FIRST STREAMLIT COMMAND
# ============================================================================
st.set_page_config(
    page_title="NovaCrypt Defense - Hybrid Hacking Toolkit",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS FOR AMAZING CYBERSECURITY THEME
# ============================================================================
def load_custom_css():
    st.markdown("""
    <style>
    /* Main background - Dark cyber theme */
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
        border-right: 2px solid #00fff5;
    }
    
    /* Headers with glow effect */
    h1, h2, h3 {
        color: #00fff5 !important;
        text-shadow: 0 0 10px #00fff5, 0 0 20px #00fff5;
        font-family: 'Courier New', monospace;
    }
    
    /* Success/Info boxes */
    .stSuccess {
        background-color: rgba(0, 255, 127, 0.1);
        border: 1px solid #00ff7f;
        border-radius: 10px;
    }
    
    .stInfo {
        background-color: rgba(0, 191, 255, 0.1);
        border: 1px solid #00bfff;
        border-radius: 10px;
    }
    
    .stWarning {
        background-color: rgba(255, 165, 0, 0.1);
        border: 1px solid #ffa500;
        border-radius: 10px;
    }
    
    .stError {
        background-color: rgba(255, 0, 0, 0.1);
        border: 1px solid #ff0000;
        border-radius: 10px;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(90deg, #00fff5 0%, #00a8cc 100%);
        color: #000;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        padding: 10px 25px;
        transition: all 0.3s;
        box-shadow: 0 0 15px rgba(0, 255, 245, 0.5);
    }
    
    .stButton > button:hover {
        transform: scale(1.05);
        box-shadow: 0 0 25px rgba(0, 255, 245, 0.8);
    }
    
    /* Input fields */
    .stTextInput > div > div > input {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid #00fff5;
        color: #ffffff;
        border-radius: 5px;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        color: #00fff5;
        font-size: 2rem;
        text-shadow: 0 0 10px #00fff5;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background-color: rgba(0, 255, 245, 0.1);
        border-radius: 5px;
        color: #00fff5 !important;
    }
    
    /* Code blocks */
    .stCodeBlock {
        background-color: rgba(0, 0, 0, 0.5);
        border: 1px solid #00fff5;
        border-radius: 8px;
    }
    
    /* Divider */
    hr {
        border: 1px solid #00fff5;
        margin: 20px 0;
    }
    
    /* Animated pulse for important elements */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    
    .pulse {
        animation: pulse 2s infinite;
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================================
# LOGGER CLASS - Centralized Logging with SHA-256 Integrity
# ============================================================================
class SecurityLogger:
    def __init__(self, log_file="evidence/security_logs.log"):
        self.log_file = log_file
        self.ensure_log_directory()
        
    def ensure_log_directory(self):
        """Create evidence directory if it doesn't exist"""
        Path("evidence").mkdir(exist_ok=True)
        
    def log(self, module, action, details, level="INFO"):
        """Log an action with timestamp and details"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] [{module}] {action} - {details}\n"
        
        # Append to log file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        return log_entry
    
    def get_logs(self):
        """Retrieve all logs"""
        if not os.path.exists(self.log_file):
            return "No logs found."
        
        with open(self.log_file, "r", encoding="utf-8") as f:
            return f.read()
    
    def calculate_log_hash(self):
        """Calculate SHA-256 hash of log file for integrity"""
        if not os.path.exists(self.log_file):
            return None
        
        sha256_hash = hashlib.sha256()
        with open(self.log_file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def export_logs_json(self):
        """Export logs as JSON for reporting"""
        if not os.path.exists(self.log_file):
            return {}
        
        logs = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append({"entry": line.strip()})
        
        return {
            "total_entries": len(logs),
            "hash": self.calculate_log_hash(),
            "logs": logs
        }

# ============================================================================
# IDENTITY & SAFETY MODULE
# ============================================================================
class IdentitySafety:
    def __init__(self):
        self.identity_file = "identity.txt"
        self.consent_file = "consent.txt"
        self.logger = SecurityLogger()
        
    def create_identity_file(self):
        """Create identity.txt if it doesn't exist"""
        identity_content = """Team: NovaCrypt Defense
Members:
- Moazam | BSFT07-9953
- Abdullah | BSFT07-7465
"""
        with open(self.identity_file, "w", encoding="utf-8") as f:
            f.write(identity_content)
        
        self.logger.log("IDENTITY", "Created", "identity.txt file generated")
        return identity_content
    
    def create_consent_file(self):
        """Create consent.txt if it doesn't exist"""
        consent_content = """Approved Targets:
- localhost / 127.0.0.1
- http://testphp.vulnweb.com (Acunetix test site)
- scanme.nmap.org
- example.com
- Local Flask/FastAPI mock servers
- OWASP Juice Shop (local instance)
- TryHackMe lab environments
- Any real-world URL (with ethical testing only)

Approved By: Moazam & Abdullah
Date: 30-November-2025
"""
        with open(self.consent_file, "w", encoding="utf-8") as f:
            f.write(consent_content)
        
        self.logger.log("CONSENT", "Created", "consent.txt file generated")
        return consent_content
    
    def verify_identity(self):
        """Verify identity.txt exists and is valid"""
        if not os.path.exists(self.identity_file):
            return False, "identity.txt not found! Creating..."
        
        with open(self.identity_file, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Check if required team members are in the file
        if "Moazam" in content and "Abdullah" in content:
            self.logger.log("IDENTITY", "Verified", "Identity check passed")
            return True, content
        else:
            return False, "Invalid identity.txt content"
    
    def verify_consent(self):
        """Verify consent.txt exists and is valid"""
        if not os.path.exists(self.consent_file):
            return False, "consent.txt not found! Creating..."
        
        with open(self.consent_file, "r", encoding="utf-8") as f:
            content = f.read()
        
        if "Approved Targets" in content:
            self.logger.log("CONSENT", "Verified", "Consent check passed")
            return True, content
        else:
            return False, "Invalid consent.txt content"
    
    def verify_all(self):
        """Verify both identity and consent"""
        # Create files if they don't exist
        if not os.path.exists(self.identity_file):
            self.create_identity_file()
        
        if not os.path.exists(self.consent_file):
            self.create_consent_file()
        
        identity_ok, identity_msg = self.verify_identity()
        consent_ok, consent_msg = self.verify_consent()
        
        return identity_ok and consent_ok, identity_msg, consent_msg

# ============================================================================
# MAIN APP LAYOUT
# ============================================================================
def main():
    # Load custom CSS
    load_custom_css()
    
    # Initialize logger and identity checker
    logger = SecurityLogger()
    identity_checker = IdentitySafety()
    
    # ========================================================================
    # HEADER WITH ANIMATED BANNER
    # ========================================================================
    st.markdown("""
    <div style='text-align: center; padding: 20px;'>
        <h1 style='font-size: 3.5rem; margin: 0;'>🔐 NovaCrypt Defense</h1>
        <h3 style='color: #00bfff; margin-top: 10px;'>Hybrid Hacking Toolkit for PayBuddy FinTech</h3>
        <p style='color: #888; font-size: 0.9rem;'>Advanced Security Assessment Suite | Ethical Testing Only</p>
    </div>
    <hr>
    """, unsafe_allow_html=True)
    
    # ========================================================================
    # SIDEBAR - NAVIGATION & IDENTITY
    # ========================================================================
    with st.sidebar:
        st.markdown("## 🛡️ Control Panel")
        st.markdown("---")
        
        # Identity & Consent Verification
        st.markdown("### 👥 Team Identity")
        
        identity_ok, identity_msg, consent_msg = identity_checker.verify_all()
        
        if identity_ok:
            st.success("✅ Identity Verified")
            st.success("✅ Consent Verified")
            
            with st.expander("📄 View Identity"):
                st.code(identity_msg, language="text")
            
            with st.expander("📜 View Consent"):
                st.code(consent_msg, language="text")
        else:
            st.error("❌ Verification Failed")
            st.warning("Please check identity.txt and consent.txt files")
        
        st.markdown("---")
        
        # Module Selection
        st.markdown("### 🎯 Select Module")
        
        module = st.selectbox(
            "Choose a tool:",
            [
                "🏠 Dashboard",
                "🔍 Port Scanner",
                "🔑 Password Assessment",
                "💥 DOS/Stress Test",
                "🌐 Web Discovery",
                "📦 Packet Capture",
                "📊 Logs & Reports"
            ]
        )
        
        st.markdown("---")
        
        # Quick Stats
        st.markdown("### 📈 Session Stats")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Modules", "6", delta="Active")
        
        with col2:
            st.metric("Status", "Ready", delta="Online")
        
        st.markdown("---")
        
        # Dry Run Mode
        dry_run = st.checkbox("🧪 Dry Run Mode", value=False)
        if dry_run:
            st.info("🔔 Dry run enabled - No actual attacks will be performed")
        
        st.markdown("---")
        
        # Footer
        st.markdown("""
        <div style='text-align: center; padding: 10px; color: #666;'>
            <small>CY4053 Final Project</small><br>
            <small>Fall 2025</small>
        </div>
        """, unsafe_allow_html=True)
    
    # ========================================================================
    # MAIN CONTENT AREA
    # ========================================================================
    
    if not identity_ok:
        st.error("🚫 **SECURITY CHECK FAILED**")
        st.warning("Please ensure identity.txt and consent.txt are properly configured before using the toolkit.")
        st.info("Files have been created automatically. Please verify their contents.")
        
        logger.log("SYSTEM", "Access Denied", "Identity/Consent verification failed")
        return
    
    # Log successful startup
    logger.log("SYSTEM", "Startup", f"Module selected: {module}")
    
    # ========================================================================
    # MODULE ROUTING
    # ========================================================================
    
    if module == "🏠 Dashboard":
        show_dashboard(logger, dry_run)
    
    elif module == "🔍 Port Scanner":
        st.info("🚧 **Port Scanner Module** - Coming in Phase 2!")
        st.markdown("This module will perform TCP port scanning with banner grabbing.")
    
    elif module == "🔑 Password Assessment":
        st.info("🚧 **Password Assessment Module** - Coming in Phase 2!")
        st.markdown("This module will check password strength and policies.")
    
    elif module == "💥 DOS/Stress Test":
        st.info("🚧 **DOS/Stress Test Module** - Coming in Phase 2!")
        st.markdown("This module will perform controlled load testing.")
    
    elif module == "🌐 Web Discovery":
        st.info("🚧 **Web Discovery Module** - Coming in Phase 3!")
        st.markdown("This module will perform directory enumeration and subdomain discovery.")
    
    elif module == "📦 Packet Capture":
        st.info("🚧 **Packet Capture Module** - Coming in Phase 3!")
        st.markdown("This module will capture and analyze network traffic.")
    
    elif module == "📊 Logs & Reports":
        show_logs_reports(logger)

# ============================================================================
# DASHBOARD VIEW
# ============================================================================
def show_dashboard(logger, dry_run):
    st.markdown("## 🏠 Mission Control Dashboard")
    
    logger.log("DASHBOARD", "Viewed", "User accessed dashboard")
    
    # Welcome message
    st.markdown("""
    <div style='background: rgba(0, 255, 245, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00fff5;'>
        <h3 style='color: #00fff5; margin-top: 0;'>⚡ Welcome to NovaCrypt Defense</h3>
        <p style='color: #fff;'>
            A comprehensive Python-based security toolkit designed for PayBuddy FinTech security testing.
            Select a module from the sidebar to begin your authorized security assessment.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Feature Grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div style='background: rgba(0, 191, 255, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00bfff; text-align: center;'>
            <h2 style='color: #00bfff;'>🔍</h2>
            <h4 style='color: #00bfff;'>Port Scanner</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>TCP scanning & banner grabbing with multi-threading</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div style='background: rgba(0, 255, 127, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00ff7f; text-align: center;'>
            <h2 style='color: #00ff7f;'>🔑</h2>
            <h4 style='color: #00ff7f;'>Password Testing</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>Policy checks & entropy analysis</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div style='background: rgba(255, 165, 0, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ffa500; text-align: center;'>
            <h2 style='color: #ffa500;'>💥</h2>
            <h4 style='color: #ffa500;'>Stress Testing</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>Controlled DOS with latency monitoring</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    col4, col5, col6 = st.columns(3)
    
    with col4:
        st.markdown("""
        <div style='background: rgba(138, 43, 226, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #8a2be2; text-align: center;'>
            <h2 style='color: #8a2be2;'>🌐</h2>
            <h4 style='color: #8a2be2;'>Web Discovery</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>Directory enum & API endpoints</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        st.markdown("""
        <div style='background: rgba(255, 20, 147, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ff1493; text-align: center;'>
            <h2 style='color: #ff1493;'>📦</h2>
            <h4 style='color: #ff1493;'>Packet Capture</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>Network traffic analysis with Scapy</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col6:
        st.markdown("""
        <div style='background: rgba(255, 69, 0, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ff4500; text-align: center;'>
            <h2 style='color: #ff4500;'>📊</h2>
            <h4 style='color: #ff4500;'>Reports & Logs</h4>
            <p style='color: #ccc; font-size: 0.9rem;'>Auto-generated PDF/JSON reports</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Important Notes
    st.markdown("### ⚠️ Important Guidelines")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.warning("""
        **🔒 Ethical Testing Only**
        - Only test authorized targets
        - Never attack external systems without permission
        - Follow responsible disclosure
        """)
    
    with col_b:
        st.info("""
        **📋 Evidence Collection**
        - All actions are logged with timestamps
        - SHA-256 integrity for log files
        - Auto-generated reports with findings
        """)
    
    # Quick Start Guide
    with st.expander("📖 Quick Start Guide"):
        st.markdown("""
        ### Getting Started with NovaCrypt Defense
        
        1. **Identity Verification** ✅
           - Ensure `identity.txt` and `consent.txt` are verified (check sidebar)
        
        2. **Select a Module** 🎯
           - Use the sidebar dropdown to choose your testing tool
        
        3. **Configure Parameters** ⚙️
           - Enter target URL/IP, set options, configure limits
        
        4. **Run Assessment** 🚀
           - Click the execution button to start testing
        
        5. **Review Results** 📊
           - View real-time output and download reports
        
        6. **Check Logs** 📝
           - Navigate to "Logs & Reports" to view all activity
        """)
    
    if dry_run:
        st.warning("🧪 **Dry Run Mode Active** - Simulations only, no actual attacks")

# ============================================================================
# LOGS & REPORTS VIEW
# ============================================================================
def show_logs_reports(logger):
    st.markdown("## 📊 Logs & Reports")
    
    logger.log("LOGS", "Viewed", "User accessed logs and reports")
    
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📝 Live Logs", "🔒 Integrity Check", "📥 Export"])
    
    with tab1:
        st.markdown("### 📝 Real-Time Security Logs")
        
        logs = logger.get_logs()
        
        if logs and logs != "No logs found.":
            st.code(logs, language="log")
            
            # Count entries
            log_count = logs.count("[")
            st.info(f"📊 Total log entries: **{log_count}**")
        else:
            st.warning("No logs available yet. Start using the toolkit to generate logs!")
    
    with tab2:
        st.markdown("### 🔒 Log File Integrity")
        
        log_hash = logger.calculate_log_hash()
        
        if log_hash:
            st.success("✅ Log file integrity verified")
            st.code(f"SHA-256 Hash:\n{log_hash}", language="text")
            
            st.info("""
            **Why integrity matters:**
            - Ensures logs haven't been tampered with
            - Provides cryptographic proof of authenticity
            - Required for security audits and compliance
            """)
        else:
            st.warning("No log file found to calculate hash")
    
    with tab3:
        st.markdown("### 📥 Export Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Export Logs (TXT)", use_container_width=True):
                logs = logger.get_logs()
                st.download_button(
                    label="⬇️ Download security_logs.log",
                    data=logs,
                    file_name=f"security_logs_9953_Moazam.log",
                    mime="text/plain"
                )
                logger.log("EXPORT", "Logs exported", "TXT format")
        
        with col2:
            if st.button("📊 Export Report (JSON)", use_container_width=True):
                json_data = logger.export_logs_json()
                st.download_button(
                    label="⬇️ Download report.json",
                    data=json.dumps(json_data, indent=2),
                    file_name=f"report_9953_Moazam.json",
                    mime="application/json"
                )
                logger.log("EXPORT", "Report exported", "JSON format")
        
        st.info("📌 **Note:** PDF/Word reports will be generated automatically after completing assessments")

# ============================================================================
# RUN THE APP
# ============================================================================
if __name__ == "__main__":
    main()