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
    
    # Welcome message with more details
    st.markdown("""
    <div style='background: rgba(0, 255, 245, 0.1); padding: 25px; border-radius: 10px; border: 1px solid #00fff5;'>
        <h3 style='color: #00fff5; margin-top: 0;'>⚡ Welcome to NovaCrypt Defense</h3>
        <p style='color: #fff; font-size: 1.1rem; line-height: 1.6;'>
            A comprehensive Python-based security toolkit designed for PayBuddy FinTech security testing.
            This suite provides <strong>6 powerful modules</strong> for authorized penetration testing and vulnerability assessment.
        </p>
        <p style='color: #00bfff; margin-bottom: 0;'>
            📌 <strong>Select any module below or use the sidebar</strong> to begin your security assessment.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Feature Grid with clickable cards
    st.markdown("### 🎯 Available Security Modules")
    st.markdown("*Click on any module card to start testing*")
    st.markdown("<br>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Port Scanner", key="btn_port", use_container_width=True):
            st.session_state.selected_module = "🔍 Port Scanner"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(0, 191, 255, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00bfff; min-height: 180px;'>
            <h4 style='color: #00bfff;'>🔍 Port Scanner</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • Multi-threaded TCP port scanning<br>
                • Service detection & banner grabbing<br>
                • Export results to JSON/HTML<br>
                • Identify open ports & running services
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        if st.button("🔑 Password Testing", key="btn_pass", use_container_width=True):
            st.session_state.selected_module = "🔑 Password Assessment"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(0, 255, 127, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00ff7f; min-height: 180px;'>
            <h4 style='color: #00ff7f;'>🔑 Password Testing</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • Password strength analysis<br>
                • Policy compliance checking<br>
                • Entropy calculation (Shannon)<br>
                • Hash simulation (MD5/SHA256/bcrypt)
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        if st.button("💥 Stress Testing", key="btn_dos", use_container_width=True):
            st.session_state.selected_module = "💥 DOS/Stress Test"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(255, 165, 0, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ffa500; min-height: 180px;'>
            <h4 style='color: #ffa500;'>💥 Stress Testing</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • Controlled DOS simulation<br>
                • HTTP flood testing (max 200 clients)<br>
                • Real-time latency monitoring<br>
                • Performance graphs & reports
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    col4, col5, col6 = st.columns(3)
    
    with col4:
        if st.button("🌐 Web Discovery", key="btn_web", use_container_width=True):
            st.session_state.selected_module = "🌐 Web Discovery"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(138, 43, 226, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #8a2be2; min-height: 180px;'>
            <h4 style='color: #8a2be2;'>🌐 Web Discovery</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • Directory enumeration (DIRB-style)<br>
                • Subdomain discovery<br>
                • API endpoint detection<br>
                • Hidden resource identification
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        if st.button("📦 Packet Capture", key="btn_packet", use_container_width=True):
            st.session_state.selected_module = "📦 Packet Capture"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(255, 20, 147, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ff1493; min-height: 180px;'>
            <h4 style='color: #ff1493;'>📦 Packet Capture</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • Real-time traffic capture<br>
                • Protocol analysis (HTTP/DNS/TCP)<br>
                • Save .pcap files<br>
                • Network traffic visualization
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col6:
        if st.button("📊 Reports & Logs", key="btn_logs", use_container_width=True):
            st.session_state.selected_module = "📊 Logs & Reports"
            st.rerun()
        st.markdown("""
        <div style='background: rgba(255, 69, 0, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #ff4500; min-height: 180px;'>
            <h4 style='color: #ff4500;'>📊 Reports & Logs</h4>
            <p style='color: #ccc; font-size: 0.9rem; line-height: 1.5;'>
                <strong>Capabilities:</strong><br>
                • View all security logs<br>
                • SHA-256 integrity verification<br>
                • Export PDF/Word/JSON reports<br>
                • Comprehensive findings summary
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Important Notes with more details
    st.markdown("### ⚠️ Important Security Guidelines")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.warning("""
        **🔒 Ethical Testing Principles**
        
        - ✅ Only test **authorized targets** listed in consent.txt
        - ✅ Never attack external/public systems without written permission
        - ✅ Follow **responsible disclosure** for discovered vulnerabilities
        - ✅ Use **rate limiting** to avoid service disruption
        - ✅ Document all activities for audit trails
        
        **⚖️ Legal Compliance:**
        Unauthorized access to computer systems is illegal under computer fraud laws.
        Always obtain proper authorization before testing.
        """)
    
    with col_b:
        st.info("""
        **📋 Evidence Collection System**
        
        - 📝 **Timestamped Logging:** Every action recorded with precise timestamps
        - 🔐 **SHA-256 Integrity:** Cryptographic verification of log authenticity
        - 📊 **Auto Reports:** PDF/Word/JSON exports with findings
        - 💾 **Persistent Storage:** All logs saved to `evidence/` directory
        - 🔍 **Audit Ready:** Logs formatted for security audits
        
        **📌 File Naming Convention:**
        All outputs include registration numbers (e.g., `scan_9953_Moazam.json`)
        """)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Module Status Overview
    st.markdown("### 📊 Module Status Overview")
    
    status_col1, status_col2, status_col3, status_col4, status_col5, status_col6 = st.columns(6)
    
    with status_col1:
        st.metric("Port Scanner", "✅ Ready", delta="Active")
    
    with status_col2:
        st.metric("Password Test", "✅ Ready", delta="Active")
    
    with status_col3:
        st.metric("Stress Test", "✅ Ready", delta="Active")
    
    with status_col4:
        st.metric("Web Discovery", "✅ Ready", delta="Active")
    
    with status_col5:
        st.metric("Packet Capture", "✅ Ready", delta="Active")
    
    with status_col6:
        st.metric("Reports", "✅ Ready", delta="Active")
    
    # Quick Start Guide with more details
    with st.expander("📖 Quick Start Guide - How to Use This Toolkit"):
        st.markdown("""
        ### 🚀 Getting Started with NovaCrypt Defense
        
        #### **Step 1: Identity Verification** ✅
        - The system automatically verifies `identity.txt` and `consent.txt`
        - Check the sidebar for ✅ green checkmarks confirming verification
        - If files are missing, they'll be created automatically with team information
        
        #### **Step 2: Select Your Module** 🎯
        You can select a module in **two ways**:
        - **Option A:** Click any module card on the dashboard (above)
        - **Option B:** Use the dropdown in the sidebar under "Select Module"
        
        #### **Step 3: Configure Testing Parameters** ⚙️
        Each module has specific configuration options:
        - **Port Scanner:** Enter target IP/domain, port range, thread count
        - **Password Test:** Input passwords for analysis or upload hash files
        - **Stress Test:** Set target URL, client count (max 200), duration
        - **Web Discovery:** Specify target domain, wordlist selection
        - **Packet Capture:** Choose network interface, filter protocols
        
        #### **Step 4: Run Your Security Assessment** 🚀
        - Review all parameters before execution
        - Click the main action button (e.g., "Start Scan", "Run Test")
        - Monitor real-time output in the interface
        - All actions are logged automatically
        
        #### **Step 5: Analyze Results** 📊
        - View detailed results directly in the interface
        - Download reports in multiple formats (PDF/Word/JSON)
        - Check "Logs & Reports" module for complete activity history
        - Export findings for documentation
        
        #### **Step 6: Review Security Logs** 📝
        - Navigate to "Logs & Reports" from sidebar or dashboard
        - View timestamped entries for all activities
        - Verify log integrity with SHA-256 hash
        - Export logs for audit purposes
        
        ---
        
        ### 🛡️ Best Practices
        
        **Before Testing:**
        - ✅ Verify you have written authorization
        - ✅ Ensure targets are in consent.txt
        - ✅ Use dry-run mode first to test configuration
        - ✅ Review rate limits and throttling settings
        
        **During Testing:**
        - ⚡ Monitor system resources
        - ⚡ Watch for error messages or warnings
        - ⚡ Keep notes of unusual findings
        - ⚡ Be prepared to stop tests if issues arise
        
        **After Testing:**
        - 📋 Generate comprehensive reports
        - 📋 Document all vulnerabilities found
        - 📋 Provide remediation recommendations
        - 📋 Archive logs for compliance
        
        ---
        
        ### 💡 Pro Tips
        
        - 🎯 Start with **Port Scanner** to identify open services
        - 🎯 Use **Password Assessment** to test authentication strength
        - 🎯 Run **Stress Tests** during off-peak hours
        - 🎯 **Web Discovery** is great for API reconnaissance
        - 🎯 **Packet Capture** helps understand traffic patterns
        - 🎯 Always check **Logs & Reports** after each test
        
        ---
        
        ### 🆘 Troubleshooting
        
        **Issue: Module not responding**
        - Check your internet connection
        - Verify target is accessible
        - Review firewall settings
        
        **Issue: Permission errors**
        - Ensure identity.txt and consent.txt are present
        - Verify target is in approved list
        - Check file permissions
        
        **Issue: Export not working**
        - Ensure evidence/ directory exists
        - Check available disk space
        - Try different export format
        """)
    
    if dry_run:
        st.warning("🧪 **Dry Run Mode Active** - Simulations only, no actual attacks will be performed")
    
    # Additional Context Section
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🎓 Academic Context")
    
    info_col1, info_col2, info_col3 = st.columns(3)
    
    with info_col1:
        st.info("""
        **📚 Course Information**
        
        - **Course:** CY4053 - Cybersecurity for FinTech
        - **Semester:** Fall 2025
        - **Institution:** BSFT 7th Semester
        - **Project Type:** Final Group Project
        """)
    
    with info_col2:
        st.success("""
        **👥 Team: NovaCrypt Defense**
        
        - Moazam (BSFT07-9953)
        - Abdullah (BSFT07-7465)
        
        **Deadline:** November 30, 2025
        """)
    
    with info_col3:
        st.warning("""
        **🎯 Project Scenario**
        
        Security testing toolkit for **PayBuddy** - a fictional FinTech startup processing online payments and micro-transactions.
        """)

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
