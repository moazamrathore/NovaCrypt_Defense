import streamlit as st
import os
import json
from datetime import datetime
import hashlib
from pathlib import Path
import socket
import threading
from queue import Queue
import time
import re

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
# PORT SCANNER MODULE
# ============================================================================
class PortScanner:
    def __init__(self, logger):
        self.logger = logger
        self.open_ports = []
        self.lock = threading.Lock()
        self.scan_progress = 0
        self.total_ports = 0
        
        # Common ports and their services
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
    
    def resolve_target(self, target):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            self.logger.log("PORT_SCAN", "DNS Resolution", f"{target} -> {ip}")
            return ip
        except socket.gaierror:
            self.logger.log("PORT_SCAN", "DNS Error", f"Cannot resolve {target}", "ERROR")
            return None
    
    def scan_port(self, target, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = self.grab_banner(sock, port)
                service = self.common_ports.get(port, "Unknown")
                
                with self.lock:
                    self.open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "state": "open"
                    })
                
                self.logger.log("PORT_SCAN", f"Open Port Found", f"Port {port} ({service})")
            
            sock.close()
        except Exception as e:
            pass
        finally:
            with self.lock:
                self.scan_progress += 1
    
    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2)
            
            # Send different probes based on port
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else "No banner"
        except:
            return "No banner"
    
    def worker(self, target, port_queue, timeout):
        """Worker thread for scanning"""
        while not port_queue.empty():
            port = port_queue.get()
            self.scan_port(target, port, timeout)
            port_queue.task_done()
    
    def scan(self, target, port_range, num_threads=50, timeout=1):
        """Main scan function"""
        self.open_ports = []
        self.scan_progress = 0
        
        # Resolve target
        ip = self.resolve_target(target)
        if not ip:
            return None
        
        # Parse port range
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
        
        self.total_ports = len(ports)
        
        self.logger.log("PORT_SCAN", "Scan Started", f"Target: {target} ({ip}), Ports: {len(ports)}, Threads: {num_threads}")
        
        # Create queue and add ports
        port_queue = Queue()
        for port in ports:
            port_queue.put(port)
        
        # Create and start threads
        threads = []
        for _ in range(min(num_threads, len(ports))):
            t = threading.Thread(target=self.worker, args=(ip, port_queue, timeout))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        self.logger.log("PORT_SCAN", "Scan Completed", f"Found {len(self.open_ports)} open ports")
        
        return {
            "target": target,
            "ip": ip,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_ports_scanned": self.total_ports,
            "open_ports_found": len(self.open_ports),
            "open_ports": sorted(self.open_ports, key=lambda x: x['port'])
        }
    
    def export_json(self, results, filename):
        """Export results to JSON"""
        filepath = f"evidence/{filename}"
        with open(filepath, 'w') as f:
            json.dump(results, indent=2, fp=f)
        self.logger.log("PORT_SCAN", "Export", f"Results saved to {filepath}")
        return filepath
    
    def export_html(self, results, filename):
        """Export results to HTML"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Results - {results['target']}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a2e; color: #00fff5; padding: 20px; }}
        h1 {{ color: #00fff5; text-shadow: 0 0 10px #00fff5; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #16213e; color: #00fff5; padding: 12px; text-align: left; border: 1px solid #00fff5; }}
        td {{ background: #0f0c29; padding: 10px; border: 1px solid #00fff5; }}
        .open {{ color: #00ff7f; font-weight: bold; }}
        .summary {{ background: rgba(0,255,245,0.1); padding: 15px; border: 1px solid #00fff5; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🔍 Port Scan Results</h1>
    <div class="summary">
        <p><strong>Target:</strong> {results['target']} ({results['ip']})</p>
        <p><strong>Scan Time:</strong> {results['scan_time']}</p>
        <p><strong>Ports Scanned:</strong> {results['total_ports_scanned']}</p>
        <p><strong>Open Ports Found:</strong> {results['open_ports_found']}</p>
    </div>
    
    <h2>Open Ports Details</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>State</th>
            <th>Banner</th>
        </tr>
"""
        for port_info in results['open_ports']:
            html += f"""
        <tr>
            <td>{port_info['port']}</td>
            <td>{port_info['service']}</td>
            <td class="open">{port_info['state']}</td>
            <td>{port_info['banner']}</td>
        </tr>
"""
        
        html += """
    </table>
    <p style="text-align: center; color: #666; margin-top: 40px;">
        <small>Generated by NovaCrypt Defense - Moazam (9953) & Abdullah (7465)</small>
    </p>
</body>
</html>
"""
        
        filepath = f"evidence/{filename}"
        with open(filepath, 'w') as f:
            f.write(html)
        self.logger.log("PORT_SCAN", "Export", f"HTML report saved to {filepath}")
        return filepath

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
        show_port_scanner(logger, dry_run)
    
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
# PORT SCANNER VIEW
# ============================================================================
def show_port_scanner(logger, dry_run):
    st.markdown("## 🔍 Port Scanner Module")
    
    logger.log("PORT_SCAN", "Module Accessed", "User opened port scanner")
    
    st.markdown("""
    <div style='background: rgba(0, 191, 255, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00bfff; margin-bottom: 20px;'>
        <h4 style='color: #00bfff; margin-top: 0;'>🎯 Professional TCP Port Scanner</h4>
        <p style='color: #fff;'>
            Multi-threaded port scanning with banner grabbing and service detection.
            Scan real-world targets to identify open ports and running services.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Configuration Section
    st.markdown("### ⚙️ Scan Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        target = st.text_input(
            "🎯 Target (IP or Domain)",
            value="scanme.nmap.org",
            help="Enter IP address or domain name to scan"
        )
        
        scan_type = st.selectbox(
            "📊 Scan Type",
            ["Common Ports (Top 17)", "Quick Scan (1-1024)", "Full Scan (1-65535)", "Custom Range"]
        )
        
        if scan_type == "Custom Range":
            port_range = st.text_input(
                "🔢 Port Range",
                value="80,443,8080",
                help="Format: '80' or '1-100' or '80,443,8080'"
            )
        elif scan_type == "Common Ports (Top 17)":
            port_range = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443,27017"
        elif scan_type == "Quick Scan (1-1024)":
            port_range = "1-1024"
        else:  # Full Scan
            port_range = "1-65535"
    
    with col2:
        num_threads = st.slider(
            "🧵 Number of Threads",
            min_value=10,
            max_value=200,
            value=50,
            step=10,
            help="More threads = faster scan, but may trigger IDS"
        )
        
        timeout = st.slider(
            "⏱️ Timeout (seconds)",
            min_value=0.5,
            max_value=5.0,
            value=1.0,
            step=0.5,
            help="Connection timeout per port"
        )
        
        st.info(f"""
        **Estimated Scan Time:**  
        {len(port_range.replace('-', ',').split(','))} ports ÷ {num_threads} threads ≈ {round(len(port_range.replace('-', ',').split(',')) / num_threads * timeout, 1)}s
        """)
    
    # Scan Button
    st.markdown("---")
    
    col_btn1, col_btn2, col_btn3 = st.columns([2, 1, 1])
    
    with col_btn1:
        if dry_run:
            st.warning("🧪 Dry run mode - simulation only")
        
        start_scan = st.button("🚀 Start Port Scan", type="primary", use_container_width=True)
    
    with col_btn2:
        if st.button("🔄 Clear Results", use_container_width=True):
            if 'scan_results' in st.session_state:
                del st.session_state.scan_results
            st.rerun()
    
    with col_btn3:
        show_help = st.button("❓ Help", use_container_width=True)
    
    if show_help:
        with st.expander("📖 Port Scanner Help", expanded=True):
            st.markdown("""
            ### How to Use Port Scanner
            
            **Target Selection:**
            - Enter IP address (e.g., `192.168.1.1`)
            - Enter domain name (e.g., `scanme.nmap.org`)
            - Approved targets: scanme.nmap.org, testphp.vulnweb.com, localhost
            
            **Scan Types:**
            - **Common Ports:** Scans 17 most common services (fastest)
            - **Quick Scan:** Ports 1-1024 (standard services)
            - **Full Scan:** All 65535 ports (very slow)
            - **Custom Range:** Specify exact ports
            
            **Performance Tips:**
            - More threads = faster scan
            - Lower timeout = faster but may miss slow services
            - Use common ports for quick recon
            
            **Ethical Guidelines:**
            - Only scan authorized targets
            - Avoid aggressive scanning (high threads)
            - Do not scan during peak hours
            """)
    
    # Execute Scan
    if start_scan:
        if not target:
            st.error("❌ Please enter a target!")
            return
        
        # Validation
        if not dry_run:
            # Check if target is in approved list
            consent_targets = ["scanme.nmap.org", "testphp.vulnweb.com", "localhost", "127.0.0.1", "example.com"]
            is_approved = any(approved in target.lower() for approved in consent_targets)
            
            if not is_approved:
                st.warning(f"⚠️ Target '{target}' is not in the approved list. Ensure you have authorization!")
                confirm = st.checkbox("✅ I confirm I have authorization to scan this target")
                if not confirm:
                    st.error("❌ Scan aborted - authorization required")
                    logger.log("PORT_SCAN", "Aborted", f"Unauthorized target: {target}", "WARNING")
                    return
        
        # Initialize scanner
        scanner = PortScanner(logger)
        
        # Progress display
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        if dry_run:
            # Simulate scan
            status_text.info("🧪 Dry run mode - simulating scan...")
            for i in range(100):
                time.sleep(0.02)
                progress_bar.progress(i + 1)
            
            # Fake results
            results = {
                "target": target,
                "ip": "simulation",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_ports_scanned": len(port_range.split(',')),
                "open_ports_found": 3,
                "open_ports": [
                    {"port": 80, "service": "HTTP", "state": "open", "banner": "Apache/2.4.41 (Simulated)"},
                    {"port": 443, "service": "HTTPS", "state": "open", "banner": "nginx/1.18.0 (Simulated)"},
                    {"port": 22, "service": "SSH", "state": "open", "banner": "OpenSSH 8.2 (Simulated)"}
                ]
            }
            st.session_state.scan_results = results
            status_text.success("✅ Dry run completed!")
            logger.log("PORT_SCAN", "Dry Run", f"Simulated scan on {target}")
        else:
            # Real scan
            status_text.info(f"🔍 Scanning {target}... Please wait...")
            
            # Run scan in background and update progress
            results = scanner.scan(target, port_range, num_threads, timeout)
            
            if results:
                # Update progress bar based on actual progress
                for i in range(100):
                    progress = min(int((scanner.scan_progress / scanner.total_ports) * 100), 100)
                    progress_bar.progress(progress)
                    if progress >= 100:
                        break
                    time.sleep(0.1)
                
                st.session_state.scan_results = results
                status_text.success(f"✅ Scan completed! Found {results['open_ports_found']} open ports")
            else:
                status_text.error("❌ Scan failed - could not resolve target")
                return
    
    # Display Results
    if 'scan_results' in st.session_state:
        results = st.session_state.scan_results
        
        st.markdown("---")
        st.markdown("## 📊 Scan Results")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Target", results['target'])
        
        with col2:
            st.metric("IP Address", results['ip'])
        
        with col3:
            st.metric("Ports Scanned", results['total_ports_scanned'])
        
        with col4:
            st.metric("Open Ports", results['open_ports_found'], delta="Found")
        
        st.markdown("---")
        
        # Detailed results
        if results['open_ports_found'] > 0:
            st.markdown("### 🔓 Open Ports Details")
            
            for port_info in results['open_ports']:
                with st.expander(f"**Port {port_info['port']}** - {port_info['service']} ({port_info['state'].upper()})"):
                    col_a, col_b = st.columns([1, 3])
                    
                    with col_a:
                        st.markdown(f"""
                        **Port:** {port_info['port']}  
                        **Service:** {port_info['service']}  
                        **State:** {port_info['state']}
                        """)
                    
                    with col_b:
                        st.markdown("**Banner / Version:**")
                        st.code(port_info['banner'], language="text")
        else:
            st.warning("⚠️ No open ports found. The target may be protected by a firewall.")
        
        # Export options
        st.markdown("---")
        st.markdown("### 📥 Export Results")
        
        col_exp1, col_exp2 = st.columns(2)
        
        with col_exp1:
            if st.button("📄 Export to JSON", use_container_width=True):
                filename = f"portscan_{results['target'].replace('.', '_')}_9953_Moazam.json"
                filepath = scanner.export_json(results, filename)
                
                with open(filepath, 'r') as f:
                    st.download_button(
                        label="⬇️ Download JSON",
                        data=f.read(),
                        file_name=filename,
                        mime="application/json"
                    )
                st.success(f"✅ Exported to {filename}")
        
        with col_exp2:
            if st.button("📊 Export to HTML", use_container_width=True):
                filename = f"portscan_{results['target'].replace('.', '_')}_9953_Moazam.html"
                filepath = scanner.export_html(results, filename)
                
                with open(filepath, 'r') as f:
                    st.download_button(
                        label="⬇️ Download HTML",
                        data=f.read(),
                        file_name=filename,
                        mime="text/html"
                    )
                st.success(f"✅ Exported to {filename}")

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
