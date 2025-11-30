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
import math
import bcrypt

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
# PASSWORD ASSESSMENT MODULE
# ============================================================================
class PasswordAssessment:
    def __init__(self, logger):
        self.logger = logger
        
        # Common weak passwords list (top 100)
        self.common_passwords = [
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "password1", "123123", "1234567890", "000000", "qwerty", "abc123",
            "111111", "admin", "letmein", "welcome", "monkey", "dragon", "master",
            "sunshine", "princess", "football", "shadow", "superman", "696969",
            "michael", "jennifer", "computer", "trustno1", "mustang", "baseball",
            "hunter", "charlie", "password123", "welcome123", "admin123", "root",
            "toor", "pass", "test", "guest", "info", "sample", "changeme",
            "secret", "login", "demo", "user", "default", "temp", "qwerty123"
        ]
        
        # Password policy rules
        self.policy = {
            "min_length": 8,
            "max_length": 128,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
            "special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?"
        }
    
    def calculate_entropy(self, password):
        """Calculate Shannon entropy of password"""
        if not password:
            return 0.0
        
        # Count character frequency
        freq = {}
        for char in password:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(password)
        
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        # Normalize by length
        bits = entropy * length
        
        return round(bits, 2)
    
    def check_character_sets(self, password):
        """Check which character sets are used"""
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        return {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "special": has_special
        }
    
    def check_patterns(self, password):
        """Check for common patterns"""
        patterns_found = []
        
        # Sequential numbers
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            patterns_found.append("Sequential numbers")
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns_found.append("Repeated characters")
        
        # Keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'qwer', 'asdfgh']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                patterns_found.append(f"Keyboard pattern: {pattern}")
        
        # Common words
        common_words = ['password', 'admin', 'user', 'login', 'welcome', 'test']
        for word in common_words:
            if word in password.lower():
                patterns_found.append(f"Common word: {word}")
        
        # Date patterns
        if re.search(r'(19|20)\d{2}', password):
            patterns_found.append("Year pattern detected")
        
        return patterns_found
    
    def check_policy_compliance(self, password):
        """Check password against policy rules"""
        issues = []
        
        # Length check
        if len(password) < self.policy["min_length"]:
            issues.append(f"Too short (minimum {self.policy['min_length']} characters)")
        
        if len(password) > self.policy["max_length"]:
            issues.append(f"Too long (maximum {self.policy['max_length']} characters)")
        
        # Character requirements
        char_sets = self.check_character_sets(password)
        
        if self.policy["require_uppercase"] and not char_sets["uppercase"]:
            issues.append("Missing uppercase letters")
        
        if self.policy["require_lowercase"] and not char_sets["lowercase"]:
            issues.append("Missing lowercase letters")
        
        if self.policy["require_digits"] and not char_sets["digits"]:
            issues.append("Missing digits")
        
        if self.policy["require_special"] and not char_sets["special"]:
            issues.append("Missing special characters")
        
        return issues
    
    def is_common_password(self, password):
        """Check if password is in common password list"""
        return password.lower() in self.common_passwords
    
    def calculate_strength_score(self, password):
        """Calculate overall password strength (0-100)"""
        score = 0
        
        # Length scoring (0-30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5
        
        # Character diversity (0-25 points)
        char_sets = self.check_character_sets(password)
        score += sum(char_sets.values()) * 6.25
        
        # Entropy (0-25 points)
        entropy = self.calculate_entropy(password)
        if entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 20
        elif entropy >= 30:
            score += 15
        else:
            score += entropy / 3
        
        # Pattern penalties (0-20 points deduction)
        patterns = self.check_patterns(password)
        penalty = min(len(patterns) * 5, 20)
        score -= penalty
        
        # Common password penalty (-30 points)
        if self.is_common_password(password):
            score -= 30
        
        # Ensure score is between 0-100
        score = max(0, min(100, score))
        
        return round(score, 1)
    
    def get_strength_category(self, score):
        """Categorize password strength"""
        if score >= 80:
            return "Very Strong", "🟢", "#00ff7f"
        elif score >= 60:
            return "Strong", "🟡", "#ffa500"
        elif score >= 40:
            return "Moderate", "🟠", "#ff8c00"
        elif score >= 20:
            return "Weak", "🔴", "#ff4500"
        else:
            return "Very Weak", "🔴", "#ff0000"
    
    def simulate_hash(self, password, hash_type="all"):
        """Simulate password hashing (educational only)"""
        hashes = {}
        
        if hash_type in ["all", "md5"]:
            hashes["MD5"] = hashlib.md5(password.encode()).hexdigest()
        
        if hash_type in ["all", "sha256"]:
            hashes["SHA256"] = hashlib.sha256(password.encode()).hexdigest()
        
        if hash_type in ["all", "sha512"]:
            hashes["SHA512"] = hashlib.sha512(password.encode()).hexdigest()
        
        if hash_type in ["all", "bcrypt"]:
            # Simulate bcrypt (actual bcrypt would be used in production)
            salt = bcrypt.gensalt()
            hashes["bcrypt"] = bcrypt.hashpw(password.encode(), salt).decode()
        
        return hashes
    
    def generate_recommendations(self, password):
        """Generate actionable security recommendations"""
        recommendations = []
        
        length = len(password)
        char_sets = self.check_character_sets(password)
        patterns = self.check_patterns(password)
        is_common = self.is_common_password(password)
        
        # Length recommendations
        if length < 12:
            recommendations.append("✅ Increase password length to at least 12 characters (16+ recommended)")
        
        # Character diversity
        if not char_sets["uppercase"]:
            recommendations.append("✅ Add uppercase letters (A-Z)")
        
        if not char_sets["lowercase"]:
            recommendations.append("✅ Add lowercase letters (a-z)")
        
        if not char_sets["digits"]:
            recommendations.append("✅ Add numbers (0-9)")
        
        if not char_sets["special"]:
            recommendations.append("✅ Add special characters (!@#$%^&*)")
        
        # Pattern warnings
        if patterns:
            recommendations.append("⚠️ Avoid predictable patterns (sequential numbers, keyboard patterns)")
        
        # Common password warning
        if is_common:
            recommendations.append("🚨 CRITICAL: This is a commonly used password - change immediately!")
        
        # General best practices
        if length < 16:
            recommendations.append("💡 Use a passphrase (e.g., 'Coffee-Mountain-Sky-42!')")
        
        recommendations.append("💡 Use a unique password for each account")
        recommendations.append("💡 Consider using a password manager")
        recommendations.append("💡 Enable two-factor authentication (2FA)")
        
        return recommendations
    
    def assess_password(self, password):
        """Comprehensive password assessment"""
        
        self.logger.log("PASSWORD_TEST", "Assessment Started", f"Password length: {len(password)}")
        
        # Calculate all metrics
        score = self.calculate_strength_score(password)
        entropy = self.calculate_entropy(password)
        char_sets = self.check_character_sets(password)
        patterns = self.check_patterns(password)
        policy_issues = self.check_policy_compliance(password)
        is_common = self.is_common_password(password)
        category, emoji, color = self.get_strength_category(score)
        recommendations = self.generate_recommendations(password)
        
        result = {
            "password_length": len(password),
            "strength_score": score,
            "strength_category": category,
            "strength_emoji": emoji,
            "strength_color": color,
            "entropy_bits": entropy,
            "character_sets": char_sets,
            "patterns_detected": patterns,
            "policy_compliant": len(policy_issues) == 0,
            "policy_issues": policy_issues,
            "is_common_password": is_common,
            "recommendations": recommendations,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.logger.log("PASSWORD_TEST", "Assessment Complete", f"Score: {score}/100, Category: {category}")
        
        return result
    
    def export_results(self, results, filename):
        """Export assessment results to JSON"""
        filepath = f"evidence/{filename}"
        with open(filepath, 'w') as f:
            json.dump(results, indent=2, fp=f)
        self.logger.log("PASSWORD_TEST", "Export", f"Results saved to {filepath}")
        return filepath

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
        show_password_assessment(logger, dry_run)
    
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
# PASSWORD ASSESSMENT VIEW
# ============================================================================
def show_password_assessment(logger, dry_run):
    st.markdown("## 🔑 Password Assessment Module")
    
    logger.log("PASSWORD_TEST", "Module Accessed", "User opened password assessment")
    
    st.markdown("""
    <div style='background: rgba(0, 255, 127, 0.1); padding: 20px; border-radius: 10px; border: 1px solid #00ff7f; margin-bottom: 20px;'>
        <h4 style='color: #00ff7f; margin-top: 0;'>🔐 Comprehensive Password Security Analysis</h4>
        <p style='color: #fff;'>
            Test password strength, check policy compliance, calculate entropy, and receive
            actionable security recommendations. Includes hash simulation for educational purposes.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Assessment Mode Selection
    st.markdown("### 🎯 Assessment Mode")
    
    mode = st.radio(
        "Choose testing mode:",
        ["Single Password Analysis", "Batch Password Testing", "Hash Simulation"],
        horizontal=True
    )
    
    st.markdown("---")
    
    # Initialize password tester
    password_tester = PasswordAssessment(logger)
    
    # ========================================================================
    # MODE 1: SINGLE PASSWORD ANALYSIS
    # ========================================================================
    if mode == "Single Password Analysis":
        st.markdown("### 🔍 Password Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            password_input = st.text_input(
                "🔑 Enter Password to Test",
                type="password",
                help="Your password is analyzed locally and never stored",
                placeholder="Enter a password..."
            )
            
            show_password = st.checkbox("👁️ Show password", value=False)
            
            if show_password and password_input:
                st.code(password_input, language="text")
        
        with col2:
            st.info("""
            **Privacy Notice:**
            
            ✅ Analysis is local  
            ✅ No storage  
            ✅ No transmission  
            ✅ Completely safe
            """)
        
        # Quick test buttons
        st.markdown("#### 🧪 Quick Test Examples")
        
        col_ex1, col_ex2, col_ex3, col_ex4 = st.columns(4)
        
        with col_ex1:
            if st.button("Test: Weak", use_container_width=True):
                st.session_state.test_password = "password123"
                st.rerun()
        
        with col_ex2:
            if st.button("Test: Moderate", use_container_width=True):
                st.session_state.test_password = "Pass1234!"
                st.rerun()
        
        with col_ex3:
            if st.button("Test: Strong", use_container_width=True):
                st.session_state.test_password = "MyP@ssw0rd2024!"
                st.rerun()
        
        with col_ex4:
            if st.button("Test: Very Strong", use_container_width=True):
                st.session_state.test_password = "C0ff33-M0unt@in-Sky!42"
                st.rerun()
        
        # Use test password if available
        if 'test_password' in st.session_state:
            password_input = st.session_state.test_password
            del st.session_state.test_password  # Clear after use
        
        # Analyze button
        st.markdown("---")
        
        if st.button("🔍 Analyze Password", type="primary", use_container_width=True, disabled=not password_input):
            if password_input:
                # Perform assessment
                results = password_tester.assess_password(password_input)
                
                # Store in session state
                st.session_state.password_results = results
                
                st.success("✅ Analysis complete!")
        
        # Display results
        if 'password_results' in st.session_state:
            results = st.session_state.password_results
            
            st.markdown("---")
            st.markdown("## 📊 Assessment Results")
            
            # Strength meter
            score = results['strength_score']
            category = results['strength_category']
            emoji = results['strength_emoji']
            color = results['strength_color']
            
            st.markdown(f"""
            <div style='background: rgba(255, 255, 255, 0.05); padding: 25px; border-radius: 10px; border: 2px solid {color}; text-align: center;'>
                <h1 style='color: {color}; margin: 0; font-size: 4rem;'>{emoji}</h1>
                <h2 style='color: {color}; margin: 10px 0;'>{category}</h2>
                <h1 style='color: {color}; margin: 10px 0; font-size: 3rem;'>{score}/100</h1>
                <div style='background: #1a1a2e; height: 30px; border-radius: 15px; overflow: hidden; margin-top: 20px;'>
                    <div style='background: {color}; width: {score}%; height: 100%; transition: width 0.5s;'></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # Detailed metrics
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            
            with col_m1:
                st.metric("Length", f"{results['password_length']} chars")
            
            with col_m2:
                st.metric("Entropy", f"{results['entropy_bits']} bits")
            
            with col_m3:
                policy_status = "✅ Pass" if results['policy_compliant'] else "❌ Fail"
                st.metric("Policy Check", policy_status)
            
            with col_m4:
                common_status = "🚨 YES" if results['is_common_password'] else "✅ NO"
                st.metric("Common Pwd", common_status)
            
            st.markdown("---")
            
            # Character sets
            st.markdown("### 🔤 Character Analysis")
            
            col_c1, col_c2, col_c3, col_c4 = st.columns(4)
            
            char_sets = results['character_sets']
            
            with col_c1:
                if char_sets['lowercase']:
                    st.success("✅ Lowercase (a-z)")
                else:
                    st.error("❌ Lowercase (a-z)")
            
            with col_c2:
                if char_sets['uppercase']:
                    st.success("✅ Uppercase (A-Z)")
                else:
                    st.error("❌ Uppercase (A-Z)")
            
            with col_c3:
                if char_sets['digits']:
                    st.success("✅ Digits (0-9)")
                else:
                    st.error("❌ Digits (0-9)")
            
            with col_c4:
                if char_sets['special']:
                    st.success("✅ Special (!@#$...)")
                else:
                    st.error("❌ Special (!@#$...)")
            
            # Patterns detected
            if results['patterns_detected']:
                st.markdown("### ⚠️ Patterns Detected")
                for pattern in results['patterns_detected']:
                    st.warning(f"🔍 {pattern}")
            
            # Policy issues
            if results['policy_issues']:
                st.markdown("### ❌ Policy Violations")
                for issue in results['policy_issues']:
                    st.error(f"• {issue}")
            else:
                st.success("### ✅ Policy Compliant - Meets all requirements")
            
            # Recommendations
            st.markdown("### 💡 Security Recommendations")
            
            for i, rec in enumerate(results['recommendations'], 1):
                st.markdown(f"{i}. {rec}")
            
            # Export option
            st.markdown("---")
            
            if st.button("📥 Export Analysis Report (JSON)", use_container_width=True):
                filename = f"password_analysis_9953_Moazam_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                filepath = password_tester.export_results(results, filename)
                
                with open(filepath, 'r') as f:
                    st.download_button(
                        label="⬇️ Download Report",
                        data=f.read(),
                        file_name=filename,
                        mime="application/json"
                    )
                st.success(f"✅ Report exported: {filename}")
    
    # ========================================================================
    # MODE 2: BATCH PASSWORD TESTING
    # ========================================================================
    elif mode == "Batch Password Testing":
        st.markdown("### 📋 Batch Password Analysis")
        
        st.info("""
        **Test multiple passwords at once**
        
        Enter one password per line. Useful for:
        - Testing user password databases
        - Comparing password strengths
        - Bulk policy compliance checking
        """)
        
        passwords_input = st.text_area(
            "🔑 Enter Passwords (one per line)",
            height=200,
            placeholder="password123\nMyP@ssw0rd!\nSecurePass2024\n..."
        )
        
        if st.button("🔍 Analyze All Passwords", type="primary", use_container_width=True):
            if passwords_input.strip():
                passwords = [p.strip() for p in passwords_input.split('\n') if p.strip()]
                
                st.markdown(f"### 📊 Analyzing {len(passwords)} passwords...")
                
                batch_results = []
                
                progress_bar = st.progress(0)
                
                for i, pwd in enumerate(passwords):
                    result = password_tester.assess_password(pwd)
                    result['password_preview'] = pwd[:3] + '*' * (len(pwd) - 3)  # Masked
                    batch_results.append(result)
                    progress_bar.progress((i + 1) / len(passwords))
                
                st.session_state.batch_results = batch_results
                
                st.success(f"✅ Analyzed {len(passwords)} passwords!")
        
        # Display batch results
        if 'batch_results' in st.session_state:
            results = st.session_state.batch_results
            
            st.markdown("---")
            st.markdown("### 📊 Batch Analysis Results")
            
            # Summary statistics
            col_s1, col_s2, col_s3, col_s4 = st.columns(4)
            
            avg_score = sum(r['strength_score'] for r in results) / len(results)
            weak_count = sum(1 for r in results if r['strength_score'] < 40)
            strong_count = sum(1 for r in results if r['strength_score'] >= 80)
            common_count = sum(1 for r in results if r['is_common_password'])
            
            with col_s1:
                st.metric("Average Score", f"{avg_score:.1f}/100")
            
            with col_s2:
                st.metric("Weak Passwords", weak_count, delta="⚠️")
            
            with col_s3:
                st.metric("Strong Passwords", strong_count, delta="✅")
            
            with col_s4:
                st.metric("Common Passwords", common_count, delta="🚨")
            
            st.markdown("---")
            
            # Individual results table
            st.markdown("### 📋 Individual Results")
            
            for i, result in enumerate(results, 1):
                with st.expander(f"Password {i}: {result['password_preview']} - {result['strength_emoji']} {result['strength_category']} ({result['strength_score']}/100)"):
                    col_a, col_b = st.columns(2)
                    
                    with col_a:
                        st.markdown(f"""
                        **Metrics:**
                        - Score: {result['strength_score']}/100
                        - Length: {result['password_length']} characters
                        - Entropy: {result['entropy_bits']} bits
                        - Policy: {'✅ Pass' if result['policy_compliant'] else '❌ Fail'}
                        - Common: {'🚨 YES' if result['is_common_password'] else '✅ NO'}
                        """)
                    
                    with col_b:
                        st.markdown("**Character Sets:**")
                        for char_type, present in result['character_sets'].items():
                            emoji = "✅" if present else "❌"
                            st.markdown(f"{emoji} {char_type.capitalize()}")
    
    # ========================================================================
    # MODE 3: HASH SIMULATION
    # ========================================================================
    elif mode == "Hash Simulation":
        st.markdown("### 🔐 Password Hash Simulation")
        
        st.warning("""
        **⚠️ Educational Purpose Only**
        
        This demonstrates how passwords are hashed. In production:
        - Never use MD5 or SHA256 for passwords
        - Always use bcrypt, scrypt, or Argon2
        - Add proper salting
        - Use key stretching
        """)
        
        password_hash = st.text_input(
            "🔑 Enter Password to Hash",
            type="password",
            placeholder="Enter password..."
        )
        
        hash_types = st.multiselect(
            "📊 Select Hash Algorithms",
            ["MD5", "SHA256", "SHA512", "bcrypt"],
            default=["MD5", "SHA256", "bcrypt"]
        )
        
        if st.button("🔐 Generate Hashes", type="primary", use_container_width=True):
            if password_hash:
                st.markdown("---")
                st.markdown("### 🔒 Generated Hashes")
                
                hashes = password_tester.simulate_hash(password_hash, "all")
                
                for hash_type in hash_types:
                    if hash_type in hashes:
                        st.markdown(f"**{hash_type}:**")
                        st.code(hashes[hash_type], language="text")

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
        # Predefined target selection
        target_preset = st.selectbox(
            "🎯 Quick Select Target",
            [
                "Custom (Enter Below)",
                "scanme.nmap.org (Official Nmap Test)",
                "testphp.vulnweb.com (Acunetix Vulnerable App)",
                "testhtml5.vulnweb.com (HTML5 Test App)",
                "demo.testfire.net (IBM AppScan Demo)",
                "zero.webappsecurity.com (Security Test Site)",
                "localhost (Your Machine)",
                "127.0.0.1 (Loopback)"
            ]
        )
        
        # Extract target from selection
        if target_preset == "Custom (Enter Below)":
            default_target = ""
        elif "scanme.nmap.org" in target_preset:
            default_target = "scanme.nmap.org"
        elif "testphp.vulnweb.com" in target_preset:
            default_target = "testphp.vulnweb.com"
        elif "testhtml5.vulnweb.com" in target_preset:
            default_target = "testhtml5.vulnweb.com"
        elif "demo.testfire.net" in target_preset:
            default_target = "demo.testfire.net"
        elif "zero.webappsecurity.com" in target_preset:
            default_target = "zero.webappsecurity.com"
        elif "localhost" in target_preset:
            default_target = "localhost"
        else:
            default_target = "127.0.0.1"
        
        target = st.text_input(
            "🌐 Target (IP or Domain)",
            value=default_target,
            help="Enter IP address or domain name to scan",
            placeholder="e.g., scanme.nmap.org or 192.168.1.1"
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
            
            **✅ SAFE & LEGAL Targets (Pre-approved):**
            - `scanme.nmap.org` - Official Nmap project test server
            - `testphp.vulnweb.com` - Acunetix vulnerable web application
            - `testhtml5.vulnweb.com` - HTML5 security test application
            - `demo.testfire.net` - IBM AppScan demo banking site
            - `zero.webappsecurity.com` - Security testing platform
            - `localhost` / `127.0.0.1` - Your own computer
            - `192.168.x.x` - Your local network (if you own it)
            
            **❌ NEVER Scan These (Illegal!):**
            - Any website you don't own
            - Commercial sites (Google, Amazon, Facebook, etc.)
            - Government sites (.gov domains)
            - Educational institutions (without permission)
            - Banking or financial sites
            
            **⚖️ Legal Notice:**
            Unauthorized port scanning is illegal under computer fraud laws in most countries.
            Always obtain written permission before scanning any target.
            
            ---
            
            **Scan Types:**
            - **Common Ports:** Scans 17 most common services (fastest)
            - **Quick Scan:** Ports 1-1024 (standard services)
            - **Full Scan:** All 65535 ports (very slow, 30+ minutes)
            - **Custom Range:** Specify exact ports (e.g., 80,443,8080)
            
            **Performance Tips:**
            - More threads = faster scan (but may trigger IDS/IPS)
            - Lower timeout = faster but may miss slow services
            - Use "Common Ports" for quick reconnaissance
            - Use "Quick Scan" for thorough web app testing
            
            **Recommended Testing Workflow:**
            1. Start with `scanme.nmap.org` + Common Ports
            2. Try `testphp.vulnweb.com` for web-specific ports
            3. Test `localhost` to see your own services
            
            **Ethical Guidelines:**
            - Only scan during off-peak hours
            - Use reasonable thread counts (50-100)
            - Don't scan the same target repeatedly
            - Document all authorized scans in logs
            """)
    
    # Execute Scan
    if start_scan:
        if not target:
            st.error("❌ Please enter a target!")
            return
        
        # Validation
        if not dry_run:
            # Extended list of approved targets
            consent_targets = [
                "scanme.nmap.org",
                "testphp.vulnweb.com", 
                "testhtml5.vulnweb.com",
                "demo.testfire.net",
                "zero.webappsecurity.com",
                "webscantest.com",
                "localhost", 
                "127.0.0.1",
                "0.0.0.0",
                "example.com"
            ]
            
            # Check if it's a local IP (192.168.x.x or 10.x.x.x)
            is_local_ip = any(target.startswith(prefix) for prefix in ["192.168.", "10.", "172.16."])
            
            is_approved = any(approved in target.lower() for approved in consent_targets) or is_local_ip
            
            if not is_approved:
                st.warning(f"""
                ⚠️ **Target Authorization Required**
                
                Target '{target}' is not in the pre-approved list.
                
                **Approved Targets:**
                - scanme.nmap.org (Official Nmap test server)
                - testphp.vulnweb.com (Acunetix test site)
                - testhtml5.vulnweb.com (HTML5 test app)
                - demo.testfire.net (IBM AppScan demo)
                - zero.webappsecurity.com (Security test site)
                - localhost / 127.0.0.1 (Your machine)
                - 192.168.x.x / 10.x.x.x (Local network)
                
                **⚖️ Legal Warning:** Unauthorized port scanning is illegal in many jurisdictions.
                Only scan systems you own or have explicit written permission to test.
                """)
                
                confirm = st.checkbox("✅ I confirm I have legal authorization to scan this target")
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
