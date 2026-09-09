#!/usr/bin/env python3
"""
Static Analyzer for iOS Apps
Performs offline analysis of iOS application bundles without running the app.
"""

import os
import sys
import json
import plistlib
import subprocess
import tempfile
import shutil
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import zipfile
import hashlib
import binascii

# Try to import optional dependencies
try:
    import macholib.MachO
    MACHO_AVAILABLE = True
except ImportError:
    MACHO_AVAILABLE = False
    print("[!] macholib not installed. Install with: pip install macholib")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class PlistAnalysis:
    """Results from analyzing Info.plist"""
    bundle_id: str = ""
    app_name: str = ""
    version: str = ""
    build: str = ""
    minimum_os: str = ""
    ats_config: Dict = field(default_factory=dict)
    entitlements: Dict = field(default_factory=dict)
    privacy_usage: List[str] = field(default_factory=list)
    background_modes: List[str] = field(default_factory=list)
    url_types: List[Dict] = field(default_factory=list)
    is_encryption_exported: bool = False
    encryption_applies: bool = False

@dataclass
class BinaryAnalysis:
    """Results from analyzing the binary executable"""
    architecture: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    hardcoded_urls: List[str] = field(default_factory=list)
    hardcoded_secrets: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    crypto_functions: List[str] = field(default_factory=list)
    weak_crypto_found: List[str] = field(default_factory=list)
    linked_libraries: List[str] = field(default_factory=list)
    exported_symbols: List[str] = field(default_factory=list)
    entitilements_found: List[str] = field(default_factory=list)

@dataclass
class StaticReport:
    """Complete static analysis report"""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    app_bundle_path: str = ""
    plist_analysis: PlistAnalysis = field(default_factory=PlistAnalysis)
    binary_analysis: BinaryAnalysis = field(default_factory=BinaryAnalysis)
    security_score: int = 0
    security_issues: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""

# ---------------------------------------------------------------------------
# Static Analyzer Class
# ---------------------------------------------------------------------------
class iOSStaticAnalyzer:
    def __init__(self, output_dir: Path = Path("reports")):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ios_static_"))
        self.report = StaticReport()
        self.app_bundle_path: Optional[Path] = None
        
    def cleanup(self):
        """Remove temporary files"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            
    def analyze_app(self, app_path: Path, bundle_id: Optional[str] = None) -> StaticReport:
        """
        Main entry point for static analysis
        Args:
            app_path: Path to .ipa file or extracted .app bundle
            bundle_id: Optional bundle ID to search for (if path is a directory of IPAs)
        """
        self.app_bundle_path = app_path
        print(f"\n[STATIC] Analyzing: {app_path}")
        
        # Step 1: Locate the .app bundle
        app_bundle = self._locate_app_bundle(app_path, bundle_id)
        if not app_bundle:
            print("[STATIC] ERROR: Could not locate .app bundle")
            return self.report
            
        print(f"[STATIC] App bundle found: {app_bundle}")
        
        # Step 2: Analyze Info.plist
        plist_path = app_bundle / "Info.plist"
        if plist_path.exists():
            self.report.plist_analysis = self._analyze_plist(plist_path)
            print(f"[STATIC] Bundle ID: {self.report.plist_analysis.bundle_id}")
            print(f"[STATIC] App Name: {self.report.plist_analysis.app_name}")
        else:
            print("[STATIC] WARNING: Info.plist not found")
            
        # Step 3: Analyze binary
        binary_path = self._find_binary(app_bundle)
        if binary_path:
            self.report.binary_analysis = self._analyze_binary(binary_path)
            print(f"[STATIC] Binary analyzed: {binary_path.name}")
        else:
            print("[STATIC] WARNING: Binary executable not found")
            
        # Step 4: Analyze entitlements
        entitlements_path = app_bundle / "entitlements.plist"
        if entitlements_path.exists():
            self.report.binary_analysis.entitilements_found = self._parse_entitlements(entitlements_path)
            
        # Step 5: Calculate security score
        self._calculate_security_score()
        
        # Step 6: Generate recommendations
        self._generate_recommendations()
        
        print(f"[STATIC] Analysis complete. Security score: {self.report.security_score}/100")
        return self.report
    
    def _locate_app_bundle(self, path: Path, bundle_id: Optional[str] = None) -> Optional[Path]:
        """Find the .app bundle from IPA or directory"""
        # If it's already a .app directory
        if path.suffix == ".app" and path.is_dir():
            return path
            
        # If it's an IPA file
        if path.suffix == ".ipa" and path.exists():
            return self._extract_ipa(path, bundle_id)
            
        # If it's a directory containing IPAs or .app bundles
        if path.is_dir():
            # Check for .app bundles directly
            app_bundles = list(path.glob("*.app"))
            if app_bundles:
                if len(app_bundles) == 1:
                    return app_bundles[0]
                else:
                    # Find by bundle ID if provided
                    if bundle_id:
                        for app_dir in app_bundles:
                            plist = app_dir / "Info.plist"
                            if plist.exists():
                                try:
                                    with open(plist, 'rb') as f:
                                        info = plistlib.load(f)
                                        if info.get('CFBundleIdentifier') == bundle_id:
                                            return app_dir
                                        if app_dir.name.replace('.app', '') == bundle_id.split('.')[-1]:
                                            return app_dir
                                except:
                                    pass
                    # Ask user
                    print(f"\n[STATIC] Multiple .app bundles found:")
                    for i, app_dir in enumerate(app_bundles, 1):
                        print(f"  {i}. {app_dir.name}")
                    choice = input(f"Select app bundle (1-{len(app_bundles)}): ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(app_bundles):
                        return app_bundles[int(choice) - 1]
            
            # Check for IPA files
            ipa_files = list(path.glob("*.ipa"))
            if ipa_files:
                if len(ipa_files) == 1:
                    return self._extract_ipa(ipa_files[0], bundle_id)
                else:
                    # Find by bundle ID if provided
                    if bundle_id:
                        for ipa in ipa_files:
                            extracted = self._extract_ipa(ipa, bundle_id)
                            if extracted:
                                return extracted
                    # Ask user
                    print(f"\n[STATIC] Multiple IPA files found:")
                    for i, ipa in enumerate(ipa_files, 1):
                        print(f"  {i}. {ipa.name}")
                    choice = input(f"Select IPA (1-{len(ipa_files)}): ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(ipa_files):
                        return self._extract_ipa(ipa_files[int(choice) - 1], bundle_id)
        
        return None
    
    def _extract_ipa(self, ipa_path: Path, bundle_id: Optional[str] = None) -> Optional[Path]:
        """Extract IPA and find .app bundle"""
        extract_dir = self.temp_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[STATIC] Extracting IPA: {ipa_path.name}")
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        except Exception as e:
            print(f"[STATIC] Failed to extract IPA: {e}")
            return None
            
        # Find Payload directory
        payload_dir = extract_dir / "Payload"
        if not payload_dir.exists():
            # Some IPAs might have different structure
            app_bundles = list(extract_dir.glob("*.app"))
            if app_bundles:
                return app_bundles[0]
            return None
            
        # Find .app in Payload
        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            return None
            
        if len(app_bundles) == 1:
            return app_bundles[0]
            
        # Multiple app bundles - try to match by bundle ID
        if bundle_id:
            for app_dir in app_bundles:
                plist = app_dir / "Info.plist"
                if plist.exists():
                    try:
                        with open(plist, 'rb') as f:
                            info = plistlib.load(f)
                            if info.get('CFBundleIdentifier') == bundle_id:
                                return app_dir
                    except:
                        pass
                        
        # Return the first one
        return app_bundles[0]
    
    def _find_binary(self, app_bundle: Path) -> Optional[Path]:
        """Find the executable binary in the app bundle"""
        # First check Info.plist for executable name
        plist_path = app_bundle / "Info.plist"
        if plist_path.exists():
            try:
                with open(plist_path, 'rb') as f:
                    info = plistlib.load(f)
                    exec_name = info.get('CFBundleExecutable')
                    if exec_name:
                        binary = app_bundle / exec_name
                        if binary.exists():
                            return binary
            except:
                pass
                
        # Fallback: search for Mach-O files
        for file in app_bundle.iterdir():
            if file.suffix == "" and file.is_file():
                # Check if it's a Mach-O binary
                try:
                    with open(file, 'rb') as f:
                        magic = f.read(4)
                        if magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
                                     b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
                            return file
                except:
                    pass
                    
        # Search subdirectories
        for file in app_bundle.rglob("*"):
            if file.is_file() and file.suffix == "":
                try:
                    with open(file, 'rb') as f:
                        magic = f.read(4)
                        if magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
                                     b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
                            return file
                except:
                    pass
                    
        return None
    
    def _analyze_plist(self, plist_path: Path) -> PlistAnalysis:
        """Analyze Info.plist for security-relevant info"""
        result = PlistAnalysis()
        
        try:
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
                
            # Basic info
            result.bundle_id = plist.get('CFBundleIdentifier', '')
            result.app_name = plist.get('CFBundleName', plist.get('CFBundleDisplayName', ''))
            result.version = plist.get('CFBundleShortVersionString', '')
            result.build = plist.get('CFBundleVersion', '')
            result.minimum_os = plist.get('MinimumOSVersion', '')
            
            # App Transport Security (ATS)
            ats = plist.get('NSAppTransportSecurity', {})
            result.ats_config = ats
            
            # Privacy usage descriptions
            privacy_keys = [
                'NSBluetoothAlwaysUsageDescription',
                'NSBluetoothPeripheralUsageDescription',
                'NSCalendarsUsageDescription',
                'NSCameraUsageDescription',
                'NSContactsUsageDescription',
                'NSFaceIDUsageDescription',
                'NSHealthShareUsageDescription',
                'NSHealthUpdateUsageDescription',
                'NSHomeKitUsageDescription',
                'NSLocationAlwaysAndWhenInUseUsageDescription',
                'NSLocationAlwaysUsageDescription',
                'NSLocationWhenInUseUsageDescription',
                'NSMicrophoneUsageDescription',
                'NSMotionUsageDescription',
                'NSPhotoLibraryAddUsageDescription',
                'NSPhotoLibraryUsageDescription',
                'NSRemindersUsageDescription',
                'NSSpeechRecognitionUsageDescription',
                'NSUserTrackingUsageDescription'
            ]
            for key in privacy_keys:
                if plist.get(key):
                    result.privacy_usage.append(key)
                    
            # Background modes
            bg_modes = plist.get('UIBackgroundModes', [])
            if isinstance(bg_modes, list):
                result.background_modes = bg_modes
            
            # URL types
            url_types = plist.get('CFBundleURLTypes', [])
            if isinstance(url_types, list):
                result.url_types = url_types
                
            # Encryption
            result.is_encryption_exported = plist.get('ITSEncryptionExportComplianceCode', False)
            result.encryption_applies = plist.get('ITSAppUsesNonExemptEncryption', False)
            
        except Exception as e:
            print(f"[STATIC] Error parsing plist: {e}")
            
        return result
    
    def _analyze_binary(self, binary_path: Path) -> BinaryAnalysis:
        """Analyze the binary executable for security issues"""
        result = BinaryAnalysis()
        
        try:
            # Get file info
            stat_info = os.stat(binary_path)
            file_size = stat_info.st_size
            print(f"[STATIC] Binary size: {file_size / 1024 / 1024:.2f} MB")
            
            # Extract strings
            strings = self._extract_strings(binary_path)
            
            # Check architectures (using file command)
            try:
                output = subprocess.check_output(['file', str(binary_path)], text=True)
                if 'Mach-O' in output:
                    # Parse architecture
                    arch_pattern = re.compile(r'(arm64|armv7|armv7s|x86_64|i386)')
                    architectures = arch_pattern.findall(output)
                    result.architecture = list(set(architectures))
            except:
                pass
                
            # Find frameworks
            result.frameworks = self._find_frameworks(strings)
            
            # Find hardcoded URLs
            result.hardcoded_urls = self._find_urls(strings)
            
            # Find hardcoded secrets
            result.hardcoded_secrets = self._find_secrets(strings)
            
            # Find suspicious strings
            result.suspicious_strings = self._find_suspicious_strings(strings)
            
            # Find crypto functions
            result.crypto_functions = self._find_crypto_functions(strings)
            
            # Find weak crypto
            result.weak_crypto_found = self._find_weak_crypto(strings)
            
            # Find linked libraries (using otool if available)
            try:
                output = subprocess.check_output(['otool', '-L', str(binary_path)], text=True)
                for line in output.split('\n'):
                    if '.dylib' in line or '.framework' in line:
                        lib = line.strip().split(' ')[0]
                        if lib:
                            result.linked_libraries.append(lib)
            except:
                pass
                
        except Exception as e:
            print(f"[STATIC] Error analyzing binary: {e}")
            
        return result
    
    def _extract_strings(self, binary_path: Path) -> List[str]:
        """Extract strings from binary using strings command"""
        strings_list = []
        try:
            # Use system strings command
            output = subprocess.check_output(['strings', '-n', '4', str(binary_path)], text=True)
            strings_list = output.split('\n')
        except:
            # Fallback: read binary and extract ASCII strings
            try:
                with open(binary_path, 'rb') as f:
                    data = f.read()
                    pattern = re.compile(rb'[A-Za-z0-9./:?&=_+%#@-]{4,}')
                    matches = pattern.findall(data)
                    strings_list = [m.decode('ascii', errors='ignore') for m in matches]
            except:
                pass
        return strings_list
    
    def _find_frameworks(self, strings: List[str]) -> List[str]:
        """Identify third-party frameworks from strings"""
        frameworks = []
        known_frameworks = [
            'TrustKit', 'AFNetworking', 'Alamofire', 'Firebase', 'GoogleAnalytics',
            'Flurry', 'Mixpanel', 'Fabric', 'Crashlytics', 'AppsFlyer', 'Adjust',
            'Kochava', 'Branch', 'OneSignal', 'UrbanAirship', 'Parse',
            'Realm', 'CoreData', 'SQLite', 'FMDB', 'SDWebImage', 'Kingfisher',
            'SwiftyJSON', 'Mantle', 'ReactiveCocoa', 'RxSwift', 'Combine',
            'Starscream', 'SocketRocket', 'GRPC', 'Apollo', 'Moya',
            'CocoaAsyncSocket', 'ASIHTTPRequest', 'RestKit', 'ObjectMapper'
        ]
        
        for fw in known_frameworks:
            for s in strings:
                if fw.lower() in s.lower():
                    frameworks.append(fw)
                    break
        return list(set(frameworks))
    
    def _find_urls(self, strings: List[str]) -> List[str]:
        """Find hardcoded URLs in strings"""
        url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[-\w%!$&\'()*+,;=:@/~]*)*'
        )
        urls = []
        for s in strings:
            matches = url_pattern.findall(s)
            urls.extend(matches)
        return list(set(urls))[:50]  # Limit to avoid overwhelming
    
    def _find_secrets(self, strings: List[str]) -> List[str]:
        """Find potential hardcoded secrets"""
        secrets = []
        patterns = [
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64-like
            r'sk_live_[A-Za-z0-9]{24,}',   # Stripe live key
            r'sk_test_[A-Za-z0-9]{24,}',   # Stripe test key
            r'AIza[0-9A-Za-z\-_]{35}',     # Firebase API key
            r'-----BEGIN RSA PRIVATE KEY-----',
            r'-----BEGIN EC PRIVATE KEY-----',
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY-----',
            r'[A-Za-z0-9+/]{20,}={0,2}',   # Generic base64
        ]
        
        for pattern in patterns:
            for s in strings:
                if re.search(pattern, s):
                    # Only add if it looks like a secret (not just a long URL)
                    if not any(x in s.lower() for x in ['http', 'https', '.com', '.org', '.net']):
                        secrets.append(s[:50] + '...' if len(s) > 50 else s)
        return list(set(secrets))[:20]
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find suspicious or sensitive strings"""
        suspicious_keywords = [
            'password', 'passcode', 'secret', 'key', 'token', 'auth', 'login',
            'credential', 'certificate', 'private', 'confidential', 'secret',
            'encrypt', 'decrypt', 'cydia', 'jailbreak', 'root', 'ssh', 'sshd',
            'frida', 'debug', 'debugger', 'ptrace', 'sysctl', 'sandbox',
            'entitlement', 'provisioning', 'provision', 'mobileprovision'
        ]
        suspicious = []
        for s in strings:
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in suspicious_keywords):
                # Avoid common false positives
                if not any(x in s for x in ['/System/Library', '/usr/lib', '/Applications']):
                    suspicious.append(s[:50] + '...' if len(s) > 50 else s)
        return list(set(suspicious))[:30]
    
    def _find_crypto_functions(self, strings: List[str]) -> List[str]:
        """Find cryptographic functions used"""
        crypto_patterns = [
            'CC_SHA256', 'CC_SHA1', 'CC_MD5', 'CommonCrypto', 
            'SecKey', 'SecCertificate', 'SecTrust', 'SSL',
            'RSA', 'AES', '3DES', 'Blowfish', 'HMAC', 'PBKDF2',
            'OpenSSL', 'BoringSSL', 'LibreSSL', 'GnuTLS',
            'Cryptokit', 'CryptoSwift', 'SwiftyRSA'
        ]
        crypto_functions = []
        for s in strings:
            for pattern in crypto_patterns:
                if pattern.lower() in s.lower():
                    crypto_functions.append(pattern)
                    break
        return list(set(crypto_functions))
    
    def _find_weak_crypto(self, strings: List[str]) -> List[str]:
        """Identify weak cryptographic algorithms"""
        weak = []
        weak_patterns = ['MD5', 'SHA1', 'RC4', 'RC2', 'DES', '3DES', 'SSLv2', 'SSLv3']
        for s in strings:
            for pattern in weak_patterns:
                if pattern.lower() in s.lower():
                    weak.append(pattern)
                    break
        return list(set(weak))
    
    def _parse_entitlements(self, entitlements_path: Path) -> List[str]:
        """Parse entitlement file"""
        entitlements = []
        try:
            with open(entitlements_path, 'rb') as f:
                data = plistlib.load(f)
            for key in data.keys():
                entitlements.append(key)
        except:
            pass
        return entitlements
    
    def _calculate_security_score(self):
        """Calculate a security score based on findings"""
        score = 100
        issues = []
        
        # Check ATS
        ats = self.report.plist_analysis.ats_config
        if ats.get('NSAllowsArbitraryLoads') == True:
            score -= 15
            issues.append({'severity': 'HIGH', 'issue': 'ATS disabled - allows arbitrary HTTP connections'})
        if ats.get('NSAllowsArbitraryLoadsForMedia') == True:
            score -= 5
            issues.append({'severity': 'MEDIUM', 'issue': 'ATS partially disabled for media'})
            
        # Check encryption
        if not self.report.plist_analysis.encryption_applies:
            score -= 5
            issues.append({'severity': 'LOW', 'issue': 'App does not declare encryption usage'})
            
        # Check weak crypto
        if self.report.binary_analysis.weak_crypto_found:
            score -= 15
            issues.append({'severity': 'HIGH', 'issue': f'Weak crypto found: {", ".join(self.report.binary_analysis.weak_crypto_found)}'})
            
        # Check for hardcoded secrets
        if self.report.binary_analysis.hardcoded_secrets:
            score -= 20
            issues.append({'severity': 'CRITICAL', 'issue': f'Hardcoded secrets found ({len(self.report.binary_analysis.hardcoded_secrets)} instances)'})
            
        # Check for jailbreak detection
        jb_detection = ['cydia', 'jailbreak', 'root', 'ssh', 'sshd', 'fork', 'ptrace']
        found_jb = [s for s in self.report.binary_analysis.suspicious_strings if any(x in s.lower() for x in jb_detection)]
        if found_jb:
            score -= 10
            issues.append({'severity': 'HIGH', 'issue': f'Jailbreak detection mechanisms detected'})
            
        # Check for SSL pinning libraries
        pinning_libraries = ['TrustKit', 'AFNetworking', 'Alamofire']
        found_pinning = [fw for fw in self.report.binary_analysis.frameworks if fw in pinning_libraries]
        if found_pinning:
            score += 5  # Good - they're using pinning
            issues.append({'severity': 'INFO', 'issue': f'SSL pinning libraries found: {", ".join(found_pinning)}'})
            
        # Check for privacy violations
        if self.report.plist_analysis.privacy_usage:
            score -= len(self.report.plist_analysis.privacy_usage) * 2
            issues.append({'severity': 'MEDIUM', 'issue': f'App accesses {len(self.report.plist_analysis.privacy_usage)} sensitive permissions'})
            
        self.report.security_score = max(0, score)
        self.report.security_issues = issues
    
    def _generate_recommendations(self):
        """Generate recommendations based on findings"""
        recs = []
        
        ats = self.report.plist_analysis.ats_config
        if ats.get('NSAllowsArbitraryLoads') == True:
            recs.append("Enable App Transport Security (ATS) by setting NSAllowsArbitraryLoads to false")
            
        if self.report.binary_analysis.hardcoded_secrets:
            recs.append("Remove hardcoded secrets from binary - use secure storage or runtime retrieval")
            
        if self.report.binary_analysis.weak_crypto_found:
            recs.append(f"Replace weak cryptography ({', '.join(self.report.binary_analysis.weak_crypto_found)}) with modern algorithms")
            
        if not self.report.plist_analysis.encryption_applies:
            recs.append("Declare encryption usage in ITSAppUsesNonExemptEncryption for App Store compliance")
            
        self.report.recommendation = "\n".join(recs) if recs else "No critical issues found. Continue with dynamic testing."
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report"""
        return {
            "timestamp": self.report.timestamp,
            "app_bundle_path": str(self.app_bundle_path) if self.app_bundle_path else "",
            "plist_analysis": asdict(self.report.plist_analysis),
            "binary_analysis": asdict(self.report.binary_analysis),
            "security_score": self.report.security_score,
            "security_issues": self.report.security_issues,
            "recommendation": self.report.recommendation
        }
    
    def generate_html_report(self) -> Path:
        """Generate an HTML report"""
        data = self.generate_report()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Static Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -30px -30px 20px -30px; padding: 30px; }}
                .score {{ font-size: 48px; font-weight: bold; text-align: center; padding: 20px; }}
                .score-good {{ color: #27ae60; }}
                .score-medium {{ color: #f39c12; }}
                .score-bad {{ color: #e74c3c; }}
                .section {{ margin: 20px 0; }}
                .section-title {{ font-size: 20px; font-weight: bold; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .issue {{ margin: 10px 0; padding: 10px; border-left: 5px solid #ccc; }}
                .critical {{ border-color: #e74c3c; background: #fde8e8; }}
                .high {{ border-color: #e67e22; background: #fef3e2; }}
                .medium {{ border-color: #f1c40f; background: #fef9e7; }}
                .low {{ border-color: #2ecc71; background: #eafaf1; }}
                .info {{ border-color: #3498db; background: #ebf5fb; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #ecf0f1; }}
                .footer {{ margin-top: 30px; color: #7f8c8d; text-align: center; font-size: 12px; }}
                pre {{ background: #eee; padding: 10px; border-radius: 3px; overflow-x: auto; max-height: 200px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>iOS Static Analysis Report</h1>
                    <p><strong>App:</strong> {data['plist_analysis']['app_name']} ({data['plist_analysis']['bundle_id']})</p>
                    <p><strong>Version:</strong> {data['plist_analysis']['version']} ({data['plist_analysis']['build']})</p>
                    <p><strong>Date:</strong> {data['timestamp']}</p>
                </div>
                
                <div class="score {'score-good' if data['security_score'] >= 70 else 'score-medium' if data['security_score'] >= 40 else 'score-bad'}">
                    Security Score: {data['security_score']}/100
                </div>
                
                <div class="section">
                    <div class="section-title">App Transport Security (ATS)</div>
                    <pre>{json.dumps(data['plist_analysis']['ats_config'], indent=2)}</pre>
                </div>
                
                <div class="section">
                    <div class="section-title">Privacy Usage</div>
                    <ul>
                        {''.join(f'<li>{p}</li>' for p in data['plist_analysis']['privacy_usage'])}
                    </ul>
                </div>
                
                <div class="section">
                    <div class="section-title">Frameworks Detected</div>
                    <ul>
                        {''.join(f'<li>{f}</li>' for f in data['binary_analysis']['frameworks'])}
                    </ul>
                </div>
                
                <div class="section">
                    <div class="section-title">Security Issues</div>
                    {''.join(f'<div class="issue {issue["severity"].lower()}">{issue["severity"]}: {issue["issue"]}</div>' for issue in data['security_issues'])}
                </div>
                
                <div class="section">
                    <div class="section-title">Recommendations</div>
                    <pre>{data['recommendation']}</pre>
                </div>
                
                <div class="section">
                    <div class="section-title">Hardcoded URLs</div>
                    <ul>
                        {''.join(f'<li>{u}</li>' for u in data['binary_analysis']['hardcoded_urls'])}
                    </ul>
                </div>
                
                <div class="section">
                    <div class="section-title">Hardcoded Secrets</div>
                    <ul>
                        {''.join(f'<li><code>{s}</code></li>' for s in data['binary_analysis']['hardcoded_secrets'])}
                    </ul>
                </div>
                
                <div class="section">
                    <div class="section-title">Cryptography</div>
                    <table>
                        <tr><th>Function</th></tr>
                        {''.join(f'<tr><td>{c}</td></tr>' for c in data['binary_analysis']['crypto_functions'])}
                    </table>
                </div>
                
                <div class="footer">Generated by iOS Auto Frida v2.0 - Static Analyzer</div>
            </div>
        </body>
        </html>
        """
        
        filename = f"static_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        out_path = self.output_dir / filename
        out_path.write_text(html, encoding='utf-8')
        return out_path
    
    def generate_json_report(self) -> Path:
        """Generate a JSON report"""
        data = self.generate_report()
        filename = f"static_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out_path = self.output_dir / filename
        with open(out_path, 'w') as f:
            json.dump(data, f, indent=2)
        return out_path


# ---------------------------------------------------------------------------
# CLI for standalone static analysis
# ---------------------------------------------------------------------------
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="iOS Static Analyzer")
    parser.add_argument("app_path", help="Path to .ipa file or .app bundle or directory containing them")
    parser.add_argument("--bundle-id", "-b", help="Bundle ID to analyze (if multiple apps found)")
    parser.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    
    args = parser.parse_args()
    
    analyzer = iOSStaticAnalyzer(Path(args.output))
    try:
        report = analyzer.analyze_app(Path(args.app_path), args.bundle_id)
        html_path = analyzer.generate_html_report()
        print(f"\n[STATIC] HTML report saved to: {html_path}")
        
        if args.json:
            json_path = analyzer.generate_json_report()
            print(f"[STATIC] JSON report saved to: {json_path}")
            
    finally:
        analyzer.cleanup()


if __name__ == "__main__":
    main()