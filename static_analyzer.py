#!/usr/bin/env python3
"""
Static Analyzer for iOS Apps
Performs offline analysis of iOS application bundles without running the app.
Uses LIEF for binary parsing (easier to install than macholib).
"""

import os
import sys
import json
import plistlib
import subprocess
import tempfile
import shutil
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib

# Use LIEF instead of macholib - much easier to install!
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    print("[!] LIEF not installed. Install with: pip install lief")

# Optional dependencies
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
    device_family: List[int] = field(default_factory=list)
    supported_orientations: List[str] = field(default_factory=list)

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
    entitlements_found: List[str] = field(default_factory=list)
    binary_size: int = 0
    entry_point: Optional[str] = None
    sections: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    objc_classes: List[str] = field(default_factory=list)
    objc_protocols: List[str] = field(default_factory=list)
    
    # LIEF-specific
    has_encryption_info: bool = False
    has_code_signature: bool = False

@dataclass
class StaticReport:
    """Complete static analysis report"""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    app_bundle_path: str = ""
    plist_analysis: PlistAnalysis = field(default_factory=PlistAnalysis)
    binary_analysis: BinaryAnalysis = field(default_factory=BinaryAnalysis)
    security_score: int = 100
    security_issues: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    findings_summary: Dict[str, int] = field(default_factory=dict)

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
        self.binary_path: Optional[Path] = None
        
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
        print(f"\n{Colors.BLUE}[STATIC] Analyzing: {app_path}{Colors.END}")
        
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
            print(f"[STATIC] Version: {self.report.plist_analysis.version}")
        else:
            print("[STATIC] WARNING: Info.plist not found")
            
        # Step 3: Analyze binary
        self.binary_path = self._find_binary(app_bundle)
        if self.binary_path:
            self.report.binary_analysis = self._analyze_binary(self.binary_path)
            print(f"[STATIC] Binary analyzed: {self.binary_path.name}")
            print(f"[STATIC] Architecture: {', '.join(self.report.binary_analysis.architecture)}")
        else:
            print("[STATIC] WARNING: Binary executable not found")
            
        # Step 4: Analyze entitlements
        entitlements_path = app_bundle / "entitlements.plist"
        if entitlements_path.exists():
            self.report.binary_analysis.entitlements_found = self._parse_entitlements(entitlements_path)
            
        # Step 5: Calculate security score
        self._calculate_security_score()
        
        # Step 6: Generate recommendations
        self._generate_recommendations()
        
        # Step 7: Generate findings summary
        self._generate_findings_summary()
        
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
                
        # Search for Mach-O files (including in subdirectories)
        for file in app_bundle.rglob("*"):
            if file.is_file() and not file.suffix:
                # Check if it's a Mach-O binary
                try:
                    with open(file, 'rb') as f:
                        magic = f.read(4)
                        # Mach-O magic numbers
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
            
            # Device family
            device_family = plist.get('UIDeviceFamily', [])
            if isinstance(device_family, list):
                result.device_family = device_family
            elif isinstance(device_family, int):
                result.device_family = [device_family]
            
            # Supported orientations
            orientations = plist.get('UISupportedInterfaceOrientations', [])
            if isinstance(orientations, list):
                result.supported_orientations = orientations
            elif isinstance(orientations, str):
                result.supported_orientations = [orientations]
            
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
                'NSUserTrackingUsageDescription',
                'NSAppTrackingUsageDescription'
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
        """Analyze the binary executable using LIEF"""
        result = BinaryAnalysis()
        
        # Get binary size
        stat_info = os.stat(binary_path)
        result.binary_size = stat_info.st_size
        print(f"[STATIC] Binary size: {result.binary_size / 1024 / 1024:.2f} MB")
        
        # Extract strings (regardless of LIEF availability)
        strings = self._extract_strings(binary_path)
        
        # Use LIEF if available
        if LIEF_AVAILABLE:
            try:
                binary = lief.parse(str(binary_path))
                if binary:
                    self._analyze_with_lief(binary, result, strings)
            except Exception as e:
                print(f"[STATIC] LIEF parsing failed: {e}. Falling back to strings analysis.")
                self._analyze_with_strings_only(result, strings)
        else:
            print("[STATIC] LIEF not available. Using strings-only analysis.")
            self._analyze_with_strings_only(result, strings)
            
        return result
    
    def _analyze_with_lief(self, binary: lief.MachO, result: BinaryAnalysis, strings: List[str]):
        """Analyze binary using LIEF's full capabilities"""
        try:
            # Architecture
            if binary.header:
                cpu_type = binary.header.cpu_type
                if cpu_type:
                    result.architecture = self._get_architecture_from_lief(cpu_type)
            
            # Entry point
            if hasattr(binary, 'entrypoint') and binary.entrypoint:
                result.entry_point = hex(binary.entrypoint)
            
            # Sections
            for section in binary.sections:
                result.sections.append({
                    'name': section.name if hasattr(section, 'name') else 'Unknown',
                    'virtual_address': hex(section.virtual_address) if hasattr(section, 'virtual_address') else '0x0',
                    'size': section.size if hasattr(section, 'size') else 0,
                    'alignment': section.alignment if hasattr(section, 'alignment') else 0
                })
            
            # Linked libraries
            for library in binary.libraries:
                if hasattr(library, 'name'):
                    result.linked_libraries.append(library.name)
            
            # Imported symbols
            for symbol in binary.imported_symbols:
                if hasattr(symbol, 'name') and symbol.name:
                    result.imports.append(symbol.name)
            
            # Exported symbols
            for symbol in binary.exported_symbols:
                if hasattr(symbol, 'name') and symbol.name:
                    result.exported_symbols.append(symbol.name)
            
            # Objective-C metadata (if available)
            if hasattr(binary, 'objc_classes'):
                for cls in binary.objc_classes:
                    if hasattr(cls, 'name') and cls.name:
                        result.objc_classes.append(cls.name)
            
            if hasattr(binary, 'objc_protocols'):
                for proto in binary.objc_protocols:
                    if hasattr(proto, 'name') and proto.name:
                        result.objc_protocols.append(proto.name)
            
            # Check for code signature
            if hasattr(binary, 'signature'):
                result.has_code_signature = True
                
            # Check for encryption info (like FairPlay)
            if hasattr(binary, 'encryption_info'):
                result.has_encryption_info = True
                
        except Exception as e:
            print(f"[STATIC] LIEF analysis error: {e}")
            
        # Always analyze strings (LIEF may not catch everything)
        self._analyze_strings(result, strings)
    
    def _analyze_with_strings_only(self, result: BinaryAnalysis, strings: List[str]):
        """Fallback when LIEF is not available"""
        # Architecture from file command
        if self.binary_path:
            try:
                output = subprocess.check_output(['file', str(self.binary_path)], text=True)
                if 'Mach-O' in output:
                    arch_pattern = re.compile(r'(arm64|armv7|armv7s|x86_64|i386)')
                    architectures = arch_pattern.findall(output)
                    result.architecture = list(set(architectures))
            except:
                pass
        
        # Get libraries from otool if available
        if self.binary_path:
            try:
                output = subprocess.check_output(['otool', '-L', str(self.binary_path)], text=True)
                for line in output.split('\n'):
                    if '.dylib' in line or '.framework' in line:
                        lib = line.strip().split(' ')[0]
                        if lib:
                            result.linked_libraries.append(lib)
            except:
                pass
        
        # Analyze strings
        self._analyze_strings(result, strings)
    
    def _analyze_strings(self, result: BinaryAnalysis, strings: List[str]):
        """Analyze extracted strings from the binary"""
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
    
    def _get_architecture_from_lief(self, cpu_type: Any) -> List[str]:
        """Convert LIEF CPU type to readable architecture names"""
        archs = []
        try:
            # Common Mach-O CPU types
            cpu_map = {
                7: "arm",
                12: "arm64",
                13: "arm64e",
                0x1000007: "arm64e",
                0x0100000c: "arm64",
                18: "x86_64",
                0x01000000: "x86_64",
                7: "i386",
            }
            if cpu_type in cpu_map:
                archs.append(cpu_map[cpu_type])
            else:
                archs.append(str(cpu_type))
        except:
            archs.append("unknown")
        return archs
    
    def _extract_strings(self, binary_path: Path) -> List[str]:
        """Extract strings from binary using strings command"""
        strings_list = []
        try:
            # Use system strings command
            output = subprocess.check_output(['strings', '-n', '4', str(binary_path)], text=True, stderr=subprocess.DEVNULL)
            strings_list = output.split('\n')
        except:
            # Fallback: read binary and extract ASCII strings
            try:
                with open(binary_path, 'rb') as f:
                    data = f.read()
                    # Find ASCII strings (4+ characters)
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
            'CocoaAsyncSocket', 'ASIHTTPRequest', 'RestKit', 'ObjectMapper',
            'Masonry', 'SnapKit', 'Texture', 'IGListKit', 'R.swift',
            'SwiftyBeaver', 'CocoaLumberjack', 'Reachability', 'SVProgressHUD'
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
        seen = set()
        for s in strings:
            matches = url_pattern.findall(s)
            for url in matches:
                if url not in seen and len(url) > 10:
                    seen.add(url)
                    urls.append(url)
        return urls[:50]  # Limit to avoid overwhelming
    
    def _find_secrets(self, strings: List[str]) -> List[str]:
        """Find potential hardcoded secrets"""
        secrets = []
        seen = set()
        
        patterns = [
            # API Keys and tokens
            (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe live key'),
            (r'sk_test_[A-Za-z0-9]{24,}', 'Stripe test key'),
            (r'pk_live_[A-Za-z0-9]{24,}', 'Stripe publishable live key'),
            (r'pk_test_[A-Za-z0-9]{24,}', 'Stripe publishable test key'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Firebase API key'),
            (r'[A-Za-z0-9]{32,}', 'Potential API key (32+ chars)'),
            # Private keys
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA private key'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC private key'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH private key'),
            (r'-----BEGIN PGP PRIVATE KEY-----', 'PGP private key'),
            # Other secrets
            (r'[A-Za-z0-9+/]{20,}={0,2}', 'Base64 encoded data'),
            (r'[0-9a-f]{32,}', 'Hex hash (32+ chars)'),
            (r'password\s*[:=]\s*["\'][^"\']+["\']', 'Password assignment'),
            (r'secret\s*[:=]\s*["\'][^"\']+["\']', 'Secret assignment'),
            (r'key\s*[:=]\s*["\'][^"\']+["\']', 'Key assignment'),
            (r'token\s*[:=]\s*["\'][^"\']+["\']', 'Token assignment'),
            (r'auth\s*[:=]\s*["\'][^"\']+["\']', 'Auth assignment'),
        ]
        
        for pattern, desc in patterns:
            for s in strings:
                matches = re.findall(pattern, s, re.IGNORECASE)
                for match in matches:
                    # Filter out common false positives
                    if len(match) > 8 and not any(x in match for x in ['http', 'https', '.com', '.org', '.net']):
                        if match not in seen:
                            seen.add(match)
                            truncated = match[:30] + '...' if len(match) > 30 else match
                            secrets.append(f"{desc}: {truncated}")
        
        return secrets[:20]
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find suspicious or sensitive strings"""
        suspicious_keywords = [
            'password', 'passcode', 'secret', 'key', 'token', 'auth', 'login',
            'credential', 'certificate', 'private', 'confidential', 'secret',
            'encrypt', 'decrypt', 'cydia', 'jailbreak', 'root', 'ssh', 'sshd',
            'frida', 'debug', 'debugger', 'ptrace', 'sysctl', 'sandbox',
            'entitlement', 'provisioning', 'provision', 'mobileprovision',
            'ssl pinning', 'certificate pinning', 'trustkit', 'verify',
            'checkjail', 'isjailbroken', 'detectjailbreak'
        ]
        suspicious = []
        seen = set()
        
        for s in strings:
            s_lower = s.lower()
            for keyword in suspicious_keywords:
                if keyword in s_lower:
                    # Avoid common false positives
                    if not any(x in s for x in ['/System/Library', '/usr/lib', '/Applications']):
                        if s not in seen and len(s) > 3:
                            seen.add(s)
                            truncated = s[:40] + '...' if len(s) > 40 else s
                            suspicious.append(f"{keyword}: {truncated}")
                            break
        return suspicious[:30]
    
    def _find_crypto_functions(self, strings: List[str]) -> List[str]:
        """Find cryptographic functions used"""
        crypto_patterns = [
            'CC_SHA256', 'CC_SHA1', 'CC_MD5', 'CommonCrypto', 
            'SecKey', 'SecCertificate', 'SecTrust', 'SSL',
            'RSA', 'AES', '3DES', 'Blowfish', 'HMAC', 'PBKDF2',
            'OpenSSL', 'BoringSSL', 'LibreSSL', 'GnuTLS',
            'CryptoKit', 'CryptoSwift', 'SwiftyRSA', 'RNCryptor',
            'JWT', 'JSONWebToken', 'OAuth', 'OAuth2'
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
            if isinstance(data, dict):
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
            
        # Check encryption declaration
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
            issues.append({'severity': 'HIGH', 'issue': f'Jailbreak detection mechanisms detected ({len(found_jb)} indicators)'})
            
        # Check for SSL pinning libraries
        pinning_libraries = ['TrustKit', 'AFNetworking', 'Alamofire', 'Moya']
        found_pinning = [fw for fw in self.report.binary_analysis.frameworks if fw in pinning_libraries]
        if found_pinning:
            score += 5  # Good - they're using pinning
            issues.append({'severity': 'INFO', 'issue': f'SSL pinning libraries found: {", ".join(found_pinning)}'})
            
        # Check for privacy usage
        privacy_count = len(self.report.plist_analysis.privacy_usage)
        if privacy_count > 5:
            score -= privacy_count
            issues.append({'severity': 'MEDIUM', 'issue': f'App accesses {privacy_count} sensitive permissions'})
            
        # Check for Objective-C classes and methods (indicates complexity)
        if self.report.binary_analysis.objc_classes:
            issues.append({'severity': 'INFO', 'issue': f'{len(self.report.binary_analysis.objc_classes)} Objective-C classes found'})
            
        self.report.security_score = max(0, min(100, score))
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
            
        jb_indicators = [s for s in self.report.binary_analysis.suspicious_strings if any(x in s.lower() for x in ['cydia', 'jailbreak', 'root', 'fork', 'ptrace'])]
        if jb_indicators:
            recs.append("Review jailbreak detection implementation - ensure it doesn't degrade user experience")
            
        if self.report.binary_analysis.objc_classes:
            recs.append("Consider hardening Objective-C code against runtime manipulation")
            
        self.report.recommendations = recs if recs else ["No critical issues found. Continue with dynamic testing."]
    
    def _generate_findings_summary(self):
        """Generate a summary of findings by category"""
        summary = {
            'total_issues': len(self.report.security_issues),
            'critical': sum(1 for i in self.report.security_issues if i.get('severity') == 'CRITICAL'),
            'high': sum(1 for i in self.report.security_issues if i.get('severity') == 'HIGH'),
            'medium': sum(1 for i in self.report.security_issues if i.get('severity') == 'MEDIUM'),
