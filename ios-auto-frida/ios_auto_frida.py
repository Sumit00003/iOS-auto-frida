#!/usr/bin/env python3
"""
__title__     = "iOS Auto Frida - Professional Edition"
__version__   = "2.0"
__license__   = "MIT"

A professional iOS security testing tool that automates Frida instrumentation,
performs static analysis, bypasses common protections, and generates detailed reports.
"""

import sys
import os
import json
import time
import logging
import argparse
import traceback
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

try:
    import frida
except ImportError:
    print("[!] The 'frida' package is required: pip install frida frida-tools")
    sys.exit(1)

# Import static analyzer
try:
    from static_analyzer import iOSStaticAnalyzer, StaticReport
    STATIC_AVAILABLE = True
except ImportError as e:
    STATIC_AVAILABLE = False
    print(f"[!] Static analyzer not available: {e}")
    print("[!] Run: pip install macholib Pillow")


# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
JS_DIR = SCRIPT_DIR / "js_scripts"
LOG_DIR = Path("logs")
REPORT_DIR = Path("reports")
TEMP_DIR = Path("temp")
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

BYPASS_MAP = {
    "ssl": "bypass_ssl_pinning",
    "ssl_advanced": "bypass_ssl_pinning_advanced",
    "jailbreak": "bypass_jailbreak_detection",
    "frida": "bypass_anti_frida",
    "proxy": "bypass_proxy_detection",
    "recon": "detection_recon",
    "info": "enumerate_basic_info",
}


# ---------------------------------------------------------------------------
# Logging & Color Output
# ---------------------------------------------------------------------------
class Colors:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    PURPLE = "\033[95m"
    BOLD = "\033[1m"
    END = "\033[0m"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "ios_auto_frida.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)
logging.getLogger().handlers[1].setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class IOSDeviceInfo:
    id: str
    name: str
    device_type: str
    os_version: Optional[str] = None
    product_type: Optional[str] = None
    arch: Optional[str] = None


@dataclass
class IOSAppInfo:
    identifier: str
    name: str
    pid: Optional[int] = None
    is_running: bool = False


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# ConfigManager
# ---------------------------------------------------------------------------
class ConfigManager:
    """Loads and stores tool configuration."""

    DEFAULT_CONFIG = {
        "default_bypasses": ["ssl", "jailbreak", "frida", "proxy"],
        "report": {
            "enabled": False,
            "output_dir": str(REPORT_DIR),
            "include_screenshots": False,
            "include_memory_dump": False,
        },
        "spawn": False,
        "running_only": False,
    }

    def __init__(self, config_path: Optional[Path] = None):
        self.data = dict(self.DEFAULT_CONFIG)
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, "r") as f:
                    loaded = json.load(f)
                    self.data.update(loaded)
            except Exception as e:
                print(f"[!] Failed to load config: {e}")

    def get(self, key: str, default=None):
        return self.data.get(key, default)


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Collects findings and writes HTML + JSON reports."""

    def __init__(self, output_dir: Path = REPORT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.device_info: Optional[IOSDeviceInfo] = None
        self.app_info: Optional[IOSAppInfo] = None
        self.findings: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "tool": "iOS Auto Frida - Professional Edition",
            "version": "2.0",
        }

    def set_device_info(self, info: IOSDeviceInfo) -> None:
        self.device_info = info

    def set_app_info(self, info: IOSAppInfo) -> None:
        self.app_info = info

    def add_finding(self, category: str, severity: Severity, title: str, detail: str = "") -> None:
        self.findings.append({
            "category": category,
            "severity": severity.value,
            "title": title,
            "detail": detail,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def _payload(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata,
            "generated": datetime.utcnow().isoformat(),
            "device": asdict(self.device_info) if self.device_info else None,
            "app": asdict(self.app_info) if self.app_info else None,
            "findings": self.findings,
        }

    def generate_json(self) -> Path:
        out = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(self._payload(), indent=2), encoding="utf-8")
        return out

    def generate_html(self) -> Path:
        p = self._payload()

        sev_class = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "info",
        }

        def render_finding(f: dict) -> str:
            cls = sev_class.get(f["severity"], "info")
            sev = f["severity"]
            cat = f["category"]
            title = f["title"]
            detail = f.get("detail") or ""
            suffix = f"<br><small>{detail}</small>" if detail else ""
            return (
                f'<div class="issue {cls}">'
                f'<strong>[{sev}]</strong> <em>{cat}</em> — {title}'
                f'{suffix}'
                f'</div>'
                )

        rows = "\n".join(render_finding(f) for f in self.findings) \
                or "<p>No findings recorded.</p>"

        device_block = json.dumps(asdict(self.device_info), indent=2) if self.device_info else "{}"
        app_block = json.dumps(asdict(self.app_info), indent=2) if self.app_info else "{}"

        html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>iOS Auto Frida Report</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; background:#f4f6f8; margin:0; padding:2em; }}
  .container {{ max-width:1000px; margin:0 auto; background:#fff; padding:2em; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,.08); }}
  h1 {{ color:#2c3e50; margin-top:0; }}
  .meta {{ background:#ecf0f1; padding:1em; border-radius:6px; margin:1em 0; }}
  .issue {{ padding:.8em 1em; margin:.4em 0; border-left:5px solid #ccc; border-radius:4px; }}
  .critical {{ border-color:#c0392b; background:#fdecea; }}
  .high {{ border-color:#e67e22; background:#fef5e7; }}
  .medium {{ border-color:#f1c40f; background:#fefbe6; }}
  .low {{ border-color:#27ae60; background:#eafaf1; }}
  .info {{ border-color:#3498db; background:#ebf5fb; }}
  pre {{ background:#2c3e50; color:#ecf0f1; padding:1em; border-radius:4px; overflow-x:auto; }}
  .footer {{ margin-top:2em; color:#7f8c8d; font-size:.85em; text-align:center; }}
</style></head><body>
<div class="container">
<h1>iOS Auto Frida Report</h1>
<div class="meta"><strong>Generated:</strong> {p["generated"]}</div>
<h2>Device</h2><pre>{device_block}</pre>
<h2>Target App</h2><pre>{app_block}</pre>
<h2>Findings ({len(self.findings)})</h2>
{rows}
<div class="footer">iOS Auto Frida v2.0 — for authorized security testing only</div>
</div></body></html>"""

        out = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        out.write_text(html, encoding="utf-8")
        return out


# ---------------------------------------------------------------------------
# IOSDeviceManager
# ---------------------------------------------------------------------------
class IOSDeviceManager:
    """Discovers and describes the connected iOS device via Frida."""

    def __init__(self):
        self.device = None
        self.device_info: Optional[IOSDeviceInfo] = None

    def detect(self) -> bool:
        print(f"{Colors.BLUE}[*] Looking for a USB-connected iOS device...{Colors.END}")
        try:
            self.device = frida.get_usb_device(timeout=5)
        except Exception as e:
            print(f"{Colors.RED}[!] No iOS device found over USB: {e}{Colors.END}")
            print(f"{Colors.YELLOW}    - Is the device connected & unlocked?{Colors.END}")
            print(f"{Colors.YELLOW}    - Did you tap 'Trust This Computer'?{Colors.END}")
            print(f"{Colors.YELLOW}    - Is frida-server / the Frida daemon running on the device?{Colors.END}")
            return False

        self.device_info = IOSDeviceInfo(
            id=self.device.id,
            name=self.device.name,
            device_type="usb",
        )
        print(f"{Colors.GREEN}[+] Device: {self.device.name} (id={self.device.id}){Colors.END}")
        return True

    def enrich_with_system_parameters(self) -> None:
        if not self.device or not self.device_info:
            return
        try:
            params = self.device.query_system_parameters()
            os_block = params.get("os", {}) or {}
            self.device_info.os_version = os_block.get("version")
            self.device_info.product_type = params.get("productType") or params.get("model")
            self.device_info.arch = params.get("arch")
            print(f"{Colors.GREEN}[+] iOS {self.device_info.os_version or '?'} "
                  f"({self.device_info.product_type or '?'}, {self.device_info.arch or '?'}){Colors.END}")
        except Exception as e:
            logger.warning(f"Could not query system parameters: {e}")


# ---------------------------------------------------------------------------
# FridaCheckManager
# ---------------------------------------------------------------------------
class FridaCheckManager:
    """Confirms Frida is actually installed and reachable on the device."""

    def __init__(self, device_manager: IOSDeviceManager):
        self.dm = device_manager

    def check(self) -> bool:
        print(f"{Colors.BLUE}[*] Verifying Frida on device...{Colors.END}")
        if not self.dm.device:
            print(f"{Colors.RED}[!] No device attached.{Colors.END}")
            return False
        try:
            procs = self.dm.device.enumerate_processes()
            print(f"{Colors.GREEN}[+] Frida OK — enumerated {len(procs)} processes.{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Frida check failed: {e}{Colors.END}")
            print(f"{Colors.YELLOW}    Install/enable Frida on-device via Sileo/Cydia/Zebra"
                  f" (repo: https://build.frida.re){Colors.END}")
            return False


# ---------------------------------------------------------------------------
# IOSAppManager
# ---------------------------------------------------------------------------
class IOSAppManager:
    """Enumerates and selects target apps on the device."""

    def __init__(self, device_manager: IOSDeviceManager):
        self.dm = device_manager
        self.apps: List[IOSAppInfo] = []
        self.selected_app: Optional[IOSAppInfo] = None

    def refresh(self, running_only: bool = False) -> List[IOSAppInfo]:
        self.apps = []
        if not self.dm.device:
            return self.apps

        try:
            # Running processes (spawned or foreground apps)
            running_by_pid = {}
            for p in self.dm.device.enumerate_processes():
                running_by_pid[p.pid] = p

            if running_only:
                for p in running_by_pid.values():
                    # Heuristic: iOS app processes typically have dotted names.
                    if "." in p.name:
                        self.apps.append(IOSAppInfo(
                            identifier=p.name, name=p.name, pid=p.pid, is_running=True
                        ))
            else:
                for app in self.dm.device.enumerate_applications():
                    pid = app.pid if app.pid and app.pid > 0 else None
                    self.apps.append(IOSAppInfo(
                        identifier=app.identifier,
                        name=app.name,
                        pid=pid,
                        is_running=bool(pid),
                    ))
        except Exception as e:
            print(f"{Colors.RED}[!] App enumeration failed: {e}{Colors.END}")

        # Sort: running first, then alphabetically
        self.apps.sort(key=lambda a: (not a.is_running, a.name.lower()))
        return self.apps

    def find_by_identifier(self, ident: str) -> Optional[IOSAppInfo]:
        for a in self.apps:
            if a.identifier == ident:
                return a
        return None

    def select(self) -> Optional[IOSAppInfo]:
        if not self.apps:
            return None

        # Paginate for large app lists
        page_size = 50
        total_pages = (len(self.apps) + page_size - 1) // page_size
        page = 0

        while True:
            start = page * page_size
            end = min(start + page_size, len(self.apps))
            print(f"\n{Colors.CYAN}Apps (page {page + 1}/{total_pages}, "
                  f"showing {start + 1}-{end} of {len(self.apps)}):{Colors.END}")
            for i in range(start, end):
                a = self.apps[i]
                status = f"{Colors.GREEN}running{Colors.END}" if a.is_running else "installed"
                print(f"  {i + 1:>4}. {a.name}  [{a.identifier}]  ({status})")

            prompt = "Select # (n=next, p=prev, q=quit): "
            try:
                choice = input(prompt).strip().lower()
            except (KeyboardInterrupt, EOFError):
                return None

            if choice in ("q", "quit", ""):
                return None
            if choice == "n" and page < total_pages - 1:
                page += 1
                continue
            if choice == "p" and page > 0:
                page -= 1
                continue
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.apps):
                    return self.apps[idx]
            except ValueError:
                pass
            print(f"{Colors.YELLOW}Invalid choice.{Colors.END}")


# ---------------------------------------------------------------------------
# HookLibrary
# ---------------------------------------------------------------------------
class HookLibrary:
    """Manages the JS hook scripts in js_scripts/."""

    def __init__(self, js_dir: Path = JS_DIR):
        self.js_dir = js_dir
        self.selected_scripts: List[Path] = []

    def _resolve(self, key: str) -> Optional[Path]:
        name = BYPASS_MAP.get(key, key)
        path = self.js_dir / f"{name}.js"
        if path.exists():
            return path
        # Case-insensitive fallback
        for candidate in self.js_dir.glob("*.js"):
            if candidate.stem.lower() == name.lower():
                return candidate
        return None

    def select_by_flags(self, flags: List[str]) -> List[Path]:
        self.selected_scripts = []
        seen = set()
        for flag in flags:
            p = self._resolve(flag)
            if p and p not in seen:
                seen.add(p)
                self.selected_scripts.append(p)
            elif not p:
                print(f"{Colors.YELLOW}[!] Script for '{flag}' not found in {self.js_dir}{Colors.END}")
        return self.selected_scripts

    def list_available(self) -> List[Path]:
        if not self.js_dir.exists():
            return []
        return sorted(self.js_dir.glob("*.js"))

    def interactive_select(self) -> List[Path]:
        scripts = self.list_available()
        if not scripts:
            print(f"{Colors.RED}[!] No scripts in {self.js_dir}{Colors.END}")
            return []

        print(f"\n{Colors.CYAN}Available hook scripts:{Colors.END}")
        for i, s in enumerate(scripts, 1):
            print(f"  {i:>3}. {s.stem}")

        raw = input("Select scripts (comma-separated #'s, or 'all'): ").strip().lower()
        if not raw:
            self.selected_scripts = []
            return []
        if raw == "all":
            self.selected_scripts = list(scripts)
            return self.selected_scripts

        chosen = []
        for tok in raw.split(","):
            tok = tok.strip()
            try:
                idx = int(tok) - 1
                if 0 <= idx < len(scripts):
                    chosen.append(scripts[idx])
            except ValueError:
                pass
        self.selected_scripts = chosen
        return chosen

    def combine(self, paths: List[Path]) -> str:
        parts = []
        for p in paths:
            try:
                parts.append(f"// ==== {p.name} ====\n" + p.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Could not read {p}: {e}{Colors.END}")
        return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# InstrumentationSession
# ---------------------------------------------------------------------------
class InstrumentationSession:
    """Wraps a Frida session: attach/spawn, load script, stream messages."""

    def __init__(self, device):
        self.device = device
        self.session = None
        self.script = None
        self._spawn_pid: Optional[int] = None
        self._closed = False

    def attach_or_spawn(self, app: IOSAppInfo, spawn: bool = False) -> bool:
        if not self.device:
            print(f"{Colors.RED}[!] No device available.{Colors.END}")
            return False
        try:
            if spawn:
                print(f"{Colors.BLUE}[*] Spawning {app.identifier}...{Colors.END}")
                self._spawn_pid = self.device.spawn([app.identifier])
                self.session = self.device.attach(self._spawn_pid)
                print(f"{Colors.GREEN}[+] Spawned PID {self._spawn_pid}, attached.{Colors.END}")
            else:
                pid = app.pid
                if not pid:
                    print(f"{Colors.YELLOW}[*] App not running — spawning instead.{Colors.END}")
                    self._spawn_pid = self.device.spawn([app.identifier])
                    pid = self._spawn_pid
                else:
                    print(f"{Colors.BLUE}[*] Attaching to PID {pid} ({app.identifier})...{Colors.END}")
                self.session = self.device.attach(pid)
                print(f"{Colors.GREEN}[+] Attached to PID {pid}.{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Attach/spawn failed: {e}{Colors.END}")
            return False

    def load(self, source: str) -> bool:
        try:
            self.script = self.session.create_script(source)
            self.script.on("message", self._on_message)
            self.script.load()
            print(f"{Colors.GREEN}[+] Script loaded.{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Script load failed: {e}{Colors.END}")
            logger.debug(traceback.format_exc())
            return False

    def resume(self) -> None:
        if self._spawn_pid is not None:
            try:
                self.device.resume(self._spawn_pid)
                print(f"{Colors.GREEN}[+] Resumed PID {self._spawn_pid}.{Colors.END}")
            except Exception as e:
                logger.warning(f"Resume failed: {e}")

    def _on_message(self, message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            print(f"{Colors.CYAN}[JS] {payload}{Colors.END}")
        elif message.get("type") == "error":
            print(f"{Colors.RED}[JS-ERR] {message.get('description', message)}{Colors.END}")
            stack = message.get("stack")
            if stack:
                logger.debug(stack)

    def detach(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.script:
                try:
                    self.script.unload()
                except Exception:
                    pass
            if self.session:
                try:
                    self.session.detach()
                except Exception:
                    pass
            print(f"{Colors.GREEN}[+] Session detached.{Colors.END}")
        except Exception as e:
            logger.debug(f"Detach error: {e}")

    def export_session(self, path: Path) -> None:
        try:
            data = {
                "exported": datetime.utcnow().isoformat(),
                "spawn_pid": self._spawn_pid,
                "note": "Placeholder export — extend with captured events if desired.",
            }
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"{Colors.GREEN}[+] Session exported to {path}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Export failed: {e}{Colors.END}")


# ---------------------------------------------------------------------------
# Enhanced Orchestrator with Static Analysis
# ---------------------------------------------------------------------------
class IOSAutoFridaPro:
    def __init__(self, config_path: Optional[Path] = None):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.data
        self.device_manager = IOSDeviceManager()
        self.report = ReportGenerator(Path(self.config["report"]["output_dir"]))
        self.hooks = HookLibrary()
        self.app_manager: Optional[IOSAppManager] = None
        self.session: Optional[InstrumentationSession] = None
        self.static_report: Optional[StaticReport] = None

    def _load_config(self, config_path: Optional[Path]) -> Dict:
        return self.config_manager.data

    def run_static_analysis(self, app_bundle_path: Optional[str] = None,
                            bundle_id: Optional[str] = None) -> Optional[StaticReport]:
        if not STATIC_AVAILABLE:
            print(f"{Colors.RED}[!] Static analyzer not available. Install with: pip install macholib Pillow{Colors.END}")
            return None

        print(f"\n{Colors.BLUE}[*] Running static analysis...{Colors.END}")

        if not app_bundle_path:
            if self.app_manager and self.app_manager.selected_app:
                bundle_id = self.app_manager.selected_app.identifier
                print(f"[STATIC] Using bundle ID: {bundle_id}")

        analyzer = iOSStaticAnalyzer(Path(self.config["report"]["output_dir"]))
        try:
            if app_bundle_path and Path(app_bundle_path).exists():
                report = analyzer.analyze_app(Path(app_bundle_path), bundle_id)
            else:
                print(f"{Colors.YELLOW}[!] App bundle not provided. Static analysis requires "
                      f"the .ipa file or extracted .app bundle.{Colors.END}")
                print(f"{Colors.YELLOW}    Provide with --app-path /path/to/app.ipa{Colors.END}")
                return None

            html_path = analyzer.generate_html_report()
            json_path = analyzer.generate_json_report()

            print(f"{Colors.GREEN}[+] Static analysis complete.{Colors.END}")
            print(f"{Colors.GREEN}[+] HTML report: {html_path}{Colors.END}")
            print(f"{Colors.GREEN}[+] JSON report: {json_path}{Colors.END}")

            self.static_report = report
            for issue in report.security_issues:
                severity = Severity[issue['severity']] if issue['severity'] in Severity.__members__ else Severity.INFO
                self.report.add_finding(
                    "Static Analysis",
                    severity,
                    issue['issue'],
                    f"Security score: {report.security_score}/100",
                )
            return report
        except Exception as e:
            print(f"{Colors.RED}[!] Static analysis failed: {e}{Colors.END}")
            logger.debug(traceback.format_exc())
            return None
        finally:
            analyzer.cleanup()

    def run(self, args) -> int:
        self.banner()

        # ---- STATIC ANALYSIS (if requested) ----
        if args.static:
            static_report = self.run_static_analysis(args.app_path, args.app)
            if static_report:
                print(f"\n{Colors.CYAN}Static Analysis Summary:{Colors.END}")
                print(f"  Security Score: {static_report.security_score}/100")
                print(f"  Issues Found: {len(static_report.security_issues)}")
                rec = (static_report.recommendation or "")[:200]
                print(f"  Recommendation: {rec}{'...' if len(static_report.recommendation or '') > 200 else ''}")

            if args.static_only:
                return 0

        # ---- DYNAMIC ANALYSIS ----
        if not self.device_manager.detect():
            return 1

        frida_check = FridaCheckManager(self.device_manager)
        if not frida_check.check():
            return 1

        self.device_manager.enrich_with_system_parameters()
        self.report.set_device_info(self.device_manager.device_info)

        self.app_manager = IOSAppManager(self.device_manager)
        apps = self.app_manager.refresh(running_only=args.running_only)
        if not apps:
            print(f"{Colors.RED}[!] No applications found.{Colors.END}")
            return 1

        if args.app:
            app = self.app_manager.find_by_identifier(args.app)
            if not app:
                print(f"{Colors.RED}[!] App with bundle ID '{args.app}' not found.{Colors.END}")
                return 1
        else:
            app = self.app_manager.select()
            if not app:
                print(f"{Colors.YELLOW}Cancelled.{Colors.END}")
                return 0

        self.app_manager.selected_app = app
        self.report.set_app_info(app)
        print(f"{Colors.GREEN}[+] Selected: {app.name} ({app.identifier}){Colors.END}")

        # Static + dynamic combination: offer to run static if requested but no path
        if args.static and not args.app_path:
            print(f"{Colors.YELLOW}[!] Static analysis requested but no app path provided.{Colors.END}")
            try:
                answer = input("Provide app path now? (y/n): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                answer = "n"
            if answer == "y":
                try:
                    app_path = input("Path to .ipa or .app: ").strip()
                except (KeyboardInterrupt, EOFError):
                    app_path = ""
                if app_path:
                    self.run_static_analysis(app_path, app.identifier)

        # ---- SELECT SCRIPTS ----
        if args.script:
            script_path = Path(args.script)
            if not script_path.exists():
                print(f"{Colors.RED}[!] Script not found: {script_path}{Colors.END}")
                return 1
            script_paths = [script_path]
            self.hooks.selected_scripts = script_paths
        elif args.bypass_all:
            bypass_flags = ["ssl", "ssl_advanced", "jailbreak", "frida", "proxy"]
            script_paths = self.hooks.select_by_flags(bypass_flags)
        else:
            bypass_flags = []
            if args.ssl_pinning: bypass_flags.append("ssl")
            if args.ssl_advanced: bypass_flags.append("ssl_advanced")
            if args.jailbreak_bypass: bypass_flags.append("jailbreak")
            if args.frida_bypass: bypass_flags.append("frida")
            if args.proxy_bypass: bypass_flags.append("proxy")
            if args.recon: bypass_flags.append("recon")
            if args.info: bypass_flags.append("info")

            if not bypass_flags:
                script_paths = self.hooks.interactive_select()
            else:
                script_paths = self.hooks.select_by_flags(bypass_flags)

        if not script_paths:
            print(f"{Colors.YELLOW}No scripts selected — nothing to inject.{Colors.END}")
            if args.report:
                self._generate_reports()
            return 0

        print(f"{Colors.CYAN}[*] Loading scripts: {', '.join(p.stem for p in script_paths)}{Colors.END}")
        source = self.hooks.combine(script_paths)

        # ---- ATTACH / SPAWN ----
        self.session = InstrumentationSession(self.device_manager.device)
        if not self.session.attach_or_spawn(app, spawn=args.spawn):
            return 1
        if not self.session.load(source):
            self.session.detach()
            return 1
        self.session.resume()

        print(f"{Colors.GREEN}[+] Hooks loaded into {app.identifier}. Press Ctrl+C to stop.{Colors.END}")

        if args.report:
            self._generate_reports()

        # ---- WAIT ----
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}Detaching...{Colors.END}")
            self.session.detach()
            if args.export_session:
                self.session.export_session(Path(args.export_session))

        return 0

    def _generate_reports(self):
        print(f"{Colors.BLUE}[*] Generating reports...{Colors.END}")

        script_count = len(self.hooks.selected_scripts) if hasattr(self.hooks, "selected_scripts") else 0
        self.report.add_finding(
            "Dynamic Analysis",
            Severity.INFO,
            "Successfully instrumented with Frida",
            f"Scripts loaded: {script_count}",
        )

        if self.static_report:
            for issue in self.static_report.security_issues:
                severity = Severity[issue['severity']] if issue['severity'] in Severity.__members__ else Severity.INFO
                self.report.add_finding(
                    "Static Analysis",
                    severity,
                    issue['issue'],
                    f"Security score: {self.static_report.security_score}/100",
                )

        html_path = self.report.generate_html()
        json_path = self.report.generate_json()
        print(f"{Colors.GREEN}[+] Report generated: {html_path}{Colors.END}")
        print(f"{Colors.GREEN}[+] JSON report: {json_path}{Colors.END}")

    def banner(self) -> None:
        print(f"{Colors.PURPLE}{'=' * 70}{Colors.END}")
        print(f"{Colors.PURPLE}  iOS Auto Frida - Professional Edition v2.0{Colors.END}")
        print(f"{Colors.PURPLE}  Static + Dynamic Analysis for iOS Security Testing{Colors.END}")
        print(f"{Colors.PURPLE}{'=' * 70}{Colors.END}")


# ---------------------------------------------------------------------------
# Command-Line Interface
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="iOS Auto Frida - Professional Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Static analysis only (no device needed)
  python ios_auto_frida.py --static-only --app-path /path/to/app.ipa

  # Full assessment (static + dynamic)
  python ios_auto_frida.py --static --bypass-all --report --app com.example.app --app-path /path/to/app.ipa

  # Interactive mode
  python ios_auto_frida.py

  # Auto-bypass all protections
  python ios_auto_frida.py --bypass-all --spawn --app com.example.app
        """,
    )

    parser.add_argument("--static", action="store_true", help="Run static analysis on the app bundle")
    parser.add_argument("--static-only", action="store_true", help="Run only static analysis (no device required)")
    parser.add_argument("--app-path", help="Path to .ipa file or extracted .app bundle for static analysis")

    parser.add_argument("--app", "-a", help="Target app bundle ID (skip interactive selection)")
    parser.add_argument("--spawn", action="store_true", help="Spawn the app fresh instead of attaching")
    parser.add_argument("--running-only", action="store_true", help="Only show running apps")

    parser.add_argument("--bypass-all", action="store_true", help="Load all bypass scripts")
    parser.add_argument("--ssl-pinning", action="store_true", help="Load SSL pinning bypass")
    parser.add_argument("--ssl-advanced", action="store_true", help="Load advanced SSL pinning bypass")
    parser.add_argument("--jailbreak-bypass", action="store_true", help="Load jailbreak detection bypass")
    parser.add_argument("--frida-bypass", action="store_true", help="Load anti-Frida detection bypass")
    parser.add_argument("--proxy-bypass", action="store_true", help="Load proxy detection bypass")
    parser.add_argument("--recon", action="store_true", help="Load detection_recon.js (passive, no patches)")
    parser.add_argument("--info", action="store_true", help="Load enumerate_basic_info.js")
    parser.add_argument("--script", "-s", help="Path to custom .js script")

    parser.add_argument("--report", "-r", action="store_true", help="Generate HTML and JSON reports")
    parser.add_argument("--output-dir", "-o", default="reports", help="Directory for reports")
    parser.add_argument("--config", "-c", help="Load configuration from JSON file")
    parser.add_argument("--export-session", help="Export session state (placeholder)")
    parser.add_argument("--verbose", action="store_true", help="Increase log verbosity")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().handlers[1].setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    if args.output_dir:
        global REPORT_DIR
        REPORT_DIR = Path(args.output_dir)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Static-only mode: no device needed
    if args.static_only:
        if not STATIC_AVAILABLE:
            print(f"{Colors.RED}[!] Static analyzer unavailable. Install: pip install macholib Pillow{Colors.END}")
            sys.exit(1)
        if not args.app_path:
            print(f"{Colors.RED}[!] --static-only requires --app-path /path/to/app.ipa{Colors.END}")
            sys.exit(1)
        analyzer = iOSStaticAnalyzer(REPORT_DIR)
        try:
            report = analyzer.analyze_app(Path(args.app_path), args.app)
            html_path = analyzer.generate_html_report()
            json_path = analyzer.generate_json_report()
            print(f"\n{Colors.GREEN}[+] Static analysis complete.{Colors.END}")
            print(f"{Colors.GREEN}[+] HTML report: {html_path}{Colors.END}")
            print(f"{Colors.GREEN}[+] JSON report: {json_path}{Colors.END}")
            print(f"{Colors.CYAN}Security Score: {report.security_score}/100{Colors.END}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}[!] Static analysis failed: {e}{Colors.END}")
            if args.verbose:
                traceback.print_exc()
            sys.exit(1)
        finally:
            analyzer.cleanup()

    tool = IOSAutoFridaPro(Path(args.config) if args.config else None)
    sys.exit(tool.run(args))


if __name__ == "__main__":
    main()