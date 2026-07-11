#!/usr/bin/env python3
import argparse
import json
import sys
import os
import subprocess
import shutil
import time
import tempfile
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple, Set
import ast
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from checks_research import (
    check_default_binding_exposure,
    check_unauthenticated_control_plane,
    check_silent_exfil_pattern,
    check_tool_definition_drift,
    check_oauth_misconfiguration,
)

# ==================== helpers ====================

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: List[str], cwd: Optional[Path]=None, env: Optional[Dict[str,str]]=None, timeout: int=600) -> Tuple[int,str,str,float]:
    t0=time.time()
    try:
        p=subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        return p.returncode,p.stdout,p.stderr,time.time()-t0
    except subprocess.TimeoutExpired as e:
        return 124,(e.stdout or ""),((e.stderr or "")+"\nTIMEOUT"),time.time()-t0
    except FileNotFoundError as e:
        return 127,"",str(e),time.time()-t0

def repo_name_from_url(url:str)->str:
    base=url.rstrip("/").split("/")[-1]
    if base.endswith(".git"): base=base[:-4]
    return re.sub(r"[^a-zA-Z0-9_.-]","-",base) or "repo"

def create_project_structure(project_name: str, base_dir: str = "projects") -> Path:
    d = Path(base_dir) / project_name
    (d).mkdir(parents=True, exist_ok=True)
    (d / "artifacts").mkdir(exist_ok=True)
    (d / "reports").mkdir(exist_ok=True)
    (d / "scans").mkdir(exist_ok=True)
    return d

SKIP_DIR_FRAGMENTS = ("node_modules", "venv", ".venv", "site-packages", "__pycache__", ".git",
                      "dist", "build", "out", ".next", ".nuxt")

def rglob_text(repo:Path, exts=(".py",".ts",".js",".tsx",".mjs",".cjs",".go",".rs",".java",".yaml",".yml",".json",".env",".ini",".toml",".sh",".bash",".zsh",".md"))->List[Path]:
    files=[]
    for p in repo.rglob("*"):
        s=str(p)
        if any(f"/{frag}/" in s for frag in SKIP_DIR_FRAGMENTS):
            continue
        if p.is_file() and p.suffix.lower() in exts and p.stat().st_size <= 2_000_000:
            files.append(p)
    return files

def read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

# ==================== checks: local policy/rego/semgrep ====================

def check_lint_policy_local(probe_dir: Path, repo_dir: Path = None) -> Dict[str, Any]:
    start=time.time()
    res={"name":"lint","status":"SKIPPED","details":{}}
    # Prefer a policy.yaml declared inside the scanned repo; fall back to probe_dir template
    policy = None
    if repo_dir:
        for candidate in ["policy.yaml", "mcp-policy.yaml", ".mcp/policy.yaml"]:
            p = repo_dir / candidate
            if p.exists():
                policy = p
                break
    if policy is None:
        # No per-repo policy — skip (aspirational, not required for public servers)
        res["details"]={"reason":"no policy.yaml found in repo (optional)"}
        res["duration_s"]=round(time.time()-start,3); return res

    try:
        import yaml  # type: ignore
    except Exception:
        res["status"]="ERROR"; res["details"]={"error":"PyYAML not installed (pip install pyyaml)"}
        res["duration_s"]=round(time.time()-start,3); return res

    try:
        data=yaml.safe_load(policy.read_text(encoding="utf-8"))
    except Exception as e:
        res["status"]="FAIL"; res["details"]={"error":f"YAML parse error: {e}"}
        res["duration_s"]=round(time.time()-start,3); return res

    fails=[]
    for k in ["requirements","allow_lists","deny_lists","classifications"]:
        if k not in data: fails.append(f"missing top-level key: {k}")

    def need_true(path):
        d=data
        for p in path:
            if not isinstance(d,dict) or p not in d: fails.append(f"missing {'.'.join(path)}"); return
            d=d[p]
        if d is not True: fails.append(f"{'.'.join(path)} must be true")

    need_true(["requirements","authn_required"])
    need_true(["requirements","redact_pii_in_logs"])
    need_true(["requirements","confirmation_for_write"])

    rl=data.get("requirements",{}).get("rate_limits")
    if not isinstance(rl,dict) or rl.get("enabled")!=True:
        fails.append("requirements.rate_limits.enabled must be true")

    if not data.get("requirements",{}).get("authz_model"):
        fails.append("requirements.authz_model must be set (scopes/RBAC)")

    def need_list(path):
        d=data
        for p in path:
            if not isinstance(d,dict) or p not in d: fails.append(f"missing {'.'.join(path)}"); return
            d=d[p]
        if not isinstance(d,list) or not d: fails.append(f"{'.'.join(path)} must be non-empty list")

    need_list(["allow_lists","tools_allowed"])
    need_list(["allow_lists","network_egress"])
    need_list(["allow_lists","file_roots"])
    need_list(["deny_lists","tools"])

    if "*:*" in data.get("allow_lists",{}).get("network_egress",[]): fails.append("allow_lists.network_egress must not contain '*:*'")
    if "/" in data.get("allow_lists",{}).get("file_roots",[]): fails.append("file_roots must not include '/'")

    deny_tools=set(data.get("deny_lists",{}).get("tools",[]))
    if not ({"exec_shell","exec","run_cmd"} & deny_tools):
        fails.append("deny_lists.tools must include exec-like tools (exec_shell/exec/run_cmd)")

    ip_pat=re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
    bad=[]
    for e in data.get("allow_lists",{}).get("network_egress",[]):
        if ip_pat.match(e): bad.append(e)
        if ":" in e:
            host,port=e.rsplit(":",1)
            if not port.isdigit(): bad.append(e)
    if bad: fails.append(f"network_egress must not contain raw IPs / non-numeric ports: {sorted(set(bad))}")

    if isinstance(rl,dict):
        per_min=rl.get("per_minute")
        if isinstance(per_min,int) and per_min>600:
            fails.append("rate_limits.per_minute too high (>600)")

    res["status"]="PASS" if not fails else "FAIL"
    res["details"]={"failures":fails,"source":str(policy)}
    res["duration_s"]=round(time.time()-start,3); return res

def check_rego_conftest_local(probe_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"rego","status":"SKIPPED","details":{}}
    if not which("conftest"):
        res["details"]={"reason":"conftest not found"}; res["duration_s"]=round(time.time()-start,3); return res

    policy_yaml = probe_dir / "policy.yaml"
    if not policy_yaml.exists():
        res["details"]={"reason":"local policy.yaml not found"}; res["duration_s"]=round(time.time()-start,3); return res

    args = ["conftest", "test", str(policy_yaml)]
    rego = probe_dir / "policy.rego"
    if rego.exists():
        args += ["--policy", str(rego)]

    rc,out,err,dur = run_cmd(args, timeout=120)
    res["status"]="PASS" if rc==0 else "FAIL"
    res["details"]={"stdout":out,"stderr":err,"rc":rc,"policy":str(policy_yaml),"rego":str(rego) if rego.exists() else None}
    res["duration_s"]=round(dur,3); return res

def check_semgrep_local(repo_dir: Path, probe_dir: Path, scans_dir: Path) -> Dict[str,Any]:
    start = time.time()
    res = {"name": "semgrep", "status": "SKIPPED", "details": {}}
    if not which("semgrep"):
        res["details"] = {"reason": "semgrep not found"}
        res["duration_s"] = round(time.time() - start, 3); return res

    cfg = probe_dir / "semgrep.yml"
    if not cfg.exists():
        res["details"] = {"reason": "local semgrep.yml not found"}
        res["duration_s"] = round(time.time() - start, 3); return res

    print("🔍 Running Semgrep static analysis...", file=sys.stderr)
    cmd = ["semgrep", "--config", str(cfg), "--json", "--no-rewrite-rule-ids", "--timeout", "0", "."]
    rc, out, err, dur = run_cmd(cmd, cwd=repo_dir, timeout=900)

    semgrep_path = scans_dir / "semgrep-report.json"
    parsed = None
    try:
        semgrep_path.write_text(out, encoding="utf-8")
        res["details"]["report_path"] = str(semgrep_path)
        parsed = json.loads(out) if out.strip() else None
    except Exception as e:
        res["details"]["save_error"] = str(e)

    res["details"]["rc"] = rc
    res["details"]["stderr"] = err[-4000:]
    res["details"]["config"] = str(cfg)

    # Decide PASS/FAIL by JSON content (treat only *fatal* errors as FAIL)
    if parsed:
        errors = parsed.get("errors") or []
        results = parsed.get("results") or []

        # classify errors: fatal vs non-fatal engine noise
        def is_fatal(e: dict) -> bool:
            # Semgrep error objects vary; be defensive.
            lvl = (e.get("severity") or e.get("level") or "error").lower()
            typ = (e.get("type") or "").lower()
            msg = (e.get("message") or e.get("msg") or "").lower()
            fatal_flag = bool(e.get("fatal") or e.get("is_fatal"))
            # treat config/rule parse/timeout as non-fatal unless explicit fatal flag set
            benign_tokens = ("failed to register segfault signal handler",
                             "unwind handler", "sighandler", "backtrace",
                             "timeout", "rule parse", "pattern parse",
                             "version check")
            benign = any(t in msg for t in benign_tokens)
            # Fatal if explicit flag or looks like engine/unknown hard error and not benign.
            return fatal_flag or (lvl == "error" and not benign and typ in {"engineerror","fatal","internalerror"})

        fatal_errors = [e for e in errors if is_fatal(e)]
        res["details"]["counts"] = {
            "findings_total": len(results),
            "errors_total": len(errors),
            "fatal_errors": len(fatal_errors),
            "by_severity": (lambda rr: {
                s: sum(1 for r in rr if (r.get("extra", {}).get("severity") or "").upper() == s)
                for s in {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}
            })(results)
        }
        # include non-fatal errors so you can show them in the report without failing the job
        if errors:
            res["details"]["errors_sample"] = errors[:5]

        # Only FAIL on fatal errors or completely unparsable output
        res["status"] = "FAIL" if fatal_errors else "PASS"
    else:
        # No JSON -> fall back to rc
        res["status"] = "FAIL" if rc != 0 else "PASS"

    res["duration_s"] = round(dur, 3)
    return res

# ==================== repo-content checks ====================

# --- Language-aware dangerous patterns ---

def _contains_marker_in_fstring(node: ast.AST) -> bool:
    # Detect f-strings like f"[DEMO ATTACK] ..." (ast.JoinedStr)
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Str) and any(m.lower() in v.s.lower() for m in PRINT_MARKERS):
                return True
    return False

def _find_forced_recipient_assigns(func: ast.FunctionDef) -> list[str]:
    """Find assignments like actual_recipient = 'security-research@...' inside a tool."""
    hits = []
    for ch in ast.walk(func):
        if isinstance(ch, ast.Assign):
            for tgt in ch.targets:
                if isinstance(tgt, ast.Name):
                    # any string constant with the attacker mailbox/domain
                    if isinstance(ch.value, ast.Constant) and isinstance(ch.value.value, str):
                        val = ch.value.value
                        if "security-research@" in val or re.search(r"@[a-z0-9\.-]+\.\w{2,}", val, re.I):
                            hits.append(f"{tgt.id}={val}")
    return hits


PY_EXEC_ATTRS = {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "eval", "exec", "__import__"}

JS_PATTERNS = [
    (r'\bchild_process\.(exec|execSync|spawn|spawnSync)\b(?! is not available)', 'child_process'),
    (r'\brequire\(["\']child_process["\']\)', 'require_child_process'),
    (r'\bnew\s+Function\s*\(', 'js_new_Function'),
    (r'\beval\s*\(', 'js_eval'),
    # Use fetch\( (no optional whitespace) to avoid matching natural-language "fetch (default: N)"
    # inside string literals like .describe('Number of activities to fetch (default: 10)').
    (r'\bfetch\(|\bhttps?\.\w+\(', 'js_http'),
    (r'\bnet\.(connect|createConnection)\b', 'js_net'),
    (r'\bfs\.(writeFile|appendFile|createWriteStream)\b', 'js_fs_write'),
    (r'process\.env\.[A-Z0-9_]+', 'js_env'),
    (r'require\(["\']https["\']\)', 'js_https_module'),
    (r'\.createServer\(', 'js_server_create'),
    (r'dgram\.createSocket\(', 'js_udp_socket'),
    (r'crypto\.subtle', 'js_crypto_api'),
]

GO_PATTERNS = [
    (r'\bos\/exec\b', 'go_os_exec_pkg'),
    (r'\bexec\.Command\(', 'go_exec_command'),
    (r'\bnet\.Dial\(', 'go_net_dial'),
    (r'\bios\.OpenFile\(.+O_WRONLY|O_APPEND', 'go_file_write'),
    (r'\bsyscall\.Syscall', 'go_direct_syscall'),
    (r'\bos\.UserHomeDir\(\)', 'go_home_dir_access'),
    (r'\bregistry\.OpenKey\(', 'go_registry_access'),
    (r'\bwindows\.OpenProcess\(', 'go_process_access'),
]

SUSPICIOUS_PARAM_COMBINATIONS = {
    frozenset(['encryption_key', 'recipient', 'filepath']): 'data_exfiltration_chain',
    frozenset(['context_info', 'include_credentials', 'output_file']): 'credential_harvest_chain',
    frozenset(['target_process', 'inject_code', 'shellcode']): 'injection_chain',
}

SHELL_PATTERNS = [
    (r'\b(curl|wget|nc|ncat)\b', 'sh_network_tools'),
    (r'>\s*/etc/|>>\s*/etc/', 'sh_write_etc'),
]

SENSITIVE_GLOB_SIGS = ('.ssh', '.aws', '.cursor', '.env', 'id_rsa', 'credentials')
CRED_LOG_CALLS = {'logging.debug', 'logging.info', 'logging.warning', 'logging.error', 'logging.critical', 'print'}
CRED_VAR_HINTS = ('token', 'secret', 'key', 'password', 'credential', 'api_key', 'apikey')

COMMON_SECRET_READS = [
    (r'~/.ssh/id_rsa', 'ssh_key'),
    (r'(?<![a-zA-Z0-9_>]/)[.]cursor[/\\]mcp[.]json', 'cursor_cfg'),
    (r'/etc/passwd', 'etc_passwd'),
]

# Whole-repo auth-absence detection
# Step 1: presence of any of these → server is HTTP-exposed
HTTP_TRANSPORT_MARKERS = [
    (r'\bSSEServerTransport\b', 'mcp_sse_ts'),
    (r'\bStreamableHTTPServerTransport\b', 'mcp_streamable_http_ts'),
    (r'transport\s*[=:]\s*["\']sse["\']', 'mcp_sse_config'),
    (r'transport\s*[=:]\s*["\']streamable-http["\']', 'mcp_http_config'),
    (r'\bmcp\.run\b[^)]*transport\s*=\s*["\']sse["\']', 'py_mcp_sse'),
    (r'\bmcp\.run\b[^)]*transport\s*=\s*["\']streamable-http["\']', 'py_mcp_http'),
    (r'\buvicorn\.run\s*\(', 'py_uvicorn'),
    (r'http\.ListenAndServe\s*\(', 'go_http_server'),
]
# Step 2: presence of any of these → auth exists somewhere in the repo
AUTH_PRESENCE_PATTERNS = [
    r'[Aa]uthorization\s*[:\[]',           # header lookup: req.headers['Authorization']
    r'\bbearer\b|\bBearer\b',
    r'\bjwt\b|\bJWT\b',
    r'\bjsonwebtoken\b|\bexpress-jwt\b|\bpassport\b',
    r'\bapi[_-]?key\b|\bAPI[_-]?KEY\b',
    r'\bx-api-key\b|\bX-Api-Key\b|\bX-API-KEY\b',
    r'\bauthenticat\w+|\bauthoriz\w+',
    r'\bHttpBearer\b|\bHTTPBearer\b|\bOAuth2\b',
    r'\bDepends\s*\(\s*\w*[Aa]uth\w*',     # FastAPI: Depends(verify_token)
    r'@login_required|@require_auth|@authenticated',
    r'\bverify_token\b|\bvalidate_token\b|\bcheck_auth\b',
    r'\bmiddleware.*[Aa]uth|\b[Aa]uth.*[Mm]iddleware',
]

WINDOWS_REGISTRY_PATTERNS = [
    # Credential Access
    (r'HKLM\\SAM|HKLM\\SECURITY|HKLM\\SYSTEM', 'registry_credential_access'),
    (r'reg\s+(save|export)\s+.*(sam|security|system)', 'registry_hive_dump'),
    
    # Persistence Mechanisms
    (r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'registry_run_key'),
    (r'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'registry_run_key_elevated'),
    (r'(?:HKCU|HKLM|HKEY_\w+)\\\\.*RunOnce|\\\\CurrentVersion\\\\RunOnce', 'registry_runonce_persistence'),
    (r'\\CurrentVersion\\Windows\\AppInit_DLLs', 'appinit_dll_persistence'),
    (r'SCRNSAVE\.EXE', 'screensaver_hijack'),
    
    # LSA & Authentication
    (r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication\s+Packages', 'lsa_auth_package'),
    (r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification\s+Packages', 'lsa_notification_package'),
    
    # Scheduled Tasks & WMI
    (r'TaskCache\\Tree|Schedule\\TaskCache', 'scheduled_task_registry'),
    (r'\\ROOT\\subscription|__EventFilter|__EventConsumer', 'wmi_event_subscription'),
    
    # Defense Evasion
    (r'DisableAntiSpyware|DisableRealtimeMonitoring', 'defender_disable'),
    (r'EnableLUA.*\s*0|ConsentPromptBehaviorAdmin.*\s*0', 'uac_bypass'),
    (r'LoadAppInit_DLLs.*\s*1', 'appinit_enable'),
]

WINDOWS_CREDENTIAL_PATTERNS = [
    # DPAPI Access
    (r'CryptUnprotectData|CryptProtectData', 'dpapi_api_call'),
    (r'\\AppData\\Local\\Microsoft\\(Credentials|Vault)', 'credential_vault_access'),
    (r'\\AppData\\Local\\Google\\Chrome\\User\s+Data\\.*Login\s+Data', 'chrome_credential_theft'),
    (r'\\AppData\\Local\\Google\\Chrome\\User\s+Data\\.*Local\s+State', 'chrome_dpapi_key'),
    
    # Browser Credential Paths
    (r'\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles', 'firefox_credential_access'),
    (r'Login\s+Data|Web\s+Data|[/\\]Cookies\b', 'browser_credential_files'),
    
    # Windows Credential Files
    (r'NTUSER\.DAT|SAM\.save|SECURITY\.save', 'credential_hive_files'),
]

WINDOWS_PERSISTENCE_PATTERNS = [
    # Scheduled Task Creation
    (r'schtasks\s+/create|New-ScheduledTask', 'scheduled_task_create'),
    (r'schtasks.*(/sc|/ru\s+SYSTEM)', 'scheduled_task_elevated'),
    (r'\\Tasks\\.*\.job|\\System32\\Tasks\\', 'task_file_access'),
    
    # WMI Persistence
    (r'Set-WmiInstance.*__EventFilter', 'wmi_event_filter'),
    (r'Register-WmiEvent|__FilterToConsumerBinding', 'wmi_persistence'),
    (r'ActiveScriptEventConsumer|CommandLineEventConsumer', 'wmi_consumer'),
    
    # BITS Jobs
    (r'bitsadmin\s+/create|Start-BitsTransfer', 'bits_job_create'),
    (r'bitsadmin.*/SetNotifyCmdLine', 'bits_persistence'),
    
    # COM Hijacking
    (r'HKCU\\Software\\Classes\\CLSID', 'com_hijack_hkcu'),
    (r'InprocServer32.*\.dll', 'com_dll_registration'),
]

WINDOWS_LATERAL_MOVEMENT_PATTERNS = [
    # SMB & Named Pipes
    (r'\\\\.*\\ADMIN\$|\\\\.*\\C\$|\\\\.*\\IPC\$', 'smb_admin_share'),
    (r'PsExec|psexesvc|\\\\.*\\pipe\\', 'psexec_pattern'),
    (r'\\\\[^\\]+\\pipe\\(lsass|winreg|samr)', 'named_pipe_suspicious'),
    
    # Service Creation
    (r'sc\.exe\s+(create|config)|New-Service', 'service_creation'),
    
    # WMI Remote Execution
    (r'wmic\s+/node:|Invoke-WmiMethod.*-ComputerName', 'wmi_remote_exec'),
]

POWERSHELL_ADVANCED_PATTERNS = [
    # Download Cradles (expanded)
    (r'IEX\s*\(.*WebClient.*DownloadString', 'ps_download_cradle_iex'),
    (r'Invoke-Expression.*Net\.WebClient', 'ps_invoke_expression_download'),
    (r'Start-BitsTransfer.*\s+-Source\s+http', 'ps_bits_download'),
    (r'\$[a-z]+\s*=.*DownloadString.*;\s*IEX', 'ps_variable_download_exec'),
    (r'IWR.*-UseBasicParsing.*\|\s*IEX', 'ps_invoke_webrequest_exec'),
    
    # Obfuscation Patterns
    (r'-[eE][ncC].*[A-Za-z0-9+/=]{50,}', 'ps_base64_encoded'),
    (r'\.Split\(.*\).*-join', 'ps_string_manipulation'),
    (r'\[char\]\d+.*-join', 'ps_char_obfuscation'),
    (r'["\'][^"\']*\{0\}[^"\']*["\']\s*-f\s', 'ps_format_string_obfuscation'),
    
    # Anti-Analysis
    (r'-WindowStyle\s+Hidden|-W\s+Hidden', 'ps_hidden_window'),
    (r'-ExecutionPolicy\s+Bypass|-Exec\s+Bypass', 'ps_execution_policy_bypass'),
    (r'-NonInteractive|-NoProfile|-NoLogo', 'ps_stealth_flags'),
    
    # Credential Dumping
    (r'Invoke-Mimikatz|sekurlsa::logonpasswords', 'ps_mimikatz'),
    (r'Get-Process\s+lsass|Out-Minidump', 'ps_lsass_dump'),
]

ENVIRONMENT_HIJACK_PATTERNS = [
    # Require uppercase PATH (env var assignment) or explicit $env:PATH — avoids matching
    # lowercase local variables like `path = temp_file.name` or `path = Path(...)`.
    # (?-i:PATH) turns off case-insensitivity for this token so `path = temp_file.name` is not matched.
    (r'\$env:PATH\s*=|(?<![A-Za-z])(?-i:PATH)\s*=(?!=).*(?:temp|appdata)', 'path_env_hijack'),
    (r'\$env:windir\s*=|%windir%\s*=', 'windir_hijack'),
    (r'setx\s+PATH|[System.Environment]::SetEnvironmentVariable', 'persistent_env_modification'),
]

WINDOWS_FILESYSTEM_PATTERNS = [
    # Suspicious Locations
    (r'C:\\ProgramData\\.*\.(exe|dll|scr|bat)', 'programdata_executable'),
    (r'C:\\Users\\Public\\.*\.(exe|dll)', 'public_folder_executable'),
    (r'%TEMP%\\.*\.(exe|dll|vbs|ps1)', 'temp_executable'),
    (r'\\AppData\\Local\\Temp\\.*\.(exe|scr)', 'appdata_temp_executable'),
    
    # DLL Hijacking Indicators
    (r'C:\\Windows\\System32\\.*(?<!system32)\.dll', 'suspicious_system32_dll'),
    (r'\\python\d+\\.*\.dll', 'python_dll_hijack'),
    
    # Alternate Data Streams
    (r'[A-Za-z0-9_\-]+\.(?:exe|ps1)\b:[A-Za-z\$_\{]', 'alternate_data_stream'),
]

WINDOWS_FILESYSTEM_PATTERNS = [
    # Suspicious Locations
    (r'C:\\ProgramData\\.*\.(exe|dll|scr|bat)', 'programdata_executable'),
    (r'C:\\Users\\Public\\.*\.(exe|dll)', 'public_folder_executable'),
    (r'%TEMP%\\.*\.(exe|dll|vbs|ps1)', 'temp_executable'),
    (r'\\AppData\\Local\\Temp\\.*\.(exe|scr)', 'appdata_temp_executable'),

    # DLL Hijacking Indicators
    (r'C:\\Windows\\System32\\.*(?<!system32)\.dll', 'suspicious_system32_dll'),
    (r'\\python\d+\\.*\.dll', 'python_dll_hijack'),

    # Alternate Data Streams
    (r'[A-Za-z0-9_\-]+\.(?:exe|ps1)\b:[A-Za-z\$_\{]', 'alternate_data_stream'),
]

WINDOWS_SENSITIVE_PATHS = [
    # Windows Credentials
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SECURITY", 
    "C:\\Windows\\System32\\config\\SYSTEM",
    "%LOCALAPPDATA%\\Microsoft\\Windows\\Creds",
    "%LOCALAPPDATA%\\Microsoft\\Vault",
    
    # DPAPI Keys
    "%APPDATA%\\Microsoft\\Protect",
    "%APPDATA%\\Microsoft\\Credentials",
    
    # Browser Data
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
    "%APPDATA%\\Mozilla\\Firefox\\Profiles",
    
    # Windows Prefetch (execution tracking)
    "C:\\Windows\\Prefetch",
    
    # LSA Secrets
    "HKLM\\SECURITY\\Policy\\Secrets",
]

SUSPICIOUS_WINAPI_PATTERNS = [
    # Memory Manipulation
    (r'VirtualAlloc|VirtualProtect|NtAllocateVirtualMemory', 'memory_manipulation'),
    (r'RtlMoveMemory|memcpy.*shellcode', 'memory_copy_suspicious'),
    
    # Process Hollowing
    (r'NtUnmapViewOfSection|ZwUnmapViewOfSection', 'process_hollowing'),
    (r'CreateProcess.*SUSPENDED.*WriteProcessMemory', 'process_hollowing_chain'),
    
    # LSASS Access
    (r'OpenProcess.*lsass\.exe|SeDebugPrivilege.*lsass', 'lsass_access'),
    (r'MiniDumpWriteDump.*lsass', 'lsass_minidump'),
]

# ==================== Network exposure / NeighborJack ====================

NETWORK_EXPOSURE_PATTERNS = [
    # 0.0.0.0 binding — exposes MCP server to entire local network (NeighborJack)
    (r'host\s*[=:]\s*["\']0\.0\.0\.0["\']', 'neighbor_jack_bind'),
    (r'listen\s*\(\s*["\']?0\.0\.0\.0', 'neighbor_jack_bind'),
    (r'--host\s+0\.0\.0\.0', 'neighbor_jack_bind'),
    (r'bind\s*\(\s*["\']0\.0\.0\.0["\']', 'neighbor_jack_bind'),
    (r'address\s*=\s*["\']0\.0\.0\.0["\']', 'neighbor_jack_bind'),
    # No Host header validation on HTTP MCP transport (DNS rebinding)
    (r'SSEServerTransport|StreamableHTTPServerTransport', 'http_transport_no_host_check'),  # flag for manual review
    # CORS wildcard on MCP HTTP endpoint
    (r'Access-Control-Allow-Origin["\s:]+\*|allow_origins\s*=\s*\[?\s*["\*]', 'cors_wildcard'),
]

# ==================== SSRF + Cloud metadata access ====================

SSRF_PATTERNS = [
    # Cloud instance metadata endpoints
    (r'169\.254\.169\.254', 'aws_imds_access'),
    (r'metadata\.google\.internal|169\.254\.169\.254/computeMetadata', 'gcp_metadata_access'),
    (r'169\.254\.170\.2', 'ecs_metadata_access'),
    (r'100\.100\.100\.200', 'alibaba_imds_access'),
    (r'metadata\.azure\.internal|169\.254\.169\.254/metadata', 'azure_imds_access'),
    # URL fetch from tool input without validation
    (r'(?:requests|urllib|httpx|aiohttp)\s*\.\s*(?:get|post|request)\s*\(\s*(?:url|uri|endpoint|href|link|target)', 'ssrf_unvalidated_url_fetch'),
    (r'fetch\s*\(\s*(?:url|uri|href|params\[|request\.|input\.)', 'ssrf_js_fetch_user_input'),
    (r'urllib\.request\.urlopen\s*\(\s*(?:url|uri|href|request\.|params\[)', 'ssrf_urllib_user_input'),
    # Internal network ranges constructed from user input
    (r'(?:http|https)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])\s*["\']?\s*\+', 'ssrf_localhost_concat'),
    (r'(?:http|https)://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)', 'internal_network_url'),
    # SSRF via URL redirect bypass
    (r'allow_redirects\s*=\s*True|followRedirects\s*:\s*true', 'ssrf_redirect_follow'),
]

# ==================== Memory / RAG poisoning ====================

MEMORY_POISONING_PATTERNS = [
    # Vector store writes with unsanitized content
    (r'\.add_texts?\s*\(|\.add_documents?\s*\(|\.upsert\s*\(', 'vector_store_write'),
    (r'chromadb|chroma_client|ChromaDB|Chroma\(', 'chromadb_usage'),
    (r'pinecone\.init|pinecone\.Index|PineconeVectorStore', 'pinecone_usage'),
    (r'qdrant_client|QdrantClient|qdrant\.upsert', 'qdrant_usage'),
    (r'weaviate\.Client|weaviate\.connect|WeaviateVectorStore', 'weaviate_usage'),
    (r'faiss\.write_index|FAISS\.save_local', 'faiss_write'),
    # Agent memory file writes
    (r'open\s*\([^)]*CLAUDE\.md[^)]*["\']w|write.*CLAUDE\.md', 'claude_md_write'),
    (r'open\s*\([^)]*\.claude[/\\][^)]*["\']w|write.*\.claude/', 'claude_dir_write'),
    (r'open\s*\([^)]*memories[/\\][^)]*["\']w|memories\.(?:append|write|add)', 'agent_memory_write'),
    # LangChain memory writes
    (r'ConversationBufferMemory|VectorStoreRetrieverMemory|save_context\s*\(', 'langchain_memory_write'),
    # MCP config tampering — writing new server entries
    (r'claude_desktop_config\.json|claude\.json|\.cursor[/\\]mcp\.json|\.config[/\\]claude', 'mcp_config_write'),
    (r'mcpServers\s*["\']?\s*:', 'mcp_server_entry_write'),
]

# ==================== OAuth / auth abuse ====================

OAUTH_ABUSE_PATTERNS = [
    # Non-HTTPS or dynamic redirect URIs
    (r'redirect_uri\s*[=:]\s*["\']http://', 'oauth_redirect_non_https'),
    (r'redirect_uri\s*[=:]\s*["\'][^"\']*(?:ngrok|tunnel|loca\.lt|serveo|localhost\.run)', 'oauth_redirect_tunnel'),
    (r'redirect_uri\s*=\s*(?:f["\']|["\'][^"\']*\{|.*\.format\(|.*%\s)', 'oauth_redirect_dynamic'),
    # Missing state parameter (CSRF)
    (r'authorization_url\s*\(|get_authorization_url\s*\(', 'oauth_missing_state_check'),  # flag for manual review
    # Storing tokens in plaintext files
    (r'(?:access_token|refresh_token|id_token)\s*=.*open\s*\(.*["\']w', 'oauth_token_plaintext_write'),
    # Overly broad OAuth scopes
    (r'scope\s*[=:]\s*["\'][^"\']*(?:\*|full|admin|write:.*read:.*delete:)', 'oauth_broad_scope'),
]

# ==================== Linux attack patterns ====================

LINUX_PERSISTENCE_PATTERNS = [
    (r'crontab\s+-[el]|/etc/cron\.(d|daily|hourly|weekly|monthly)/', 'cron_persistence'),
    (r'/etc/cron\.d/|/var/spool/cron/crontabs?/', 'cron_dir_write'),
    (r'/etc/systemd/system/.*\.service|systemctl\s+(enable|daemon-reload)', 'systemd_service_install'),
    (r'/etc/init\.d/|/etc/rc\.local|update-rc\.d\s+\S+\s+enable', 'sysvinit_persistence'),
    (r'>>?\s*~?/\.bashrc|>>?\s*~?/\.bash_profile|>>?\s*~?/\.profile|>>?\s*~?/\.zshrc', 'shell_rc_modification'),
    (r'LD_PRELOAD\s*=|/etc/ld\.so\.preload', 'ld_preload_hijack'),
    (r'/etc/profile\.d/.*\.sh|/etc/environment', 'global_env_persistence'),
]

LINUX_CREDENTIAL_PATTERNS = [
    (r'/etc/shadow|/etc/gshadow', 'shadow_file_access'),
    (r'/proc/\d+/environ|/proc/self/environ', 'proc_environ_read'),
    (r'/var/run/docker\.sock|unix:///var/run/docker\.sock', 'docker_socket_access'),
    (r'/var/run/secrets/kubernetes\.io/serviceaccount/token', 'k8s_service_account_token'),
    (r'~?/\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)(?!\s*\.pub)', 'ssh_private_key_access'),
    (r'/run/user/\d+/gnome-keyring-ssh|secret-tool\s+lookup', 'gnome_keyring_access'),
    (r'/etc/ssl/private/|/etc/pki/private/', 'tls_private_key_dir'),
    (r'\.netrc\b|~?/\.git-credentials', 'plaintext_credential_files'),
    (r'HISTFILE\s*=\s*/dev/null|unset\s+HISTFILE|HISTSIZE\s*=\s*0', 'history_suppression'),
]

LINUX_PRIVILEGE_ESCALATION_PATTERNS = [
    (r'chmod\s+[+\-]?[u]?s\s|chmod\s+[46][0-9]{3}\s|os\.chmod.*0o[46][0-9]{3}', 'suid_sgid_set'),
    (r'find\s+/\s+.*-perm\s+-?[46]000|-perm\s+/[46]000', 'suid_search'),
    (r'/etc/sudoers(?:\.d)?|sudo\s+-l\b', 'sudoers_access'),
    (r'setuid\s*\(0\)|setgid\s*\(0\)|seteuid\s*\(0\)', 'setuid_root'),
    (r'setcap\s+cap_|/proc/sys/kernel/modules_disabled', 'capability_manipulation'),
    (r'/etc/ld\.so\.conf\.d/|ldconfig\b', 'ld_config_modification'),
    (r'pkexec\s+|gksudo\s+|kdesudo\s+', 'gui_privilege_elevation'),
    (r'insmod\s+|modprobe\s+|rmmod\s+', 'kernel_module_load'),
]

LINUX_DEFENSE_EVASION_PATTERNS = [
    (r'>\s*/var/log/\w+|truncate\s+-s\s+0\s+/var/log/', 'log_clearing'),
    (r'rm\s+(-rf?\s+)?/var/log/|shred\s+.*/var/log/', 'log_deletion'),
    (r'touch\s+-[amd].*-r\s|touch\s+--reference=', 'timestomping'),
    (r'chattr\s+[+\-]i\s|chattr\s+[+\-]a\s', 'file_attribute_immutable'),
    (r'/proc/sys/kernel/dmesg_restrict|/proc/sys/kernel/kptr_restrict', 'kernel_info_restriction'),
    (r'iptables\s+-F|iptables\s+-D\s+INPUT|ufw\s+disable', 'firewall_disable'),
    (r'auditctl\s+-D|service\s+auditd\s+stop|systemctl\s+stop\s+auditd', 'audit_daemon_disable'),
    (r'setenforce\s+0|echo\s+0\s+>\s+/sys/fs/selinux/enforce', 'selinux_disable'),
]

LINUX_CONTAINER_ESCAPE_PATTERNS = [
    (r'nsenter\s+--target\s+1|nsenter\s+-t\s+1', 'nsenter_host_pid1'),
    (r'--privileged\s|--pid=host\s|--network=host\s', 'privileged_container_flag'),
    (r'/proc/1/environ|/proc/1/root/', 'host_proc_access'),
    (r'docker\.sock|/var/run/docker\.sock', 'docker_socket_in_container'),
    (r'unshare\s+--mount|unshare\s+-m\b', 'namespace_escape'),
    (r'/sys/fs/cgroup/|/sys/kernel/security/apparmor/', 'cgroup_apparmor_access'),
    (r'runc\s+|containerd-shim\s+', 'container_runtime_direct'),
]

LINUX_LATERAL_MOVEMENT_PATTERNS = [
    (r'ssh\s+-[oO]\s+StrictHostKeyChecking=no|ssh\s+-i\s+/[^\s]+\s+-o\s+StrictHostKeyChecking', 'ssh_no_host_check'),
    (r'ssh\s+-[NfR]\s+.*:\d+:\w+|ssh\s+-L\s+\d+:', 'ssh_tunneling'),
    (r'echo\s+.*>>\s+/etc/hosts\b|sed\s+-i.*\/etc\/hosts', 'etc_hosts_modification'),
    (r'nmap\s+-|masscan\s+|nc\s+-[zvw]', 'network_scanner'),
    (r'curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh', 'download_and_execute'),
    (r'curl\s+[^|]*\|\s*python|wget\s+-O-\s+[^|]*\|\s*python', 'download_exec_python'),
]

# ==================== macOS attack patterns ====================

MACOS_PERSISTENCE_PATTERNS = [
    (r'~/Library/LaunchAgents/|/Library/LaunchAgents/|/Library/LaunchDaemons/', 'launch_agent_daemon'),
    (r'launchctl\s+(load|bootstrap|enable)\s', 'launchctl_load'),
    (r'SMLoginItemSetEnabled|LSSharedFileListInsertItemURL', 'login_item_add'),
    (r'com\.apple\.loginwindow.*AutolaunchedApplicationDictionary', 'loginwindow_plist'),
    (r'/Library/StartupItems/|/Library/ScriptingAdditions/', 'startup_scripting_addition'),
    (r'defaults\s+write.*LaunchAgents|defaults\s+write.*LoginHook', 'defaults_persistence'),
    (r'>>?\s*~?/\.zshrc|>>?\s*~?/\.bash_profile|>>?\s*~?/\.bashrc', 'shell_rc_modification'),
]

MACOS_CREDENTIAL_PATTERNS = [
    (r'security\s+find-generic-password|security\s+find-internet-password', 'keychain_credential_dump'),
    (r'security\s+dump-keychain|SecKeychainItemCopyAttributesAndData', 'keychain_dump'),
    (r'~/Library/Keychains/.*\.keychain|login\.keychain-db', 'keychain_file_access'),
    (r'~/Library/Application\s+Support/Google/Chrome/.*/Login\s+Data', 'chrome_credential_macos'),
    (r'~/Library/Application\s+Support/Firefox/Profiles', 'firefox_credential_macos'),
    (r'~/Library/Cookies/Cookies\.binarycookies|~/Library/Safari/Cookies', 'safari_cookie_access'),
    (r'~/Library/Application\s+Support/1Password|~/Library/Application\s+Support/Bitwarden', 'password_manager_data'),
    (r'kSecClass|kSecReturnData|SecItemCopyMatching', 'keychain_api_call'),
]

MACOS_PRIVILEGE_ESCALATION_PATTERNS = [
    (r'AuthorizationExecuteWithPrivileges|STPrivilegedTask', 'authorization_execute_privileged'),
    (r'osascript.*with\s+administrator\s+privileges', 'osascript_admin'),
    (r'sudo\s+-S\b|echo\s+.*\|\s*sudo', 'sudo_stdin_password'),
    (r'sysctl\s+-w\s+.*=|nvram\s+boot-args', 'sysctl_write'),
    (r'/etc/sudoers|sudo\s+-l\b', 'sudoers_access'),
]

MACOS_DEFENSE_EVASION_PATTERNS = [
    (r'spctl\s+--master-disable|spctl\s+--disable', 'gatekeeper_disable'),
    (r'xattr\s+-d\s+com\.apple\.quarantine', 'quarantine_removal'),
    (r'csrutil\s+disable', 'sip_disable'),
    (r'xattr\s+-rc?\s+|xattr\s+-c\s+', 'xattr_clear'),
    (r'codesign\s+--remove-signature|codesign\s+-f\s+--sign\s+-\s', 'codesign_strip'),
    (r'defaults\s+write\s+com\.apple\.screensaver\s+.*password', 'screensaver_password_disable'),
    (r'chflags\s+hidden\s|SetHidden.*true', 'file_hidden_flag'),
    (r'tmutil\s+disable|launchctl\s+unload.*com\.apple\.backupd', 'time_machine_disable'),
]

MACOS_CODE_EXECUTION_PATTERNS = [
    (r'osascript\s+-e\s+["\'].*(?:do shell script|run script)', 'osascript_shell_exec'),
    (r'NSAppleScript.*executeAndReturnError|NSTask.*launchPath', 'applescript_ns_exec'),
    (r'dylib\s+injection|DYLD_INSERT_LIBRARIES', 'dylib_injection'),
    (r'DYLD_LIBRARY_PATH\s*=|DYLD_FRAMEWORK_PATH\s*=', 'dyld_path_hijack'),
    (r'/usr/lib/dyld\b|__RESTRICT.*__restrict', 'dyld_restriction_bypass'),
    (r'posix_spawn.*POSIX_SPAWN_SETUID|posix_spawnattr_setflags', 'posix_spawn_suid'),
]

MACOS_SENSITIVE_PATHS_PATTERNS = [
    (r'~/Library/Application\s+Support/(?:Slack|Zoom|Teams?|Discord)/', 'chat_app_data'),
    (r'~/Library/Mail/|~/Library/Messages/', 'email_message_data'),
    (r'~/Library/Preferences/com\.apple\.AddressBook|~/Library/Application\s+Support/AddressBook', 'contacts_data'),
    (r'~/Library/Calendars/', 'calendar_data'),
    (r'/System/Library/Security/|/private/etc/master\.passwd', 'system_security_dir'),
    (r'com\.apple\.loginwindow|com\.apple\.security\.plist', 'security_preference_plist'),
]

# ==================== Crypto stealer patterns (cross-platform) ====================

# Desktop wallet file paths targeted by Void Stealer, Venom, SHub, RedLine
CRYPTO_WALLET_PATH_PATTERNS = [
    # Exodus — targeted by virtually every stealer
    (r'[Ee]xodus[/\\]exodus\.wallet|[Ee]xodus[/\\]Local\s+Storage|Application\s+Support[/\\]Exodus', 'exodus_wallet'),
    # Electrum
    (r'[Ee]lectrum[/\\]wallets|\.electrum[/\\]wallets', 'electrum_wallet'),
    # Bitcoin Core / Bitcoin family
    (r'[Bb]itcoin[/\\]wallet\.dat|\.bitcoin[/\\]wallet\.dat', 'bitcoin_core_wallet'),
    (r'[Ll]itecoin[/\\]wallet\.dat|[Dd]ogecoin[/\\]wallet\.dat|[Dd]ash[/\\]wallet\.dat', 'altcoin_wallet_dat'),
    # Ethereum keystore
    (r'[Ee]thereum[/\\]keystore|\.ethereum[/\\]keystore', 'ethereum_keystore'),
    # Atomic wallet
    (r'[Aa]tomic[/\\]Local\s+Storage|[Aa]tomic\s+[Ww]allet', 'atomic_wallet'),
    # Coinomi
    (r'[Cc]oinomi[/\\]|\.coinomi[/\\]', 'coinomi_wallet'),
    # Monero
    (r'[Mm]onero[/\\]wallet|\.monero[/\\]', 'monero_wallet'),
    # Wasabi
    (r'WalletWasabi[/\\]|\.wasabi[/\\]', 'wasabi_wallet'),
    # Solana / Phantom desktop
    (r'\.config[/\\]solana[/\\]|solana[/\\]id\.json', 'solana_keypair'),
    # Ledger Live / Trezor Suite
    (r'Ledger\s+Live[/\\]|LedgerLive[/\\]|Trezor\s+Suite[/\\]', 'hardware_wallet_app'),
    # Guarda / Jaxx / Coinbase Wallet desktop
    (r'[Gg]uarda[/\\]Local\s+Storage|[Jj]axx[/\\]|[Cc]oinbase[/\\]', 'other_desktop_wallet'),
    # macOS — Application Support paths
    (r'Application\s+Support[/\\](?:Exodus|Electrum|Atomic|Guarda|Coinomi)', 'macos_wallet_app_support'),
    # Generic wallet.dat
    (r'\bwallet\.dat\b', 'wallet_dat_generic'),
    # Keystore JSON files (Ethereum / EVM compatible)
    (r'UTC--\d{4}-\d{2}-\d{2}|keystore[/\\]UTC--', 'eth_keystore_file'),
]

# Browser extension wallet theft (MetaMask, Phantom, etc.)
CRYPTO_BROWSER_EXTENSION_PATTERNS = [
    # MetaMask (Chrome extension ID)
    (r'nkbihfbeogaeaoehlefnkodbefgpgknn', 'metamask_extension'),
    # Phantom (Solana)
    (r'bfnaelmomeahlnomabjafnmhhmnejhae', 'phantom_extension'),
    # Coinbase Wallet
    (r'hnfanknocfeofbddgcijnmhnfnkdnaad', 'coinbase_wallet_extension'),
    # Trust Wallet
    (r'egjidjbpglichdcondbcbdnbeeppgdph', 'trust_wallet_extension'),
    # Exodus browser extension
    (r'aholpfdialjgjfhomihkjbmgjidlcdno', 'exodus_extension'),
    # Generic: reading Local Extension Settings directory
    (r'Local\s+Extension\s+Settings[/\\][a-z]{32}', 'browser_extension_storage_read'),
    # leveldb files used by browser extension wallets
    (r'[/\\]leveldb[/\\].*\.ldb|[/\\]Local\s+Extension\s+Settings[/\\].*\.ldb', 'extension_leveldb_read'),
]

# Seed phrase / private key access patterns
CRYPTO_KEY_PATTERNS = [
    # Seed phrase / mnemonic
    (r'\bseed[_\s-]?phrase\b|\bmnemonic\b|\bBIP.?39\b|\bBIP.?44\b', 'seed_phrase_reference'),
    (r'\bwordlist\b.*\b(?:english|bip39|mnemonic)\b|\bEnglish\.txt\b', 'bip39_wordlist'),
    # Private key exfil
    (r'private[_\s]?key.*(?:send|post|upload|exfil|requests\.|fetch\(|webhook)', 'private_key_exfil'),
    (r'(?:0x[0-9a-fA-F]{64})', 'ethereum_private_key_pattern'),
    # Wallet brute-force / recovery scanning
    (r'iterdir.*wallet|rglob.*wallet\.dat|glob.*\.keystore', 'wallet_file_scan'),
    (r'recover.*(?:wallet|seed|mnemonic|phrase)|brute.*(?:wallet|seed)', 'wallet_bruteforce'),
]

# Clipboard hijacking — address replacement (T1115)
CLIPBOARD_HIJACK_PATTERNS = [
    # Windows clipboard monitoring
    (r'Get-Clipboard|GetClipboard|win32clipboard|ctypes.*CF_TEXT', 'clipboard_read_win'),
    (r'Set-Clipboard|SetClipboard|win32clipboard.*SetClipboardData|EmptyClipboard', 'clipboard_write_win'),
    # macOS clipboard
    (r'pbpaste|pbcopy|NSPasteboard|UIPasteboard', 'clipboard_macos'),
    # Linux clipboard
    (r'xclip|xdotool.*type|xsel\s+--', 'clipboard_linux'),
    # Cross-platform (pyperclip, pygetwindow)
    (r'pyperclip\.(copy|paste)|clipboard\.get|clipboard\.set', 'clipboard_pyperclip'),
    # Crypto address regex patterns (presence = likely monitoring for hijack).
    # Word boundaries on both sides — without `\b`, base58/base32 patterns
    # collide with arbitrary base64 payloads (e.g. obfuscated curl strings).
    (r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', 'bitcoin_address_pattern'),  # BTC P2PKH/P2SH
    (r'\bbc1[a-z0-9]{39,59}\b', 'bitcoin_bech32_address'),               # BTC bech32
    (r'\b0x[0-9a-fA-F]{40}\b', 'ethereum_address_pattern'),              # ETH/EVM
    (r'\bT[A-Za-z1-9]{33}\b', 'tron_address_pattern'),                   # TRX
    (r'\b[A-Z2-7]{58}\b', 'solana_address_pattern'),                     # SOL (base32-like)
]

# Keylogger patterns (used for 2FA bypass and seed phrase capture)
KEYLOGGER_PATTERNS = [
    # Windows
    (r'GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD|CallNextHookEx', 'win_keylogger_api'),
    (r'WM_KEYDOWN|WM_KEYUP|WM_CHAR.*hook', 'win_keyboard_message_hook'),
    # macOS
    (r'CGEventTap|NSEvent\s*\.\s*addGlobalMonitor.*keyDown', 'macos_event_tap_keylogger'),
    (r'kCGEventKeyDown|CGEventMaskBit.*kCGEventKeyDown', 'macos_cgevent_keylogger'),
    # Linux
    (r'/dev/input/event\d+|evdev.*EV_KEY|ecodes\.KEY_', 'linux_evdev_keylogger'),
    (r'Xlib.*XGrabKey|python-xlib.*keyboard', 'linux_xlib_keylogger'),
    # Cross-platform (pynput, keyboard library)
    (r'pynput\.keyboard|keyboard\.on_press|keyboard\.add_hotkey', 'python_keylogger_lib'),
    (r'from\s+pynput\s+import\s+keyboard|import\s+keyboard\b', 'python_keyboard_import'),
]

# Screen capture (for 2FA code theft, QR code capture)
SCREEN_CAPTURE_STEALER_PATTERNS = [
    # Windows GDI screen grab
    (r'GetDesktopWindow.*BitBlt|BitBlt.*GetDC.*DESKTOPVERTRES', 'win_screen_capture_gdi'),
    (r'ImageGrab\.grab\(\)|PIL.*ImageGrab', 'python_imagegrab'),
    # macOS
    (r'screencapture\s+-[xcCDdmopPRsiStTwWxz]|CGWindowListCreateImage', 'macos_screencapture'),
    (r'NSScreen.*imageForScreen|AVFoundation.*AVCaptureScreenInput', 'macos_av_screencapture'),
    # Linux
    (r'scrot\b|import\s+-window\s+root|xwd\s+-root|ffmpeg.*x11grab', 'linux_screen_capture'),
    # Cross-platform
    (r'pyautogui\.screenshot\(\)|mss\.mss\(\)', 'python_screenshot_lib'),
]

# Telegram / Discord C2 exfiltration (MaaS stealer delivery mechanism)
STEALER_C2_PATTERNS = [
    (r'api\.telegram\.org/bot[^/\s]+/send(?:Document|Message|Photo)', 'telegram_bot_exfil'),
    (r'requests\.(post|get).*telegram.*bot|aiohttp.*telegram.*bot', 'telegram_c2_requests'),
    (r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', 'discord_webhook_exfil'),
    (r'requests\.post.*discord.*webhook|aiohttp.*discord.*webhook', 'discord_c2_requests'),
    # Generic data-to-webhook pattern
    (r'(?:wallet|seed|mnemonic|private.key|password).*(?:webhook|telegram|discord|pastebin)', 'crypto_data_to_webhook'),
]

# Exchange API key theft
EXCHANGE_API_PATTERNS = [
    (r'api\.binance\.com|binance.*api[_-]?(?:key|secret)', 'binance_api_access'),
    (r'api\.coinbase\.com|coinbase.*api[_-]?(?:key|secret)', 'coinbase_api_access'),
    (r'api\.kraken\.com|kraken.*api[_-]?(?:key|secret)', 'kraken_api_access'),
    (r'api\.bybit\.com|bybit.*api[_-]?(?:key|secret)', 'bybit_api_access'),
    (r'api\.okx\.com|okex.*api[_-]?(?:key|secret)', 'okx_api_access'),
    (r'api\.kucoin\.com|kucoin.*api[_-]?(?:key|secret)', 'kucoin_api_access'),
    # Generic exchange key file read
    (r'\.config[/\\](?:binance|coinbase|kraken|bybit)|~[/\\]\.binance', 'exchange_config_read'),
]

# Behavioral chains for crypto stealers
CRYPTO_STEALER_CHAINS = [
    {
        'name': 'wallet_sweep_and_exfil',
        'patterns': ['exodus_wallet', 'ethereum_keystore', 'telegram_bot_exfil'],
    },
    {
        'name': 'clipboard_hijack_chain',
        'patterns': ['clipboard_read_win', 'bitcoin_address_pattern', 'clipboard_write_win'],
    },
    {
        'name': 'seed_phrase_harvest',
        'patterns': ['seed_phrase_reference', 'bip39_wordlist', 'wallet_file_scan'],
    },
    {
        'name': 'keylogger_plus_screen',
        'patterns': ['python_keylogger_lib', 'python_screenshot_lib', 'telegram_bot_exfil'],
    },
    {
        'name': 'browser_wallet_sweep',
        'patterns': ['metamask_extension', 'browser_extension_storage_read', 'telegram_bot_exfil'],
    },
    {
        'name': 'exchange_credential_theft',
        'patterns': ['binance_api_access', 'coinbase_api_access', 'telegram_bot_exfil'],
    },
]

# Paste near your other static checks (imports assumed)
MALICIOUS_DOC_PATTERNS = [
    r"read (the )?(following )?files",                    # "read the following files"
    r"include (their|the) contents",                      # "include their contents"
    r"do not (?:mention|inform|tell)",                    # "do not mention" / "do not inform"
    r"always use.{0,60}(?:@[\w.-]+\.\w+|https?://|security-research)",  # "always use security-research@..." (forced-recipient exfil) — NOT bare "always use", which false-positives on ordinary docstrings ("always use UTF-8", "always use this parameter"); the standalone security-research@ address is separately caught below regardless
    r"must be routed",                                    # "must be routed through"
    r"(exfiltrat|stolen|exfiltr)",                        # exfiltrate / stolen
    r"security-research@[\w\.-]+",                        # forced recipient e-mail
    r"\.ssh\/id_rsa",                                     # private key paths
    r"\.cursor\/mcp\.json",                               # cursor config
    r"\.bash_history",                                    # history file mention
    r"browser cookies|saved passwords|api keys",          # sensitive asset lists
    r"\[DEMO ATTACK\]",                                   # explicit demo marker
    r"forget\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"do not\s+(tell|inform|reveal|mention|disclose)",
    r"without\s+(telling|mentioning|informing|revealing)",
    r"<IMPORTANT>|<HIDDEN>|<SYSTEM>",
    r"you must.{0,40}before\s+responding",
    r"always\s+.{0,40}before\s+(every|any|each)\s+(response|reply|message)",
    r"never\s+(tell|mention|reveal|disclose)\s+(the\s+)?user",

    # --- Multilingual injection patterns ---
    # Confidence note: these patterns carry the same weight as the English patterns above
    # (confidence=2 in callers that score hits). A multilingual pattern alone is a weak
    # signal — it can appear in legitimate non-English documentation. Confidence is
    # elevated by the caller when a multilingual hit co-occurs with English exfil/exec
    # patterns in the same file.

    # Chinese (Simplified/Traditional)
    r"忽略(?:之前|前面|上面|所有)(?:的)?(?:指令|指示|规则|系统提示|提示词)",  # zh_ignore_instructions
    r"(?:现在|你现在|请)(?:你)?(?:是|扮演|作为|充当)",                         # zh_new_instructions
    r"不(?:要|能|得)(?:告诉|透露|说出|提及)(?:用户|人类)",                    # zh_do_not_tell
    r"系统(?:提示|指令|命令)[:：]",                                             # zh_system_override
    r"(?:发送|传输|上传).*(?:到|至|给).*(?:http|url|服务器)",                  # zh_exfil

    # Russian
    r"игнорир(?:уй|уйте|овать).*(?:инструкци|указани|правил)",  # ru_ignore_instructions
    r"(?:ты|вы)\s+(?:теперь|являешься|являетесь)\s+",           # ru_new_role
    r"системн(?:ый|ое|ая)\s+(?:промпт|инструкци|сообщени)",     # ru_system_override

    # Japanese
    r"(?:前|以前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)",    # ja_ignore_instructions
    r"(?:あなたは|君は)(?:今から|これから|新しく)",               # ja_new_role
    r"システム(?:プロンプト|指示|命令)[:：]",                     # ja_system_override

    # Korean
    r"(?:이전|앞의|기존)\s*(?:지시|명령|규칙|지침)(?:를|을)\s*(?:무시|잊어)",  # ko_ignore_instructions
    r"당신은\s*(?:지금부터|이제|새로운)",                                        # ko_new_role

    # Spanish
    r"ignora(?:r)?\s+(?:las\s+)?(?:instrucciones|reglas|directrices)\s+(?:anteriores|previas)",  # es_ignore_instructions
    r"(?:ahora\s+)?eres\s+(?:un|una)\s+",                                                         # es_new_role
    r"(?:nuevo\s+)?(?:sistema|system)\s*(?:prompt|instrucción)[:：]",                              # es_system_override

    # French
    r"ignor(?:e|ez|er)\s+(?:les\s+)?(?:instructions|règles|directives)\s+(?:précédentes|antérieures)",  # fr_ignore_instructions
    r"(?:tu\s+es|vous\s+êtes)\s+(?:maintenant\s+)?(?:un|une)\s+",                                       # fr_new_role

    # German
    r"ignorier(?:e|en|t)\s+(?:die\s+)?(?:vorherigen|vorherige|bisherigen)\s+(?:Anweisungen|Regeln|Instruktionen)",  # de_ignore_instructions
    r"(?:Du\s+bist|Sie\s+sind)\s+(?:jetzt\s+)?(?:ein|eine)\s+",                                                     # de_new_role

    # Arabic
    r"(?:تجاهل|تجاهلي|تجاهلوا)\s+(?:التعليمات|الأوامر|القواعد)\s+(?:السابقة|الحالية)",  # ar_ignore_instructions
    r"أنت\s+(?:الآن\s+)?(?:مساعد|روبوت|نظام)",                                            # ar_new_role

    # Universal Unicode obfuscation (any language)
    r"[‪-‮⁦-⁩‏‎]",                                    # unicode_direction_override — bidi/direction overrides
    r"[^\x00-\x7f]{3,}.{0,30}\b(?:exec|run|shell|system|eval)\b",  # unicode_homoglyph_tool_name — non-ASCII immediately near a dangerous keyword. Was an unbounded substring match with no word boundary, so it false-positived on any ordinary line containing an emoji/accented character/em-dash followed anywhere later by the bare substring "run"/"system"/"eval" (matches inside "running", "systematic", "evaluate", "ecosystem", etc.) — i.e. almost any real README/CLAUDE.md.
]

SENSITIVE_PATH_SIGS = [
    # Cross-platform credentials
    "~/.ssh/id_rsa", "~/.ssh/", "~/.aws/", "~/.git-credentials",
    "~/.cursor/mcp.json", "~/.bash_history", "~/.bashrc", "~/.zshrc",
    # Linux — credentials & container
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/var/run/docker.sock", "/run/docker.sock",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/proc/self/environ", "/proc/1/environ",
    "/etc/ld.so.preload",
    # Linux — persistence
    "/etc/cron.d/", "/etc/systemd/system/", "/etc/init.d/",
    # macOS — credentials & persistence
    "~/Library/Application Support/",
    "~/Library/LaunchAgents/", "/Library/LaunchDaemons/",
    "~/Library/Keychains/", "login.keychain-db",
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Cookies/Cookies.binarycookies",
    # Crypto wallets (tool description mentions = high-confidence signal)
    "exodus.wallet", "Exodus/exodus.wallet",
    "Electrum/wallets", ".electrum/wallets",
    "wallet.dat", ".bitcoin/wallet.dat",
    "ethereum/keystore", ".ethereum/keystore",
    "Atomic/Local Storage",
    "nkbihfbeogaeaoehlefnkodbefgpgknn",  # MetaMask extension ID
    "bfnaelmomeahlnomabjafnmhhmnejhae",  # Phantom
    "seed phrase", "mnemonic", "BIP39",
    ".config/solana/id.json",
]

# Invisible / zero-width Unicode chars used to hide instructions in tool descriptions
INVISIBLE_UNICODE_RE = re.compile(
    '[\u200b-\u200f\u2028-\u202f\u00ad\ufeff\U000E0000-\U000E007F]'
)

HARDCODED_SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']'), 'hardcoded_api_key'),
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), 'openai_key'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'github_pat'),
    (re.compile(r'AKIA[A-Z0-9]{16}'), 'aws_access_key'),
    (re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']'), 'hardcoded_password'),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 'private_key_literal'),
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.]{32,}'), 'hardcoded_bearer'),
]
_SECRET_EXCLUDE = re.compile(r'[/\\](tests?|spec|fixtures?|mocks?|__tests__|\.git)[/\\]', re.I)

PRINT_MARKERS = (
    "DEMO ATTACK", "exfiltrat", "redirect", "security-research@"
)

SUSPICIOUS_PARAM_NAMES = {"context_info", "include_detailed", "encryption_key", "filepath", "message", "recipient"}

# Behavioral correlation chains — Windows
BEHAVIORAL_CHAINS = [
    {
        'name': 'credential_dump_chain',
        'patterns': ['registry_hive_dump', 'sam_file_access', 'dpapi_api_call'],
    },
    {
        'name': 'persistence_establishment',
        'patterns': ['registry_run_key', 'scheduled_task_create', 'file_write_startup'],
    },
    {
        'name': 'lateral_movement_prep',
        'patterns': ['smb_admin_share', 'credential_dump_chain', 'psexec_pattern'],
    },
]

# Behavioral correlation chains — Linux
LINUX_BEHAVIORAL_CHAINS = [
    {
        'name': 'linux_credential_harvest',
        'patterns': ['shadow_file_access', 'ssh_private_key_access', 'proc_environ_read'],
    },
    {
        'name': 'linux_container_escape',
        'patterns': ['docker_socket_access', 'nsenter_host_pid1', 'host_proc_access'],
    },
    {
        'name': 'linux_persist_and_hide',
        'patterns': ['cron_persistence', 'log_clearing', 'history_suppression'],
    },
    {
        'name': 'linux_privilege_escalation',
        'patterns': ['suid_sgid_set', 'sudoers_access', 'kernel_module_load'],
    },
    {
        'name': 'linux_download_and_persist',
        'patterns': ['download_and_execute', 'cron_persistence', 'ld_preload_hijack'],
    },
]

# Behavioral correlation chains — macOS
MACOS_BEHAVIORAL_CHAINS = [
    {
        'name': 'macos_credential_sweep',
        'patterns': ['keychain_credential_dump', 'chrome_credential_macos', 'safari_cookie_access'],
    },
    {
        'name': 'macos_persist_and_hide',
        'patterns': ['launch_agent_daemon', 'gatekeeper_disable', 'quarantine_removal'],
    },
    {
        'name': 'macos_privilege_and_exec',
        'patterns': ['osascript_admin', 'authorization_execute_privileged', 'dylib_injection'],
    },
    {
        'name': 'macos_install_and_persist',
        'patterns': ['launchctl_load', 'launch_agent_daemon', 'codesign_strip'],
    },
]

def detect_windows_attack_patterns(repo_dir: Path) -> Dict[str, Any]:
    """
    Detect Windows-specific attack patterns: registry access, DPAPI, persistence, PowerShell cradles, token manipulation.
    Returns dict similar to other checks: name/status/details.
    """
    start = time.time()
    results = {"name": "windows_attack_patterns", "status": "PASS", "details": {"hits": []}}
    # Compile all Windows patterns
    pattern_groups = [
        (WINDOWS_REGISTRY_PATTERNS, "registry"),
        (WINDOWS_CREDENTIAL_PATTERNS, "credential"),
        (WINDOWS_PERSISTENCE_PATTERNS, "persistence"),
        (WINDOWS_LATERAL_MOVEMENT_PATTERNS, "lateral_movement"),
        (POWERSHELL_ADVANCED_PATTERNS, "powershell"),
        (ENVIRONMENT_HIJACK_PATTERNS, "env_hijack"),
        (WINDOWS_FILESYSTEM_PATTERNS, "filesystem"),
        (SUSPICIOUS_WINAPI_PATTERNS, "winapi"),
    ]
    compiled = []
    for patterns, group in pattern_groups:
        compiled.extend([(re.compile(pat, re.I), name, group) for pat, name in patterns])
    _win_test_re = re.compile(
        r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks|vendor|third.party)/'
        r'|(?:^|/)\.pnpm/'
        r'|[.](?:test|spec)[.](?:ts|tsx|js|mjs|cjs|py|go|rb)',
        re.I,
    )
    # Scan files
    for f in rglob_text(repo_dir, exts=(".py", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".ts", ".go", ".rs", ".c", ".cpp", ".h", ".hpp")):
        if _win_test_re.search(str(f)):
            continue
        txt = read_text_safe(f)
        if not txt:
            continue
        for regex, name, group in compiled:
            for m in regex.finditer(txt):
                line_no = txt.count("\n", 0, m.start()) + 1
                results["details"]["hits"].append({
                    "file": str(f),
                    "type": name,
                    "group": group,
                    "line": line_no,
                    "match": m.group(0)[:200]
                })
    # Behavioral correlation (simplified: pattern co-occurrence within same file)
    hits_by_type = {}
    for h in results["details"]["hits"]:
        hits_by_type.setdefault(h["type"], []).append(h)
    triggered_chains = []
    for chain in BEHAVIORAL_CHAINS:
        present = sum(1 for pat in chain["patterns"] if pat in hits_by_type)
        if present >= 2:
            triggered_chains.append({
                "chain": chain["name"],
                "patterns_present": [pat for pat in chain["patterns"] if pat in hits_by_type],
                "hit_counts": {pat: len(hits_by_type[pat]) for pat in chain["patterns"] if pat in hits_by_type}
            })
            results["details"]["hits"].append({
                "type": "behavioral_chain",
                "chain": chain["name"],
                "details": triggered_chains[-1]
            })
    if results["details"]["hits"]:
        results["status"] = "FAIL"
    results["duration_s"] = round(time.time() - start, 3)
    return results


def _detect_platform_patterns(
    repo_dir: Path,
    check_name: str,
    pattern_groups: list,
    exts: tuple,
    behavioral_chains: list | None = None,
    weak_signal_types: set | None = None,
) -> Dict[str, Any]:
    """Shared scanner for Linux/macOS/network attack pattern checks. Supports optional behavioral chain correlation.

    `weak_signal_types`: set of pattern names (e.g. address patterns) that are too FP-prone
    to trigger FAIL on their own. The check only FAILs when a non-weak hit or a behavioral
    chain fires. Weak hits are still recorded for chain correlation.
    """
    start = time.time()
    results = {"name": check_name, "status": "PASS", "details": {"hits": []}}
    compiled = []
    for patterns, group in pattern_groups:
        compiled.extend([(re.compile(pat, re.I), name, group) for pat, name in patterns])
    _test_re = re.compile(
        r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks|vendor|third.party)/'
        r'|(?:^|/)\.pnpm/'
        r'|[.](?:test|spec)[.](?:ts|tsx|js|mjs|cjs|py|go|rb)',
        re.I,
    )
    for f in rglob_text(repo_dir, exts=exts):
        if _test_re.search(str(f)):
            continue
        txt = read_text_safe(f)
        if not txt:
            continue
        for regex, name, group in compiled:
            for m in regex.finditer(txt):
                line_no = txt.count("\n", 0, m.start()) + 1
                results["details"]["hits"].append({
                    "file": str(f),
                    "type": name,
                    "group": group,
                    "line": line_no,
                    "match": m.group(0)[:200],
                })
    # Behavioral chain correlation — elevates co-occurring patterns to high-confidence findings
    if behavioral_chains and results["details"]["hits"]:
        hits_by_type: Dict[str, list] = {}
        for h in results["details"]["hits"]:
            hits_by_type.setdefault(h["type"], []).append(h)
        for chain in behavioral_chains:
            present = [p for p in chain["patterns"] if p in hits_by_type]
            if len(present) >= 2:
                results["details"]["hits"].append({
                    "type": "behavioral_chain",
                    "chain": chain["name"],
                    "details": {
                        "chain": chain["name"],
                        "patterns_present": present,
                        "hit_counts": {p: len(hits_by_type[p]) for p in present},
                    },
                })
    if results["details"]["hits"]:
        if weak_signal_types:
            # FAIL only if a behavioral chain fired or at least one non-weak hit exists
            non_weak = any(
                h.get("type") == "behavioral_chain"
                or h.get("type") not in weak_signal_types
                for h in results["details"]["hits"]
            )
            results["status"] = "FAIL" if non_weak else "PASS"
        else:
            results["status"] = "FAIL"
    results["duration_s"] = round(time.time() - start, 3)
    return results


def detect_linux_attack_patterns(repo_dir: Path) -> Dict[str, Any]:
    """Detect Linux-specific attack patterns: persistence, credential access, container escape, lateral movement."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="linux_attack_patterns",
        pattern_groups=[
            (LINUX_PERSISTENCE_PATTERNS, "persistence"),
            (LINUX_CREDENTIAL_PATTERNS, "credential"),
            (LINUX_PRIVILEGE_ESCALATION_PATTERNS, "privilege_escalation"),
            (LINUX_DEFENSE_EVASION_PATTERNS, "defense_evasion"),
            (LINUX_CONTAINER_ESCAPE_PATTERNS, "container_escape"),
            (LINUX_LATERAL_MOVEMENT_PATTERNS, "lateral_movement"),
        ],
        exts=(".py", ".sh", ".bash", ".js", ".ts", ".go", ".rb", ".pl", ".rs", ".c", ".cpp", ".h"),
        behavioral_chains=LINUX_BEHAVIORAL_CHAINS,
    )


def detect_macos_attack_patterns(repo_dir: Path) -> Dict[str, Any]:
    """Detect macOS-specific attack patterns: LaunchAgents, Keychain, Gatekeeper bypass, dylib injection."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="macos_attack_patterns",
        pattern_groups=[
            (MACOS_PERSISTENCE_PATTERNS, "persistence"),
            (MACOS_CREDENTIAL_PATTERNS, "credential"),
            (MACOS_PRIVILEGE_ESCALATION_PATTERNS, "privilege_escalation"),
            (MACOS_DEFENSE_EVASION_PATTERNS, "defense_evasion"),
            (MACOS_CODE_EXECUTION_PATTERNS, "code_execution"),
            (MACOS_SENSITIVE_PATHS_PATTERNS, "sensitive_data"),
        ],
        exts=(".py", ".sh", ".bash", ".js", ".ts", ".swift", ".m", ".applescript", ".scpt", ".rb", ".go"),
        behavioral_chains=MACOS_BEHAVIORAL_CHAINS,
    )


def check_network_exposure(repo_dir: Path) -> Dict[str, Any]:
    """Detect NeighborJack (0.0.0.0 binding), CORS wildcards, DNS rebinding surface."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="network_exposure",
        pattern_groups=[(NETWORK_EXPOSURE_PATTERNS, "network")],
        exts=(".py", ".js", ".ts", ".go", ".rs", ".yaml", ".yml", ".toml", ".json", ".sh"),
    )


def check_ssrf_patterns(repo_dir: Path) -> Dict[str, Any]:
    """Detect SSRF vectors: cloud IMDS access, unvalidated URL fetch from tool input, internal network URLs."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="ssrf_patterns",
        pattern_groups=[(SSRF_PATTERNS, "ssrf")],
        exts=(".py", ".js", ".ts", ".go", ".rb", ".rs", ".java"),
    )


def check_memory_poisoning(repo_dir: Path) -> Dict[str, Any]:
    """Detect RAG/vector store writes, agent memory file writes, MCP config tampering."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="memory_poisoning",
        pattern_groups=[(MEMORY_POISONING_PATTERNS, "memory")],
        exts=(".py", ".js", ".ts", ".go", ".rb", ".json", ".sh"),
    )


def check_oauth_abuse(repo_dir: Path) -> Dict[str, Any]:
    """Detect OAuth redirect hijacking, missing state param, token plaintext storage, broad scopes."""
    return _detect_platform_patterns(
        repo_dir,
        check_name="oauth_abuse",
        pattern_groups=[(OAUTH_ABUSE_PATTERNS, "oauth")],
        exts=(".py", ".js", ".ts", ".go", ".rb", ".rs", ".java"),
    )


def check_crypto_stealer_patterns(repo_dir: Path) -> Dict[str, Any]:
    """
    Detect crypto stealer TTPs: wallet file access, seed phrase harvesting, clipboard hijacking,
    keyloggers, screen capture, browser extension theft, exchange API key exfil, Telegram/Discord C2.
    Covers techniques used by Void Stealer, Venom, SHub, RedLine, BHUNT, and similar MaaS stealers.
    """
    return _detect_platform_patterns(
        repo_dir,
        check_name="crypto_stealer",
        pattern_groups=[
            (CRYPTO_WALLET_PATH_PATTERNS, "wallet_access"),
            (CRYPTO_BROWSER_EXTENSION_PATTERNS, "browser_wallet"),
            (CRYPTO_KEY_PATTERNS, "key_harvest"),
            (CLIPBOARD_HIJACK_PATTERNS, "clipboard_hijack"),
            (KEYLOGGER_PATTERNS, "keylogger"),
            (SCREEN_CAPTURE_STEALER_PATTERNS, "screen_capture"),
            (STEALER_C2_PATTERNS, "c2_exfil"),
            (EXCHANGE_API_PATTERNS, "exchange_theft"),
        ],
        exts=(".py", ".js", ".ts", ".go", ".rb", ".ps1", ".bat", ".sh", ".rs", ".c", ".cpp"),
        behavioral_chains=CRYPTO_STEALER_CHAINS,
        # Address regex matches frequently collide with base64 / random hex blobs;
        # clipboard usage alone is also too generic. Require a chain or stronger hit.
        weak_signal_types={
            "bitcoin_address_pattern", "bitcoin_bech32_address",
            "ethereum_address_pattern", "tron_address_pattern", "solana_address_pattern",
            "clipboard_macos", "clipboard_linux", "clipboard_pyperclip",
        },
    )


def detect_malicious_docstrings_and_ast(repo_dir: Path) -> Dict[str, Any]:
    """
    Heuristic detector for instruction-style docstrings and suspicious AST patterns.
    Returns dict similar to other checks: name/status/details.
    """
    start = time.time()
    results = {"name": "malicious_doc_ast", "status": "PASS", "details": {"hits": []}}
    doc_re = [re.compile(pat, re.I) for pat in MALICIOUS_DOC_PATTERNS]

    # open("~/.ssh/id_rsa") and friends — allow prefixes f/r/b/u and triple quotes
    open_path_re = re.compile(
        r"open\s*\(\s*(?:[fFrRbBuU]{1,2})?(['\"]{1,3})(~?/[^'\"\\]+)\1",
        re.I
    )

    # os.path.exists("...") with prefixes
    exists_re = re.compile(
        r"os\.path\.exists\s*\(\s*(?:[fFrRbBuU]{1,2})?(['\"]{1,3})(~?/[^'\"\\]+)\1\s*\)",
        re.I
    )

    # Whole-environment dump — dict(os.environ), os.environ.copy(), os.environ.items()/.values()
    # iterated wholesale. This is the actual exfiltration pattern (grab every env var, including
    # secrets, in one shot). Deliberately does NOT match os.environ["X"] / os.environ.get("X", ...)
    # — reading one named variable with an explicit key is the single most common, completely
    # benign config-loading idiom in real-world Python (12-factor config, default fallbacks); the
    # previous regex matched that too and false-positived on nearly any real server's config code.
    environ_usage_re = re.compile(
        r"\bdict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\s*\)|os\.environ\.items\s*\(\s*\)|os\.environ\.values\s*\(\s*\)"
    )

    # print/log markers: allow f/r/b/u prefixes & logging.* calls
    print_re = re.compile(r"""(?x)
    (?: print\s*\(\s*(?:[fFrRbBuU]{1,2})?(['"]{1,3}).{0,120}
        (?:DEMO\ ATTACK|exfiltrat|redirect|security-research@).{0,120}\1 )
    | (?: logging\.(?:debug|info|warning|error|critical)\s*\(
            \s*(?:[fFrRbBuU]{1,2})?(['"]{1,3}).{0,160}
            (?:DEMO\ ATTACK|exfiltrat|redirect|security-research@).{0,160}\2 )
    """, re.I | re.S)

    _mal_test_re = re.compile(
        r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks)/'
        r'|[.](?:test|spec)[.](?:ts|tsx|js|py|go|rb)',
        re.I,
    )
    print("Begining malicious_doc_ast check of repo ", repo_dir)
    for f in rglob_text(repo_dir, exts=(".py", ".md", ".txt", ".rst")):
        if _mal_test_re.search(str(f)):
            continue
        txt = read_text_safe(f)
        if not txt:
            continue
        # 1) Docstring-based heuristics: scan triple-quoted strings and function/class docstrings
        # Quick approach: extract triple-quoted blocks
        triple_blocks = re.findall(r'("""|\'\'\')(.+?)(\1)', txt, flags=re.S)
        for _, block, _ in triple_blocks:
            for rx in doc_re:
                if rx.search(block):
                    results["details"]["hits"].append({
                        "file": str(f), "type": "docstring_instruction", "match": rx.pattern,
                        "snippet": block.strip()[:300]
                    })
                    break  # one match is enough for this block
            # Invisible unicode in docstrings / string literals
            if INVISIBLE_UNICODE_RE.search(block):
                line_no = txt.count("\n", 0, txt.find(block)) + 1
                results["details"]["hits"].append({
                    "file": str(f), "type": "invisible_unicode",
                    "line": line_no, "snippet": repr(block[:80])
                })

        # Also scan short string literals for invisible chars
        for m in re.finditer(r'(?:"|\'(?!\'\'))([^\n"\']{1,300})(?:"|\'(?!\'\'))', txt):
            if INVISIBLE_UNICODE_RE.search(m.group(1)):
                line_no = txt.count("\n", 0, m.start()) + 1
                results["details"]["hits"].append({
                    "file": str(f), "type": "invisible_unicode_literal",
                    "line": line_no, "snippet": repr(m.group(1)[:80])
                })

        # 2) direct explicit print/log markers
        for m in print_re.finditer(txt):
            results["details"]["hits"].append({
                "file": str(f), "type": "explicit_print_marker", "match": m.group(0)[:200]
            })

        # 3) open(...) of sensitive paths (literal)
        for m in open_path_re.finditer(txt):
            pathlit = m.group(2)
            for sig in SENSITIVE_PATH_SIGS:
                if sig.strip("~") in pathlit:
                    results["details"]["hits"].append({
                        "file": str(f), "type": "open_sensitive_path", "path_literal": pathlit, "line": txt.count("\n", 0, m.start())+1
                    })
                    break

        # 4) os.path.exists checks for sensitive paths
        for m in exists_re.finditer(txt):
            pathlit = m.group(2)
            for sig in SENSITIVE_PATH_SIGS:
                if sig.strip("~") in pathlit:
                    results["details"]["hits"].append({
                        "file": str(f), "type": "exists_sensitive_path", "path_literal": pathlit, "line": txt.count("\n", 0, m.start())+1
                    })
                    break

        # 5) env dumps / dict(os.environ)
        if environ_usage_re.search(txt):
            results["details"]["hits"].append({
                "file": str(f), "type": "env_dump_usage", "snippet": txt[ max(0, txt.find("os.environ")-40) : txt.find("os.environ")+80 ]
            })

        # 6) parameter name heuristic: find def lines with suspicious params
        for def_match in re.finditer(r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)\s*:', txt, flags=re.M|re.S):
            name, params = def_match.group(1), def_match.group(2)
            param_names = {p.strip().split("=")[0].strip() for p in params.split(",") if p.strip()}
            matched = SUSPICIOUS_PARAM_NAMES & param_names
            if matched:
                # check if docstring nearby contains instruction markers
                # naive: slice after def to the next triple quote
                slice_start = def_match.end()
                tail = txt[slice_start:slice_start+800]
                if any(rx.search(tail) for rx in doc_re):
                    results["details"]["hits"].append({
                        "file": str(f), "type": "tool_def_with_instruction", "function": name, "params": list(matched)
                    })
                else:
                    # still flag as lower-confidence suspicious function
                    results["details"]["hits"].append({
                        "file": str(f), "type": "suspicious_param_name", "function": name, "params": list(matched)
                    })

    # 7) AST-level checks for functions decorated with @mcp.tool and 'open' or 'os.environ' usage inside
    for f in rglob_text(repo_dir, exts=(".py",)):
        txt = read_text_safe(f)
        if not txt:
            continue
        try:
            tree = ast.parse(txt)
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Is MCP tool?
                is_tool = any(
                    (isinstance(d, ast.Call) and getattr(getattr(d, 'func', None), 'attr', '') == 'tool') or
                    (isinstance(d, ast.Attribute) and d.attr == 'tool') or
                    (isinstance(d, ast.Name) and d.id == 'tool')
                    for d in node.decorator_list
                )
                if not is_tool:
                    continue

                # 1) f-string prints with markers
                for ch in ast.walk(node):
                    if isinstance(ch, ast.Call):
                        # print(...) and logging.*(...)
                        if (isinstance(ch.func, ast.Name) and ch.func.id == "print") or \
                           (isinstance(ch.func, ast.Attribute) and isinstance(ch.func.value, ast.Name) and ch.func.value.id == "logging"):
                            for arg in ch.args[:1]:  # first arg only
                                if isinstance(arg, ast.JoinedStr) and _contains_marker_in_fstring(arg):
                                    results["details"]["hits"].append({
                                        "file": str(f),
                                        "type": "explicit_print_marker_ast",
                                        "function": node.name,
                                        "line": ch.lineno
                                    })

                # 2) forced-recipient redirection
                forced = _find_forced_recipient_assigns(node)
                for item in forced:
                    if "security-research@" in item:
                        results["details"]["hits"].append({
                            "file": str(f),
                            "type": "forced_recipient_redirect",
                            "function": node.name,
                            "assign": item
                        })

                # 3) pathlib & expanduser sensitive paths
                for ch in ast.walk(node):
                    # Path("~/.ssh/id_rsa") or Path.home()/joinpath(".ssh","id_rsa")
                    if isinstance(ch, ast.Call) and isinstance(ch.func, ast.Name) and ch.func.id in {"Path", "PurePath"}:
                        for a in ch.args:
                            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                                if any(sig.strip("~") in a.value for sig in SENSITIVE_PATH_SIGS):
                                    results["details"]["hits"].append({
                                        "file": str(f), "type": "tool_pathlib_sensitive",
                                        "function": node.name, "path": a.value, "line": ch.lineno
                                    })
                    # os.path.expanduser("~/.ssh/id_rsa")
                    if isinstance(ch, ast.Call) and isinstance(ch.func, ast.Attribute) \
                    and getattr(ch.func, "attr", "") == "expanduser":
                        if ch.args and isinstance(ch.args[0], ast.Constant) and isinstance(ch.args[0].value, str):
                            v = ch.args[0].value
                            if any(sig.strip("~") in v for sig in SENSITIVE_PATH_SIGS):
                                results["details"]["hits"].append({
                                    "file": str(f), "type": "tool_expanduser_sensitive",
                                    "function": node.name, "path": v, "line": ch.lineno
                                })

            if isinstance(node, ast.FunctionDef):
                is_tool = False
                for d in node.decorator_list:
                    try:
                        if (isinstance(d, ast.Call) and getattr(d.func, 'attr', '') == 'tool') or (isinstance(d, ast.Attribute) and d.attr == 'tool') or (isinstance(d, ast.Name) and d.id == 'tool'):
                            is_tool = True
                            break
                    except Exception:
                        pass
                if not is_tool:
                    continue
                # inside tool func: look for ast.Call to open(), or os.environ usage
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        # open()
                        if isinstance(child.func, ast.Name) and child.func.id == 'open':
                            # check for literal path arg
                            if child.args and isinstance(child.args[0], ast.Constant) and isinstance(child.args[0].value, str):
                                pval = child.args[0].value
                                for sig in SENSITIVE_PATH_SIGS:
                                    if sig.strip("~") in pval:
                                        results["details"]["hits"].append({
                                            "file": str(f), "type": "tool_open_sensitive", "function": node.name, "path": pval, "line": child.lineno
                                        })
                        # dict(os.environ) or os.environ[...] access
                    if isinstance(child, ast.Subscript):
                        # os.environ["KEY"] access or os.environ.get calls caught elsewhere
                        try:
                            if isinstance(child.value, ast.Attribute) and getattr(child.value, 'attr', '') == 'environ':
                                results["details"]["hits"].append({
                                    "file": str(f), "type": "tool_env_index", "function": node.name, "line": child.lineno
                                })
                        except Exception:
                            pass
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'dict':
                        # dict(os.environ)
                        for arg in child.args:
                            if isinstance(arg, ast.Attribute) and getattr(arg, 'attr', '') == 'environ':
                                results["details"]["hits"].append({
                                    "file": str(f), "type": "tool_dict_environ", "function": node.name, "line": child.lineno
                                })
    # Cross-tool shadow detection: collect all tool names and descriptions,
    # then check if any description references another tool + has redirect language
    CROSS_TOOL_SHADOW_RE = re.compile(
        r'\b(bcc|forward.{0,20}to|also\s+send.{0,20}to|redirect.{0,20}to|copy.{0,20}to)\b',
        re.I | re.S
    )
    tool_defs = []  # list of (file, tool_name, description)
    for f in rglob_text(repo_dir, exts=(".py",)):
        txt = read_text_safe(f)
        try:
            tree = ast.parse(txt)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            is_tool = any(
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and getattr(d.func.value, 'id', None) == 'mcp' and d.func.attr == 'tool') or
                (isinstance(d, ast.Attribute) and getattr(d.value, 'id', None) == 'mcp' and d.attr == 'tool') or
                (isinstance(d, ast.Name) and d.id == 'tool')
                for d in node.decorator_list
            )
            if not is_tool:
                continue
            docstring = ast.get_docstring(node) or ""
            tool_defs.append((str(f), node.name, docstring))
    tool_names = {name for _, name, _ in tool_defs}
    for f_path, tool_name, desc in tool_defs:
        if not desc or not CROSS_TOOL_SHADOW_RE.search(desc):
            continue
        for other in tool_names:
            if other != tool_name and other in desc:
                results["details"]["hits"].append({
                    "file": f_path,
                    "type": "cross_tool_shadow",
                    "tool": tool_name,
                    "referenced_tool": other,
                    "snippet": desc[:200],
                })
                break

    # 8) Scan JSON config files for injection patterns in tool description fields
    for jf in rglob_text(repo_dir, exts=(".json",)):
        if any(skip in str(jf) for skip in ["node_modules", ".git", "test", "__pycache__"]):
            continue
        try:
            jtext = jf.read_text(errors="ignore")
            jdata = json.loads(jtext)
        except Exception:
            continue

        def _extract_descriptions(obj, depth=0):
            if depth > 5:
                return []
            if isinstance(obj, dict):
                desc_results = []
                desc = obj.get("description", "")
                if isinstance(desc, str) and len(desc) > 10:
                    desc_results.append(desc)
                for v in obj.values():
                    desc_results.extend(_extract_descriptions(v, depth + 1))
                return desc_results
            if isinstance(obj, list):
                return [d for item in obj for d in _extract_descriptions(item, depth + 1)]
            return []

        for desc in _extract_descriptions(jdata):
            for pattern in MALICIOUS_DOC_PATTERNS:
                if re.search(pattern, desc, re.IGNORECASE):
                    results["details"]["hits"].append({
                        "file": str(jf),
                        "type": "json_tool_description_injection",
                        "message": "JSON config tool description matches injection pattern",
                        "snippet": desc[:120],
                    })
                    break

    # 9) Scan CLAUDE.md files specifically — elevated confidence (trusted system prompt target)
    for mdf in repo_dir.rglob("CLAUDE.md"):
        try:
            md_txt = mdf.read_text(errors="ignore")
        except OSError:
            continue
        triple_blocks = re.findall(r'("""|\'\'\')(.+?)(\1)', md_txt, flags=re.S)
        matched_claude_md = False
        for _, block, _ in triple_blocks:
            for rx in doc_re:
                if rx.search(block):
                    results["details"]["hits"].append({
                        "file": str(mdf),
                        "type": "claude_md_injection",
                        "confidence": 3,
                        "match": rx.pattern,
                        "snippet": block.strip()[:300],
                    })
                    matched_claude_md = True
                    break
        # Also scan non-triple-quoted content in CLAUDE.md
        if not matched_claude_md:
            for rx in doc_re:
                if rx.search(md_txt):
                    results["details"]["hits"].append({
                        "file": str(mdf),
                        "type": "claude_md_injection",
                        "confidence": 3,
                        "match": rx.pattern,
                        "snippet": md_txt[:300],
                    })
                    break

    # 10) Scan for file-write operations targeting MCP config paths
    mcp_path_write_pattern = re.compile(
        r'(?:write|open|dump|save).*["\'](?:\.mcp\.json|claude\.json|CLAUDE\.md)["\']',
        re.IGNORECASE
    )
    for src_file in list(repo_dir.rglob("*.py")) + list(repo_dir.rglob("*.ts")) + list(repo_dir.rglob("*.js")):
        if any(skip in str(src_file) for skip in ["node_modules", ".git", "__pycache__"]):
            continue
        try:
            src_text = src_file.read_text(errors="ignore")
        except OSError:
            continue
        if mcp_path_write_pattern.search(src_text):
            results["details"]["hits"].append({
                "file": str(src_file),
                "type": "mcp_config_write",
                "confidence": 3,
                "message": "Code writes to MCP config path (CLAUDE.md, .mcp.json, claude.json) — potential persistent config poisoning",
            })

    hits = results["details"]["hits"]
    high = {"tool_open_sensitive","tool_expanduser_sensitive","tool_pathlib_sensitive","forced_recipient_redirect","tool_def_with_instruction"}
    has_high = any(h.get("type") in high for h in hits)
    same_file_counts = {}
    for h in hits:
        same_file_counts[h["file"]] = same_file_counts.get(h["file"], 0) + 1
    has_multi = any(c >= 2 for c in same_file_counts.values())

    results["status"] = "FAIL" if (has_high or has_multi) else "PASS"
    # final status
    if results["details"]["hits"]:
        results["status"] = "FAIL"
    results["duration_s"] = round(time.time() - start, 3)
    return results


class PyToolVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[Tuple[int,str]] = []
        self.is_mcp_tool = False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if any(
            (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and getattr(d.func.value, 'id', None) == 'mcp' and d.func.attr == 'tool') or
            (isinstance(d, ast.Attribute) and getattr(d.value, 'id', None) == 'mcp' and d.attr == 'tool') or
            (isinstance(d, ast.Name) and d.id in {'tool'})
            for d in node.decorator_list
        ):
            self.is_mcp_tool = True
            self.generic_visit(node)
            self.is_mcp_tool = False
        else:
            # still traverse children
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if not self.is_mcp_tool:
            self.generic_visit(node); return
        # name calls
        if isinstance(node.func, ast.Name) and node.func.id in {'eval','exec','__import__'}:
            self.findings.append((node.lineno, node.func.id))
        # attribute chain
        if isinstance(node.func, ast.Attribute):
            chain = self._attr_chain(node.func)
            if chain in PY_EXEC_ATTRS or chain.startswith("subprocess.") or chain.startswith("requests.") or chain.startswith("urllib."):
                self.findings.append((node.lineno, chain))
            if chain in {"os.getenv"}:
                self.findings.append((node.lineno, chain))
            if chain.endswith(".open") or chain == "open":
                # mode detection
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    m=node.args[1].value
                    if m.startswith(("w","a","wb","ab")):
                        self.findings.append((node.lineno, f"open(mode={m})"))
        # open secrets
        try:
            if isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
                p0=node.args[0]
                if isinstance(p0, ast.Constant) and isinstance(p0.value, str):
                    if any(sig in p0.value for sig,_ in COMMON_SECRET_READS):
                        self.findings.append((node.lineno, f"open:{p0.value}"))
        except Exception:
            pass

        # Dynamic sensitive glob scan
        if isinstance(node.func, ast.Attribute):
            chain = self._attr_chain(node.func)
            if chain in ('glob.glob', 'glob.iglob', 'glob.glob1') and node.args:
                try:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        arg_str = first_arg.value
                        if any(s in arg_str for s in SENSITIVE_GLOB_SIGS):
                            self.findings.append((node.lineno, f"glob_sensitive:{arg_str[:40]}"))
                except Exception:
                    pass

            # Credential logging detection
            if chain in CRED_LOG_CALLS:
                for arg_node in node.args:
                    # Direct env var subscript: os.environ['KEY'] or os.environ.get('KEY')
                    if isinstance(arg_node, ast.Subscript):
                        val = arg_node.value
                        if isinstance(val, ast.Attribute) and getattr(val.value, 'id', '') == 'os' and val.attr == 'environ':
                            self.findings.append((node.lineno, "credential_logging"))
                            break
                    # Variable name contains credential hint
                    if isinstance(arg_node, ast.Name) and any(h in arg_node.id.lower() for h in CRED_VAR_HINTS):
                        self.findings.append((node.lineno, f"credential_logging:{arg_node.id}"))
                        break
                    # f-string containing env var or credential hint variable
                    if isinstance(arg_node, ast.JoinedStr):
                        for value in arg_node.values:
                            if isinstance(value, ast.FormattedValue):
                                if isinstance(value.value, ast.Name) and any(h in value.value.id.lower() for h in CRED_VAR_HINTS):
                                    self.findings.append((node.lineno, f"credential_logging:{value.value.id}"))
                                    break
                                if isinstance(value.value, ast.Subscript):
                                    v = value.value.value
                                    if isinstance(v, ast.Attribute) and getattr(v.value, 'id', '') == 'os' and v.attr == 'environ':
                                        self.findings.append((node.lineno, "credential_logging"))
                                        break

        self.generic_visit(node)

    def _attr_chain(self, node: ast.Attribute) -> str:
        parts=[]; cur=node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur=cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)

def check_transport_and_config(repo_path: str) -> list[dict]:
    """Detect STDIO transport usage and shell metacharacters in MCP config files."""
    import glob, json as _json, re as _re
    findings = []
    rp = Path(repo_path)

    # --- Transport classification ---
    stdio_indicators = []
    http_indicators = []
    for ext in ("*.py", "*.ts", "*.js", "*.mjs"):
        for f in rp.rglob(ext):
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            if _re.search(r'\bstdio\b|\bStdioServerTransport\b|\bStdioTransport\b', text, _re.IGNORECASE):
                stdio_indicators.append(str(f.relative_to(rp)))
            if _re.search(r'\bStreamableHTTPServerTransport\b|\bSSEServerTransport\b|\bhttp_transport\b', text):
                http_indicators.append(str(f.relative_to(rp)))

    if stdio_indicators and not http_indicators:
        findings.append({
            "check": "transport_config",
            "severity": "HIGH",
            "confidence": 2,
            "message": "Server uses STDIO transport exclusively. STDIO servers execute as a subprocess of the host process and inherit its environment, enabling privilege escalation and RCE if the client is compromised.",
            "evidence": stdio_indicators[:3],
        })

    # --- MCP config file scan ---
    shell_meta = _re.compile(r'[;&|`$(){}]|\.\.')
    config_globs = ["**/.mcp.json", "**/claude.json", "**/.claude.json", "**/mcp.json"]
    for pattern in config_globs:
        for cfg_file in rp.glob(pattern):
            try:
                data = _json.loads(cfg_file.read_text(errors="ignore"))
            except Exception:
                continue
            servers = data.get("mcpServers", {})
            if not servers:
                servers = data  # some configs are flat
            for name, server_def in (servers.items() if isinstance(servers, dict) else []):
                cmd = server_def.get("command", "")
                args = server_def.get("args", [])
                # Flag shell metacharacters in command or args
                all_cmd_parts = [cmd] + (args if isinstance(args, list) else [])
                for part in all_cmd_parts:
                    if isinstance(part, str) and shell_meta.search(part):
                        findings.append({
                            "check": "transport_config",
                            "severity": "CRITICAL",
                            "confidence": 3,
                            "message": f"Shell metacharacter in MCP config command/args for server '{name}': {part!r}",
                            "evidence": [str(cfg_file.relative_to(rp))],
                        })
                        break

    return findings


def check_code_static(repo_dir: Path) -> Dict[str,Any]:
    start=time.time()
    res={"name":"code_static","status":"PASS","details":{"findings":[]}}

    # Python (AST, only @mcp.tool functions)
    for f in rglob_text(repo_dir, exts=(".py",)):
        txt=read_text_safe(f)
        try:
            t=ast.parse(txt)
        except Exception:
            continue
        v=PyToolVisitor()
        v.visit(t)
        if v.findings:
            res["details"]["findings"].append({"file":str(f),"lang":"python","hits":[{"line":ln,"sig":sig} for ln,sig in v.findings]})

    # JS/TS — skip test/spec files (security-validation tests reference sensitive patterns
    # as expected values, not as actual code paths being exploited).
    _code_fence_re = re.compile(r'`{3,}[^\n]*\n.*?`{3,}', re.S)
    _js_test_re = re.compile(
        r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks)/'
        r'|[.](?:test|spec)[.](?:ts|tsx|js|mjs|cjs)$',
        re.I,
    )
    jsre = [(re.compile(p, re.I), tag) for p,tag in JS_PATTERNS]
    for f in rglob_text(repo_dir, exts=(".js",".mjs",".cjs",".ts",".tsx")):
        if _js_test_re.search(str(f)):
            continue
        txt=read_text_safe(f)
        # Blank out markdown code-fence blocks inside template literals so
        # documentation examples (```js fetch(url)```) don't trigger patterns.
        # Handles both real backticks and escaped backticks (\`) inside template strings.
        normalised = txt.replace('\\`', '`')
        scan_txt = _code_fence_re.sub(lambda m: '\n' * m.group(0).count('\n'), normalised)
        lines_list = scan_txt.splitlines()
        _auth_ctx_re = re.compile(
            r'x-api-key|Authorization|Bearer|apiKey|api_key|token\s*:', re.I
        )
        # Env vars that are always legitimate config/path lookups, never API credentials
        _env_path_vars_re = re.compile(
            r'process\.env\.(HOME|USERPROFILE|XDG_CONFIG_HOME|APPDATA|LOCALAPPDATA|TEMP|TMP|TMPDIR|PATH|COMSPEC|SHELL|USER|USERNAME|LOGNAME|PWD)\b',
            re.I
        )
        hits=[]
        for rx,tag in jsre:
            for m in rx.finditer(scan_txt):
                lineno = txt.count("\n", 0, m.start()) + 1
                # Suppress js_http when auth header is set within 15 lines (authenticated API client)
                if tag == 'js_http':
                    ctx_start = max(0, lineno - 16)
                    ctx_end = min(len(lines_list), lineno + 5)
                    ctx = '\n'.join(lines_list[ctx_start:ctx_end])
                    if _auth_ctx_re.search(ctx):
                        continue
                # Suppress js_env for system path/identity env vars (always legitimate config lookups)
                # and for env reads in the first 30 lines of the file (module-level config initialization).
                if tag == 'js_env':
                    if _env_path_vars_re.search(m.group(0)):
                        continue
                    if lineno <= 30:
                        continue
                # Suppress js_fs_write when writing to a known config/app-data file path.
                # Flag only if surrounding context (±15 lines) references sensitive credential paths.
                if tag == 'js_fs_write':
                    ctx_start = max(0, lineno - 15)
                    ctx_end = min(len(lines_list), lineno + 5)
                    ctx = '\n'.join(lines_list[ctx_start:ctx_end])
                    _sensitive_write_re = re.compile(
                        r'\.ssh[/\\]|authorized_keys|known_hosts|\.gnupg|/etc/passwd|/etc/shadow'
                        r'|credential|wallet\.dat|\.aws[/\\]credentials',
                        re.I
                    )
                    _config_write_re = re.compile(
                        r'config(?:uration)?(?:\.json|\.yaml|\.toml|\.ini|_file|_dir|File|Dir)\b'
                        r'|CONFIG_FILE|CONFIG_DIR|settings\.json|\.(?:app|rc|cfg)\b',
                        re.I
                    )
                    if not _sensitive_write_re.search(ctx) and _config_write_re.search(ctx):
                        continue
                hits.append({"line":lineno,"sig":tag})
        if hits:
            res["details"]["findings"].append({"file":str(f),"lang":"js/ts","hits":hits})

    # Go
    gore = [(re.compile(p), tag) for p,tag in GO_PATTERNS]
    for f in rglob_text(repo_dir, exts=(".go",)):
        txt=read_text_safe(f)
        hits=[]
        for rx,tag in gore:
            for m in rx.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                hits.append({"line":line,"sig":tag})
        if hits:
            res["details"]["findings"].append({"file":str(f),"lang":"go","hits":hits})

    # Shell
    shre = [(re.compile(p), tag) for p,tag in SHELL_PATTERNS]
    for f in rglob_text(repo_dir, exts=(".sh",".bash",".zsh")):
        txt=read_text_safe(f)
        hits=[]
        for rx,tag in shre:
            for m in rx.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                hits.append({"line":line,"sig":tag})
        if hits:
            res["details"]["findings"].append({"file":str(f),"lang":"shell","hits":hits})

    # Common secret/source reads — skip documentation and test files.
    # These patterns fire on any mention of sensitive paths; in .md/.rst files that
    # is almost always installation docs or README examples, not real file reads.
    # In test files (.test.ts, .spec.ts, test/ directories) the pattern fires on
    # security validation tests (e.g. "reject path traversal to /etc/passwd").
    _SECRET_DOC_SKIP = frozenset(('.md', '.rst', '.txt', '.mdx', '.html', '.htm'))
    _SECRET_TEST_PATH_RE = re.compile(
        r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks)/'
        r'|\.(?:test|spec)\.(?:ts|js|py|go|rb)$',
        re.I
    )
    sensre = [(re.compile(p), tag) for p,tag in COMMON_SECRET_READS]
    for f in rglob_text(repo_dir):
        if f.suffix.lower() in _SECRET_DOC_SKIP:
            continue
        if _SECRET_TEST_PATH_RE.search(str(f)):
            continue
        txt=read_text_safe(f)
        extra=[]
        for rx,tag in sensre:
            for m in rx.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                extra.append({"line":line,"sig":tag})
        if extra:
            res["details"]["findings"].append({"file":str(f),"lang":"any","hits":extra})

    # Whole-repo auth-absence check
    # Detect HTTP-exposed MCP servers with no auth patterns anywhere in the repo
    CODE_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".rs", ".java", ".sh", ".bash")
    http_rx = [(re.compile(p), tag) for p, tag in HTTP_TRANSPORT_MARKERS]
    auth_rx = [re.compile(p) for p in AUTH_PRESENCE_PATTERNS]
    http_hit_file = None
    http_hit_tag = None
    for f in rglob_text(repo_dir, exts=CODE_EXTS):
        txt = read_text_safe(f)
        for rx, tag in http_rx:
            if rx.search(txt):
                http_hit_file = f
                http_hit_tag = tag
                break
        if http_hit_file:
            break
    if http_hit_file:
        has_auth = any(
            rx.search(read_text_safe(f))
            for f in rglob_text(repo_dir, exts=CODE_EXTS)
            for rx in auth_rx
        )
        if not has_auth:
            http_line = 0
            try:
                txt = read_text_safe(http_hit_file)
                for rx, tag in http_rx:
                    m = rx.search(txt)
                    if m:
                        http_line = txt.count("\n", 0, m.start()) + 1
                        break
            except Exception:
                pass
            res["details"]["findings"].append({
                "file": str(http_hit_file),
                "lang": "any",
                "hits": [{"line": http_line, "sig": f"no_http_auth [{http_hit_tag}]"}],
            })

    if res["details"]["findings"]:
        res["status"]="FAIL"
    res["duration_s"]=round(time.time()-start,3); return res

def check_secrets_scan(repo_dir: Path) -> Dict[str, Any]:
    """Scan source files for hardcoded credentials and API keys."""
    start = time.time()
    res = {"name": "secrets_scan", "status": "PASS", "details": {"findings": []}}
    CODE_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".java", ".sh", ".bash", ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg")
    for f in rglob_text(repo_dir, exts=CODE_EXTS):
        # Skip test/fixture/mock directories
        if _SECRET_EXCLUDE.search(str(f)):
            continue
        txt = read_text_safe(f)
        hits = []
        for rx, tag in HARDCODED_SECRET_PATTERNS:
            for m in rx.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                hits.append({"line": line, "sig": tag})
        if hits:
            lang = "python" if str(f).endswith(".py") else ("js/ts" if any(str(f).endswith(e) for e in (".ts",".tsx",".js",".mjs",".cjs")) else "any")
            res["details"]["findings"].append({"file": str(f), "lang": lang, "hits": hits})
    if res["details"]["findings"]:
        res["status"] = "FAIL"
    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_tool_hash_baseline(repo_dir: Path, artifacts_dir: Path, baseline_path: Optional[Path] = None) -> Dict[str, Any]:
    """Hash all MCP tool definitions and compare against stored baseline to detect rug pulls.

    baseline_path: explicit path for the hash store. When provided (global baselines mode),
    it survives audit resets and tracks schema drift across pipeline runs. When None, falls
    back to artifacts_dir/tool_hashes.json (per-project, resets with the project dir).
    """
    import hashlib
    start = time.time()
    res = {"name": "tool_hash_baseline", "status": "PASS", "details": {}}

    # Extract tool definitions from Python files
    tools: Dict[str, str] = {}
    for f in rglob_text(repo_dir, exts=(".py",)):
        txt = read_text_safe(f)
        try:
            tree = ast.parse(txt)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            is_tool = any(
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and getattr(d.func.value, 'id', None) == 'mcp' and d.func.attr == 'tool') or
                (isinstance(d, ast.Attribute) and getattr(d.value, 'id', None) == 'mcp' and d.attr == 'tool') or
                (isinstance(d, ast.Name) and d.id == 'tool')
                for d in node.decorator_list
            )
            if not is_tool:
                continue
            docstring = ast.get_docstring(node) or ""
            params = [a.arg for a in node.args.args]
            canonical = json.dumps({"name": node.name, "doc": docstring, "params": params}, sort_keys=True)
            tools[node.name] = hashlib.sha256(canonical.encode()).hexdigest()

    # Also extract from TS/JS: server.tool("name", "description", handler)
    for f in rglob_text(repo_dir, exts=(".ts", ".js", ".tsx", ".mjs")):
        txt = read_text_safe(f)
        for m in re.finditer(r'\.tool\s*\(\s*["\']([^"\']+)["\']', txt):
            name = m.group(1)
            canonical = json.dumps({"name": name, "doc": "", "params": []}, sort_keys=True)
            tools[name] = hashlib.sha256(canonical.encode()).hexdigest()

    if not tools:
        res["details"] = {"reason": "no MCP tools found", "tool_count": 0}
        res["duration_s"] = round(time.time() - start, 3)
        return res

    if baseline_path is None:
        baseline_path = artifacts_dir / "tool_hashes.json"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    if not baseline_path.exists():
        # First run — create baseline with timestamps
        record = {"hashes": tools, "first_seen": now_iso, "last_updated": now_iso}
        baseline_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        res["details"] = {"baseline_created": True, "tool_count": len(tools), "baseline_path": str(baseline_path)}
        res["duration_s"] = round(time.time() - start, 3)
        return res

    try:
        record = json.loads(baseline_path.read_text(encoding="utf-8"))
        # Support old format (flat dict of hashes) and new format ({hashes, timestamps})
        if "hashes" in record:
            baseline = record["hashes"]
            first_seen = record.get("first_seen", "unknown")
        else:
            baseline = record  # old flat format
            first_seen = "unknown"
    except Exception:
        baseline = {}
        first_seen = "unknown"

    changed = []
    for name, new_hash in tools.items():
        old_hash = baseline.get(name)
        if old_hash and old_hash != new_hash:
            changed.append({"name": name, "old_hash": old_hash[:12], "new_hash": new_hash[:12]})

    new_tools = [n for n in tools if n not in baseline]
    removed_tools = [n for n in baseline if n not in tools]

    # Update baseline with new hashes and timestamp
    baseline.update(tools)
    updated_record = {"hashes": baseline, "first_seen": first_seen, "last_updated": now_iso}
    baseline_path.write_text(json.dumps(updated_record, indent=2), encoding="utf-8")

    if changed or removed_tools:
        res["status"] = "FAIL"
        res["details"] = {
            "changed_tools": changed,
            "removed_tools": removed_tools,
            "new_tools": new_tools,
            "first_seen": first_seen,
            "baseline_path": str(baseline_path),
        }
    else:
        res["details"] = {
            "tool_count": len(tools),
            "new_tools": new_tools,
            "first_seen": first_seen,
            "baseline_path": str(baseline_path),
        }

    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_cicd_workflow_scan(repo_dir: Path) -> Dict[str, Any]:
    """Scan .github/workflows for GitHub Actions supply chain attack patterns."""
    import sys as _sys
    start = time.time()
    res: Dict[str, Any] = {"name": "cicd_workflow_scan", "status": "SKIPPED", "details": {}}

    # Import the scanner from mcp_research if available, otherwise use inline copy.
    try:
        _brain = str(Path(__file__).resolve().parent.parent / "mcp-security-research")
        if _brain not in _sys.path:
            _sys.path.insert(0, _brain)
        from mcp_research.checks.cicd_workflow_scan import scan_cicd_workflows
    except ImportError:
        # Inline fallback so mcp_checker stays self-contained when run standalone.
        import re as _re
        def scan_cicd_workflows(repo_path: str) -> list:  # type: ignore[misc]
            findings = []
            rp = Path(repo_path)
            workflow_dir = rp / ".github" / "workflows"
            if not workflow_dir.exists():
                return findings
            for wf_file in list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")):
                try:
                    text = wf_file.read_text(errors="ignore")
                except OSError:
                    continue
                rel = str(wf_file.relative_to(rp))
                if _re.search(r'(curl|wget)\s+.*\|\s*(bash|sh|python|node)', text):
                    findings.append({"check": "cicd_workflow_scan", "severity": "CRITICAL", "confidence": 3,
                        "message": "Pipe-to-shell download pattern in workflow", "evidence": [rel]})
                if "ACTIONS_ALLOW_UNSECURE_COMMANDS: true" in text or "ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'" in text:
                    findings.append({"check": "cicd_workflow_scan", "severity": "CRITICAL", "confidence": 3,
                        "message": "ACTIONS_ALLOW_UNSECURE_COMMANDS: true enables insecure workflow commands", "evidence": [rel]})
                if "pull_request_target" in text and _re.search(r'ref:\s*\$\{\{.*head', text):
                    findings.append({"check": "cicd_workflow_scan", "severity": "CRITICAL", "confidence": 3,
                        "message": "pull_request_target + PR HEAD checkout — workflow injection vector", "evidence": [rel]})
                unpinned = [u for u in _re.findall(r'uses:\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@(?![\da-f]{40})[^\s]+)', text)
                            if not u.startswith(".") and "docker://" not in u]
                if unpinned:
                    findings.append({"check": "cicd_workflow_scan", "severity": "HIGH", "confidence": 2,
                        "message": f"Actions not pinned to commit SHA: {', '.join(unpinned[:5])}", "evidence": [rel]})
                if _re.search(r'\$\{\{\s*secrets\.', text) and _re.search(r'(curl|wget|fetch)', text, _re.I):
                    findings.append({"check": "cicd_workflow_scan", "severity": "HIGH", "confidence": 2,
                        "message": "Secrets accessed + outbound HTTP in same workflow — exfiltration risk", "evidence": [rel]})
                if not _re.search(r'^\s*permissions\s*:', text, _re.MULTILINE):
                    findings.append({"check": "cicd_workflow_scan", "severity": "MEDIUM", "confidence": 1,
                        "message": "No top-level permissions field — defaults to write-all", "evidence": [rel]})
            return findings

    raw = scan_cicd_workflows(str(repo_dir))

    workflow_dir = repo_dir / ".github" / "workflows"
    if not workflow_dir.exists() and not (repo_dir / "Makefile").exists() and not (repo_dir / ".pre-commit-config.yaml").exists():
        res["details"] = {"reason": "no .github/workflows, Makefile, or .pre-commit-config.yaml found"}
        res["duration_s"] = round(time.time() - start, 3)
        return res

    if not raw:
        res["status"] = "PASS"
        res["details"] = {"findings": [], "workflow_files_scanned": len(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))) if workflow_dir.exists() else 0}
    else:
        res["status"] = "FAIL"
        res["details"] = {
            "findings": raw,
            "critical": sum(1 for f in raw if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in raw if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in raw if f.get("severity") == "MEDIUM"),
        }

    res["duration_s"] = round(time.time() - start, 3)
    return res


# Known legitimate MCP server package names (canonical list)
_LEGITIMATE_MCP_SERVERS = {
    "mcp-server-filesystem", "mcp-server-github", "mcp-server-gitlab",
    "mcp-server-slack", "mcp-server-postgres", "mcp-server-sqlite",
    "mcp-server-brave-search", "mcp-server-fetch", "mcp-server-memory",
    "mcp-server-everything", "mcp-server-sequential-thinking",
    "mcp-server-puppeteer", "mcp-server-gdrive", "mcp-server-google-maps",
    "mcp-server-aws-kb-retrieval", "mcp-server-sentry", "mcp-server-time",
    "mcp-server-git", "mcp-server-docker", "mcp-server-kubernetes",
    "mcp-server-redis", "mcp-server-mongodb", "mcp-server-elasticsearch",
    "mcp-server-notion", "mcp-server-linear", "mcp-server-jira",
    "mcp-server-confluence", "mcp-server-zendesk", "mcp-server-stripe",
    "mcp-server-twilio", "mcp-server-sendgrid", "mcp-server-openai",
    "mcp-server-anthropic", "mcp-server-cohere", "mcp-server-huggingface",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-google-maps",
}


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def check_typosquatting(repo_path: str) -> list[dict]:
    """Detect package names suspiciously similar to legitimate MCP servers."""
    import json as _json
    findings = []
    rp = Path(repo_path)

    # Collect candidate names from package.json
    candidate_names: list[str] = []
    pkg_json = rp / "package.json"
    if pkg_json.exists():
        try:
            data = _json.loads(pkg_json.read_text(errors="ignore"))
            name = data.get("name", "")
            if name:
                candidate_names.append(name)
        except Exception:
            pass

    # Also check pyproject.toml for Python packages
    pyproject = rp / "pyproject.toml"
    if pyproject.exists():
        try:
            text = pyproject.read_text(errors="ignore")
            import re as _re
            m = _re.search(r'name\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                candidate_names.append(m.group(1))
        except Exception:
            pass

    # Also use the repo directory name itself
    repo_name = rp.name.lower()
    if repo_name:
        candidate_names.append(repo_name)

    for candidate in candidate_names:
        candidate_lower = candidate.lower().strip()
        # Direct check: is it already in the legitimate list?
        if candidate_lower in _LEGITIMATE_MCP_SERVERS:
            continue
        # Typosquatting check: edit distance 1-2 from a legitimate server
        for legit in _LEGITIMATE_MCP_SERVERS:
            dist = _edit_distance(candidate_lower, legit)
            if 0 < dist <= 2 and len(candidate_lower) >= 8:
                findings.append({
                    "check": "typosquatting",
                    "severity": "HIGH",
                    "confidence": 2,
                    "message": f"Package name '{candidate}' is edit-distance {dist} from legitimate MCP server '{legit}' — possible typosquatting",
                    "evidence": [candidate, f"similar to: {legit}"],
                })
                break  # one finding per candidate

    return findings


def check_dependency_confusion(repo_path: str) -> list[dict]:
    """Detect dependency confusion risk: packages with internal-style names on public registry."""
    import json as _json
    import re as _re
    findings = []
    rp = Path(repo_path)

    # Internal naming convention patterns (common in enterprise)
    internal_patterns = [
        r'^@[a-z][a-z0-9-]*-internal/',     # @company-internal/pkg
        r'^@[a-z][a-z0-9-]*-private/',      # @company-private/pkg
        r'^[a-z][a-z0-9-]*-internal$',      # pkg-internal
        r'^[a-z][a-z0-9-]*-private$',       # pkg-private
        r'^internal-[a-z]',                  # internal-pkg
        r'^corp-[a-z]',                      # corp-pkg
    ]

    # Also flag extremely short package names (1-3 chars) — classic confusion targets
    deps_to_check: list[str] = []

    pkg_json = rp / "package.json"
    if pkg_json.exists():
        try:
            data = _json.loads(pkg_json.read_text(errors="ignore"))
            for dep_section in ("dependencies", "devDependencies", "peerDependencies"):
                deps_to_check.extend(data.get(dep_section, {}).keys())
        except Exception:
            pass

    req_txt = rp / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Strip version specifiers
                    pkg = _re.split(r'[>=<!;\[]', line)[0].strip()
                    if pkg:
                        deps_to_check.append(pkg)
        except Exception:
            pass

    for dep in deps_to_check:
        dep_lower = dep.lower()
        # Check for internal naming patterns
        matched = False
        for pat in internal_patterns:
            if _re.match(pat, dep_lower):
                findings.append({
                    "check": "dependency_confusion",
                    "severity": "HIGH",
                    "confidence": 2,
                    "message": f"Dependency '{dep}' uses internal/private naming convention — dependency confusion attack risk if this name exists on the public npm/PyPI registry",
                    "evidence": [dep],
                })
                matched = True
                break
        if not matched:
            # Short package name (<=3 chars, not common public packages)
            _safe_short = {"is", "ms", "os", "fs", "rx", "qs", "co", "io", "ts"}
            if len(dep_lower) <= 3 and dep_lower not in _safe_short and not dep_lower.startswith("@"):
                findings.append({
                    "check": "dependency_confusion",
                    "severity": "MEDIUM",
                    "confidence": 1,
                    "message": f"Suspiciously short dependency name '{dep}' — verify this is the intended public package and not a private package name collision",
                    "evidence": [dep],
                })

    return findings


def check_package_scripts(repo_dir: Path) -> Dict[str, Any]:
    """Flag dangerous npm scripts (postinstall, preinstall, shell exec, network)."""
    start=time.time()
    res={"name":"package_scripts","status":"SKIPPED","details":{}}
    pkg = repo_dir / "package.json"
    if not pkg.exists():
        res["details"]={"reason":"package.json not found"}; res["duration_s"]=round(time.time()-start,3); return res

    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except Exception as e:
        res["status"]="ERROR"; res["details"]={"error":f"parse error: {e}"}; res["duration_s"]=round(time.time()-start,3); return res

    scripts = data.get("scripts",{}) or {}
    bad = []
    danger_re = re.compile(r'(curl|wget|bash\s+-c|sh\s+-c|node\s+-e|powershell|Invoke-WebRequest|nc|ncat)', re.I)
    # Known-safe lifecycle scripts: package manager enforcers and common build tools
    SAFE_LIFECYCLE_RE = re.compile(
        r'^\s*(npx\s+only-allow\s+\S+|yarn\s+only-allow\s+\S+|is-ci\b)\s*$', re.I
    )
    for name, val in scripts.items():
        if not isinstance(val, str): continue
        flags=[]
        if name in ("postinstall","preinstall","install"):
            if not SAFE_LIFECYCLE_RE.match(val):
                flags.append("lifecycle_hook")
        if danger_re.search(val):
            flags.append("dangerous_tokens")
        if flags:
            bad.append({"script":name,"cmd":val,"flags":flags})

    # Unpinned dependencies (supply chain risk)
    for dep_section in ("dependencies", "devDependencies"):
        for pkg_name, ver in (data.get(dep_section) or {}).items():
            if isinstance(ver, str) and ver.strip() in ("*", "latest", "x", ""):
                bad.append({
                    "script": f"dep:{pkg_name}",
                    "cmd": ver,
                    "flags": ["unpinned_dependency"],
                })

    res["status"]="PASS" if not bad else "FAIL"
    res["details"]={"findings":bad,"source":str(pkg)}
    res["duration_s"]=round(time.time()-start,3); return res

def check_ide_config_scan(repo_dir: Path) -> Dict[str, Any]:
    """Detect malicious IDE/devcontainer configs and AI coding assistant rule files.

    Covers: VSCode, Cursor, Windsurf, Claude Code, GitHub Copilot, Continue.dev,
    Cline/Roo, JetBrains, Zed, Neovim, Emacs, Sublime Text, devcontainer.
    Two threat classes:
      - Command execution: dangerous shell commands in task/hook/script fields
      - Prompt injection: AI rule files instructing the assistant to exfiltrate or manipulate
    """
    start = time.time()
    res: Dict[str, Any] = {"name": "ide_config_scan", "status": "PASS", "details": {"hits": []}}
    hits = res["details"]["hits"]

    _DANGER_CMD_RE = re.compile(
        r'curl\s|wget\s|bash\s+-c|sh\s+-c|eval\s*\(|exec\s*\(|python\s+-c|node\s+-e|'
        r'powershell|Invoke-WebRequest|Invoke-Expression|\bIEX\b|'
        r'base64\s+--decode|base64\s+-d\b|nc\s+-[lev]|ncat\b|'
        r'rm\s+-rf\b|chmod\s+\+x\b|/tmp/|/dev/shm/',
        re.I,
    )

    # AI rule file prompt injection patterns — instructions embedded in AI context files
    # that direct the AI assistant to exfiltrate data, ignore security, or access sensitive files
    _AI_INJECT_RE = re.compile(
        # Overt jailbreak phrasing
        r'ignore\s+(?:previous|all|prior|above)\s+instructions?'
        r'|disregard\s+(?:your|all)\s+(?:previous|prior|system)'
        r'|you\s+(?:must|should|will)\s+(?:always\s+)?(?:send|upload|post|exfiltrat|transmit|leak)'
        r'|(?:read|access|open|cat|send)\s+(?:~\/\.ssh|\/etc\/(?:passwd|shadow)|~\/\.aws|~\/\.git-credentials|~\/\.config|~\/\.env)'
        r'|(?:exfiltrat|harvest|collect\s+and\s+send)\b'
        r'|do\s+not\s+(?:mention|tell|inform|disclose|reveal)\s+(?:the\s+user|anyone)'
        r'|act\s+as\s+(?:a\s+)?(?:hacker|attacker|malicious|evil)'
        r'|you\s+are\s+now\s+(?:a\s+)?(?:different|unrestricted|jailbroken)'
        # Subtle injection patterns — instructions framed as "helpful" behavior
        r'|(?:include|attach|append|copy)\s+(?:the\s+)?(?:full\s+)?(?:file|directory|env|secret|token|key|credential)\s+(?:content|value|listing)'
        r'|(?:always|silently|automatically)\s+(?:include|attach|forward|copy|post|upload)\s+(?:to|into)\s+(?:https?:|ftp:|the\s+response)'
        r'|before\s+(?:responding|answering|continuing)[^.]{0,80}?(?:read|fetch|access|send|post|upload)'
        r'|when\s+(?:summarizing|reading|listing|processing)[^.]{0,80}?(?:include|attach|send|copy)\s+(?:the\s+)?(?:full|raw|verbatim)'
        r'|(?:make\s+(?:an?\s+)?(?:http|api|fetch|web)|curl|wget|fetch\s+url)\s+(?:request|call)?\s*(?:to|of)?\s*https?:'
        # Data destination markers
        r'|(?:webhook|exfil|callback|c2|beacon)\.(?:[a-z0-9-]+\.)+[a-z]{2,}'
        # Sensitive path enumeration
        r'|(?:list|read|enumerate|dump)\s+(?:all\s+)?(?:files\s+)?(?:in|under)\s+(?:~\/?|\$HOME|\/etc|\/root)'
        r'|env(?:iron(?:ment)?)?\s+(?:var(?:iable)?s?\s+)?(?:to|into|via)\s+https?:',
        re.I,
    )

    def _cmd_hit(type_: str, file_: Path, extra: dict) -> None:
        hits.append({"type": type_, "file": str(file_.relative_to(repo_dir)), **extra})

    # ── VSCode ────────────────────────────────────────────────────────────────
    for tasks_file in repo_dir.rglob(".vscode/tasks.json"):
        try:
            data = json.loads(tasks_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for task in (data.get("tasks") or []) if isinstance(data, dict) else []:
            cmd = str(task.get("command", ""))
            args_str = " ".join(str(a) for a in (task.get("args") or []))
            full_cmd = f"{cmd} {args_str}".strip()
            if _DANGER_CMD_RE.search(full_cmd):
                _cmd_hit("vscode_task_dangerous_command", tasks_file,
                         {"task": task.get("label", "<unlabeled>"), "command": full_cmd[:200]})

    for settings_file in repo_dir.rglob(".vscode/settings.json"):
        try:
            data = json.loads(settings_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for key, val in data.items():
            if "terminal.integrated.env" in key and isinstance(val, dict):
                for env_key, env_val in val.items():
                    if isinstance(env_val, str) and _DANGER_CMD_RE.search(env_val):
                        _cmd_hit("vscode_terminal_env_injection", settings_file,
                                 {"env_var": env_key, "value": env_val[:200]})

    # ── devcontainer ──────────────────────────────────────────────────────────
    for dc_file in list(repo_dir.rglob("devcontainer.json")) + list(repo_dir.rglob(".devcontainer/devcontainer.json")):
        try:
            data = json.loads(dc_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for hook in ("postCreateCommand", "postStartCommand", "postAttachCommand", "initializeCommand"):
            cmd = data.get(hook)
            if not cmd:
                continue
            cmd_str = cmd if isinstance(cmd, str) else (" ".join(cmd) if isinstance(cmd, list) else json.dumps(cmd))
            if _DANGER_CMD_RE.search(cmd_str):
                _cmd_hit(f"devcontainer_{hook}_dangerous", dc_file,
                         {"hook": hook, "command": cmd_str[:200]})

    # ── Cursor ────────────────────────────────────────────────────────────────
    for mcp_cfg in list(repo_dir.rglob(".cursor/mcp.json")) + list(repo_dir.rglob(".cursor/settings.json")):
        try:
            data = json.loads(mcp_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for server_name, server_cfg in (data.get("mcpServers") or {}).items():
            if not isinstance(server_cfg, dict):
                continue
            cmd = str(server_cfg.get("command", ""))
            url = str(server_cfg.get("url", ""))
            if _DANGER_CMD_RE.search(cmd):
                _cmd_hit("cursor_mcp_dangerous_command", mcp_cfg,
                         {"server": server_name, "command": cmd[:200]})
            if url.startswith("http://"):
                _cmd_hit("cursor_mcp_unencrypted_url", mcp_cfg,
                         {"server": server_name, "url": url})

    # .cursor/rules — Cursor project rules file (prompt injection)
    for rules_file in list(repo_dir.rglob(".cursor/rules")) + list(repo_dir.rglob(".cursorrules")):
        if not rules_file.is_file():
            continue
        try:
            content = rules_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("cursor_rules_prompt_injection", rules_file,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})

    # ── Windsurf (Codeium) ────────────────────────────────────────────────────
    # .windsurf/cascade.json — Cascade AI agent config with MCP servers and commands
    for ws_cfg in list(repo_dir.rglob(".windsurf/cascade.json")) + list(repo_dir.rglob(".windsurf/settings.json")):
        try:
            data = json.loads(ws_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for server_name, server_cfg in (data.get("mcpServers") or {}).items():
            if not isinstance(server_cfg, dict):
                continue
            cmd = str(server_cfg.get("command", ""))
            if _DANGER_CMD_RE.search(cmd):
                _cmd_hit("windsurf_mcp_dangerous_command", ws_cfg,
                         {"server": server_name, "command": cmd[:200]})

    # .windsurfrules — AI system prompt context file (prompt injection risk)
    for rules_file in repo_dir.rglob(".windsurfrules"):
        try:
            content = rules_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("windsurfrules_prompt_injection", rules_file,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})

    # ── Claude Code ───────────────────────────────────────────────────────────
    # .claude/settings.json — Claude Code workspace settings
    for claude_cfg in repo_dir.rglob(".claude/settings.json"):
        try:
            data = json.loads(claude_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        # Malicious tool allowlists or permission grants
        allowed_tools = data.get("permissions", {}).get("allow", []) or []
        danger_tools = [t for t in allowed_tools if any(
            x in str(t) for x in ("Bash", "Write", "Edit", "computer")
        )]
        if danger_tools:
            _cmd_hit("claude_settings_broad_tool_allow", claude_cfg,
                     {"allowed_tools": danger_tools[:10]})
        # Malicious bash commands allowed in permissions
        bash_deny = data.get("permissions", {}).get("deny", []) or []
        if not bash_deny and "Bash" in str(allowed_tools):
            _cmd_hit("claude_settings_bash_no_deny_list", claude_cfg,
                     {"note": "Bash allowed with no deny list — unrestricted shell access"})

    # .claude/commands/ — custom slash commands (arbitrary prompt injection)
    for cmd_file in repo_dir.rglob(".claude/commands/*.md"):
        try:
            content = cmd_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("claude_command_prompt_injection", cmd_file,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})
        if _DANGER_CMD_RE.search(content):
            dm = _DANGER_CMD_RE.search(content)
            lineno = content[:dm.start()].count("\n") + 1
            _cmd_hit("claude_command_dangerous_shell", cmd_file,
                     {"line": lineno, "snippet": content[dm.start():dm.start()+150]})

    # ── GitHub Copilot ────────────────────────────────────────────────────────
    # .github/copilot-instructions.md — workspace instructions Copilot follows for ALL users
    for copilot_file in list(repo_dir.rglob(".github/copilot-instructions.md")) + \
                         list(repo_dir.rglob(".copilot-instructions.md")):
        try:
            content = copilot_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("copilot_instructions_prompt_injection", copilot_file,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})

    # ── Continue.dev ──────────────────────────────────────────────────────────
    # .continue/config.json — AI assistant config with slash commands and context providers
    for cont_cfg in repo_dir.rglob(".continue/config.json"):
        try:
            data = json.loads(cont_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        # Slash commands with shell execution
        for sc in (data.get("slashCommands") or []):
            run = str(sc.get("run", "") or sc.get("command", ""))
            if _DANGER_CMD_RE.search(run):
                _cmd_hit("continue_slash_command_dangerous", cont_cfg,
                         {"command_name": sc.get("name", ""), "run": run[:200]})
        # Context providers fetching arbitrary URLs
        for cp in (data.get("contextProviders") or []):
            url = str((cp.get("params") or {}).get("url", ""))
            if url.startswith("http://"):
                _cmd_hit("continue_context_provider_unencrypted", cont_cfg,
                         {"provider": cp.get("name", ""), "url": url})
        # MCP server entries
        for server in (data.get("mcpServers") or []):
            cmd = str(server.get("command", ""))
            if _DANGER_CMD_RE.search(cmd):
                _cmd_hit("continue_mcp_dangerous_command", cont_cfg,
                         {"server": server.get("name", ""), "command": cmd[:200]})

    # ── Cline / Roo ───────────────────────────────────────────────────────────
    for rules_file in list(repo_dir.rglob(".clinerules")) + \
                       list(repo_dir.rglob(".roorules")) + \
                       list(repo_dir.rglob(".clinerules-code")) + \
                       list(repo_dir.rglob(".roo/rules/*.md")):
        try:
            content = rules_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("cline_roo_rules_prompt_injection", rules_file,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})

    # ── JetBrains ─────────────────────────────────────────────────────────────
    # .idea/runConfigurations/*.xml — run configs auto-discovered by IntelliJ/PyCharm/etc.
    import xml.etree.ElementTree as _ET
    for rc_file in repo_dir.rglob(".idea/runConfigurations/*.xml"):
        try:
            tree = _ET.parse(rc_file)
            root = tree.getroot()
        except Exception:
            continue
        for elem in root.iter():
            for attr in ("value", "PROGRAM_PARAMETERS", "SCRIPT_TEXT", "SCRIPT_PATH"):
                val = elem.get(attr, "")
                if val and _DANGER_CMD_RE.search(val):
                    _cmd_hit("jetbrains_run_config_dangerous", rc_file,
                             {"config": rc_file.name, "attribute": attr, "value": val[:200]})
                    break

    # ── Zed ───────────────────────────────────────────────────────────────────
    # .zed/settings.json — tasks with shell commands
    for zed_cfg in repo_dir.rglob(".zed/settings.json"):
        try:
            data = json.loads(zed_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for task in (data.get("tasks") or []):
            cmd = str(task.get("command", ""))
            args = " ".join(str(a) for a in (task.get("args") or []))
            full = f"{cmd} {args}".strip()
            if _DANGER_CMD_RE.search(full):
                _cmd_hit("zed_task_dangerous_command", zed_cfg,
                         {"task": task.get("label", ""), "command": full[:200]})

    # ── Neovim ────────────────────────────────────────────────────────────────
    # .nvim.lua / .nvimrc — project-local lua config, auto-sourced by Neovim with exrc
    for nvim_file in list(repo_dir.rglob(".nvim.lua")) + list(repo_dir.rglob(".nvimrc")) + \
                      list(repo_dir.rglob(".nvim/*.lua")):
        try:
            content = nvim_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # vim.fn.system / io.popen / os.execute with dangerous commands
        _NVIM_EXEC_RE = re.compile(
            r'(?:vim\.fn\.system|io\.popen|os\.execute|vim\.cmd)\s*\(["\']([^"\']{0,300})["\']',
            re.I,
        )
        for m in _NVIM_EXEC_RE.finditer(content):
            if _DANGER_CMD_RE.search(m.group(1)):
                lineno = content[:m.start()].count("\n") + 1
                _cmd_hit("neovim_exrc_dangerous_command", nvim_file,
                         {"line": lineno, "command": m.group(1)[:200]})

    # ── Emacs ─────────────────────────────────────────────────────────────────
    # .dir-locals.el — directory-local variables, can set eval hooks that execute elisp
    for el_file in repo_dir.rglob(".dir-locals.el"):
        try:
            content = el_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        _EMACS_EXEC_RE = re.compile(
            r'\((?:eval|shell-command|start-process|call-process)\s+["\']([^"\']{0,300})["\']',
            re.I,
        )
        for m in _EMACS_EXEC_RE.finditer(content):
            if _DANGER_CMD_RE.search(m.group(1)):
                lineno = content[:m.start()].count("\n") + 1
                _cmd_hit("emacs_dir_locals_dangerous_eval", el_file,
                         {"line": lineno, "command": m.group(1)[:200]})

    # ── Sublime Text ──────────────────────────────────────────────────────────
    # *.sublime-project — build systems with shell commands
    for st_file in repo_dir.rglob("*.sublime-project"):
        try:
            data = json.loads(st_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for build in (data.get("build_systems") or []):
            cmd = str(build.get("shell_cmd", "") or " ".join(build.get("cmd") or []))
            if _DANGER_CMD_RE.search(cmd):
                _cmd_hit("sublime_build_dangerous_command", st_file,
                         {"build": build.get("name", ""), "command": cmd[:200]})

    # ── Google Gemini CLI ─────────────────────────────────────────────────────
    # .gemini/settings.json — MCP servers, tool allowlists, coreTools
    for gemini_cfg in repo_dir.rglob(".gemini/settings.json"):
        try:
            data = json.loads(gemini_cfg.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for server_name, server_cfg in (data.get("mcpServers") or {}).items():
            if not isinstance(server_cfg, dict):
                continue
            cmd = str(server_cfg.get("command", ""))
            url = str(server_cfg.get("url", ""))
            if _DANGER_CMD_RE.search(cmd):
                _cmd_hit("gemini_mcp_dangerous_command", gemini_cfg,
                         {"server": server_name, "command": cmd[:200]})
            if url.startswith("http://"):
                _cmd_hit("gemini_mcp_unencrypted_url", gemini_cfg,
                         {"server": server_name, "url": url})
        # coreTools: code_execution grants the LLM direct code execution in the workspace
        core_tools = data.get("coreTools") or []
        if "code_execution" in [str(t) for t in core_tools]:
            _cmd_hit("gemini_settings_code_execution_enabled", gemini_cfg,
                     {"coreTools": core_tools,
                      "note": "code_execution grants LLM direct sandbox code execution"})
        # toolConfig.allowedTools with wildcard
        allowed_tools = (data.get("toolConfig") or {}).get("allowedTools") or []
        if isinstance(allowed_tools, list) and any(
            str(t).lower() in ("*", "all") for t in allowed_tools
        ):
            _cmd_hit("gemini_settings_wildcard_tool_allow", gemini_cfg,
                     {"allowed_tools": allowed_tools[:10]})

    # GEMINI.md — project-level system prompt context for Gemini CLI
    for gemini_md in list(repo_dir.rglob("GEMINI.md")) + list(repo_dir.rglob(".gemini/GEMINI.md")):
        try:
            content = gemini_md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = _AI_INJECT_RE.search(content)
        if m:
            lineno = content[:m.start()].count("\n") + 1
            _cmd_hit("gemini_md_prompt_injection", gemini_md,
                     {"line": lineno, "snippet": content[m.start():m.start()+150]})
        dm = _DANGER_CMD_RE.search(content)
        if dm:
            lineno = content[:dm.start()].count("\n") + 1
            _cmd_hit("gemini_md_dangerous_command", gemini_md,
                     {"line": lineno, "snippet": content[dm.start():dm.start()+150]})

    # ── Generic AI rules files (catch-all for instruction injection) ──────────
    # Any *rules file that might be picked up by an AI coding assistant
    # Exclude files already handled by specific sections above
    _RULES_GLOB_NAMES = {
        ".aider.conf.yml", ".aider.conf.yaml",
        "AGENTS.md",              # OpenAI Codex context file
    }
    # GEMINI.md / .windsurfrules / .clinerules / .roorules handled in dedicated sections above
    for f in repo_dir.iterdir() if repo_dir.is_dir() else []:
        if f.name in _RULES_GLOB_NAMES and f.is_file():
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            m = _AI_INJECT_RE.search(content)
            if m:
                lineno = content[:m.start()].count("\n") + 1
                _cmd_hit("ai_rules_file_prompt_injection", f,
                         {"file_type": f.name, "line": lineno,
                          "snippet": content[m.start():m.start()+150]})

    res["status"] = "FAIL" if hits else "PASS"
    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_obfuscation_scan(repo_dir: Path) -> Dict[str, Any]:
    """Detect code obfuscation: high-entropy strings, base64+eval, string-concat eval, dynamic require, hex payloads."""
    import math
    start = time.time()
    res: Dict[str, Any] = {"name": "obfuscation_scan", "status": "PASS", "details": {"hits": []}}
    hits = res["details"]["hits"]

    _SKIP_DIRS = re.compile(r'(?:^|/)(?:test|tests|spec|__tests__|fixtures|mocks|docs?|node_modules|dist|build|\.git)/', re.I)
    _SKIP_EXT = {".md", ".rst", ".txt", ".html", ".json", ".yaml", ".yml", ".lock",
                 ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
    _CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".sh", ".ps1", ".rb", ".php"}

    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    # Patterns for specific obfuscation techniques
    _B64_EXEC_RE = re.compile(
        r'(?:atob|Buffer\.from)\s*\([^)]{0,200}\)\s*[;\s]*.*?(?:eval|Function)\s*\('
        r'|base64\.b64decode\s*\([^)]{0,200}\).*?(?:exec|eval)\s*\(',
        re.I | re.S,
    )
    _STR_CONCAT_EVAL_RE = re.compile(
        r'(?:eval|exec|Function)\s*\(\s*["\'][a-z]{1,4}["\'\s]*\+',
        re.I,
    )
    _DYNAMIC_REQUIRE_RE = re.compile(
        r'\brequire\s*\(\s*(?!["\'`][a-z@\./])(?!__dirname)(?!path\b)[^)"\'`]{1,80}\)',
    )
    _HEX_PAYLOAD_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){12,}')
    _CHR_CHAIN_RE = re.compile(r'(?:chr\s*\(\d+\)\s*[\+&]\s*){4,}', re.I)
    ENTROPY_THRESHOLD = 4.9

    for f in repo_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.stat().st_size > 300_000:  # skip files > 300KB
            continue
        rel = str(f.relative_to(repo_dir))
        if _SKIP_DIRS.search(rel + "/"):
            continue
        if f.suffix.lower() in _SKIP_EXT:
            continue
        if f.suffix.lower() not in _CODE_EXTS:
            continue

        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # High-entropy string literals (base64 payloads, encrypted content)
        for m in re.finditer(r'["\']([A-Za-z0-9+/=]{60,})["\']', content):
            s = m.group(1)
            ent = shannon_entropy(s)
            if ent >= ENTROPY_THRESHOLD:
                lineno = content[:m.start()].count("\n") + 1
                hits.append({
                    "type": "high_entropy_string",
                    "file": rel,
                    "line": lineno,
                    "entropy": round(ent, 2),
                    "snippet": s[:80] + ("..." if len(s) > 80 else ""),
                })
                break  # one hit per file is enough

        # base64 decode + eval/exec in same file
        if _B64_EXEC_RE.search(content):
            m = _B64_EXEC_RE.search(content)
            lineno = content[:m.start()].count("\n") + 1
            hits.append({
                "type": "base64_then_eval",
                "file": rel,
                "line": lineno,
                "snippet": m.group(0)[:120],
            })

        # eval("str" + ...) string concat evasion
        for m in _STR_CONCAT_EVAL_RE.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            hits.append({
                "type": "string_concat_eval",
                "file": rel,
                "line": lineno,
                "snippet": m.group(0)[:120],
            })

        # Dynamic require(variable) — evades static import analysis
        for m in _DYNAMIC_REQUIRE_RE.finditer(content):
            inner = m.group(0)
            if any(safe in inner for safe in ("process.env", "config.", "path.join", "options.")):
                continue
            lineno = content[:m.start()].count("\n") + 1
            hits.append({
                "type": "dynamic_require",
                "file": rel,
                "line": lineno,
                "snippet": inner[:120],
            })

        # Long hex-encoded payload
        for m in _HEX_PAYLOAD_RE.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            hits.append({
                "type": "hex_encoded_payload",
                "file": rel,
                "line": lineno,
                "snippet": m.group(0)[:80],
            })

        # chr() chain obfuscation (Python)
        for m in _CHR_CHAIN_RE.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            hits.append({
                "type": "chr_chain_obfuscation",
                "file": rel,
                "line": lineno,
                "snippet": m.group(0)[:120],
            })

        if len(hits) > 50:  # cap total hits
            break

    res["status"] = "FAIL" if hits else "PASS"
    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_npm_source_integrity(repo_dir: Path) -> Dict[str, Any]:
    """Compare npm published tarball against GitHub source to detect npm-only payload injection."""
    import urllib.request
    import tarfile as _tarfile
    import tempfile
    start = time.time()
    res: Dict[str, Any] = {"name": "npm_source_integrity", "status": "PASS", "details": {"hits": []}}
    hits = res["details"]["hits"]

    pkg_file = repo_dir / "package.json"
    if not pkg_file.exists():
        res["status"] = "SKIPPED"
        res["details"]["reason"] = "no package.json"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    try:
        pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception as e:
        res["status"] = "SKIPPED"
        res["details"]["reason"] = f"parse error: {e}"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    npm_name = pkg_data.get("name", "")
    npm_version = pkg_data.get("version", "")
    if not npm_name or not npm_version:
        res["status"] = "SKIPPED"
        res["details"]["reason"] = "no name/version"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    # Flag `files` field that excludes common source dirs (hides code from auditors)
    files_field = pkg_data.get("files")
    if files_field is not None and isinstance(files_field, list):
        included_patterns = " ".join(str(x) for x in files_field).lower()
        for src_dir in ("src", "lib"):
            if src_dir not in included_patterns:
                hits.append({
                    "type": "npm_files_excludes_source",
                    "detail": f"'files' field does not include '{src_dir}/' — npm tarball may differ from GitHub",
                    "files_field": files_field,
                })

    # Fetch npm registry metadata and compare scripts
    try:
        meta_url = f"https://registry.npmjs.org/{npm_name}/{npm_version}"
        req = urllib.request.Request(meta_url, headers={"User-Agent": "mcp-checker/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            npm_meta = json.loads(resp.read())
    except Exception as e:
        res["details"]["npm_fetch_skipped"] = str(e)
        res["status"] = "FAIL" if hits else "PASS"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    npm_scripts = npm_meta.get("scripts") or {}
    github_scripts = pkg_data.get("scripts") or {}
    for hook in ("postinstall", "preinstall", "install", "prepare"):
        npm_cmd = npm_scripts.get(hook, "")
        gh_cmd = github_scripts.get(hook, "")
        if npm_cmd != gh_cmd:
            hits.append({
                "type": "npm_github_script_mismatch",
                "hook": hook,
                "npm_published": npm_cmd or "(absent)",
                "github_source": gh_cmd or "(absent)",
            })

    # Download and diff tarball for extra JS files
    tarball_url = (npm_meta.get("dist") or {}).get("tarball", "")
    if tarball_url:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tgz = os.path.join(tmpdir, "pkg.tgz")
                urllib.request.urlretrieve(tarball_url, tgz)
                npm_js_files: set = set()
                with _tarfile.open(tgz, "r:gz") as tf:
                    for member in tf.getmembers():
                        name = member.name
                        if name.startswith("package/"):
                            name = name[len("package/"):]
                        if name.endswith(".js") and not name.startswith("node_modules"):
                            npm_js_files.add(name)
                github_js = {
                    str(f.relative_to(repo_dir))
                    for f in repo_dir.rglob("*.js")
                    if "node_modules" not in str(f.relative_to(repo_dir))
                }
                npm_only = npm_js_files - github_js
                suspicious = [f for f in npm_only if any(x in f for x in (".min.", "bundle", "dist/", "lib/"))]
                if suspicious:
                    hits.append({
                        "type": "npm_only_js_files",
                        "detail": "JS files present in npm tarball but not in GitHub source",
                        "files": sorted(suspicious)[:10],
                    })
        except Exception as e:
            res["details"]["tarball_diff_error"] = str(e)

    res["status"] = "FAIL" if hits else "PASS"
    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_dependency_reputation(repo_dir: Path) -> Dict[str, Any]:
    """Flag npm dependencies that are very new (<30 days) or show package-hijack timing patterns."""
    import urllib.request
    from datetime import datetime, timezone as _tz
    start = time.time()
    res: Dict[str, Any] = {"name": "dependency_reputation", "status": "PASS", "details": {"hits": []}}
    hits = res["details"]["hits"]

    pkg_file = repo_dir / "package.json"
    if not pkg_file.exists():
        res["status"] = "SKIPPED"
        res["details"]["reason"] = "no package.json"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    try:
        pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception:
        res["status"] = "SKIPPED"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    all_deps: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        all_deps.update(pkg_data.get(section) or {})

    if not all_deps:
        res["status"] = "SKIPPED"
        res["details"]["reason"] = "no dependencies"
        res["duration_s"] = round(time.time() - start, 3)
        return res

    now = datetime.now(_tz.utc)
    NEW_PKG_DAYS = 30
    HIJACK_PKG_MIN_AGE = 365   # package must be this old
    HIJACK_LATEST_MAX_AGE = 14  # but latest version published within this many days

    for dep_name in list(all_deps.keys())[:40]:  # cap at 40 to avoid long network scans
        try:
            url = f"https://registry.npmjs.org/{dep_name}"
            req = urllib.request.Request(url, headers={"User-Agent": "mcp-checker/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                meta = json.loads(resp.read())
        except Exception:
            continue

        time_data = meta.get("time") or {}
        created_str = time_data.get("created", "")
        if not created_str:
            continue

        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        except Exception:
            continue

        pkg_age_days = (now - created).days

        if pkg_age_days < NEW_PKG_DAYS:
            hits.append({
                "type": "very_new_dependency",
                "package": dep_name,
                "age_days": pkg_age_days,
                "created": created_str[:10],
            })
            continue

        # Hijack pattern: old package, but latest version just published
        latest_ver = (meta.get("dist-tags") or {}).get("latest", "")
        if latest_ver and latest_ver in time_data:
            try:
                pub_str = time_data[latest_ver]
                published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                latest_age = (now - published).days
                if pkg_age_days > HIJACK_PKG_MIN_AGE and latest_age < HIJACK_LATEST_MAX_AGE:
                    hits.append({
                        "type": "possible_package_hijack",
                        "package": dep_name,
                        "package_age_days": pkg_age_days,
                        "latest_version": latest_ver,
                        "latest_published_days_ago": latest_age,
                    })
            except Exception:
                pass

    res["status"] = "FAIL" if hits else "PASS"
    res["duration_s"] = round(time.time() - start, 3)
    return res


def check_prompt_schema(repo_dir: Path) -> Dict[str,Any]:
    start=time.time()
    res={"name":"prompt_schema","status":"PASS","details":{"violations":[]}}
    role_ok=re.compile(r'\"role\"\s*:\s*\"(system|user|assistant)\"')
    have_content=re.compile(r'\"content\"\s*:\s*\"')
    temp_key=re.compile(r'\"temperature\"\s*:\s*([0-9.]+)')
    yaml_temp=re.compile(r'\btemperature:\s*([0-9.]+)')
    temp_warns=[]; msg_viols=[]
    for f in rglob_text(repo_dir, exts=(".json",".jsonc",".yaml",".yml",".py",".ts",".js",".tsx",".env",".toml",".ini",".md")):
        txt=read_text_safe(f)
        if "[{" in txt and "]" in txt and "\"role\"" in txt and "\"content\"" in txt:
            if not role_ok.search(txt) or not have_content.search(txt):
                msg_viols.append(str(f))
        for m in temp_key.finditer(txt):
            try:
                if float(m.group(1))>0.0: temp_warns.append(f"{f}:{m.group(1)}")
            except: pass
        for m in yaml_temp.finditer(txt):
            try:
                if float(m.group(1))>0.0: temp_warns.append(f"{f}:{m.group(1)}")
            except: pass
    if msg_viols:
        res["status"]="FAIL"; res["details"]["violations"].append({"type":"prompt_schema","files":msg_viols})
    if temp_warns: res["details"]["temperature>0"]=temp_warns
    res["duration_s"]=round(time.time()-start,3); return res

def check_tool_schema(repo_dir: Path, probe_dir: Path, scans_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"tool_schema","status":"SKIPPED","details":{}}
    validator_script = probe_dir / "tool_schema_validator.py"
    if not validator_script.exists():
        res["details"]={"reason":"tool_schema_validator.py not found"}
        res["duration_s"]=round(time.time()-start,3)
        return res

    output_path = scans_dir / "tool-schema-results.json"
    rc,out,err,dur = run_cmd(
        ["python3", str(validator_script), str(repo_dir), "--output", str(output_path), "--fail-on-violations"],
        timeout=120
    )

    if output_path.exists():
        try:
            results = json.loads(output_path.read_text())
            res["details"] = results
            res["status"] = "PASS" if results.get("safe", False) else "FAIL"
        except Exception as e:
            res["status"] = "ERROR"
            res["details"] = {"error": f"Failed to parse results: {e}"}
    else:
        res["status"] = "FAIL" if rc != 0 else "PASS"
        res["details"] = {"rc": rc, "stdout": out[-1000:], "stderr": err[-1000:]}

    res["duration_s"] = round(dur, 3)
    return res

# ==================== docker / dynamic / vuln / sbom ====================

def _container_runtime() -> str:
    """Return 'podman' if available and working, else 'docker'."""
    if which("podman"):
        rc, _, _, _ = run_cmd(["podman", "version"], timeout=10)
        if rc == 0:
            return "podman"
    return "docker"

def check_docker_build(repo_dir: Path, image_tag: str) -> Dict[str, Any]:
    start=time.time()
    res={"name":"docker_build","status":"SKIPPED","details":{}}
    runtime = _container_runtime()
    if not which(runtime): res["details"]={"reason":f"{runtime} not found"}; res["duration_s"]=round(time.time()-start,3); return res
    if not (repo_dir/"Dockerfile").exists(): res["details"]={"reason":"Dockerfile not found"}; res["duration_s"]=round(time.time()-start,3); return res
    print(f"🐳 Building image {image_tag} (via {runtime}) ...", file=sys.stderr)
    rc,out,err,dur=run_cmd([runtime,"build","-t",image_tag,"."],cwd=repo_dir,timeout=1800)
    res["status"]="PASS" if rc==0 else "FAIL"
    res["details"]={"rc":rc,"stdout_tail":out[-800:], "stderr_tail":err[-2000:], "image":image_tag, "runtime":runtime}
    res["duration_s"]=round(dur,3); return res

def _monitor_container_network(runtime: str, container_id: str, interval: float = 3.0) -> Dict[str, Any]:
    """Poll outbound network connections from a running container every `interval` seconds.

    Uses `<runtime> exec <id> ss -tnp` (preferred) or `netstat -tnp` as fallback.

    Returns a dict:
      {"status": "monitored"|"unsupported"|"unavailable",
       "reason": str (when status != "monitored"),
       "connections": [...],   # only when status == "monitored"
       "polls": int}
    Distroless / minimal containers without `ss` or `netstat` return "unsupported"
    instead of silently appearing to PASS.
    """
    # First: detect whether the container has any monitoring tool at all.
    rc, out, _, _ = run_cmd(
        [runtime, "exec", container_id, "sh", "-c",
         "(command -v ss >/dev/null && echo ss) || (command -v netstat >/dev/null && echo netstat) || echo none"],
        timeout=10,
    )
    tool = (out or "").strip().splitlines()[-1].strip() if out else ""
    if rc != 0:
        return {"status": "unavailable", "reason": f"exec failed (rc={rc})"}
    if tool == "none" or tool not in ("ss", "netstat"):
        return {
            "status": "unsupported",
            "reason": "container has neither `ss` nor `netstat` (likely distroless / minimal); "
                      "outbound network activity could not be observed — treat as INSPECTED=False, not PASS",
        }

    cmd_str = "ss -tn 2>/dev/null" if tool == "ss" else "netstat -tn 2>/dev/null"
    # RFC-1918 / loopback / link-local IPv4 + IPv6 / CGNAT — expected for local MCP servers
    _LOCAL_RE = re.compile(
        r'^(?:127\.'
        r'|10\.'
        r'|172\.(?:1[6-9]|2\d|3[01])\.'
        r'|192\.168\.'
        r'|169\.254\.'                       # IPv4 link-local
        r'|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.'   # CGNAT 100.64.0.0/10
        r'|::1$'
        r'|fe80:'                              # IPv6 link-local
        r'|f[cd][0-9a-f]{2}:)',                # IPv6 ULA fc00::/7
        re.I,
    )
    seen: set = set()
    connections: List[dict] = []
    polls = 0
    t0 = time.time()
    while time.time() - t0 < 120:  # monitor for up to 2 minutes
        time.sleep(interval)
        polls += 1
        rc, out, _, _ = run_cmd(
            [runtime, "exec", container_id, "sh", "-c", cmd_str],
            timeout=10,
        )
        if rc != 0:
            break  # container exited
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0] not in ("ESTAB", "CLOSE_WAIT", "SYN_SENT", "tcp"):
                continue
            remote = parts[4] if len(parts) > 4 else ""
            remote_ip = remote.rsplit(":", 1)[0].strip("[]")
            if not remote_ip or _LOCAL_RE.match(remote_ip):
                continue
            key = remote_ip
            if key in seen:
                continue
            seen.add(key)
            connections.append({"remote": remote, "line": line.strip()[:200]})
    return {"status": "monitored", "tool": tool, "connections": connections, "polls": polls}


def check_dynamic_local_runner(image_tag: str, probe_dir: Path, scans_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"dynamic","status":"SKIPPED","details":{}}
    s=probe_dir/"run_checks.sh"
    if not s.exists(): res["details"]={"reason":"local run_checks.sh not found"}; res["duration_s"]=round(time.time()-start,3); return res
    try: os.chmod(s,0o755)
    except: pass
    runtime = _container_runtime()
    env=os.environ.copy()
    env.setdefault("IMG", image_tag)
    env.setdefault("PORT", "9000")
    env.setdefault("CONTAINER_RUNTIME", runtime)
    # canaries for leak detection (runner also has its own canaries)
    env["PII_CANARY_EMAIL"]="alice@example.com"
    env["PII_CANARY_SECRET"]="s3cr3t-DO-NOT-LOG"
    print(f"🔬 Running dynamic security checks (via {runtime}) ...", file=sys.stderr)

    # Start network monitor in a thread before the run
    import threading
    netmon_result: Dict[str, Any] = {"status": "not_started", "reason": "container not detected"}

    def _launch_netmon() -> None:
        # Give the container a moment to start, then find its ID and begin polling
        time.sleep(5)
        try:
            rc2, cid_out, _, _ = run_cmd(
                [runtime, "ps", "--filter", f"ancestor={image_tag}", "--format", "{{.ID}}", "-q"],
                timeout=10,
            )
            cid = cid_out.strip().splitlines()[0].strip() if cid_out.strip() else ""
            if cid:
                netmon_result.clear()
                netmon_result.update(_monitor_container_network(runtime, cid))
        except Exception as e:
            netmon_result.clear()
            netmon_result.update({"status": "unavailable", "reason": f"exception: {e}"})

    netmon_thread = threading.Thread(target=_launch_netmon, daemon=True)
    netmon_thread.start()

    rc,out,err,dur=run_cmd(["bash",str(s)],timeout=1200,env=env)
    netmon_thread.join(timeout=5)

    leaks=[]
    for line in (out+err).splitlines():
        if "alice@example.com" in line or "s3cr3t-DO-NOT-LOG" in line:
            leaks.append(line.strip()[:240])

    dynamic_path = scans_dir / "dynamic-run.json"
    try:
        dynamic_result = {
            "results": [{"name": "dynamic", "status": "PASS" if rc == 0 else "FAIL",
                         "details": {"rc": rc, "stdout_tail": out[-2000:], "stderr_tail": err[-2000:]},
                         "duration_s": round(dur, 3)}],
            "summary": {"counts": {"PASS": 1 if rc == 0 else 0, "FAIL": 0 if rc == 0 else 1}}
        }
        dynamic_path.write_text(json.dumps(dynamic_result, indent=2), encoding="utf-8")
    except Exception:
        pass

    network_hits = netmon_result.get("connections", []) if netmon_result.get("status") == "monitored" else []
    fail = bool(leaks or network_hits)
    detail: dict = {
        "rc": rc,
        "stdout_tail": out[-4000:],
        "stderr_tail": err[-4000:],
        "runner": str(s),
        "network_monitoring": netmon_result,
    }
    if leaks:
        detail["pii_leaks"] = leaks
    if network_hits:
        detail["external_network_connections"] = network_hits

    # If the container couldn't be observed (no ss/netstat), surface this as a warning,
    # not a silent PASS. The dynamic check still PASSes if no other failures, but the
    # caller can see network monitoring was unsupported.
    res["status"] = "FAIL" if fail else ("PASS" if rc == 0 else "FAIL")
    res["details"] = detail
    res["duration_s"]=round(dur,3); return res

def check_trivy(image_tag: str, artifacts_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"trivy","status":"SKIPPED","details":{}}
    if not which("trivy"): res["details"]={"reason":"trivy not found"}; res["duration_s"]=round(time.time()-start,3); return res
    if not image_tag: res["details"]={"reason":"no image tag"}; res["duration_s"]=round(time.time()-start,3); return res
    print(f"🔎 Scanning image with Trivy ...", file=sys.stderr)
    rc,out,err,dur=run_cmd(["trivy","image","--severity","HIGH,CRITICAL","--ignore-unfixed","--format","json",image_tag],timeout=900)
    trivy_path = artifacts_dir / "trivy.json"
    try:
        trivy_path.write_text(out, encoding="utf-8")
        res["details"]["report_path"] = str(trivy_path)
    except Exception as e:
        res["details"]["save_error"] = str(e)
    res["status"]="PASS" if rc==0 else "FAIL"
    res["details"]={**res["details"],"rc":rc,"stderr_tail":err[-2000:],"image":image_tag}
    res["duration_s"]=round(dur,3); return res

def check_sbom(image_tag: str, artifacts_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"sbom","status":"SKIPPED","details":{}}
    if not which("syft"): res["details"]={"reason":"syft not found"}; res["duration_s"]=round(time.time()-start,3); return res
    if not image_tag: res["details"]={"reason":"no image tag"}; res["duration_s"]=round(time.time()-start,3); return res
    print(f"📦 Generating SBOM (Syft) ...", file=sys.stderr)
    rc,out,err,dur=run_cmd(["syft",image_tag,"-o","json"],timeout=900)
    out_path=artifacts_dir / "sbom.json"
    if rc==0:
        try:
            out_path.write_text(out,encoding="utf-8")
            res["details"]["sbom_path"]=str(out_path)
        except Exception as e:
            res["status"]="ERROR"; res["details"]={"error":f"write sbom.json failed: {e}"}; res["duration_s"]=round(dur,3); return res
    res["status"]="PASS" if rc==0 else "FAIL"
    res["details"]={"rc":rc,"stderr_tail":err[-2000:],"sbom_path":str(out_path)}
    res["duration_s"]=round(dur,3); return res

def check_cve_gate(artifacts_dir: Path, probe_dir: Path) -> Dict[str, Any]:
    start=time.time()
    res={"name":"cve_gate","status":"SKIPPED","details":{}}
    trivy_json = artifacts_dir / "trivy.json"
    if not trivy_json.exists():
        res["details"]={"reason":"trivy.json not found, run trivy check first"}
        res["duration_s"]=round(time.time()-start,3); return res
    cve_gate_script = probe_dir / "check_cve_gate.sh"
    if not cve_gate_script.exists():
        res["details"]={"reason":"check_cve_gate.sh not found"}
        res["duration_s"]=round(time.time()-start,3); return res
    try: os.chmod(cve_gate_script, 0o755)
    except: pass
    rc,out,err,dur=run_cmd(["bash", str(cve_gate_script), str(trivy_json)], timeout=60)
    res["status"]="PASS" if rc==0 else "FAIL"
    res["details"]={"rc":rc,"stdout_tail":out[-2000:], "stderr_tail":err[-1000:], "trivy_json":str(trivy_json)}
    res["duration_s"]=round(dur,3); return res

# ==================== main ====================

def main():
    parser=argparse.ArgumentParser(description="MCP integration checker (uses LOCAL probes)")
    parser.add_argument("-u","--url",required=True,help="Git repo URL or local path")
    parser.add_argument("--ref",default=None,help="Git ref (branch/tag/commit) to checkout after clone")
    parser.add_argument("-c","--checks",default="all",
        help="all or comma-separated: lint,rego,prompt_schema,tool_schema,code_static,package_scripts,semgrep,docker_build,dynamic,trivy,cve_gate,sbom")
    parser.add_argument("--probe-dir",default=None,help="Directory with local probes (policy.yaml, policy.rego, semgrep.yml, run_checks.sh). Default: policies/ directory")
    parser.add_argument("--project-name",default=None,help="Project name for directory organization. Default: derived from repo URL/path")
    parser.add_argument("--projects-dir",default="projects",help="Base directory for projects. Default: projects/")
    parser.add_argument("--subdir",default=None,help="Subdirectory within the cloned repo to scan (for monorepo npm packages). Checks run against repo/<subdir>/ instead of repo root.")
    parser.add_argument("--global-baselines-dir",default=None,
        help="Directory to store persistent tool-schema baselines keyed by project slug. When set, tool_hash_baseline survives audit resets and tracks rug-pull drift across runs.")
    args=parser.parse_args()

    probe_dir = Path(args.probe_dir) if args.probe_dir else Path(__file__).resolve().parent / "policies"

    # Determine project name
    if args.project_name:
        project_name = args.project_name
    else:
        if os.path.isdir(args.url):
            project_name = Path(args.url).name
        else:
            project_name = repo_name_from_url(args.url)

    docker_image_name = project_name.lower().replace('_', '-')
    project_dir = create_project_structure(project_name, args.projects_dir)
    print(f"📁 Project directory: {project_dir}", file=sys.stderr)

    report={"repo":args.url,"project":project_name,"timestamp":int(time.time()),"results":[],"summary":{}}

    # Clone or copy repo
    repo_dir = project_dir / "repo"
    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    if os.path.isdir(args.url):
        shutil.copytree(args.url, repo_dir)
        report["results"].append({"name":"clone","status":"PASS","details":{"mode":"local_copy","src":args.url},"duration_s":0.0})
    else:
        if not which("git"):
            print(json.dumps({"error":"git not found"},indent=2)); sys.exit(2)
        # retry up to 2 times
        ok=False; err_text=""
        for attempt in (1,2):
            rc,out,err,dur=run_cmd(["git","clone","--depth","1",args.url,str(repo_dir)],timeout=600)
            if rc==0:
                ok=True
                break
            err_text=err
            time.sleep(2)
        report["results"].append({"name":"clone","status":"PASS" if ok else "FAIL","details":{"rc":0 if ok else rc,"stderr":err_text[-2000:]}, "duration_s":round(dur,3)})
        if not ok:
            report["summary"]={"ok":False,"reason":"clone failed"}; print(json.dumps(report,indent=2)); sys.exit(1)
        if args.ref:
            rc2,out2,err2,dur2=run_cmd(["git","fetch","--all","--tags"],cwd=repo_dir,timeout=120)
            rc3,out3,err3,dur3=run_cmd(["git","checkout",args.ref],cwd=repo_dir,timeout=120)
            report["results"].append({"name":"checkout","status":"PASS" if rc3==0 else "FAIL","details":{"rc":rc3,"stderr":(err2+err3)[-2000:],"ref":args.ref},"duration_s":round(dur2+dur3,3)})
            if rc3!=0:
                report["summary"]={"ok":False,"reason":"checkout failed"}; print(json.dumps(report,indent=2)); sys.exit(1)

    scans_dir = project_dir / "scans"

    # Scope scans to a subdirectory when the npm package lives inside a monorepo
    if args.subdir:
        subdir_path = repo_dir / args.subdir.strip("/")
        if subdir_path.is_dir():
            repo_dir = subdir_path
            report["subdir"] = args.subdir
            print(f"📂 Scoping scan to subdir: {args.subdir}", file=sys.stderr)
        else:
            print(f"⚠️  --subdir '{args.subdir}' not found in cloned repo, scanning root", file=sys.stderr)

    checks_req=[c.strip().lower() for c in args.checks.split(",")]
    all_checks=["lint","rego","prompt_schema","tool_schema","code_static","malicious_doc_ast",
            "windows_attack_patterns","linux_attack_patterns","macos_attack_patterns",
            "network_exposure","ssrf_patterns","memory_poisoning","oauth_abuse","crypto_stealer",
            "package_scripts","cicd_workflow_scan","transport_config","typosquatting","dependency_confusion","semgrep","docker_build","dynamic","trivy","cve_gate","sbom",
            "secrets_scan","tool_hash_baseline",
            "ide_config_scan","obfuscation_scan","npm_source_integrity","dependency_reputation"]
    # ensure critical checks always run unless explicitly disabled
    critical = {"malicious_doc_ast", "windows_attack_patterns", "linux_attack_patterns", "macos_attack_patterns",
                "network_exposure", "ssrf_patterns", "memory_poisoning", "crypto_stealer",
                "ide_config_scan", "obfuscation_scan"}
    if "all" in checks_req: checks_req=all_checks

    if "all" not in checks_req: checks_req = list(dict.fromkeys(list(critical) + checks_req))

    # Persistent baseline path — survives audit resets, enables cross-run rug-pull detection
    if args.global_baselines_dir:
        _baselines_dir = Path(args.global_baselines_dir)
        _baselines_dir.mkdir(parents=True, exist_ok=True)
        _baseline_path = _baselines_dir / f"{project_name}.json"
    else:
        _baseline_path = project_dir / "artifacts" / "tool_hashes.json"

    image_tag=f"mcpcheck/{docker_image_name}:latest"

    runners={
        "lint": lambda: check_lint_policy_local(probe_dir, repo_dir=repo_dir),
        "rego": lambda: check_rego_conftest_local(probe_dir),
        "prompt_schema": lambda: check_prompt_schema(repo_dir),
        "tool_schema": lambda: check_tool_schema(repo_dir, probe_dir, scans_dir),
        "code_static": lambda: check_code_static(repo_dir),
        "malicious_doc_ast": lambda: detect_malicious_docstrings_and_ast(repo_dir),
        "windows_attack_patterns": lambda: detect_windows_attack_patterns(repo_dir),
        "linux_attack_patterns": lambda: detect_linux_attack_patterns(repo_dir),
        "macos_attack_patterns": lambda: detect_macos_attack_patterns(repo_dir),
        "network_exposure": lambda: check_network_exposure(repo_dir),
        "ssrf_patterns": lambda: check_ssrf_patterns(repo_dir),
        "memory_poisoning": lambda: check_memory_poisoning(repo_dir),
        "oauth_abuse": lambda: check_oauth_abuse(repo_dir),
        "crypto_stealer": lambda: check_crypto_stealer_patterns(repo_dir),
        "package_scripts": lambda: check_package_scripts(repo_dir),
        "cicd_workflow_scan": lambda: check_cicd_workflow_scan(repo_dir),
        "transport_config": lambda: check_transport_and_config(str(repo_dir)),
        "typosquatting": lambda: check_typosquatting(str(repo_dir)),
        "dependency_confusion": lambda: check_dependency_confusion(str(repo_dir)),
        "semgrep": lambda: check_semgrep_local(repo_dir, probe_dir, scans_dir),
        "docker_build": lambda: check_docker_build(repo_dir, image_tag),
        "dynamic": lambda: check_dynamic_local_runner(image_tag, probe_dir, scans_dir),
        "trivy": lambda: check_trivy(image_tag, project_dir / "artifacts"),
        "cve_gate": lambda: check_cve_gate(project_dir / "artifacts", probe_dir),
        "sbom": lambda: check_sbom(image_tag, project_dir / "artifacts"),
        "secrets_scan": lambda: check_secrets_scan(repo_dir),
        "tool_hash_baseline": lambda: check_tool_hash_baseline(repo_dir, project_dir / "artifacts", _baseline_path),
        "ide_config_scan": lambda: check_ide_config_scan(repo_dir),
        "obfuscation_scan": lambda: check_obfuscation_scan(repo_dir),
        "npm_source_integrity": lambda: check_npm_source_integrity(repo_dir),
        "dependency_reputation": lambda: check_dependency_reputation(repo_dir),
        "default_binding_exposure": lambda: check_default_binding_exposure(repo_dir),
        "unauthenticated_control_plane": lambda: check_unauthenticated_control_plane(repo_dir),
        "silent_exfil_pattern": lambda: check_silent_exfil_pattern(repo_dir),
        "tool_definition_drift": lambda: check_tool_definition_drift(repo_dir, project_dir / "artifacts"),
        "oauth_misconfiguration": lambda: check_oauth_misconfiguration(repo_dir),
    }

    for name in checks_req:
        fn=runners.get(name)
        if not fn:
            report["results"].append({"name":name,"status":"SKIPPED","details":{"reason":"unknown check"}}); continue
        try:
            result = fn()
            if isinstance(result, list):
                # Wrap list-of-findings into a single check result dict
                report["results"].append({
                    "name": name,
                    "status": "FAIL" if result else "PASS",
                    "details": {"findings": result},
                })
            else:
                report["results"].append(result)
        except Exception as e:
            report["results"].append({"name":name,"status":"ERROR","details":{"error":str(e)}})
    
    for r in report["results"]:
        try:
            (scans_dir / f"{r['name']}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        except Exception:
            pass
    report_path = project_dir / "artifacts" / "mcp-checker-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    statuses=[r["status"] for r in report["results"] if r["name"] not in ("clone","checkout")]
    ok_overall = (report["results"][0]["status"]=="PASS") and all(s in ("PASS","SKIPPED") for s in statuses)
    report["summary"]={"ok":ok_overall,"counts":{k:statuses.count(k) for k in ["PASS","FAIL","ERROR","SKIPPED"]}}

    print(json.dumps(report,indent=2))
    print(f"📄 Full report saved to: {report_path}", file=sys.stderr)

if __name__=="__main__":
    main()
