#!/usr/bin/env python3
"""
Tool schema validator for MCP servers.
Ensures tool definitions don't allow dangerous operations like shell execution,
network calls, secret/env harvest, or covert exfil parameters.
"""

import json
import sys
import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional

# -------------------------
# Config / Signatures
# -------------------------

# Dangerous patterns in descriptions (kept, but AST is primary)
DANGEROUS_KEYWORDS: Set[str] = {
    # exec/shell
    'shell', 'bash', 'sh', 'cmd', 'powershell', 'execute', 'exec', 'eval',
    'system', 'popen', 'subprocess', 'os.system', 'command',
    # network/exfil
    'curl', 'wget', 'network', 'socket', 'http', 'https', 'ftp', 'ssh', 'telnet',
    'download', 'upload', 'exfiltrate', 'send', 'post', 'get',
    # fs destructive
    'file_write', 'write_file', 'delete', 'remove', 'rm', 'unlink',
    # secrets
    'token', 'api_key', 'apikey', 'bearer', 'password', 'passwd', 'secret',
    'private_key', 'id_rsa', 'credentials', 'auth', 'cookie',
    # dynamic import
    '__import__', 'importlib', 'getattr'
}

# Suspicious parameter names
DANGEROUS_PARAMS: Set[str] = {
    'command', 'cmd', 'shell', 'script', 'code', 'eval', 'exec',
    'url', 'endpoint', 'host', 'address', 'destination',
    'path', 'file_path', 'filename', 'directory',
    # covert exfil patterns commonly seen in malicious MCP demos
    'context_info', 'full_prompt', 'prompt', 'recipient', 'bcc'
}

SAFE_CATEGORIES: Set[str] = {'read_only', 'query', 'search', 'list', 'get', 'fetch', 'view', 'show'}

# Regex signatures used across code/doc scanning
RX = {
    'env_enum': re.compile(r'\bos\.environ\b', re.I),
    'env_getenv': re.compile(r'\bos\.getenv\(', re.I),
    'env_iter': re.compile(r'os\.environ\.items\(\)', re.I),
    'ssh_key': re.compile(r'open\(\s*[\'"]~\/\.ssh\/id_rsa', re.I),
    'cursor_cfg': re.compile(r'\.cursor\/mcp\.json', re.I),
    'recipient_override': re.compile(r'"sent_to"\s*:\s*"[^\"]+@[^\"]+"', re.I),
    'dyn_import': re.compile(
        r'(__import__|importlib\.import_module)\s*\(\s*[\'"]?(os|subprocess|socket|shutil|requests|urllib)[\'"]?',
        re.I
    ),
    'builtins_eval': re.compile(r'getattr\(__builtins__\s*,\s*[\'"](eval|exec)[\'"]\)', re.I),
    'eval_exec': re.compile(r'\b(eval|exec)\s*\(', re.I),
    'subproc': re.compile(r'\bsubprocess\.(run|Popen|call|check_output)\b', re.I),
    'os_system': re.compile(r'\bos\.system\(', re.I),
    'http_client': re.compile(r'\b(requests|urllib|http\.client)\b', re.I),
    'file_write': re.compile(r'open\(\s*["\'][^"\']*["\']\s*,\s*[\'"](w|a|wb|ab)\b', re.I),
    'sensitive_paths': re.compile(r'(~\/\.ssh\/id_rsa|\.cursor\/mcp\.json|\/etc\/passwd)', re.I),
}

SENSITIVE_MODULES = {'os', 'subprocess', 'socket', 'requests', 'urllib', 'shutil', 'http.client'}
EXFIL_PARAM_HINTS = {'context_info', 'full_prompt', 'prompt', 'recipient', 'bcc'}

# Weighting for scoring signals (AST hits > regex keywords)
WEIGHTS = {
    'ast_exec': 3,
    'ast_network': 3,
    'ast_dyn_import': 3,
    'ast_env': 2,
    'ast_file_write': 2,
    'ast_sensitive_read': 2,
    'regex_exec': 2,
    'regex_network': 2,
    'regex_write': 1,
    'regex_sensitive': 1,
    'kw': 1,
}
THRESHOLD = 3  # conservative; adjust per environment


# -------------------------
# JSON Tool Schema Validator (backward compatible)
# -------------------------

class ToolSchemaValidator:
    def __init__(self):
        self.violations: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []

    def _danger_from_description(self, text: str, tool_name: str, where: str):
        t = (text or '').lower()
        for keyword in DANGEROUS_KEYWORDS:
            if keyword in t:
                self.violations.append({
                    'tool': tool_name,
                    'type': f'dangerous_{where}',
                    'keyword': keyword,
                    'description': (text or '')[:200]
                })

    def validate_tool_definition(self, tool: Dict[str, Any], tool_name: str) -> bool:
        """Validate a single JSON-style tool definition (if present in project)."""
        is_safe = True

        # Description keywords
        description = tool.get('description', '')
        before_v = len(self.violations)
        self._danger_from_description(description, tool_name, 'description')
        if len(self.violations) > before_v:
            is_safe = False

        # Safe categories
        is_safe_category = any(cat in (description or '').lower() for cat in SAFE_CATEGORIES)

        # Parameters
        input_schema = tool.get('inputSchema', {}) or {}
        properties = input_schema.get('properties', {}) or {}

        for param_name, param_def in properties.items():
            p_name = (param_name or '').lower()

            # Suspicious parameter names
            if p_name in DANGEROUS_PARAMS and not is_safe_category:
                self.violations.append({
                    'tool': tool_name,
                    'type': 'dangerous_parameter',
                    'parameter': param_name,
                    'description': (param_def.get('description', '') or '')[:200]
                })
                is_safe = False

            # Parameter description keywords
            p_desc = (param_def.get('description', '') or '').lower()
            for keyword in DANGEROUS_KEYWORDS:
                if keyword in p_desc:
                    self.warnings.append({
                        'tool': tool_name,
                        'type': 'suspicious_param_description',
                        'parameter': param_name,
                        'keyword': keyword,
                        'description': (param_def.get('description', '') or '')[:200]
                    })

        # Required dangerous params
        required = input_schema.get('required', []) or []
        for req in required:
            if (req or '').lower() in DANGEROUS_PARAMS:
                self.violations.append({
                    'tool': tool_name,
                    'type': 'required_dangerous_parameter',
                    'parameter': req
                })
                is_safe = False

        return is_safe


# -------------------------
# AST-based MCP tool inspection
# -------------------------

def _is_mcp_tool_func(fn: ast.FunctionDef) -> bool:
    """Detect functions decorated with @mcp.tool(...) or @tool (LangChain-like)."""
    for dec in fn.decorator_list:
        # @mcp.tool(...)
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            if getattr(dec.func.value, 'id', None) == 'mcp' and dec.func.attr == 'tool':
                return True
        # @tool or @mcp.tool without args
        if isinstance(dec, ast.Name) and dec.id in {'tool'}:
            return True
        if isinstance(dec, ast.Attribute) and getattr(dec.value, 'id', None) == 'mcp' and dec.attr == 'tool':
            return True
    return False


class ToolFunctionInspector(ast.NodeVisitor):
    """Walk a function body to collect risky behaviors/signals."""

    def __init__(self, filename: str):
        self.filename = filename
        self.signals: List[Tuple[str, str, int]] = []  # (tag, detail, lineno)

    def _add(self, tag: str, detail: str, node: ast.AST):
        self.signals.append((tag, detail, getattr(node, 'lineno', 0) or 0))

    # Helpers to identify attribute chains, e.g., subprocess.run / os.system
    @staticmethod
    def _attr_chain(node: ast.AST) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return '.'.join(parts)

    def visit_Call(self, node: ast.Call):
        # Detect eval/exec
        if isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec', '__import__'}:
            self._add('ast_exec' if node.func.id in {'eval', 'exec'} else 'ast_dyn_import',
                      node.func.id, node)

        # getattr(__builtins__, 'eval'|'exec')
        if isinstance(node.func, ast.Name) and node.func.id == 'getattr' and len(node.args) >= 2:
            s0 = node.args[0]
            s1 = node.args[1]
            if isinstance(s0, ast.Name) and s0.id == '__builtins__':
                if isinstance(s1, ast.Constant) and str(s1.value) in {'eval', 'exec'}:
                    self._add('ast_exec', 'builtins_eval/exec', node)

        # importlib.import_module("os"/"subprocess"/...)
        func_chain = self._attr_chain(node.func) if isinstance(node.func, ast.Attribute) else ''
        if func_chain == 'importlib.import_module' and node.args:
            mod_name = None
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                mod_name = a0.value.split('.')[0]
            if mod_name in SENSITIVE_MODULES:
                self._add('ast_dyn_import', f'importlib:{mod_name}', node)

        # os.system / subprocess.run / requests.get / urllib.request...
        if isinstance(node.func, ast.Attribute):
            chain = self._attr_chain(node.func)
            if chain in {'os.system'}:
                self._add('ast_exec', chain, node)
            if chain.startswith('subprocess.'):
                self._add('ast_exec', chain, node)
            if chain.startswith('requests.') or chain.startswith('urllib.') or chain == 'http.client':
                self._add('ast_network', chain, node)
            if chain == 'open' or chain.endswith('.open'):
                # detect write/append mode
                if len(node.args) >= 2:
                    mode = node.args[1]
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                        if any(mode.value.startswith(m) for m in ('w', 'a', 'wb', 'ab')):
                            self._add('ast_file_write', f'open(mode={mode.value})', node)

        # open("~/.ssh/id_rsa", "r") etc.
        if isinstance(node.func, ast.Name) and node.func.id == 'open' and node.args:
            p0 = node.args[0]
            if isinstance(p0, ast.Constant) and isinstance(p0.value, str):
                if '~/.ssh/id_rsa' in p0.value or '/etc/passwd' in p0.value or '.cursor/mcp.json' in p0.value:
                    # read is also sensitive (exfil source)
                    self._add('ast_sensitive_read', f'open({p0.value})', node)

        # os.getenv / os.environ[...] / for k,v in os.environ.items()
        if isinstance(node.func, ast.Attribute):
            chain = self._attr_chain(node.func)
            if chain in {'os.getenv'}:
                self._add('ast_env', chain, node)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # direct os.environ reference
        if self._attr_chain(node) == 'os.environ':
            self._add('ast_env', 'os.environ', node)
        self.generic_visit(node)


def inspect_python_file(path: Path) -> List[Dict[str, Any]]:
    """Return a list of violation dicts for a given python file, scanning MCP tools."""
    violations: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    try:
        code = path.read_text(encoding='utf-8')
    except Exception as e:
        warnings.append({'file': str(path), 'type': 'read_error', 'error': str(e)})
        return violations + warnings

    try:
        tree = ast.parse(code, filename=str(path))
    except SyntaxError as e:
        warnings.append({'file': str(path), 'type': 'syntax_error', 'error': str(e)})
        return violations + warnings

    # Scan docstring and text for weak signals (for context)
    doc_blob = '\n'.join([ast.get_docstring(tree) or '', code])
    soft_hits = []
    for key, rx in RX.items():
        if rx.search(doc_blob):
            soft_hits.append(key)
    if soft_hits:
        warnings.append({'file': str(path), 'type': 'docstring_or_text_hits', 'hits': soft_hits})

    # Visit all function defs; analyze only MCP tools
    for node in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if not _is_mcp_tool_func(node):
            continue

        inspector = ToolFunctionInspector(str(path))
        inspector.visit(node)

        # Parameter name checks (covert exfil)
        param_names = {arg.arg.lower() for arg in node.args.args}
        bad_params = sorted(param_names & DANGEROUS_PARAMS)
        if bad_params:
            for bp in bad_params:
                violations.append({
                    'tool': node.name,
                    'file': str(path),
                    'type': 'dangerous_parameter',
                    'parameter': bp,
                    'line': getattr(node, 'lineno', 0) or 0
                })

        # Score signals
        score = 0
        details = []
        for tag, detail, lineno in inspector.signals:
            details.append({'tag': tag, 'detail': detail, 'line': lineno})
            if tag in {'ast_exec'}:
                score += WEIGHTS['ast_exec']
            elif tag in {'ast_network'}:
                score += WEIGHTS['ast_network']
            elif tag in {'ast_dyn_import'}:
                score += WEIGHTS['ast_dyn_import']
            elif tag in {'ast_env'}:
                score += WEIGHTS['ast_env']
            elif tag in {'ast_file_write'}:
                score += WEIGHTS['ast_file_write']
            elif tag in {'ast_sensitive_read'}:
                score += WEIGHTS['ast_sensitive_read']

        # Regex reinforcement on the function source slice
        try:
            start = node.body[0].lineno if node.body else node.lineno
            end = max(getattr(n, 'lineno', start) or start for n in ast.walk(node))
            fn_src = '\n'.join(code.splitlines()[start - 1:end])
        except Exception:
            fn_src = code

        # Apply regex categories and add to score
        if RX['os_system'].search(fn_src) or RX['subproc'].search(fn_src) or RX['eval_exec'].search(fn_src) or RX['builtins_eval'].search(fn_src):
            score += WEIGHTS['regex_exec']
        if RX['http_client'].search(fn_src) or RX['dyn_import'].search(fn_src):
            score += WEIGHTS['regex_network']
        if RX['file_write'].search(fn_src):
            score += WEIGHTS['regex_write']
        if RX['sensitive_paths'].search(fn_src) or RX['recipient_override'].search(fn_src):
            score += WEIGHTS['regex_sensitive']

        if score >= THRESHOLD:
            violations.append({
                'tool': node.name,
                'file': str(path),
                'type': 'dangerous_operation_in_tool',
                'operation': 'multiple',
                'line': getattr(node, 'lineno', 0) or 0,
                'score': score,
                'signals': details
            })
        elif details:
            # downgrade to warning if signals present but below threshold
            warnings.append({
                'tool': node.name,
                'file': str(path),
                'type': 'suspicious_tool_behavior',
                'signals': details,
                'score': score
            })

    return violations + warnings


# -------------------------
# Project walker
# -------------------------

def validate_project(project_dir: Path) -> Dict[str, Any]:
    results = {
        'safe': True,
        'violations': [],
        'warnings': [],
        'tools_checked': 0,
        'files_checked': 0
    }

    validator = ToolSchemaValidator()

    # 1) JSON-like tool definitions (optional): scan any *.tools.json files
    for json_file in project_dir.rglob('*.json'):
        if 'venv' in str(json_file).lower() or 'node_modules' in str(json_file).lower():
            continue
        try:
            data = json.loads(json_file.read_text(encoding='utf-8'))
        except Exception:
            continue
        if isinstance(data, dict) and 'tools' in data and isinstance(data['tools'], list):
            for t in data['tools']:
                name = t.get('name') or t.get('title') or 'unknown'
                ok = validator.validate_tool_definition(t, name)
                results['files_checked'] += 1
                if not ok:
                    results['safe'] = False

    # 2) Python files with MCP tools (primary)
    tool_names_seen: Set[str] = set()
    for py_file in project_dir.rglob('*.py'):
        s = str(py_file).lower()
        if any(k in s for k in ('venv', '__pycache__', 'site-packages', 'tests', 'test_')):
            continue

        file_findings = inspect_python_file(py_file)
        if not file_findings:
            continue

        # Split into violations vs warnings
        results['files_checked'] += 1
        for f in file_findings:
            if f.get('type', '').startswith('dangerous'):
                results['violations'].append(f)
                results['safe'] = False
                if 'tool' in f:
                    tool_names_seen.add(f['tool'])
            else:
                results['warnings'].append(f)
                if 'tool' in f:
                    tool_names_seen.add(f['tool'])

    results['tools_checked'] = len(tool_names_seen)
    return results


# -------------------------
# CLI
# -------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Validate MCP tool schemas and code for safety')
    parser.add_argument('project_dir', help='Project directory to scan')
    parser.add_argument('--output', default=None, help='Output JSON file')
    parser.add_argument('--fail-on-violations', action='store_true', help='Exit 1 if violations found')
    args = parser.parse_args()

    project_path = Path(args.project_dir)
    if not project_path.exists():
        print(f"Error: Project directory not found: {project_path}", file=sys.stderr)
        sys.exit(2)

    results = validate_project(project_path)

    # Print results
    print(f"\n🔍 Tool Schema/Code Validation Results")
    print(f"{'='*50}")
    print(f"Files checked: {results['files_checked']}")
    print(f"Tools checked (seen in findings): {results['tools_checked']}")
    print(f"Violations: {len(results['violations'])}")
    print(f"Warnings: {len(results['warnings'])}")

    if results['violations']:
        print(f"\n❌ VIOLATIONS FOUND:")
        for v in results['violations']:
            loc = f"{v.get('file','?')}:{v.get('line','?')}"
            op = v.get('operation') or v.get('parameter') or v.get('keyword', 'N/A')
            tool = v.get('tool', 'unknown')
            print(f"  - {v['type']}: {tool} - {op}")
            print(f"    File: {loc}")
            if 'score' in v:
                print(f"    Score: {v['score']}")
            if 'signals' in v:
                for s in v['signals'][:5]:
                    print(f"      · {s['tag']} @ {s['line']}: {s['detail']}")
    if results['warnings']:
        print(f"\n⚠️  WARNINGS (top 10):")
        for w in results['warnings'][:10]:
            loc = f"{w.get('file','?')}:{w.get('line','?')}"
            tool = w.get('tool', w.get('file', 'unknown'))
            print(f"  - {w['type']}: {tool}")
            if 'score' in w:
                print(f"    Score: {w['score']}")
            if 'signals' in w:
                for s in w['signals'][:3]:
                    print(f"      · {s['tag']} @ {s['line']}: {s['detail']}")
            if w.get('hits'):
                print(f"    Hits: {w['hits']}")
            print(f"    File: {loc}")

    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2))
        print(f"\n📄 Results saved to: {output_path}")

    # Exit
    if results['safe']:
        print(f"\n✅ All scanned tools passed safety threshold")
        sys.exit(0)
    else:
        print(f"\n❌ Tool schema/code validation FAILED")
        if args.fail_on_violations:
            sys.exit(1)
        sys.exit(0)


if __name__ == '__main__':
    main()
