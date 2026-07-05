#!/usr/bin/env python3
"""
Hardened prompt schema validator with comprehensive injection detection.
Validates prompt structures and detects various attack patterns.
"""

import json
import os
import base64
import binascii
import re
import sys
import argparse
import hashlib
from typing import Dict, List, Tuple, Any
import jsonschema

# Enhanced detection patterns
BLOCK_HTML = re.compile(r"(?i)<\s*(script|img|iframe|a|link|style|meta|object|embed|form|input)[\s>]")
ZERO_WIDTH = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF]")
HIDDEN_DIRECTIVES = re.compile(r"(?i)(<!--.*?-->|\|\|hidden\|\||<!--.*?$|^\s*<!--)", re.S|re.M)
DATA_URI = re.compile(r"(?i)data:(text|application|image)/[^;]+;base64,")
EXCESSIVE_ENTITIES = re.compile(r"&[#a-zA-Z0-9]{20,};")
CSS_INJECTION = re.compile(r"(?i)(<style.*?>|@import|javascript:|expression\()")
JS_INJECTION = re.compile(r"(?i)(javascript:|vbscript:|data:text/html|on\w+\s*=)")

# Size limits (configurable via environment variables)
MAX_MSG_LEN = int(os.getenv('PROMPT_MAX_MSG_LEN', '8000'))
MAX_TOTAL_LEN = int(os.getenv('PROMPT_MAX_TOTAL_LEN', '40000'))

# Existing patterns
INJECTION_PATTERNS = [
    r"(?i)(ignore above|SYSTEM OVERRIDE|Act as:|You are DAN|<\|im_end\|>)",
    r"(?i)(tool_call|function_call|call_tool)\s*[:=]",
    r"(?i)(jsonrpc|method.*call|params.*arguments)",
    r"(?i)(prompt.*leak|reveal.*system|show.*instruction)",
    r"(?i)(eval|exec|system|subprocess|open|file)\s*\(",
    r"(?i)(cat|ls|pwd|whoami|id|uname)\s",
    r"(?i)(rm|mv|cp|chmod|chown)\s",
    r"(?i)(curl|wget|nc|netcat|ssh)\s",
    r"(?i)(http://|https://|ftp://).*\.(com|org|net|io|dev)",
    r"(0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})",
    r"(?i)(\.\./|\.\.\\|/etc/|/proc/|/sys/|~\/)",
    r"(?i)(;|&|`|\$\(|\$\{).*\b(cat|ls|rm|exec|eval|sh|bash)\b",
]

DANGEROUS_URIS = [
    r"(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
    r"(?i)https?://(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
    r"(?i)https?://(169\.254\.|link-local|local)",
    r"(?i)file:///etc/",
    r"(?i)ftp://.*\.(com|org|net)",
]

# Prompt schema
PROMPT_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "role": {"type": "string", "enum": ["system", "user", "assistant", "tool"]},
            "content": {"type": "string"},
            "tool_call": {"type": "object"},
        },
        "required": ["role", "content"],
        "additionalProperties": False,
    },
    "minItems": 1,
}

# Enhanced injection detection patterns
INJECTION_PATTERNS = [
    # System override attempts
    r'(?i)(ignore above|SYSTEM OVERRIDE|Act as:|You are now|Forget previous|New instructions:)',
    # Tool call injection attempts
    r'(?i)(tool_call|function_call|call.*tool|execute.*function|\{.*tool.*call\})',
    # JSON-RPC smuggling
    r'(?i)(jsonrpc|method.*call|params.*arguments|id.*request)',
    # Prompt leakage attempts
    r'(?i)(show.*prompt|reveal.*system|display.*instructions|print.*context)',
    # SSRF bait patterns
    r'(?i)(http://|https://|ftp://|file://|localhost|127\.0\.0\.1|0\.0\.0\.0|::1)',
    # Base64 and hex blob patterns (potential hiding)
    r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    r'(?:0x[a-fA-F0-9]{8,}|\\x[a-fA-F0-9]{2}){4,}',
    # Command injection patterns
    r'(?i)(;|\||&|`|\$\(|\$\{).*\b(cat|ls|pwd|whoami|id|uname|env|echo|print)\b',
    # File path injection
    r'(?i)(\.\./|\.\.\\\|/etc/|/proc/|/sys/|/dev/|~\/|\$HOME)',
    # Prototype pollution attempts in content
    r'(?i)(__proto__\s*\.|constructor\s*\.\s*prototype|prototype\s*\[)'
]

# Dangerous URI patterns
DANGEROUS_URIS = [
    r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)',
    r'(?i)(file://|ftp://|gopher://|dict://)',
    r'(?i)(/etc/passwd|/etc/shadow|/proc/|/sys/)',
]

def validate_prompt(prompt: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """
    Validate prompt structure and check for injection patterns.
    
    Args:
        prompt: List of message dictionaries with 'role' and 'content'
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Basic structure validation
    if not isinstance(prompt, list):
        errors.append("Prompt must be a list")
        return False, errors
    
    if not prompt:
        errors.append("Prompt cannot be empty")
        return False, errors
    
    # Enforce single leading system message
    if prompt[0].get('role') != 'system':
        errors.append("First message must be system role")
    
    # Check for multiple system messages
    system_count = sum(1 for msg in prompt if msg.get('role') == 'system')
    if system_count > 1:
        errors.append("Multiple system messages detected - only one leading system message allowed")
    
    # Validate each message
    for i, message in enumerate(prompt):
        try:
            jsonschema.validate(message, PROMPT_SCHEMA)
        except jsonschema.ValidationError as e:
            errors.append(f"Message {i}: {e.message}")
            continue
        
        # Check for injection patterns in content
        content = message.get('content', '')
        
        # Size limits to prevent DoS
def _contains_suspicious_base64(content: str) -> bool:
    """Check for suspicious base64 content that might hide malicious payloads."""
    # Look for base64 patterns longer than typical use cases (reduced threshold)
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, content)
    
    for match in matches:
        try:
            # Try to decode and check if it contains suspicious patterns
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(pattern in decoded.lower() for pattern in ['system', 'override', 'exec', 'eval', 'hack', '<script']):
                return True
        except:
            pass  # Invalid base64, ignore
    
    # Also check for obvious base64 patterns even if they decode to benign content
    if len(content) > 50 and re.search(r'(?:[A-Za-z0-9+/]{4}){12,}', content):
        return True
    
    return False

def _contains_dangerous_uris(content: str) -> bool:
    """Check for dangerous URI patterns that could lead to SSRF."""
    for pattern in DANGEROUS_URIS:
        if re.search(pattern, content):
            return True
    return False

def _contains_json_smuggling(content: str) -> bool:
    """Check for JSON-RPC smuggling attempts."""
    smuggling_patterns = [
        r'"jsonrpc"\s*:\s*"2\.0"',
        r'"method"\s*:\s*"[^"]*\.(override|system|exec)"',
        r'"params"\s*:\s*{[^}]*"role"\s*:\s*"system"',
        r'"result"\s*:\s*{[^}]*"content"\s*:\s*"[^"]*ignore',
    ]
    
    for pattern in smuggling_patterns:
        if re.search(pattern, content):
            return True
    return False

def _contains_injection_patterns(content: str) -> List[str]:
    """Check for various injection patterns in content."""
    detected = []
    
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, content):
            detected.append(f"Injection pattern: {pattern[:50]}...")
    
    return detected

def _contains_html_js_attacks(content: str) -> List[str]:
    """Check for HTML/JS injection attacks."""
    detected = []
    
    if BLOCK_HTML.search(content):
        detected.append("Active HTML/JS content detected")
    
    if ZERO_WIDTH.search(content):
        detected.append("Zero-width characters detected")
    
    if HIDDEN_DIRECTIVES.search(content):
        detected.append("Hidden directives detected (comments/markers)")
    
    if DATA_URI.search(content):
        detected.append("Data URI payload detected")
    
    if EXCESSIVE_ENTITIES.search(content):
        detected.append("Excessive HTML entities detected")
    
    if CSS_INJECTION.search(content):
        detected.append("CSS injection attempt detected")
    
    if JS_INJECTION.search(content):
        detected.append("JavaScript injection attempt detected")
    
    return detected

def validate_tool_call(tool_call: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate tool_call for dangerous function names and injection."""
    errors = []
    
    if not isinstance(tool_call, dict):
        return False, ["tool_call must be an object"]
    
    # Check for dangerous function names
    dangerous_functions = [
        "eval", "exec", "system", "subprocess", "open", "file",
        "import", "__import__", "compile", "globals", "locals", "vars",
        "exec_shell", "run_cmd", "shell_exec", "cmd_exec", "bash", "sh",
        "python_exec", "node_exec"
    ]
    
    if "function" in tool_call and "name" in tool_call["function"]:
        func_name = tool_call["function"]["name"]
        if func_name in dangerous_functions:
            errors.append(f"Dangerous function name: {func_name}")
        
        # Check for injection in function name
        if any(pattern in func_name.lower() for pattern in ["eval", "exec", "system", "shell"]):
            errors.append(f"Suspicious function name pattern: {func_name}")
    
    # Check arguments for injection
    if "arguments" in tool_call:
        args_str = json.dumps(tool_call["arguments"])
        injection_errors = _contains_injection_patterns(args_str)
        errors.extend(injection_errors)
        
        html_errors = _contains_html_js_attacks(args_str)
        errors.extend(html_errors)
    
    return len(errors) == 0, errors

def validate_prompt_structure(messages: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Validate prompt structure and role ordering."""
    errors = []
    
    if not messages:
        errors.append("Prompt cannot be empty")
        return False, errors
    
    # Validate schema
    try:
        jsonschema.validate(messages, PROMPT_SCHEMA)
    except jsonschema.ValidationError as e:
        errors.append(f"Schema validation failed: {e.message}")
    
    # Check role ordering - first message must be system
    if messages and messages[0].get("role") != "system":
        errors.append("First message must be system role")
    
    # Check for multiple system messages
    system_count = sum(1 for msg in messages if msg.get("role") == "system")
    if system_count > 1:
        errors.append(f"Multiple system messages detected ({system_count})")
    
    return len(errors) == 0, errors

def validate_prompt(messages: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Comprehensive prompt validation with enhanced detection."""
    errors = []
    
    # Structure validation
    is_valid, struct_errors = validate_prompt_structure(messages)
    if not is_valid:
        errors.extend(struct_errors)
    
    # Content validation
    total_len = 0
    for i, message in enumerate(messages):
        content = message.get("content", "")
        
        # Size checks
        msg_len = len(content)
        total_len += msg_len
        
        if msg_len > MAX_MSG_LEN:
            errors.append(f"Message {i} too long: {msg_len} > {MAX_MSG_LEN}")
        
        # Enhanced injection detection
        injection_errors = _contains_injection_patterns(content)
        errors.extend([f"Message {i}: {error}" for error in injection_errors])
        
        # HTML/JS attack detection
        html_errors = _contains_html_js_attacks(content)
        errors.extend([f"Message {i}: {error}" for error in html_errors])
        
        # Base64 detection
        if _contains_suspicious_base64(content):
            errors.append(f"Message {i}: Suspicious base64 content detected")
        
        # URI detection
        if _contains_dangerous_uris(content):
            errors.append(f"Message {i}: Dangerous URI patterns detected")
        
        # JSON smuggling detection
        if _contains_json_smuggling(content):
            errors.append(f"Message {i}: JSON-RPC smuggling pattern detected")
        
        # Tool call validation
        if "tool_call" in message:
            is_valid, tool_errors = validate_tool_call(message["tool_call"])
            if not is_valid:
                for error in tool_errors:
                    errors.append(f"Message {i} tool_call: {error}")
    
    # Total size check
    if total_len > MAX_TOTAL_LEN:
        errors.append(f"Prompt too large: {total_len} > {MAX_TOTAL_LEN}")
    
    return len(errors) == 0, errors

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="Hardened prompt schema validator")
    parser.add_argument("input", nargs="?", help="Input file (default: stdin)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    
    args = parser.parse_args()
    
    # Read input
    if args.input:
        try:
            with open(args.input, "r") as f:
                data = json.load(f)
        except Exception as e:
            result = {
                "status": "REJECT",
                "reason": f"Failed to read input file: {e}",
                "errors": [str(e)]
            }
            print(json.dumps(result, indent=2))
            sys.exit(1)
    else:
        try:
            data = json.load(sys.stdin)
        except Exception as e:
            result = {
                "status": "REJECT",
                "reason": f"Failed to parse JSON input: {e}",
                "errors": [str(e)]
            }
            print(json.dumps(result, indent=2))
            sys.exit(1)
    
    # Extract prompt messages
    messages = data.get("prompt") if isinstance(data, dict) and "prompt" in data else data
    
    if not isinstance(messages, list):
        result = {
            "status": "REJECT",
            "reason": "Invalid input format - expected prompt array",
            "errors": ["Input must be a prompt array or object with 'prompt' key"]
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)
    
    # Validate prompt
    try:
        is_valid, errors = validate_prompt(messages)
    except Exception as e:
        result = {
            "status": "REJECT",
            "reason": f"Validator exception: {e}",
            "errors": [str(e)]
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)
    
    # Generate context hash for integrity checking
    context_hash = hashlib.sha256(
        json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    
    result = {
        "status": "ACCEPT" if is_valid else "REJECT",
        "context_hash": context_hash,
        "message_count": len(messages),
        "total_length": sum(len(msg.get("content", "")) for msg in messages),
    }
    
    if not is_valid:
        result["reason"] = "Validation failed"
        result["errors"] = errors
    
    # Output result
    if args.format == "json":
        output = json.dumps(result, indent=2)
    else:
        output = f"Status: {result['status']}\n"
        output += f"Context Hash: {result['context_hash']}\n"
        output += f"Messages: {result['message_count']}\n"
        if "errors" in result:
            output += "Errors:\n"
            for error in result["errors"]:
                output += f"  - {error}\n"
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
    else:
        print(output)
    
    # Exit with appropriate code for CI
    sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()
