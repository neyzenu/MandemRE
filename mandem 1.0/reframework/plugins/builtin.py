"""
Built-in Analysis Plugins

These plugins provide common malware analysis capabilities:
- Anti-debugging detection
- Network IOC extraction
- Credential/secret detection
"""

import re
from typing import List, Dict, Any

from .base import Plugin, PluginContext, PluginResult


class AntiDebugPlugin(Plugin):
    """
    Detect anti-debugging techniques.
    
    Looks for:
    - API calls (IsDebuggerPresent, etc.)
    - Timing checks (rdtsc, QueryPerformanceCounter)
    - Exception-based detection
    - Process/thread tricks
    """
    
    name = "anti_debug"
    description = "Detect anti-debugging techniques"
    version = "1.0.0"
    author = "RE Framework"
    
    requires_functions = True
    requires_strings = True
    
    # Known anti-debug APIs
    ANTI_DEBUG_APIS = {
        'IsDebuggerPresent': ('Windows API', 5),
        'CheckRemoteDebuggerPresent': ('Windows API', 5),
        'NtQueryInformationProcess': ('NT API', 4),
        'NtSetInformationThread': ('NT API - ThreadHideFromDebugger', 4),
        'NtQuerySystemInformation': ('NT API', 3),
        'OutputDebugString': ('Windows API - timing', 2),
        'GetTickCount': ('Timing check', 2),
        'QueryPerformanceCounter': ('Timing check', 3),
        'GetSystemTime': ('Timing check', 2),
        'timeGetTime': ('Timing check', 2),
        'ptrace': ('Linux ptrace', 5),
        'prctl': ('Linux PR_SET_DUMPABLE', 3),
    }
    
    # Suspicious instruction patterns
    SUSPICIOUS_PATTERNS = [
        (b'\x0f\x31', 'rdtsc', 'Timing-based detection', 3),
        (b'\xcd\x03', 'int 3', 'Breakpoint interrupt', 2),
        (b'\xcd\x2d', 'int 2d', 'Debug interrupt', 4),
        (b'\xcc', 'int3', 'Software breakpoint', 1),
    ]
    
    def analyze(self, context: PluginContext) -> PluginResult:
        result = PluginResult(plugin_name=self.name, success=True)
        
        # Check for anti-debug API imports
        self._check_imports(context, result)
        
        # Check for anti-debug strings
        self._check_strings(context, result)
        
        # Check for suspicious instructions
        self._check_instructions(context, result)
        
        # Check for PEB access (Windows)
        self._check_peb_access(context, result)
        
        # Generate summary
        if result.findings:
            result.summary = f"Found {len(result.findings)} anti-debug indicators"
        else:
            result.summary = "No anti-debug techniques detected"
        
        return result
    
    def _check_imports(self, context: PluginContext, result: PluginResult) -> None:
        """Check imported functions for anti-debug APIs."""
        for imp in context.get_imports():
            name = imp.name if hasattr(imp, 'name') else str(imp)
            
            for api, (category, severity) in self.ANTI_DEBUG_APIS.items():
                if api.lower() in name.lower():
                    result.add_finding(
                        category="Anti-Debug Import",
                        description=f"{name} ({category})",
                        address=imp.plt_address if hasattr(imp, 'plt_address') else 0,
                        severity=severity,
                        api_name=api
                    )
    
    def _check_strings(self, context: PluginContext, result: PluginResult) -> None:
        """Check strings for anti-debug indicators."""
        suspicious_strings = [
            ('IsDebuggerPresent', 4),
            ('CheckRemoteDebugger', 4),
            ('NtQueryInformationProcess', 4),
            ('ProcessDebugPort', 4),
            ('ProcessDebugObjectHandle', 4),
            ('ThreadHideFromDebugger', 5),
            ('DebugActiveProcess', 3),
            ('SeDebugPrivilege', 3),
            ('OllyDbg', 3),
            ('x64dbg', 3),
            ('IDA', 2),
            ('Ghidra', 2),
            ('WinDbg', 3),
        ]
        
        for search, severity in suspicious_strings:
            matches = context.get_strings_containing(search)
            for s in matches:
                result.add_finding(
                    category="Anti-Debug String",
                    description=f"Found: {s.value[:50]}",
                    address=s.address,
                    severity=severity
                )
    
    def _check_instructions(self, context: PluginContext, result: PluginResult) -> None:
        """Check for suspicious instructions."""
        for pattern, name, desc, severity in self.SUSPICIOUS_PATTERNS:
            for section in context.binary.sections:
                if not section.data:
                    continue
                
                offset = 0
                while True:
                    pos = section.data.find(pattern, offset)
                    if pos == -1:
                        break
                    
                    # Skip if it's just padding
                    if pattern == b'\xcc' and pos > 0:
                        # Check if part of padding
                        if section.data[pos-1:pos] == b'\xcc':
                            offset = pos + 1
                            continue
                    
                    result.add_finding(
                        category="Anti-Debug Instruction",
                        description=f"{name}: {desc}",
                        address=section.vaddr + pos,
                        severity=severity
                    )
                    offset = pos + 1
    
    def _check_peb_access(self, context: PluginContext, result: PluginResult) -> None:
        """Check for direct PEB access (Windows anti-debug)."""
        # Look for fs:[30h] or gs:[60h] access (PEB pointer)
        # This is architecture-specific
        
        # 32-bit: mov eax, fs:[30h] = 64 A1 30 00 00 00
        # 64-bit: mov rax, gs:[60h] = 65 48 8B 04 25 60 00 00 00
        
        peb_patterns = [
            (b'\x64\xa1\x30\x00\x00\x00', 'PEB access (32-bit)', 4),
            (b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00', 'PEB access (64-bit)', 4),
            (b'\x64\x8b', 'FS segment access', 2),  # General FS access
            (b'\x65\x48\x8b', 'GS segment access (64-bit)', 2),
        ]
        
        for pattern, desc, severity in peb_patterns:
            for section in context.binary.sections:
                if not section.data:
                    continue
                
                pos = section.data.find(pattern)
                if pos != -1:
                    result.add_finding(
                        category="Anti-Debug PEB",
                        description=desc,
                        address=section.vaddr + pos,
                        severity=severity
                    )


class NetworkIOCPlugin(Plugin):
    """
    Extract network Indicators of Compromise (IOCs).
    
    Finds:
    - IP addresses
    - Domain names
    - URLs
    - Email addresses
    - Ports
    """
    
    name = "network_ioc"
    description = "Extract network IOCs (IPs, domains, URLs)"
    version = "1.0.0"
    author = "RE Framework"
    
    requires_strings = True
    
    # Regex patterns
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    URL_PATTERN = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' 
        r'(?:com|net|org|edu|gov|mil|io|co|info|biz|ru|cn|tk|xyz|top|pw|cc)\b'
    )
    
    EMAIL_PATTERN = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    )
    
    # Common non-malicious IPs to filter
    BENIGN_IPS = {
        '0.0.0.0', '127.0.0.1', '255.255.255.255',
        '192.168.0.1', '192.168.1.1', '10.0.0.1',
    }
    
    def analyze(self, context: PluginContext) -> PluginResult:
        result = PluginResult(plugin_name=self.name, success=True)
        
        seen_iocs = set()
        
        for s in context.strings:
            if not hasattr(s, 'value'):
                continue
            
            value = s.value
            
            # Extract IPs
            for match in self.IP_PATTERN.finditer(value):
                ip = match.group()
                if ip not in self.BENIGN_IPS and ip not in seen_iocs:
                    seen_iocs.add(ip)
                    result.add_finding(
                        category="IP Address",
                        description=ip,
                        address=s.address,
                        severity=3,
                        ioc_type="ip",
                        ioc_value=ip
                    )
            
            # Extract URLs
            for match in self.URL_PATTERN.finditer(value):
                url = match.group()
                if url not in seen_iocs:
                    seen_iocs.add(url)
                    result.add_finding(
                        category="URL",
                        description=url[:80],
                        address=s.address,
                        severity=4,
                        ioc_type="url",
                        ioc_value=url
                    )
            
            # Extract domains
            for match in self.DOMAIN_PATTERN.finditer(value):
                domain = match.group().lower()
                if domain not in seen_iocs and not self._is_benign_domain(domain):
                    seen_iocs.add(domain)
                    result.add_finding(
                        category="Domain",
                        description=domain,
                        address=s.address,
                        severity=3,
                        ioc_type="domain",
                        ioc_value=domain
                    )
            
            # Extract emails
            for match in self.EMAIL_PATTERN.finditer(value):
                email = match.group().lower()
                if email not in seen_iocs:
                    seen_iocs.add(email)
                    result.add_finding(
                        category="Email",
                        description=email,
                        address=s.address,
                        severity=2,
                        ioc_type="email",
                        ioc_value=email
                    )
        
        # Generate summary
        ioc_counts = {}
        for f in result.findings:
            ioc_type = f.get('ioc_type', 'unknown')
            ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1
        
        summary_parts = [f"{count} {ioc_type}s" for ioc_type, count in ioc_counts.items()]
        result.summary = f"Found {', '.join(summary_parts)}" if summary_parts else "No network IOCs found"
        
        return result
    
    def _is_benign_domain(self, domain: str) -> bool:
        """Check if domain is likely benign."""
        benign_domains = [
            'microsoft.com', 'windows.com', 'google.com',
            'github.com', 'stackoverflow.com', 'example.com',
            'localhost', 'test.com'
        ]
        return any(domain.endswith(b) for b in benign_domains)


class CredentialPlugin(Plugin):
    """
    Detect hardcoded credentials and secrets.
    
    Finds:
    - Passwords
    - API keys
    - Private keys
    - Tokens
    """
    
    name = "credentials"
    description = "Detect hardcoded credentials and secrets"
    version = "1.0.0"
    author = "RE Framework"
    
    requires_strings = True
    
    # Patterns for credential detection
    CREDENTIAL_PATTERNS = [
        # Generic password patterns
        (re.compile(r'password\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.I), 
         'Hardcoded password', 5),
        (re.compile(r'passwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.I), 
         'Hardcoded password', 5),
        (re.compile(r'pwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.I), 
         'Hardcoded password', 4),
        
        # API keys
        (re.compile(r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9]{16,})["\']?', re.I), 
         'API key', 4),
        (re.compile(r'apikey\s*[=:]\s*["\']?([a-zA-Z0-9]{16,})["\']?', re.I), 
         'API key', 4),
        
        # AWS credentials
        (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key', 5),
        (re.compile(r'aws[_-]?secret[_-]?access[_-]?key', re.I), 'AWS Secret Key reference', 4),
        
        # Private keys
        (re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'), 'Private key', 5),
        (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), 'SSH private key', 5),
        
        # Tokens
        (re.compile(r'bearer\s+[a-zA-Z0-9\-_.]+', re.I), 'Bearer token', 4),
        (re.compile(r'token\s*[=:]\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?', re.I), 
         'Auth token', 3),
        
        # Database connection strings
        (re.compile(r'mongodb://[^\s]+'), 'MongoDB connection string', 4),
        (re.compile(r'mysql://[^\s]+'), 'MySQL connection string', 4),
        (re.compile(r'postgresql://[^\s]+'), 'PostgreSQL connection string', 4),
        
        # Generic secrets
        (re.compile(r'secret\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', re.I), 
         'Hardcoded secret', 3),
    ]
    
    # High-entropy string detection threshold
    ENTROPY_THRESHOLD = 4.5
    MIN_SECRET_LENGTH = 16
    
    def analyze(self, context: PluginContext) -> PluginResult:
        result = PluginResult(plugin_name=self.name, success=True)
        
        seen = set()
        
        for s in context.strings:
            if not hasattr(s, 'value'):
                continue
            
            value = s.value
            
            # Check against known patterns
            for pattern, desc, severity in self.CREDENTIAL_PATTERNS:
                match = pattern.search(value)
                if match:
                    matched_text = match.group()
                    if matched_text not in seen:
                        seen.add(matched_text)
                        result.add_finding(
                            category="Credential",
                            description=f"{desc}: {matched_text[:40]}...",
                            address=s.address,
                            severity=severity,
                            credential_type=desc,
                            matched_value=matched_text[:100]
                        )
            
            # Check for high-entropy strings (potential encoded secrets)
            if len(value) >= self.MIN_SECRET_LENGTH:
                entropy = self._calculate_entropy(value)
                if entropy > self.ENTROPY_THRESHOLD:
                    # Additional checks to reduce false positives
                    if self._looks_like_secret(value) and value not in seen:
                        seen.add(value)
                        result.add_finding(
                            category="Potential Secret",
                            description=f"High-entropy string (entropy={entropy:.2f}): {value[:30]}...",
                            address=s.address,
                            severity=2,
                            entropy=entropy
                        )
        
        result.summary = f"Found {len(result.findings)} potential credentials/secrets"
        return result
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not s:
            return 0.0
        
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _looks_like_secret(self, s: str) -> bool:
        """Check if string looks like it could be a secret."""
        # Must have mix of character types
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        
        # Should have at least 2 of 3 character types
        char_types = sum([has_upper, has_lower, has_digit])
        if char_types < 2:
            return False
        
        # Should not be a common word or path
        common_patterns = [
            '/usr/', '/etc/', '/home/', '/var/',
            'http://', 'https://', 'file://',
            '.dll', '.exe', '.so', '.dylib',
        ]
        for pattern in common_patterns:
            if pattern in s.lower():
                return False
        
        return True


class ImportAnalysisPlugin(Plugin):
    """
    Analyze imported functions for suspicious behavior.
    """
    
    name = "import_analysis"
    description = "Analyze imports for suspicious API usage"
    version = "1.0.0"
    author = "RE Framework"
    
    # Categorized suspicious imports
    SUSPICIOUS_IMPORTS = {
        'process_injection': [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext',
            'NtCreateThreadEx', 'RtlCreateUserThread',
        ],
        'code_execution': [
            'WinExec', 'ShellExecute', 'ShellExecuteEx', 'CreateProcess',
            'system', 'popen', 'execve', 'fork',
        ],
        'persistence': [
            'RegSetValueEx', 'RegCreateKeyEx', 'CreateService',
            'StartService', 'SetWindowsHookEx',
        ],
        'evasion': [
            'VirtualProtect', 'VirtualProtectEx', 'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent', 'GetTickCount', 'Sleep',
        ],
        'network': [
            'WSAStartup', 'socket', 'connect', 'send', 'recv',
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest',
            'URLDownloadToFile', 'WinHttpOpen',
        ],
        'file_ops': [
            'DeleteFile', 'MoveFileEx', 'CopyFile', 'CreateFile',
            'WriteFile', 'ReadFile',
        ],
        'crypto': [
            'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt',
            'CryptGenKey', 'CryptImportKey',
        ],
        'keylogging': [
            'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
            'RegisterHotKey', 'GetKeyboardState',
        ],
    }
    
    def analyze(self, context: PluginContext) -> PluginResult:
        result = PluginResult(plugin_name=self.name, success=True)
        
        category_counts = {}
        
        for imp in context.get_imports():
            imp_name = imp.name if hasattr(imp, 'name') else str(imp)
            
            for category, apis in self.SUSPICIOUS_IMPORTS.items():
                for api in apis:
                    if api.lower() in imp_name.lower():
                        category_counts[category] = category_counts.get(category, 0) + 1
                        
                        severity = 3
                        if category in ('process_injection', 'keylogging'):
                            severity = 5
                        elif category in ('evasion', 'persistence'):
                            severity = 4
                        
                        result.add_finding(
                            category=f"Suspicious Import ({category})",
                            description=imp_name,
                            address=imp.plt_address if hasattr(imp, 'plt_address') else 0,
                            severity=severity,
                            api_category=category
                        )
        
        # Generate summary
        if category_counts:
            summary_parts = [f"{cat}: {count}" for cat, count in category_counts.items()]
            result.summary = f"Suspicious imports by category: {', '.join(summary_parts)}"
        else:
            result.summary = "No suspicious imports detected"
        
        return result
