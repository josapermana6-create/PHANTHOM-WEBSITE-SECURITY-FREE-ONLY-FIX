"""
Utility helper functions for Phantom WAF
"""
import re
import hashlib
import secrets
import ipaddress
from urllib.parse import urlparse, unquote
from typing import Optional, List, Dict, Any
import math


def sanitize_string(input_str: str, max_length: int = 1000) -> str:
    """Sanitize and truncate input string"""
    if not input_str:
        return ""
    
    # Truncate to max length
    sanitized = input_str[:max_length]
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    return sanitized


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    
    # Count character frequency
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def get_special_char_ratio(text: str) -> float:
    """Calculate ratio of special characters in text"""
    if not text:
        return 0.0
    
    special_chars = re.findall(r'[^a-zA-Z0-9\s]', text)
    return len(special_chars) / len(text)


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP address is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_cloud_metadata_url(url: str) -> bool:
    """Check if URL is targeting cloud metadata endpoints"""
    metadata_patterns = [
        r'169\.254\.169\.254',  # AWS/Azure/GCP metadata
        r'metadata\.google\.internal',
        r'metadata\.azure\.com',
        r'100\.100\.100\.200',  # Alibaba Cloud
    ]
    
    for pattern in metadata_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    return False


def normalize_path(path: str) -> str:
    """Normalize file path for security checks"""
    # Decode URL encoding
    decoded = unquote(path)
    
    # Remove null bytes
    decoded = decoded.replace('\x00', '')
    
    # Normalize path separators
    normalized = decoded.replace('\\', '/')
    
    # Remove duplicate slashes
    normalized = re.sub(r'/+', '/', normalized)
    
    return normalized


def count_traversal_attempts(path: str) -> int:
    """Count directory traversal attempts in path"""
    normalized = normalize_path(path)
    
    # Count ../ patterns
    dotdot_count = normalized.count('../')
    
    # Count encoded versions
    encoded_patterns = [
        '%2e%2e/',
        '..%2f',
        '%2e%2e%2f',
        '..../',
        '..\\',
    ]
    
    for pattern in encoded_patterns:
        dotdot_count += normalized.lower().count(pattern.lower())
    
    return dotdot_count


def generate_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_hex(length)


def hash_value(value: str, salt: str = "") -> str:
    """Generate SHA-256 hash of value"""
    combined = f"{value}{salt}"
    return hashlib.sha256(combined.encode()).hexdigest()


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except Exception:
        return None


def is_suspicious_user_agent(user_agent: str) -> bool:
    """Check if user agent is suspicious"""
    if not user_agent or len(user_agent) < 5:
        return True
    
    suspicious_patterns = [
        r'^curl',
        r'^wget',
        r'^python-requests',
        r'^go-http-client',
        r'scanner',
        r'sqlmap',
        r'nikto',
        r'nmap',
        r'masscan',
        r'exploit',
        r'havij',
        r'acunetix',
        r'nessus',
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return True
    
    return False


def decode_multiple_encodings(text: str, max_iterations: int = 5) -> str:
    """Decode text with multiple encoding layers"""
    decoded = text
    
    for _ in range(max_iterations):
        try:
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
        except Exception:
            break
    
    return decoded


def extract_sql_keywords(text: str) -> List[str]:
    """Extract SQL keywords from text"""
    sql_keywords = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'UNION', 'WHERE', 'FROM', 'JOIN', 'EXEC', 'EXECUTE',
        'CAST', 'CONVERT', 'CHAR', 'VARCHAR', 'NVARCHAR', 'XP_',
        'SP_', 'WAITFOR', 'DELAY', 'BENCHMARK', 'SLEEP'
    ]
    
    found_keywords = []
    text_upper = text.upper()
    
    for keyword in sql_keywords:
        if keyword in text_upper:
            found_keywords.append(keyword)
    
    return found_keywords


def contains_html_tags(text: str) -> bool:
    """Check if text contains HTML tags"""
    html_pattern = r'<[^>]+>'
    return bool(re.search(html_pattern, text))


def extract_ip_from_request(headers: Dict[str, str]) -> Optional[str]:
    """Extract real IP address from request headers"""
    # Check common proxy headers
    ip_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',
        'True-Client-IP',
        'X-Client-IP',
    ]
    
    for header in ip_headers:
        if header in headers:
            # X-Forwarded-For can contain multiple IPs
            ip_value = headers[header].split(',')[0].strip()
            if is_valid_ip(ip_value):
                return ip_value
    
    return None


def is_base64_encoded(text: str) -> bool:
    """Check if text appears to be base64 encoded"""
    # Base64 pattern
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    
    if len(text) % 4 != 0:
        return False
    
    return bool(re.match(pattern, text))


def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data in logs"""
    # Mask credit cards
    text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '****-****-****-****', text)
    
    # Mask emails partially
    text = re.sub(r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r'\1***@\2', text)
    
    # Mask potential passwords in query strings
    text = re.sub(r'(password|pwd|pass)=([^&\s]+)', r'\1=***', text, flags=re.IGNORECASE)
    
    return text


def get_file_extension(filename: str) -> str:
    """Extract file extension from filename"""
    if '.' not in filename:
        return ''
    
    return filename.rsplit('.', 1)[-1].lower()


def is_dangerous_extension(filename: str) -> bool:
    """Check if file has dangerous extension"""
    dangerous_exts = [
        'exe', 'dll', 'bat', 'cmd', 'sh', 'ps1', 'vbs',
        'js', 'jar', 'app', 'deb', 'rpm', 'php', 'asp',
        'aspx', 'jsp', 'py', 'pl', 'rb', 'cgi'
    ]
    
    ext = get_file_extension(filename)
    return ext in dangerous_exts


def truncate_log(text: str, max_length: int = 500) -> str:
    """Truncate text for logging with ellipsis"""
    if len(text) <= max_length:
        return text
    
    return text[:max_length] + '...'
