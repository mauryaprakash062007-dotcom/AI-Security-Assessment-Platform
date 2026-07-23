import re
import ipaddress
import socket
import os

class ValidationError(Exception):
    pass

def validate_target(target: str) -> bool:
    """
    Validates a scan target to prevent SSRF, command injection, and scanning of internal/private networks.
    Raises ValidationError if the target is invalid.
    Returns True if valid.
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target must be a non-empty string.")

    target = target.strip()
    
    # 1. Command Injection Prevention
    # Reject shell metacharacters
    bad_chars = [';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '\n', '\r']
    for char in bad_chars:
        if char in target:
            raise ValidationError(f"Invalid character '{char}' in target.")

    # Reject CIDR notation for now (we only want single IPs or hostnames)
    if '/' in target:
         raise ValidationError("CIDR notation is not allowed.")

    # 2. Format validation (basic check for valid hostname or IP characters)
    # Allows alphanumeric, dots, hyphens
    if not re.match(r'^[-a-zA-Z0-9.]+$', target):
        raise ValidationError("Target contains invalid characters.")

    # 3. Resolve and check against RFC1918 (Private IP space)
    try:
        # Resolve hostname to IP (or just return the IP if it's already an IP)
        ip_addr = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValidationError("Could not resolve target hostname.")
    except Exception as e:
         raise ValidationError(f"Error resolving target: {e}")

    try:
        ip = ipaddress.ip_address(ip_addr)
        if ip.is_private and str(os.getenv("ALLOW_PRIVATE_IPS", "false")).lower() != "true":
            raise ValidationError("Target resolves to a private IP address (RFC 1918).")
        if ip.is_loopback:
            raise ValidationError("Target resolves to a loopback address.")
        if ip.is_link_local:
            raise ValidationError("Target resolves to a link-local address.")
        if ip.is_multicast:
            raise ValidationError("Target resolves to a multicast address.")
        if ip.is_reserved:
            raise ValidationError("Target resolves to a reserved address.")
        if str(ip) == "0.0.0.0":
            raise ValidationError("Target resolves to 0.0.0.0.")
    except ValueError:
        # Should not happen since gethostbyname returns a valid IP string
        raise ValidationError("Invalid IP address resolved.")

    return True
