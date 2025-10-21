#!/usr/bin/env python3
"""
Response Utilities for Signsley Python Backend

Provides consistent response formatting across all verification endpoints.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def create_error_response(
    error_message: str,
    file_name: str,
    format_name: str,
    status_code: int = 500,
    structure_valid: bool = False,
    additional_fields: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a standardized error response
    
    Args:
        error_message: The error message to display
        file_name: Name of the file being processed
        format_name: Signature format (PAdES, CAdES, XAdES)
        status_code: HTTP status code
        structure_valid: Whether the file structure is valid
        additional_fields: Additional fields to include in response
    
    Returns:
        Standardized error response dictionary
    """
    
    response = {
        "valid": False,
        "format": format_name,
        "fileName": file_name,
        "structureValid": structure_valid,
        "documentIntact": None,
        "integrityReason": error_message,
        "error": error_message,
        "verificationTimestamp": datetime.now(timezone.utc).isoformat(),
        "processingTime": 0
    }
    
    if additional_fields:
        response.update(additional_fields)
    
    return response

def create_no_signature_response(
    file_name: str,
    format_name: str
) -> Dict[str, Any]:
    """
    Create response for files with no digital signatures
    
    Args:
        file_name: Name of the file
        format_name: Expected signature format
    
    Returns:
        No signature response dictionary
    """
    
    return {
        "valid": False,
        "format": format_name,
        "fileName": file_name,
        "structureValid": True,
        "documentIntact": None,
        "integrityReason": "No digital signature detected",
        "error": "No digital signature detected",
        "cryptographicVerification": False,
        "signatureValid": False,
        "certificateValid": False,
        "chainValid": False,
        "revocationChecked": False,
        "revoked": False,
        "signatureCount": 0,
        "signatures": [],
        "warnings": [],
        "troubleshooting": [],
        "verificationTimestamp": datetime.now(timezone.utc).isoformat(),
        "processingTime": 0
    }

def create_structure_invalid_response(
    file_name: str,
    format_name: str,
    reason: str,
    missing_elements: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create response for files with invalid structure
    
    Args:
        file_name: Name of the file
        format_name: Expected signature format
        reason: Reason why structure is invalid
        missing_elements: List of missing required elements
    
    Returns:
        Structure invalid response dictionary
    """
    
    warnings = []
    troubleshooting = []
    
    if missing_elements:
        troubleshooting.append(f"Missing elements: {', '.join(missing_elements)}")
    
    if format_name == "PAdES":
        troubleshooting.extend([
            "Verify the PDF contains embedded digital signatures",
            "Check if signatures are properly formatted according to PAdES standards"
        ])
    elif format_name == "CAdES":
        troubleshooting.extend([
            "Verify the file is a valid PKCS#7/CMS signature",
            "Check file integrity and encoding"
        ])
    elif format_name == "XAdES":
        troubleshooting.extend([
            "Verify the XML contains valid signature elements",
            "Check XML signature standards compliance"
        ])
    
    return {
        "valid": False,
        "format": format_name,
        "fileName": file_name,
        "structureValid": False,
        "documentIntact": None,
        "integrityReason": reason,
        "error": reason,
        "cryptographicVerification": False,
        "warnings": warnings,
        "troubleshooting": troubleshooting,
        "verificationTimestamp": datetime.now(timezone.utc).isoformat(),
        "processingTime": 0
    }

def create_limited_verification_response(
    file_name: str,
    format_name: str,
    certificate_info: Dict[str, Any],
    reason: str
) -> Dict[str, Any]:
    """
    Create response for signatures that can only be partially verified
    
    Args:
        file_name: Name of the file
        format_name: Signature format
        certificate_info: Extracted certificate information
        reason: Reason for limited verification
    
    Returns:
        Limited verification response dictionary
    """
    
    warnings = []
    troubleshooting = []
    
    if format_name == "CAdES":
        warnings.append("CAdES signatures require the original content for full cryptographic verification")
        troubleshooting.append("Use specialized CAdES validation software with original content for complete verification")
    elif format_name == "XAdES":
        warnings.append("XAdES signatures require specialized XML signature verification")
        troubleshooting.append("Use dedicated XAdES validation software for complete verification")
    
    return {
        "valid": False,
        "format": format_name,
        "fileName": file_name,
        "structureValid": True,
        "documentIntact": None,
        "integrityReason": reason,
        "cryptographicVerification": False,
        "signatureValid": True,  # Structure is valid
        "certificateValid": certificate_info.get("valid", False),
        "certificateValidAtSigning": certificate_info.get("validAtSigning", False),
        "certificateExpiredSinceSigning": certificate_info.get("expiredSinceSigning", False),
        "certificateValidNow": certificate_info.get("validNow", False),
        "signingTimeUsed": certificate_info.get("signingTime"),
        "chainValid": certificate_info.get("chainValid", True),
        "chainValidationPerformed": certificate_info.get("chainValidationPerformed", False),
        "revocationChecked": certificate_info.get("revocationChecked", False),
        "revoked": certificate_info.get("revoked", False),
        "signedBy": certificate_info.get("commonName", "Unknown"),
        "organization": certificate_info.get("organization", "Unknown"),
        "email": certificate_info.get("email", "Unknown"),
        "certificateIssuer": certificate_info.get("issuer", "Unknown"),
        "certificateValidFrom": certificate_info.get("validFrom"),
        "certificateValidTo": certificate_info.get("validTo"),
        "serialNumber": certificate_info.get("serialNumber"),
        "isSelfSigned": certificate_info.get("isSelfSigned", False),
        "signatureDate": certificate_info.get("signingTime"),
        "certificateChainLength": certificate_info.get("chainLength", 1),
        "signatureAlgorithm": certificate_info.get("algorithm", "RSA-SHA256"),
        "certificateChain": certificate_info.get("chain", []),
        "warnings": warnings,
        "troubleshooting": troubleshooting,
        "verificationTimestamp": datetime.now(timezone.utc).isoformat(),
        "processingTime": certificate_info.get("processingTime", 0)
    }

def format_datetime_for_display(dt: datetime) -> str:
    """
    Format datetime for display in API responses
    
    Args:
        dt: DateTime to format
    
    Returns:
        Formatted date string in YYYY/MM/DD format
    """
    try:
        return dt.strftime("%Y/%m/%d")
    except (AttributeError, ValueError):
        return "Unknown"

def format_certificate_name(name_attributes) -> str:
    """
    Format certificate name attributes into a readable string
    
    Args:
        name_attributes: Certificate name attributes
    
    Returns:
        Formatted name string
    """
    try:
        parts = []
        for attr in name_attributes:
            if hasattr(attr, 'oid') and hasattr(attr, 'value'):
                oid_name = getattr(attr.oid, '_name', str(attr.oid))
                parts.append(f"{oid_name}={attr.value}")
            else:
                parts.append(str(attr))
        return ", ".join(parts)
    except Exception:
        return str(name_attributes)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe processing
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    import re
    # Remove path separators and dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    return sanitized[:255] if sanitized else "unknown_file"

def calculate_processing_time(start_time: datetime) -> int:
    """
    Calculate processing time in milliseconds
    
    Args:
        start_time: Processing start time
    
    Returns:
        Processing time in milliseconds
    """
    try:
        end_time = datetime.now(timezone.utc)
        delta = end_time - start_time
        return int(delta.total_seconds() * 1000)
    except Exception:
        return 0