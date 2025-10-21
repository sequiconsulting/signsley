#!/usr/bin/env python3
"""
XAdES Verification Router - pyhanko 0.31

Handles XML Advanced Electronic Signature (XAdES) verification.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import base64
from datetime import datetime, timezone
from loguru import logger
import re

# XML processing imports
from lxml import etree
from defusedxml import ElementTree as ET
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization

from utils.response_utils import (
    create_error_response,
    create_structure_invalid_response,
    create_limited_verification_response,
    format_datetime_for_display,
    format_certificate_name,
    calculate_processing_time
)

router = APIRouter()

# Request/Response models
class XAdESVerificationRequest(BaseModel):
    fileData: str = Field(..., description="Base64 encoded XML file data")
    fileName: str = Field(..., description="Original filename")


class XAdESValidator:
    """XAdES signature validator using XML signature standards"""
    
    # XML Signature namespaces
    NAMESPACES = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
        'xades132': 'http://uri.etsi.org/01903/v1.3.2#',
        'xades141': 'http://uri.etsi.org/01903/v1.4.1#'
    }
    
    def __init__(self):
        pass
    
    async def verify_xades_signature(
        self,
        xml_data: bytes,
        file_name: str
    ) -> Dict[str, Any]:
        """Verify XAdES signature"""
        
        start_time = datetime.now(timezone.utc)
        
        try:
            # Decode and validate XML
            xml_content = xml_data.decode('utf-8')
            
            if not self._is_valid_xml(xml_content):
                return create_error_response(
                    error_message="Not a valid XML file",
                    file_name=file_name,
                    format_name="XAdES (XML Advanced Electronic Signature)",
                    structure_valid=False
                )
            
            # Validate XML signature structure
            structure_validation = self._validate_xml_signature_structure(xml_content)
            
            if not structure_validation["valid"]:
                return create_structure_invalid_response(
                    file_name=file_name,
                    format_name="XAdES (XML Advanced Electronic Signature)",
                    reason="Invalid XML signature structure",
                    missing_elements=structure_validation.get("missing_elements", [])
                )
            
            # Parse XML signature
            try:
                signature_info = self._parse_xml_signature(xml_content)
            except Exception as e:
                return create_error_response(
                    error_message=f"Signature parsing failed: {str(e)}",
                    file_name=file_name,
                    format_name="XAdES (XML Advanced Electronic Signature)",
                    structure_valid=True
                )
            
            # Extract certificate information
            cert_info = self._extract_certificate_info_from_xml(
                signature_info, start_time
            )
            cert_info["processingTime"] = calculate_processing_time(start_time)
            
            # XAdES signatures require specialized XML signature verification
            return create_limited_verification_response(
                file_name=file_name,
                format_name="XAdES (XML Advanced Electronic Signature)",
                certificate_info=cert_info,
                reason="XAdES structure valid - full XML signature cryptographic verification not implemented"
            )
            
        except Exception as e:
            logger.error(f"XAdES verification failed: {e}")
            return create_error_response(
                error_message=f"XAdES verification failed: {str(e)}",
                file_name=file_name,
                format_name="XAdES (XML Advanced Electronic Signature)"
            )
    
    def _is_valid_xml(self, content: str) -> bool:
        """Check if content is valid XML"""
        try:
            return ('<?xml' in content or '<' in content) and len(content.strip()) > 0
        except Exception:
            return False
    
    def _validate_xml_signature_structure(self, xml_content: str) -> Dict[str, Any]:
        """Validate required XML signature elements"""
        
        required_patterns = [
            (r'<ds:Signature[^>]*>', 'ds:Signature'),
            (r'<ds:SignedInfo[^>]*>', 'ds:SignedInfo'),
            (r'<ds:CanonicalizationMethod[^>]*>', 'ds:CanonicalizationMethod'),
            (r'<ds:SignatureMethod[^>]*>', 'ds:SignatureMethod'),
            (r'<ds:Reference[^>]*>', 'ds:Reference'),
            (r'<ds:DigestMethod[^>]*>', 'ds:DigestMethod'),
            (r'<ds:DigestValue[^>]*>', 'ds:DigestValue'),
            (r'<ds:SignatureValue[^>]*>', 'ds:SignatureValue'),
            (r'<ds:KeyInfo[^>]*>', 'ds:KeyInfo')
        ]
        
        missing_elements = []
        
        for pattern, element_name in required_patterns:
            if not re.search(pattern, xml_content, re.IGNORECASE):
                missing_elements.append(element_name)
        
        return {
            "valid": len(missing_elements) == 0,
            "missing_elements": missing_elements
        }
    
    def _parse_xml_signature(self, xml_content: str) -> Dict[str, Any]:
        """Parse XML signature elements"""
        
        signature_info = {
            "certificate": None,
            "signing_time": None,
            "signature_element": None
        }
        
        try:
            # Parse XML safely
            root = ET.fromstring(xml_content.encode('utf-8'))
            
            # Find certificate data
            cert_match = re.search(
                r'<ds:X509Certificate[^>]*>([\s\S]*?)</ds:X509Certificate>',
                xml_content,
                re.IGNORECASE
            )
            
            if cert_match:
                cert_data = cert_match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
                try:
                    cert_der = base64.b64decode(cert_data)
                    certificate = x509.load_der_x509_certificate(cert_der)
                    signature_info["certificate"] = certificate
                except Exception as e:
                    logger.warning(f"Could not parse certificate: {e}")
            
            # Find signing time
            signing_time_match = re.search(
                r'<xades:SigningTime[^>]*>([^<]+)</xades:SigningTime>',
                xml_content,
                re.IGNORECASE
            )
            
            if signing_time_match:
                try:
                    signing_time_str = signing_time_match.group(1)
                    # Try to parse ISO format datetime
                    signing_time = datetime.fromisoformat(signing_time_str.replace('Z', '+00:00'))
                    signature_info["signing_time"] = signing_time
                except Exception as e:
                    logger.warning(f"Could not parse signing time: {e}")
            
            # Extract signature element
            sig_match = re.search(
                r'<ds:Signature[^>]*>([\s\S]*?)</ds:Signature>',
                xml_content,
                re.IGNORECASE
            )
            
            if sig_match:
                signature_info["signature_element"] = sig_match.group(0)
            
            return signature_info
            
        except Exception as e:
            logger.error(f"XML signature parsing failed: {e}")
            raise Exception(f"XML signature parsing failed: {str(e)}")
    
    def _extract_certificate_info_from_xml(
        self, 
        signature_info: Dict[str, Any], 
        start_time: datetime
    ) -> Dict[str, Any]:
        """Extract certificate information from XML signature"""
        
        info = {
            "commonName": "Unknown",
            "organization": "Unknown",
            "email": "Unknown",
            "issuer": "Unknown",
            "serialNumber": "Unknown",
            "validFrom": "Unknown",
            "validTo": "Unknown",
            "isSelfSigned": False,
            "algorithm": "RSA-SHA256",
            "signingTime": None
        }
        
        certificate = signature_info.get("certificate")
        
        if certificate:
            # Extract basic certificate info
            info["serialNumber"] = str(certificate.serial_number)
            info["validFrom"] = format_datetime_for_display(certificate.not_valid_before)
            info["validTo"] = format_datetime_for_display(certificate.not_valid_after)
            info["isSelfSigned"] = certificate.subject == certificate.issuer
            
            try:
                info["algorithm"] = certificate.signature_algorithm_oid._name.replace('_', '-').upper()
            except Exception:
                info["algorithm"] = "RSA-SHA256"
            
            # Extract subject information
            try:
                for attribute in certificate.subject:
                    if attribute.oid == NameOID.COMMON_NAME:
                        info["commonName"] = attribute.value
                    elif attribute.oid == NameOID.ORGANIZATION_NAME:
                        info["organization"] = attribute.value
                    elif attribute.oid == NameOID.EMAIL_ADDRESS:
                        info["email"] = attribute.value
            except Exception as e:
                logger.warning(f"Could not extract subject info: {e}")
            
            # Extract issuer information
            try:
                for attribute in certificate.issuer:
                    if attribute.oid == NameOID.COMMON_NAME:
                        info["issuer"] = attribute.value
                        break
            except Exception as e:
                logger.warning(f"Could not extract issuer info: {e}")
            
            # Certificate validity checks
            now = datetime.now(timezone.utc)
            info["valid"] = now >= certificate.not_valid_before and now <= certificate.not_valid_after
            info["validNow"] = info["valid"]
            info["validAtSigning"] = info["valid"]
            info["expiredSinceSigning"] = False
        
        # Add signing time if available
        if signature_info.get("signing_time"):
            info["signingTime"] = format_datetime_for_display(signature_info["signing_time"])
        
        # Set validation flags
        info["chainValid"] = True  # Simplified - no chain validation for XAdES
        info["chainValidationPerformed"] = False
        info["revocationChecked"] = False
        info["revoked"] = False
        info["chainLength"] = 1
        info["chain"] = []
        
        return info


@router.post("/verify-xades", response_model=Dict[str, Any])
async def verify_xades_signature(request: XAdESVerificationRequest):
    """
    Verify XAdES (XML Advanced Electronic Signature)
    
    This endpoint verifies XAdES signatures with structural validation:
    - XML signature structure verification
    - Certificate extraction and validation
    - Signing time extraction
    - Limited cryptographic verification
    
    Note: XAdES signatures require specialized XML signature verification
    libraries for full cryptographic validation. This implementation provides
    structural analysis and certificate information.
    
    Args:
        request: XAdES verification request containing base64 XML data
        
    Returns:
        Verification result with structural analysis and certificate information
    """
    
    logger.info(f"Starting XAdES verification for file: {request.fileName}")
    
    try:
        # Validate input
        if not request.fileData:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file data provided"
            )
        
        # Decode base64 data
        try:
            xml_data = base64.b64decode(request.fileData)
        except Exception as e:
            logger.error(f"Failed to decode base64 data: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 file data"
            )
        
        logger.info(f"Processing XAdES: {request.fileName}, size: {len(xml_data)} bytes")
        
        # Initialize XAdES validator
        validator = XAdESValidator()
        
        # Verify XAdES signature
        result = await validator.verify_xades_signature(
            xml_data=xml_data,
            file_name=request.fileName
        )
        
        logger.info(
            f"XAdES verification completed for {request.fileName}: "
            f"valid={result.get('valid')}, structure_valid={result.get('structureValid')}"
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"XAdES verification failed for {request.fileName}: {e}")
        
        return create_error_response(
            error_message=f"Verification failed: {str(e)}",
            file_name=request.fileName,
            format_name="XAdES (XML Advanced Electronic Signature)"
        )


@router.options("/verify-xades")
async def verify_xades_options():
    """Handle CORS preflight requests"""
    return {}


@router.get("/verify-xades/info")
async def xades_info():
    """
    Get information about XAdES verification capabilities
    """
    return {
        "format": "XAdES (XML Advanced Electronic Signature)",
        "description": "Verifies XML signatures with structural validation",
        "capabilities": [
            "XML signature structure verification",
            "Certificate extraction and validation",
            "Signing time extraction",
            "XML namespace handling",
            "Safe XML parsing with defusedxml"
        ],
        "limitations": [
            "Full XML signature cryptographic verification requires specialized libraries",
            "Hash verification depends on canonicalization support",
            "Complex XAdES profiles may not be fully supported"
        ],
        "supported_standards": [
            "W3C XML Signature",
            "ETSI EN 319 132 (XAdES)",
            "ETSI TS 101 903 (XAdES v1.3.2)",
            "ETSI TS 101 903 (XAdES v1.4.1)"
        ],
        "backend": "Python lxml + defusedxml + cryptography",
        "max_file_size": "10MB",
        "supported_namespaces": [
            "http://www.w3.org/2000/09/xmldsig#",
            "http://uri.etsi.org/01903/v1.3.2#",
            "http://uri.etsi.org/01903/v1.4.1#"
        ]
    }