#!/usr/bin/env python3
"""
PAdES Verification Router - pyhanko 0.31

Handles PDF Advanced Electronic Signature (PAdES) verification.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Any, Dict
import base64
from loguru import logger

from utils.pyhanko_utils import SignsleyValidator
from utils.response_utils import create_error_response

router = APIRouter()

# Request/Response models
class PAdESVerificationRequest(BaseModel):
    fileData: str = Field(..., description="Base64 encoded PDF file data")
    fileName: str = Field(..., description="Original filename")

class PAdESVerificationResponse(BaseModel):
    valid: bool = Field(..., description="Overall validity status")
    format: str = Field(..., description="Signature format")
    fileName: str = Field(..., description="File name")
    structureValid: bool = Field(..., description="PDF structure validity")
    documentIntact: bool = Field(None, description="Document integrity status")
    integrityReason: str = Field(..., description="Integrity check reason")
    cryptographicVerification: bool = Field(..., description="Cryptographic verification performed")
    signatureValid: bool = Field(..., description="Signature validity")
    certificateValid: bool = Field(..., description="Certificate validity")
    certificateValidAtSigning: bool = Field(..., description="Certificate valid at signing time")
    certificateExpiredSinceSigning: bool = Field(..., description="Certificate expired since signing")
    certificateValidNow: bool = Field(..., description="Certificate valid now")
    signingTimeUsed: str = Field(None, description="Signing time used for validation")
    chainValid: bool = Field(..., description="Certificate chain validity")
    chainValidationPerformed: bool = Field(..., description="Chain validation performed")
    revocationChecked: bool = Field(..., description="Revocation check performed")
    revoked: bool = Field(..., description="Certificate revocation status")
    signedBy: str = Field(..., description="Signer name")
    organization: str = Field(None, description="Signer organization")
    email: str = Field(None, description="Signer email")
    certificateIssuer: str = Field(..., description="Certificate issuer")
    certificateValidFrom: str = Field(..., description="Certificate valid from date")
    certificateValidTo: str = Field(..., description="Certificate valid to date")
    serialNumber: str = Field(..., description="Certificate serial number")
    isSelfSigned: bool = Field(..., description="Self-signed certificate flag")
    signatureDate: str = Field(None, description="Signature date")
    certificateChainLength: int = Field(..., description="Certificate chain length")
    signatureAlgorithm: str = Field(..., description="Signature algorithm")
    certificateChain: list = Field(default_factory=list, description="Certificate chain details")
    signatureCount: int = Field(..., description="Number of signatures")
    signatures: list = Field(default_factory=list, description="Individual signature details")
    warnings: list = Field(default_factory=list, description="Validation warnings")
    troubleshooting: list = Field(default_factory=list, description="Troubleshooting information")
    verificationTimestamp: str = Field(..., description="Verification timestamp")
    processingTime: int = Field(..., description="Processing time in milliseconds")
    error: str = Field(None, description="Error message if verification failed")


@router.post("/verify-pades", response_model=Dict[str, Any])
async def verify_pades_signature(request: PAdESVerificationRequest):
    """
    Verify PAdES (PDF Advanced Electronic Signature) using pyhanko 0.31
    
    This endpoint verifies PDF signatures with comprehensive cryptographic validation:
    - Document integrity verification (hash comparison)
    - Certificate validation and chain verification
    - Revocation checking (OCSP/CRL)
    - Timestamp validation
    - AdES compliance checking
    
    Args:
        request: PAdES verification request containing base64 PDF data
        
    Returns:
        Comprehensive verification result matching the original API format
    """
    
    logger.info(f"Starting PAdES verification for file: {request.fileName}")
    
    try:
        # Validate input
        if not request.fileData:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file data provided"
            )
        
        # Decode base64 PDF data
        try:
            pdf_data = base64.b64decode(request.fileData)
        except Exception as e:
            logger.error(f"Failed to decode base64 data: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 file data"
            )
        
        # Validate PDF header
        if not pdf_data.startswith(b'%PDF-'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Not a valid PDF file"
            )
        
        logger.info(f"Processing PDF: {request.fileName}, size: {len(pdf_data)} bytes")
        
        # Initialize pyhanko validator
        validator = SignsleyValidator()
        
        # Verify PDF signatures
        result = await validator.verify_pdf_signatures(
            pdf_data=pdf_data,
            file_name=request.fileName
        )
        
        logger.info(
            f"PAdES verification completed for {request.fileName}: "
            f"valid={result.get('valid')}, intact={result.get('documentIntact')}, "
            f"signatures={result.get('signatureCount')}"
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PAdES verification failed for {request.fileName}: {e}")
        
        return create_error_response(
            error_message=f"Verification failed: {str(e)}",
            file_name=request.fileName,
            format_name="PAdES"
        )


@router.options("/verify-pades")
async def verify_pades_options():
    """Handle CORS preflight requests"""
    return {}


@router.get("/verify-pades/info")
async def pades_info():
    """
    Get information about PAdES verification capabilities
    """
    return {
        "format": "PAdES (PDF Advanced Electronic Signature)",
        "description": "Verifies PDF signatures with comprehensive cryptographic validation",
        "capabilities": [
            "Document integrity verification",
            "Certificate validation and chain verification", 
            "Revocation checking (OCSP/CRL)",
            "Multiple signature support",
            "AdES compliance validation",
            "Timestamp validation"
        ],
        "supported_standards": [
            "ISO 32000-2 (PDF 2.0)",
            "ETSI EN 319 142 (PAdES)",
            "ETSI EN 319 122 (CAdES)",
            "RFC 3161 (Timestamping)"
        ],
        "backend": "pyhanko 0.31",
        "max_file_size": "10MB",
        "supported_algorithms": [
            "RSA-SHA1", "RSA-SHA256", "RSA-SHA384", "RSA-SHA512",
            "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512"
        ]
    }