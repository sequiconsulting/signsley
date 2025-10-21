#!/usr/bin/env python3
"""
Netlify Python Function: Health Check
Simple health check endpoint for the Signsley Python backend
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

# Add the api directory to Python path
api_dir = Path(__file__).parent.parent.parent / "api"
sys.path.insert(0, str(api_dir))

# Test imports to verify dependencies
try:
    import pyhanko
    pyhanko_version = pyhanko.__version__
except ImportError:
    pyhanko_version = "Not available"

try:
    import cryptography
    crypto_version = cryptography.__version__
except ImportError:
    crypto_version = "Not available"

try:
    import lxml
    lxml_version = lxml.__version__
except ImportError:
    lxml_version = "Not available"

def handler(event, context):
    """
    Netlify Function handler for health check
    
    Args:
        event: Netlify event object containing HTTP request data
        context: Netlify context object
        
    Returns:
        Netlify function response object with health status
    """
    
    # CORS headers
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, OPTIONS"
    }
    
    # Handle OPTIONS (CORS preflight)
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": ""
        }
    
    try:
        # Health check response
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "Signsley Python Backend",
            "version": "4.1.0",
            "backend": "pyhanko 0.31 + Python",
            "platform": "Netlify Functions",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "dependencies": {
                "pyhanko": pyhanko_version,
                "cryptography": crypto_version,
                "lxml": lxml_version
            },
            "capabilities": [
                "PAdES signature verification",
                "CAdES signature verification", 
                "XAdES signature verification",
                "Certificate chain validation",
                "Revocation checking (OCSP/CRL)",
                "Multiple signature support"
            ],
            "endpoints": {
                "pades": "/api/verify-pades",
                "cades": "/api/verify-cades",
                "xades": "/api/verify-xades",
                "health": "/api/health"
            }
        }
        
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps(health_data, indent=2)
        }
        
    except Exception as e:
        error_response = {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps(error_response)
        }

# For testing locally
if __name__ == "__main__":
    test_event = {"httpMethod": "GET"}
    result = handler(test_event, {})
    print(json.dumps(json.loads(result["body"]), indent=2))