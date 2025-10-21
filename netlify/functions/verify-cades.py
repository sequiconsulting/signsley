#!/usr/bin/env python3
"""
Netlify Python Function: CAdES Verification
Using pyhanko 0.31 for CMS signature verification
"""

import json
import sys
import os
from pathlib import Path

# Add the api directory to Python path
api_dir = Path(__file__).parent.parent.parent / "api"
sys.path.insert(0, str(api_dir))

# Import the verification logic
try:
    from routers.verify_cades import CAdESValidator
    from utils.response_utils import create_error_response
    from utils.logging_config import setup_logging
except ImportError as e:
    # Fallback error response if imports fail
    def create_fallback_error(message):
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "POST, OPTIONS"
            },
            "body": json.dumps({
                "valid": False,
                "error": f"Import failed: {str(e)}",
                "format": "CAdES (CMS Advanced Electronic Signature)",
                "fileName": "unknown",
                "structureValid": False,
                "documentIntact": None,
                "integrityReason": f"Service initialization failed: {str(e)}"
            })
        }

import base64
import asyncio
from datetime import datetime, timezone

# Initialize logging
try:
    setup_logging("INFO")
except:
    pass

def handler(event, context):
    """
    Netlify Function handler for CAdES verification
    
    Args:
        event: Netlify event object containing HTTP request data
        context: Netlify context object
        
    Returns:
        Netlify function response object
    """
    
    # CORS headers
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS"
    }
    
    # Handle OPTIONS (CORS preflight)
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": ""
        }
    
    # Only allow POST
    if event.get("httpMethod") != "POST":
        return {
            "statusCode": 405,
            "headers": headers,
            "body": json.dumps({
                "error": "Method not allowed",
                "valid": False
            })
        }
    
    try:
        # Parse request body
        body = json.loads(event.get("body", "{}"))
        file_data = body.get("fileData")
        file_name = body.get("fileName", "unknown.p7m")
        
        if not file_data:
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "error": "No file data provided",
                    "valid": False,
                    "format": "CAdES (CMS Advanced Electronic Signature)",
                    "fileName": file_name
                })
            }
        
        # Decode base64 data
        try:
            cades_data = base64.b64decode(file_data)
        except Exception as e:
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({
                    "error": "Invalid base64 file data",
                    "valid": False,
                    "format": "CAdES (CMS Advanced Electronic Signature)",
                    "fileName": file_name
                })
            }
        
        # Initialize validator and verify
        validator = CAdESValidator()
        
        # Run async verification
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                validator.verify_cades_signature(cades_data, file_name)
            )
        finally:
            loop.close()
        
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps(result)
        }
        
    except Exception as e:
        error_msg = f"Verification failed: {str(e)}"
        
        try:
            error_response = create_error_response(
                error_message=error_msg,
                file_name=body.get("fileName", "unknown.p7m") if 'body' in locals() else "unknown.p7m",
                format_name="CAdES (CMS Advanced Electronic Signature)"
            )
        except:
            error_response = {
                "valid": False,
                "error": error_msg,
                "format": "CAdES (CMS Advanced Electronic Signature)",
                "fileName": "unknown.p7m",
                "structureValid": False,
                "documentIntact": None,
                "integrityReason": error_msg,
                "verificationTimestamp": datetime.now(timezone.utc).isoformat(),
                "processingTime": 0
            }
        
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps(error_response)
        }

# For testing locally
if __name__ == "__main__":
    # Test event
    test_event = {
        "httpMethod": "POST",
        "body": json.dumps({
            "fileData": "MIIBAgYJKoZI",  # Sample PKCS#7 header in base64
            "fileName": "test.p7m"
        })
    }
    
    result = handler(test_event, {})
    print(json.dumps(result, indent=2))