import os
import httpx
import re
from dotenv import load_dotenv
from utils.logger import logger

load_dotenv()

MISP_BASE_URL = os.getenv("MISP_BASE_URL", "").strip().rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "").strip()
MISP_TIMEOUT_MS = int(os.getenv("MISP_TIMEOUT_MS", "5000"))

def detect_indicator_type(value: str) -> str:
    """
    Detect the type of IOC (URL, SHA256, MD5, SHA1, etc.)
    """
    value = value.strip()

    # URL detection
    if value.startswith(("http://", "https://")) or re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value):
        return "url"

    # SHA256: 64 hex characters
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return "sha256"

    # SHA1: 40 hex characters
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return "sha1"

    # MD5: 32 hex characters
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return "md5"

    return "unknown"

async def lookup_misp(value: str):
    """
    Look up a value (URL or hash) in MISP Threat Intelligence.
    Returns MISP data if found, or None.
    """
    if not MISP_BASE_URL or not MISP_API_KEY:
        logger.warning("MISP configuration missing (Base URL/API Key), skipping lookup")
        return None

    url = f"{MISP_BASE_URL}/attributes/restSearch"

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    indicator_type = detect_indicator_type(value)
    payload = {
        "value": value,
        "type": indicator_type,
        "returnFormat": "json",
        "limit": 5
    }

    logger.info("MISP lookup initiated", extra={"extra_info": {
        "value": value,
        "detected_type": indicator_type
    }})

    async with httpx.AsyncClient(timeout=MISP_TIMEOUT_MS / 1000.0) as client:
        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()

            data = response.json()

            logger.info("MISP response structure", extra={"extra_info": {
                "value": value,
                "full_response": data
            }})

            if data and "response" in data and data["response"]:
                logger.info("MISP lookup successful", extra={"extra_info": {
                    "value": value,
                    "status": "found",
                    "count": len(data.get("response", []))
                }})
                return data
            else:
                logger.info("MISP lookup: value not found", extra={"extra_info": {
                    "value": value,
                    "status": "not_found"
                }})
                return None

        except httpx.HTTPStatusError as e:
            logger.error(f"MISP lookup HTTP error {e.response.status_code}", extra={"extra_info": {
                "value": value,
                "status": str(e.response.status_code),
                "error": e.response.text[:200]
            }})
            return None
        except Exception as e:
            logger.error(f"MISP lookup error: {str(e)}", extra={"extra_info": {
                "value": value,
                "error_type": type(e).__name__
            }})
            return None
