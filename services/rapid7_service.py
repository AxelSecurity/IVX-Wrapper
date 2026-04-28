import os
import httpx
from dotenv import load_dotenv
from utils.logger import logger

load_dotenv()

RAPID7_USERNAME = os.getenv("RAPID7_USERNAME", "").strip()
RAPID7_PASSWORD = os.getenv("RAPID7_PASSWORD", "").strip()
RAPID7_BASE_URL = os.getenv("RAPID7_BASE_URL", "https://api.ti.insight.rapid7.com/public/v3").strip().rstrip("/")

async def lookup_hash(hash_value: str):
    """
    Look up a hash in Rapid7 Threat Intelligence API using Basic Auth.
    """
    if not RAPID7_USERNAME or not RAPID7_PASSWORD:
        logger.warning("Rapid7 configuration missing (Username/Password), skipping lookup")
        return None

    # Endpoint: https://api.ti.insight.rapid7.com/public/v3/iocs/ioc-by-value?iocValue=
    url = f"{RAPID7_BASE_URL}/iocs/ioc-by-value"
    params = {"iocValue": hash_value}
    
    # Basic Auth
    auth = (RAPID7_USERNAME, RAPID7_PASSWORD)

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url, params=params, auth=auth)
            if response.status_code == 200:
                data = response.json()
                logger.info("Rapid7 lookup successful", extra={"extra_info": {
                    "hash": hash_value,
                    "status": "found"
                }})
                return data
            elif response.status_code == 204:
                logger.info("Rapid7 lookup: hash not found (204)", extra={"extra_info": {
                    "hash": hash_value,
                    "status": "not_known"
                }})
                return "UNKNOWN"
            elif response.status_code == 404:
                logger.info("Rapid7 lookup: hash not found", extra={"extra_info": {
                    "hash": hash_value,
                    "status": "not_found"
                }})
                return None
            else:
                logger.error(f"Rapid7 lookup failed with status {response.status_code}", extra={"extra_info": {
                    "hash": hash_value,
                    "error": response.text
                }})
                return None
        except Exception as e:
            logger.error(f"Rapid7 lookup error: {str(e)}", extra={"extra_info": {
                "hash": hash_value
            }})
            return None
