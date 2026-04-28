import os
import json
import httpx
import time
import re
from dotenv import load_dotenv
from utils.logger import logger
from services.rapid7_service import lookup_hash
from services.misp_service import lookup_misp

load_dotenv()

def normalize_tag(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'\s+', '_', text.strip())
    text = re.sub(r'-+', '_', text)
    text = re.sub(r'_+', '_', text)
    return text[:50]

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip().rstrip("/")
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY", "").strip()
AZURE_OPENAI_DEPLOYMENT_ID = os.getenv("AZURE_OPENAI_DEPLOYMENT_ID", "").strip()
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15").strip()
AZURE_TIMEOUT_MS = int(os.getenv("AZURE_TIMEOUT_MS", "3000"))

async def classify(classify_type: str, value: str):
    if not AZURE_OPENAI_ENDPOINT:
        logger.error("AZURE_OPENAI_ENDPOINT is not configured")
        raise Exception("Configuration Error")

    start_time = time.time()
    url = f"{AZURE_OPENAI_ENDPOINT}/openai/deployments/{AZURE_OPENAI_DEPLOYMENT_ID}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"

    system_prompt = "You are a cybersecurity detection engine."
    context_str = ""
    
    if classify_type == 'hash':
        # Fetch context from Rapid7
        rapid7_data = await lookup_hash(value)
        if rapid7_data == "UNKNOWN":
            logger.info("Rapid7 returned 204: Skipping OpenAI and returning clean", extra={"extra_info": {
                "type": "hash",
                "value": value
            }})
            return {
                "classification": "clean",
                "tag": "rapid7_unknown"
            }
        
        if rapid7_data:
            context_str = f"\n\nContext from Rapid7 Threat Intelligence:\n{json.dumps(rapid7_data, indent=2)}"
            prompt = f"Assess if the following file hash is likely malicious or clean based on the provided context.\n\nHash: {value}{context_str}\n\nRespond ONLY in JSON:\n{{\"classification\":\"malicious|clean\",\"tag\":\"short_tag\"}}"
        else:
            prompt = f"Assess if the following file hash is likely malicious or clean.\n\nHash: {value}\n\nRespond ONLY in JSON:\n{{\"classification\":\"malicious|clean\",\"tag\":\"short_tag\"}}"
    else:
        prompt = f"Classify the following URL as malicious or clean.\n\nURL: {value}\n\nRespond ONLY in JSON:\n{{\"classification\":\"malicious|clean\",\"tag\":\"short_tag\"}}"

    headers = {
        "api-key": AZURE_OPENAI_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0,
        "max_tokens": 50
    }

    async with httpx.AsyncClient(timeout=AZURE_TIMEOUT_MS / 1000.0) as client:
        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            
            execution_time_ms = int((time.time() - start_time) * 1000)
            data = response.json()
            content = data['choices'][0]['message']['content'].strip()
            
            logger.info("Azure OpenAI response received", extra={"extra_info": {
                "type": classify_type,
                "value": value,
                "executionTime": execution_time_ms,
                "rawResponse": content,
                "has_context": bool(context_str)
            }})

            # Strip markdown code blocks if present
            json_str = content.replace("```json", "").replace("```", "").strip()
            result = json.loads(json_str)

            return {
                "classification": result.get("classification", "clean"),
                "tag": result.get("tag", "unknown")
            }
        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.error("Azure OpenAI classification failed", extra={"extra_info": {
                "type": classify_type,
                "value": value,
                "executionTime": execution_time_ms,
                "error": str(e)
            }})
            raise e


async def classify_with_misp(classify_type: str, value: str):
    """
    Classify via MISP context + Azure OpenAI.
    If value not found in MISP, returns clean immediately.
    Otherwise, fetches MISP data and passes it as context to OpenAI.
    """
    if not AZURE_OPENAI_ENDPOINT:
        logger.error("AZURE_OPENAI_ENDPOINT is not configured")
        raise Exception("Configuration Error")

    # Fetch context from MISP
    misp_data = await lookup_misp(value)
    if not misp_data:
        logger.info("MISP lookup: value not found, returning clean", extra={"extra_info": {
            "type": classify_type,
            "value": value
        }})
        return {
            "classification": "clean",
            "tag": "misp_not_found"
        }

    # Extract info field from MISP response for signature
    misp_info = None
    if isinstance(misp_data, dict) and "response" in misp_data:
        response = misp_data["response"]
        logger.info("MISP response structure for extraction", extra={"extra_info": {
            "value": value,
            "classify_type": classify_type,
            "response_keys": list(response.keys()) if isinstance(response, dict) else "not_dict",
            "response_type": str(type(response))
        }})

        # response.Attribute is an array
        if isinstance(response, dict) and "Attribute" in response:
            attributes = response["Attribute"]
            if isinstance(attributes, list) and len(attributes) > 0:
                # Get info from first attribute's Event
                first_attr = attributes[0]
                if isinstance(first_attr, dict) and "Event" in first_attr:
                    misp_info = first_attr["Event"].get("info")
                    logger.info("MISP info field found", extra={"extra_info": {
                        "value": value,
                        "info": misp_info
                    }})

    misp_tag = f"misp_{normalize_tag(misp_info)}" if misp_info else "misp_unknown"

    start_time = time.time()
    url = f"{AZURE_OPENAI_ENDPOINT}/openai/deployments/{AZURE_OPENAI_DEPLOYMENT_ID}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"

    system_prompt = "You are a cybersecurity detection engine."
    context_str = f"\n\nContext from MISP Threat Intelligence:\n{json.dumps(misp_data, indent=2)}"
    prompt = f"Assess if the following {'URL' if classify_type == 'url' else 'file hash'} is likely malicious or clean based on the provided threat intelligence context.\n\n{'URL' if classify_type == 'url' else 'Hash'}: {value}{context_str}\n\nRespond ONLY in JSON:\n{{\"classification\":\"malicious|clean\",\"tag\":\"short_tag\"}}"

    headers = {
        "api-key": AZURE_OPENAI_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0,
        "max_tokens": 50
    }

    async with httpx.AsyncClient(timeout=AZURE_TIMEOUT_MS / 1000.0) as client:
        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()

            execution_time_ms = int((time.time() - start_time) * 1000)
            data = response.json()
            content = data['choices'][0]['message']['content'].strip()

            logger.info("Azure OpenAI response received (MISP)", extra={"extra_info": {
                "type": classify_type,
                "value": value,
                "executionTime": execution_time_ms,
                "rawResponse": content,
                "misp_info": misp_info,
                "misp_tag": misp_tag
            }})

            json_str = content.replace("```json", "").replace("```", "").strip()
            result = json.loads(json_str)

            return {
                "classification": result.get("classification", "clean"),
                "tag": misp_tag
            }
        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.error("Azure OpenAI classification failed (MISP)", extra={"extra_info": {
                "type": classify_type,
                "value": value,
                "executionTime": execution_time_ms,
                "error": str(e)
            }})
            raise e
