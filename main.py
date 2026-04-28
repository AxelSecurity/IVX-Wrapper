from fastapi import FastAPI, Query, Request, HTTPException
from fastapi.responses import JSONResponse
from utils.logger import logger
from services.openai_service import classify, classify_with_misp
import os

app = FastAPI(title="IVX Intelligence Wrapper")

ERROR_RESPONSE = {
    "data": {
        "result": {
            "verdict": "clean",
            "signature": "azure_error"
        }
    }
}

def format_response(classification, tag):
    signature = tag if tag.startswith("misp_") else f"azure_{tag}"
    return {
        "data": {
            "result": {
                "verdict": "malicious" if classification == "malicious" else "clean",
                "signature": signature
            }
        }
    }

@app.get("/analyze/url")
async def analyze_url(url: str = Query(..., description="The URL to analyze")):
    try:
        result = await classify("url", url)
        return format_response(result["classification"], result["tag"])
    except Exception:
        return JSONResponse(content=ERROR_RESPONSE)

@app.get("/analyze/hash")
async def analyze_hash(hash: str = Query(..., description="The Hash to analyze")):
    try:
        result = await classify("hash", hash)
        return format_response(result["classification"], result["tag"])
    except Exception:
        return JSONResponse(content=ERROR_RESPONSE)

@app.get("/analyze/misp")
async def analyze_misp(
    url: str = Query(None, description="The URL to analyze via MISP"),
    hash: str = Query(None, description="The Hash to analyze via MISP")
):
    if not url and not hash:
        raise HTTPException(status_code=400, detail="Either 'url' or 'hash' parameter must be provided")

    try:
        if url:
            result = await classify_with_misp("url", url)
        else:
            result = await classify_with_misp("hash", hash)
        return format_response(result["classification"], result["tag"])
    except Exception:
        return JSONResponse(content=ERROR_RESPONSE)

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "3030"))
    uvicorn.run(app, host="0.0.0.0", port=port)
