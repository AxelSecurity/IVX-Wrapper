# IVX Intelligence Wrapper (Azure OpenAI - Python)

REST service to integrate **Trellix IVX Cloud** with **Azure OpenAI** for URL and file hash classification.

## Configuration

1. Copy `.env.example` to `.env`.
2. Fill in your Azure OpenAI credentials:
   - `AZURE_OPENAI_ENDPOINT`: Your Azure OpenAI resource URL (e.g., `https://my-resource.openai.azure.com/`).
   - `AZURE_OPENAI_KEY`: Your API key.
   - `AZURE_OPENAI_DEPLOYMENT_ID`: The deployment name of your GPT model.
   - `AZURE_OPENAI_API_VERSION`: API version (default: `2023-05-15`).

## Installation

```bash
pip install -r requirements.txt
```

## Running

### Local
```bash
python main.py
# OR
uvicorn main:app --port 3030
```

### Docker
```bash
docker build -t ivx-wrapper-py .
docker run -p 3030:3030 --env-file .env ivx-wrapper-py
```

## Endpoints

### URL Analysis
- **Endpoint**: `/analyze/url?url=<URL>`
- **Method**: GET
- **Response**: IVX-compliant JSON.

### Hash Analysis
- **Endpoint**: `/analyze/hash?hash=<HASH>`
- **Method**: GET
- **Response**: IVX-compliant JSON (supports SHA256).

## IVX Configuration

### Engine URL
- **Endpoint**: `/analyze/url?url={{url}}`

### Engine HASH
- **Endpoint**: `/analyze/hash?hash={{sha256}}`

### Parsing Rules
- **Verdict Key**: `data.result.verdict`
- **Verdict Value**: `malicious`
- **Signature Key**: `data.result.signature`
