import unittest
from unittest.mock import AsyncMock, patch
import json
import asyncio
from services.openai_service import classify

class TestOpenAIService(unittest.TestCase):

    @patch("httpx.AsyncClient.post")
    def test_classify_url_success(self, mock_post):
        # Setup mock response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"classification":"malicious","tag":"phishing"}'}}]
        }
        mock_post.return_value = mock_response

        # Run async function
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(classify("url", "http://malicious.com"))

        self.assertEqual(result["classification"], "malicious")
        self.assertEqual(result["tag"], "phishing")

    @patch("httpx.AsyncClient.post")
    def test_classify_hash_markdown(self, mock_post):
        # Setup mock response with markdown
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '```json\n{"classification":"clean","tag":"office"}\n```'}}]
        }
        mock_post.return_value = mock_response

        # Run async function
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(classify("hash", "3f786850e387550fdab836ed7e6dc881de23001b"))

        self.assertEqual(result["classification"], "clean")
        self.assertEqual(result["tag"], "office")

    @patch("httpx.AsyncClient.post")
    def test_classify_error(self, mock_post):
        # Setup mock to raise error
        mock_post.side_effect = Exception("API Error")

        # Run async function
        loop = asyncio.get_event_loop()
        with self.assertRaises(Exception):
            loop.run_until_complete(classify("url", "http://example.com"))

if __name__ == "__main__":
    unittest.main()
    
