
import os
import requests
from dotenv import load_dotenv

load_dotenv()

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

def check_urlhaus(url):
    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not api_key:
        return {
            "source": "URLhaus",
            "status": "API Key Missing",
            "is_malicious": False,
            "message": "URLhaus API key is not configured."
        }

    headers = {
        "Auth-Key": api_key
    }

    try:
        response = requests.post(
            URLHAUS_API_URL,
            headers=headers,
            data={"url": url},
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "ok":
            return {
                "source": "URLhaus",
                "status": "Threat Found",
                "is_malicious": True,
                "threat": data.get("threat", "Unknown"),
                "url_status": data.get("url_status"),
                "message": "URL found in URLhaus database."
            }

        if data.get("query_status") == "no_results":
            return {
                "source": "URLhaus",
                "status": "No Match",
                "is_malicious": False,
                "message": "No matching URL found in URLhaus."
            }

        return {
            "source": "URLhaus",
            "status": "Unknown Response",
            "is_malicious": False,
            "message": data.get("query_status", "Unexpected API response.")
        }

    except requests.RequestException as error:
        return {
            "source": "URLhaus",
            "status": "API Error",
            "is_malicious": False,
            "message": str(error)
        }
