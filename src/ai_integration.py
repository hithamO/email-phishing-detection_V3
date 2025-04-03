# src/ai_integration.py

import json
import logging
import asyncio
from typing import Dict, Any, Optional

# External libraries - aiohttp is required
try:
    import aiohttp
except ImportError:
    aiohttp = None
    # Log error here as this module is unusable without aiohttp
    logging.getLogger(__name__).error("aiohttp library not found. AI integration module is non-functional.")

# Local imports
from config.config import CONFIG

logger = logging.getLogger(__name__)

# --- Expected JSON Output Structure from AI ---
# This structure guides the AI's response format.
# Ensure it matches what the AI model is trained/prompted to produce.
AI_JSON_OUTPUT_STRUCTURE = """{
  "phishing_score": "integer (0-10, where 0 is clean and 10 is definitively malicious phishing)",
  "verdict": "string ('CLEAN', 'SUSPICIOUS', 'MALICIOUS')",
  "confidence": "float (0.0-1.0, model's confidence in the verdict)",
  "explanation": "string (Detailed reasoning for the verdict, citing specific evidence such as suspicious headers, dangerous links, obfuscated content, urgent language, poor grammar, mismatched domains, failed authentication checks, high VT scores, malicious attachments, suspicious OCR text, brand impersonation, typosquatting, etc. Be concise but thorough.)",
  "suspicious_elements": [
    "string (List specific elements identified as suspicious, e.g., 'Mismatch From/Reply-To domains', 'Urgency in body text', 'Link domain X differs from mentioned brand Y', 'High VT malicious score (M:15) for attachment Z hash', 'SPF check failed for domain A', 'Link domain B suspected typosquatting of C', 'Password field found in HTML form', 'OCR text from image contains suspicious request')"
  ],
  "identified_brands": [
    "string (List of potential brand names identified or likely being impersonated, e.g., 'PayPal', 'Microsoft', 'Your Bank Name')"
  ],
  "recommendations": [
    "string (List recommendations that will guide the user into what to do with the email)"
  ]
}"""

def build_ai_prompt(analysis_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Constructs the detailed prompt dictionary to send to the AI model, incorporating
    all gathered analysis data including header, body, attachment, VT, auth, and OCR results.

    Args:
        analysis_data (Dict[str, Any]): The combined dictionary containing results from
                                       analyze_headers, analyze_body, analyze_attachments.
                                       Should have keys like "Headers", "Body", "Attachments".

    Returns:
        Optional[Dict[str, str]]: A dictionary containing the role ("user") and content (prompt string),
                                  or None if essential analysis data is missing.
    """
    # Basic check if core analysis parts exist
    if not analysis_data.get("Headers") or not analysis_data.get("Body"):
        logger.error("Cannot build AI prompt: Missing essential 'Headers' or 'Body' analysis data.")
        return None

    # Start building the prompt content string
    prompt_content = f"""You are an expert cybersecurity analyst specializing in meticulous email phishing detection. Your task is to analyze the following comprehensive email data report and provide a concise, accurate assessment.

**Instructions:**
1.  Carefully review ALL provided sections: Headers (including Authentication and IP analysis), Body (including Links, Brand Info, Typosquatting), Attachments (including Hash analysis and OCR text if present), and any listed suspicious indicators.
2.  Synthesize the findings to determine the likelihood of the email being a phishing attempt. Consider the interplay between different elements (e.g., failed SPF + suspicious link).
3.  Provide your analysis ONLY in the specified JSON format below. Do not include any introductory text, explanations outside the JSON structure, or markdown formatting like ```json. Just the raw JSON.
4.  Always keep in your mind that there are a lot of false-positives in the result of VT.
5.  In your analysis consider that even if a specific elements identified as suspicious the email could be clean.

**Required JSON Output Format:**
```json
{AI_JSON_OUTPUT_STRUCTURE}
```

--- BEGIN EMAIL ANALYSIS DATA ---

"""

    # --- Header Section ---
    headers = analysis_data.get("Headers", {})
    if headers.get("error"):
         prompt_content += "**Headers Analysis Note:** Analysis failed or was incomplete.\n"
    else:
        prompt_content += f"""**Headers:**
- Subject: {headers.get("Subject", "N/A")}
- From: {headers.get("From", "N/A")} (Domain: {headers.get("From_Domain", "N/A")})
- Reply-To: {headers.get("Reply-To", "N/A")}
"""
        auth = headers.get("Authentication", {})
        prompt_content += f"""- Authentication Status:
  - SPF: {auth.get("spf", {}).get("result", "N/A")} (Domain Checked: {auth.get("spf", {}).get("domain", "N/A")}, Source: {auth.get("spf", {}).get("source", "N/A")})
  - DKIM: {auth.get("dkim", {}).get("result", "N/A")} (Domain Signed: {auth.get("dkim", {}).get("domain", "N/A")}, Selector: {auth.get("dkim", {}).get("selector", "N/A")}, Source: {auth.get("dkim", {}).get("source", "N/A")})
  - DMARC: {auth.get("dmarc", {}).get("result", "N/A")} (Policy: {auth.get("dmarc", {}).get("policy", "N/A")}, Domain Checked: {auth.get("dmarc", {}).get("domain_to_check", "N/A")}, Source: {auth.get("dmarc", {}).get("source", "N/A")})
"""
        if auth.get("errors"):
            prompt_content += f"  - Authentication Parsing Errors: {', '.join(auth['errors'])}\n"

        ip_analysis = headers.get("IP_Analysis", {})
        if ip_analysis:
            prompt_content += "- Originating IP VirusTotal Analysis (Public IPs from Received headers):\n"
            for ip, res in ip_analysis.items():
                if res.get("error"):
                    prompt_content += f"  - {ip}: Error ({res.get('message', 'Unknown error')})\n"
                else:
                    attrs = res.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    cached = res.get("cached", False)
                    owner = attrs.get("as_owner", "N/A")
                    prompt_content += f"  - {ip}: VT M:{malicious} S:{suspicious} (Owner: {owner}) {'(Cached)' if cached else ''}\n"

        if headers.get("Suspicious_Headers"):
            prompt_content += "- Suspicious Header Notes:\n"
            for note in headers["Suspicious_Headers"]:
                prompt_content += f"    - {note}\n"
        if headers.get("Typosquatting_From"):
            typo = headers["Typosquatting_From"]
            prompt_content += f"- NOTE: From domain '{headers.get('From_Domain')}' potentially typosquats '{typo.get('similar_to')}' (Dist: {typo.get('distance')})\n"

    # --- Body Section ---
    body = analysis_data.get("Body", {})
    prompt_content += "\n**Body Analysis:**\n"
    if body.get("error"):
         prompt_content += "**Body Analysis Note:** Analysis failed or was incomplete.\n"
    else:
        if body.get("Text"):
            prompt_content += f"- Plain Text Snippet (first 500 chars):\n```\n{body['Text'][:500]}\n```\n"
        if body.get("HTML"):
            prompt_content += f"- HTML Structure Snippet (first 1000 chars - check for forms, obfuscation):\n```html\n{body['HTML'][:1000]}\n```\n"

        links = body.get("Links", [])
        url_analysis = body.get("URL_Analysis", {})
        typo_links = body.get("Typosquatting_Links", {})
        if links:
            prompt_content += f"- Links Found ({len(links)} Unique URLs):\n"
            links_to_show = links[:15] # Limit output for prompt length
            for url in links_to_show:
                res = url_analysis.get(url, {})
                typo_info = ""
                if url in typo_links:
                    typo = typo_links[url]
                    typo_info = f" [TYPO ALERT: ~'{typo.get('similar_to')}', Dist:{typo.get('distance')}]"

                if res.get("error"):
                     prompt_content += f"  - {url}: VT Error ({res.get('message', 'Unknown error')}){typo_info}\n"
                else:
                    attrs = res.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    cached = res.get("cached", False)
                    final_url = attrs.get("last_final_url", url) # Show resolved URL if available
                    final_url_str = f" -> {final_url}" if final_url != url else ""

                    prompt_content += f"  - {url}{final_url_str}: VT M:{malicious} S:{suspicious} {'(Cached)' if cached else ''}{typo_info}\n"

            if len(links) > len(links_to_show):
                prompt_content += f"    - ... (and {len(links) - len(links_to_show)} more links)\n"

        if body.get("Suspicious_Elements"):
            prompt_content += "- Suspicious Body Notes:\n"
            for note in body["Suspicious_Elements"]:
                prompt_content += f"    - {note}\n"

        brand_info_list = body.get("Brand_Info", [])
        if brand_info_list:
            prompt_content += "- Brand Impersonation Analysis:\n"
            for info in brand_info_list: # Usually just one entry currently
                prompt_content += f"    - Mentioned Brands: {', '.join(info.get('mentioned_brands', ['None']))}\n"
                prompt_content += f"    - Link Domain Match Status: {info.get('link_domains_match_status', 'N/A')}\n"
                if info.get('notes'):
                    prompt_content += "    - Brand Notes:\n"
                    for note in info['notes']:
                        prompt_content += f"      - {note}\n"

    # --- Attachments Section ---
    attachments = analysis_data.get("Attachments", {})
    prompt_content += "\n**Attachments Analysis:**\n"
    if attachments.get("error"):
        prompt_content += "**Attachment Analysis Note:** Analysis failed or was incomplete.\n"
    else:
        attachment_data = attachments.get("Data", {})
        hash_analysis = attachments.get("Hash_Analysis", {})
        if not attachment_data:
            prompt_content += "- No attachments found.\n"
        else:
            prompt_content += f"- Files Found ({len(attachment_data)}):\n"
            for name, data in attachment_data.items():
                if "error" in data:
                    prompt_content += f"  - {name}: Error processing attachment ({data['error']})\n"
                    continue

                size_kb = data.get('size', 0) // 1024
                ctype = data.get('content_type', 'unknown/unknown')
                sha256_hash = data.get("hashes", {}).get("sha256", "N/A")
                prompt_content += f"  - File: {name} (Size: {size_kb} KB, Type: {ctype}, SHA256: {sha256_hash[:12]}...)\n"

                # VT Hash Analysis Result for this file
                vt_res = hash_analysis.get(name, {})
                if vt_res.get("error"):
                     prompt_content += f"    - VT Hash Analysis: Error ({vt_res.get('message', 'Unknown error')})\n"
                else:
                    attrs = vt_res.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    cached = vt_res.get("cached", False)
                    # Meaningful names if available
                    meaningful_name = attrs.get("meaningful_name", "")
                    name_str = f" (Common Name: {meaningful_name})" if meaningful_name and meaningful_name != name else ""
                    prompt_content += f"    - VT Hash Analysis: M:{malicious} S:{suspicious}{name_str} {'(Cached)' if cached else ''}\n"

                # OCR Result for this file (if applicable)
                if "ocr_text" in data or "ocr_error" in data:
                    if data.get("ocr_error"):
                         prompt_content += f"    - OCR Analysis: Error ({data['ocr_error']})\n"
                    elif data.get("ocr_text"):
                         ocr_snippet = data["ocr_text"][:300] # Show snippet
                         prompt_content += f"    - OCR Analysis: Extracted Text (snippet):\n      ```\n      {ocr_snippet}\n      ```\n"
                    else:
                         prompt_content += f"    - OCR Analysis: No text extracted.\n"


            if attachments.get("Suspicious_Indicators"):
                prompt_content += "- Suspicious Attachment Notes:\n"
                for note in attachments["Suspicious_Indicators"]:
                    prompt_content += f"    - {note}\n"

    prompt_content += "\n--- END OF EMAIL ANALYSIS DATA ---\n\nBased on ALL the evidence provided above, generate ONLY the JSON output with your final assessment."

    # Return the structure expected by the API
    return {
        "role": "user",
        "content": prompt_content
    }


async def analyze_with_ai(analysis_data: Dict[str, Any], session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Sends the comprehensive analysis data to the configured AI model (e.g., via OpenRouter)
    asynchronously, requests a JSON response, and parses it.

    Args:
        analysis_data (Dict[str, Any]): The combined analysis results dictionary.
        session (aiohttp.ClientSession): The active aiohttp session.

    Returns:
        Dict[str, Any]: The parsed JSON response from the AI, potentially including an
                        'error' key if the AI call or parsing failed.
    """
    if aiohttp is None:
        return {"error": "library_missing", "message": "aiohttp library is required for AI analysis but not installed."}

    # Get AI configuration details
    api_key = CONFIG.get("AI_API_KEY")
    api_url = CONFIG.get("AI_API_URL")
    model = CONFIG.get("AI_MODEL")
    ai_timeout_config = CONFIG.get("AI_TIMEOUT", (10, 60))
    max_tokens = CONFIG.get("AI_MAX_TOKENS", 2000)
    temperature = CONFIG.get("AI_TEMPERATURE", 0.2)

    # Validate essential configuration
    if not api_key:
        logger.error("AI analysis skipped: AI_API_KEY is not configured.")
        return {"error": "config_missing", "message": "AI API key not configured."}
    if not api_url or not model:
        logger.error(f"AI analysis skipped: AI_API_URL ('{api_url}') or AI_MODEL ('{model}') is not configured.")
        return {"error": "config_missing", "message": "AI URL or Model not configured."}

    # Build the prompt
    prompt_message = build_ai_prompt(analysis_data)
    if prompt_message is None:
        # Error logged within build_ai_prompt
        return {"error": "prompt_error", "message": "Failed to build AI prompt due to missing analysis data."}

    # Prepare request headers and payload
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": CONFIG.get("USER_AGENT", "EmailPhishingDetector/Unknown"),

        "HTTP-Referer": "http://localhost", 
        "X-Title": "Email Phishing Detector", 
    }
    payload = {
        "model": model,
        "messages": [prompt_message],
        "temperature": temperature,
        "max_tokens": max_tokens,
        # Request JSON output format (supported by many models/APIs like OpenAI, OpenRouter)
        "response_format": {"type": "json_object"}
    }
    timeout = aiohttp.ClientTimeout(connect=ai_timeout_config[0], total=sum(ai_timeout_config))

    logger.info(f"Sending request to AI model '{model}' at {api_url.split('/')[2]}...") # Log domain, not full URL

    try:
        async with session.post(api_url, headers=headers, json=payload, timeout=timeout) as response:
            # Log status before potential raise_for_status
            logger.debug(f"AI API response status: {response.status}")

            # Check for errors first
            response.raise_for_status() # Raises exception for 4xx/5xx

            # Parse the JSON response from the AI
            result_json = await response.json()

            # --- Process AI Response ---
            # Check structure based on typical OpenAI/OpenRouter format
            if not result_json or not result_json.get("choices"):
                logger.error(f"Invalid AI API response format: Missing 'choices'. Response: {result_json}")
                raise ValueError("Invalid API response format - missing 'choices'.")

            message = result_json["choices"][0].get("message", {})
            content_str = message.get("content")

            if not content_str:
                logger.error(f"Invalid AI API response format: Missing 'content' in message. Response: {result_json}")
                raise ValueError("Invalid API response format - missing 'content'.")

            # Attempt to parse the JSON string within the 'content' field
            try:
                # Clean potential markdown ```json ... ``` wrappers
                if content_str.strip().startswith("```json"):
                    content_str = content_str.strip()[7:-3].strip()
                elif content_str.strip().startswith("```"):
                     content_str = content_str.strip()[3:-3].strip()

                # Parse the cleaned string as JSON
                ai_response_data = json.loads(content_str)

                # Validate required fields in the parsed JSON
                required_fields = list(json.loads(AI_JSON_OUTPUT_STRUCTURE).keys()) # Get keys from our defined structure
                missing_fields = [field for field in required_fields if field not in ai_response_data]
                if missing_fields:
                    logger.error(f"AI JSON response missing required fields: {missing_fields}. Got keys: {list(ai_response_data.keys())}")
                    # Return the partial data but add an error
                    ai_response_data["error"] = "missing_fields"
                    ai_response_data["message"] = f"AI response JSON missing required fields: {', '.join(missing_fields)}"
                    return ai_response_data

                logger.info(f"AI analysis successful. Verdict: {ai_response_data.get('verdict', 'N/A')}, Score: {ai_response_data.get('phishing_score', 'N/A')}")
                return ai_response_data # Return the successfully parsed and validated JSON data

            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON object from AI response content: {e}\nRaw content received:\n{content_str}")
                # Return an error dict, include raw content for debugging if not too large
                error_message = f"Failed to parse AI JSON response: {e}. Raw content: {content_str[:500]}..."
                raise ValueError(error_message) from e
            except Exception as e: # Catch other errors during content processing
                logger.error(f"Error processing AI response content: {e}\nContent:\n{content_str}")
                raise ValueError(f"Error processing AI response content: {e}") from e

    # --- Handle Request Errors ---
    except aiohttp.ClientResponseError as e:
        # Log specific HTTP errors
        logger.error(f"AI analysis HTTP error: {e.status} {e.message} for URL {api_url}. Response: {await response.text() if response else 'N/A'}")
        return {"error": f"http_{e.status}", "message": f"AI API request failed: {e.status} {e.message}"}
    except asyncio.TimeoutError:
        logger.error(f"AI analysis request timed out to {api_url} after {timeout.total} seconds.")
        return {"error": "timeout", "message": f"AI API request timed out ({timeout.total}s)."}
    except aiohttp.ClientConnectionError as e:
        logger.error(f"AI analysis connection error: {e} for URL {api_url}")
        return {"error": "connection_error", "message": f"AI API connection error: {e}"}
    except aiohttp.ClientError as e: # Catch other aiohttp client errors
        logger.error(f"AI analysis client error: {e} for URL {api_url}")
        return {"error": "client_error", "message": f"AI API client error: {e}"}
    except ValueError as e: # Catch JSON parsing/validation errors raised above
        return {"error": "parsing_error", "message": str(e)}
    except Exception as e: # Catch unexpected errors
        logger.exception(f"Unexpected error during AI analysis: {e}")
        return {"error": "unknown", "message": f"An unexpected error occurred during AI analysis: {e}"}
