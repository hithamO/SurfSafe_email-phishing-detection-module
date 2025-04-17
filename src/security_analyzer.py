# src/security_analyzer.py

import re
import hashlib
import asyncio
import logging
import time 
from email.message import EmailMessage
from email.header import decode_header
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, quote 
import ipaddress 
import io 
import base64 
from config.config import CONFIG
import os 
import json

# External libraries
try:
    import aiohttp
except ImportError:
    aiohttp = None
    logging.getLogger(__name__).warning("aiohttp library not found. Asynchronous HTTP requests (VT) will fail.")

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    levenshtein_distance = None
    logging.getLogger(__name__).warning("python-Levenshtein not found. Typosquatting checks will be less effective.")

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None
    logging.getLogger(__name__).warning("dnspython library not found. DMARC checks requiring DNS will be skipped.")


# --- OCR Dependencies ---
try:
    from PIL import Image, UnidentifiedImageError
except ImportError:
    Image = None 
    UnidentifiedImageError = None 
    logging.getLogger(__name__).warning("Pillow library not found. OCR for image attachments will be disabled.")

try:
    import pytesseract
except ImportError:
    pytesseract = None 
    logging.getLogger(__name__).warning("pytesseract library not found. OCR processing will be disabled.")


# Local imports
from config.config import CONFIG 
from src.database_manager import DatabaseManager

logger = logging.getLogger(__name__)

# --- Constants ---
URL_REGEX = r'(?:(?:https?|ftp|mailto|tel):|www\.)[^\s<>"\']+'
# Regex for extracting IPv4 addresses
IPV4_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
SUSPICIOUS_TLDS = {
    '.zip', '.mov', '.xyz', '.info', '.biz', '.top', '.live', '.icu', '.pw', '.tk', '.click', '.link', '.gdn', '.work'
    }

KNOWN_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "netflix.com", "spotify.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "docusign.com",
    "dropbox.com", "adobe.com", "fedex.com", "ups.com", "dhl.com",
}

OCR_IMAGE_CONTENT_TYPES = {'image/jpeg', 'image/png', 'image/tiff', 'image/bmp', 'image/gif'}


# --- Helper Functions ---

def generate_hashes(data: bytes) -> Dict[str, str]:
    """
    Generate MD5, SHA1, and SHA256 hashes for the given byte data.

    Args:
        data (bytes): The input data (e.g., file content).

    Returns:
        Dict[str, str]: A dictionary containing 'md5', 'sha1', and 'sha256' hex digests.
                        Returns empty strings if input data is None or empty.
    """
    if not data:
        return {"md5": "", "sha1": "", "sha256": ""}
    try:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }
    except Exception as e:
         logger.error(f"Error generating hashes: {e}")
         return {"md5": "error", "sha1": "error", "sha256": "error"}


def decode_email_header(header_value: Optional[Any]) -> str:
    """
    Safely decodes email headers (Subject, From, To etc.) potentially using RFC 2047 encoding.

    Handles bytes, strings, and potential decoding errors gracefully.

    Args:
        header_value (Optional[Any]): The raw header value obtained from email.message.

    Returns:
        str: The decoded header value as a UTF-8 string, or an empty string if input is None or decoding fails badly.
    """
    if header_value is None:
        return ""

    decoded_string = ""
    try:
        decoded_parts = decode_header(str(header_value))
        for part_bytes, charset in decoded_parts:
            if isinstance(part_bytes, bytes):
                try:
                    decoded_string += part_bytes.decode(charset if charset else 'utf-8', errors='replace')
                except LookupError: 
                     logger.warning(f"Unknown encoding '{charset}' in header, falling back to utf-8.")
                     decoded_string += part_bytes.decode('utf-8', errors='replace')
                except Exception as e:
                     logger.warning(f"Error decoding header part with charset {charset}: {e}")
                     decoded_string += f"[decoding error: {part_bytes!r}]"
            elif isinstance(part_bytes, str):
                decoded_string += part_bytes
            else:
                 logger.warning(f"Unexpected type in decoded header part: {type(part_bytes)}")
                 decoded_string += str(part_bytes) 

        return decoded_string.strip().replace('\r', '').replace('\n', ' ') 
    except Exception as e:
        logger.warning(f"Failed to decode header '{str(header_value)[:50]}...': {e}")
        return str(header_value).strip().replace('\r', '').replace('\n', ' ')


def extract_domain(url_or_email: str) -> Optional[str]:
    """
    Extracts the registered domain name (e.g., 'example.com') from a URL or email address.
    Handles basic www stripping and focuses on the core domain.

    Args:
        url_or_email (str): The input URL or email string.

    Returns:
        Optional[str]: The extracted domain name in lowercase, or None if invalid or not extractable.
    """
    if not isinstance(url_or_email, str) or not url_or_email:
        return None

    domain = None
    try:
        url_or_email = url_or_email.strip()
        if '@' in url_or_email: 
            parts = url_or_email.split('@')
            if len(parts) == 2 and parts[1]: 
                domain = parts[1]
        else: 
            if not re.match(r'^[a-zA-Z]+://', url_or_email):
                prepended_url = 'http://' + url_or_email
            else:
                 prepended_url = url_or_email

            parsed = urlparse(prepended_url)
            domain = parsed.netloc
            if domain and ':' in domain:
                domain = domain.split(':')[0]

        if not domain:
            return None

        domain = domain.lower().strip('.')
        if domain.startswith('www.'):
            domain = domain[4:]

        if '.' in domain and not re.search(r'[^\w.\-]', domain):
             if domain.startswith('.'): return None
             return domain
        else:
             logger.debug(f"Extracted value '{domain}' failed final domain validation.")
             return None

    except Exception as e:
        logger.debug(f"Exception during domain extraction from '{url_or_email}': {e}")
        return None


def is_suspicious_tld(domain: Optional[str]) -> bool:
    """Checks if a domain uses a TLD from a predefined list of suspicious TLDs."""
    if not domain:
        return False
    try:
        
        parts = domain.split('.')
        if len(parts) > 1:
             tld = '.' + parts[-1].lower()
             return tld in SUSPICIOUS_TLDS
    except Exception as e:
        logger.warning(f"Error checking TLD for domain '{domain}': {e}")
    return False


async def perform_ocr(image_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Performs OCR on image bytes using Tesseract via pytesseract.

    Args:
        image_bytes (bytes): The byte content of the image file.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing:
            - Extracted text (str) if successful, None otherwise.
            - Error message (str) if failed, None otherwise.
    """
    if not CONFIG.get("OCR_ENABLED") or Image is None or pytesseract is None:
        return None, "OCR disabled or dependencies missing (Pillow/pytesseract)"

    try:
        img = Image.open(io.BytesIO(image_bytes))
        ocr_languages = CONFIG.get("OCR_LANGUAGES", ['eng'])
        extracted_text = pytesseract.image_to_string(img, lang='+'.join(ocr_languages))
        img.close() 
        logger.debug(f"OCR successful, extracted {len(extracted_text)} characters.")
        return extracted_text.strip(), None 
    except UnidentifiedImageError:
        logger.warning("OCR failed: Cannot identify image file format.")
        return None, "Cannot identify image file format"
    except pytesseract.TesseractNotFoundError:
        logger.error("OCR failed: Tesseract executable not found or not in PATH. Configure TESSERACT_CMD in config.py if needed.")
        return None, "Tesseract not found or configured"
    except Exception as e:
        logger.exception(f"An unexpected error occurred during OCR: {e}")
        return None, f"Unexpected OCR error: {e}"


# --- VirusTotal Async Client ---

class VirusTotalClient:
    """
    Asynchronous client for interacting with the VirusTotal API v3.

    Handles API requests, rate limiting (basic delay), and caching via DatabaseManager.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str], db_manager: DatabaseManager):
        """
        Initializes the VirusTotalClient.

        Args:
            api_key (Optional[str]): VirusTotal API key. Can be None if VT is disabled.
            db_manager (DatabaseManager): The database manager instance for caching.
        """
        if aiohttp is None:
            raise ImportError("aiohttp library is required for VirusTotalClient but is not installed.")

        self.api_key = api_key
        self.db_manager = db_manager
        self.headers = {}
        self.timeout = None
        self.request_delay = 0.0 

        if self.api_key:
            self.headers = {
                'x-apikey': self.api_key,
                'User-Agent': CONFIG.get("USER_AGENT", "EmailPhishingDetector/Unknown"),
                'Accept': 'application/json',
            }
            timeout_config = CONFIG.get("VT_TIMEOUT", (10, 30))
            self.timeout = aiohttp.ClientTimeout(
                connect=timeout_config[0], 
                total=sum(timeout_config) 
            )
            self.request_delay = max(0.0, CONFIG.get("VT_REQUEST_DELAY_SECONDS", 1.0))
            logger.info(f"VirusTotalClient initialized with API key and request delay: {self.request_delay}s")
        else:
            logger.warning("VirusTotalClient initialized WITHOUT API key. VT checks will be skipped.")


    async def _request(self, session: aiohttp.ClientSession, endpoint: str, method: str = 'GET', data: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """
        Internal helper to make an asynchronous request to VirusTotal API v3.
        Supports GET and POST.

        Args:
            session (aiohttp.ClientSession): The active HTTP session.
            endpoint (str): The API endpoint path (e.g., '/ip_addresses/8.8.8.8', '/urls').
            method (str): HTTP method ('GET' or 'POST'). Defaults to 'GET'.
            data (Optional[Dict]): Data payload for POST requests (used as form data).

        Returns:
            Optional[Dict[str, Any]]: The JSON response dictionary from VT, or a dictionary
                                      containing an 'error' key on failure, or a special marker
                                      like {'_get_status': 404} for GET Not Found.
        """
        if not self.api_key or not self.headers:
            logger.debug(f"VT {method} request skipped: API key not configured.")
            return {"error": "config_missing", "message": "VT API key not configured"}

        url = f"{self.BASE_URL}{endpoint}"
        logger.debug(f"Requesting VirusTotal endpoint: {method} {endpoint}")

        if self.request_delay > 0:
            await asyncio.sleep(self.request_delay)

        try:
            request_context = None
            req_method = method.upper()

            if req_method == 'GET':
                request_context = session.get(url, headers=self.headers, timeout=self.timeout)
            elif req_method == 'POST':
                post_headers = self.headers.copy()
                post_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                request_context = session.post(url, headers=post_headers, data=data, timeout=self.timeout)
            else:
                logger.error(f"Unsupported HTTP method for VT request: {method}")
                return {"error": "internal_error", "message": f"Unsupported method: {method}"}

            async with request_context as response:
                logger.debug(f"VirusTotal response status for {method} {endpoint}: {response.status}")

                # --- Special handling for 404 on GET ---
                if req_method == 'GET' and response.status == 404:
                    logger.info(f"VirusTotal indicator not found via GET: {endpoint}")
                    return {"_get_status": 404, "error": "not_found", "message": f"Indicator not found by VT GET: {endpoint.split('/')[-1]}"}

                response.raise_for_status()

                try:
                    result = await response.json()
                    result['_status'] = response.status 
                    return result
                except (aiohttp.ContentTypeError, json.JSONDecodeError):
                    logger.debug(f"VT response for {method} {endpoint} was successful ({response.status}) but not JSON.")
                    if req_method == 'POST' and response.status == 200:
                        return {"_post_status": 200, "message": "Submission successful (no JSON body)"}
                    else:
                        return {"error": "invalid_response", "message": f"Non-JSON response received on {response.status}."}

        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                logger.error(f"VT API key invalid/unauthorized for {method} {endpoint}.")
                return {"error": "unauthorized", "message": "Invalid or unauthorized API key."}
            elif e.status == 429:
                logger.warning(f"VT rate limit exceeded for {method} {endpoint}.")
                return {"error": "rate_limit", "message": "API rate limit exceeded."}
            else:
                logger.error(f"VT HTTP error for {method} {endpoint}: {e.status} - {e.message}")
                return {"error": f"http_{e.status}", "message": f"HTTP error {e.status}: {e.message}"}
        except asyncio.TimeoutError:
            logger.error(f"VT request timed out for {method} {endpoint} after {self.timeout.total}s.")
            return {"error": "timeout", "message": f"Request timed out ({self.timeout.total}s)"}
        except aiohttp.ClientConnectionError as e:
            logger.error(f"VT connection error for {method} {endpoint}: {e}")
            return {"error": "connection_error", "message": f"Could not connect to VT: {e}"}
        except aiohttp.ClientError as e:
            logger.error(f"VT client error for {method} {endpoint}: {e}")
            return {"error": "client_error", "message": f"VT client error: {e}"}
        except Exception as e:
            logger.exception(f"Unexpected error during VT request for {method} {endpoint}: {e}")
            return {"error": "unknown", "message": f"Unexpected error: {e}"}

    async def check_indicator(self, session: aiohttp.ClientSession, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Checks an indicator (IP, URL, hash) against VirusTotal API v3, utilizing a cache.
        For URLs, if GET by hash returns 404 Not Found, optionally submits the URL via POST.

        Args:
            session (aiohttp.ClientSession): The active aiohttp session.
            indicator (str): The indicator value (e.g., '8.8.8.8', 'http://bad.com', 'hashvalue').
            indicator_type (str): Type of indicator: 'ip', 'url', or 'hash'.

        Returns:
            Dict[str, Any]: A dictionary containing the analysis results.
                            Includes 'attributes' (dict) from VT GET on success.
                            Includes 'error' (str) and 'message' (str) on failure or if not found.
                            Includes 'cached' (bool) indicating if the result was from cache.
                            Includes 'indicator' (str) and 'indicator_type' (str) for context.
                            May include 'submitted_for_analysis': True if POST was successful.
        """
        base_result = {"indicator": indicator, "indicator_type": indicator_type, "cached": False}

        if not self.api_key:
             return {**base_result, "error": "api_key_missing", "message": "VirusTotal API key not configured."}

        # 1. Check Cache
        cached_attributes = await self.db_manager.get_cached_result(indicator, indicator_type)
        if cached_attributes is not None and isinstance(cached_attributes, dict):
            logger.debug(f"VT cache hit for {indicator_type}: {indicator}")
            return {**base_result, "attributes": cached_attributes, "cached": True}
        elif cached_attributes is not None:
             logger.warning(f"VT cache returned non-dict data for {indicator_type} {indicator}. Type: {type(cached_attributes)}. Ignoring cache.")


        
        get_endpoint = None
        api_id_for_get = None 

        if indicator_type == 'ip':
            try:
                ip_obj = ipaddress.ip_address(indicator)
                api_id_for_get = str(ip_obj)
                get_endpoint = f"/ip_addresses/{api_id_for_get}"
            except ValueError:
                 logger.warning(f"Invalid IP address format provided for VT check: {indicator}")
                 return {**base_result, "error": "invalid_format", "message": f"Invalid IP address format: {indicator}"}

        elif indicator_type == 'url':
            try:
                parsed_url = urlparse(indicator)
                if not parsed_url.scheme or not parsed_url.netloc:
                     raise ValueError("URL must include scheme (http/https) and netloc (domain).")
                url_hash = hashlib.sha256(indicator.encode()).hexdigest()
                api_id_for_get = url_hash 
                get_endpoint = f"/urls/{api_id_for_get}"
            except ValueError as e:
                 logger.warning(f"Invalid URL format provided for VT check: {indicator} - {e}")
                 return {**base_result, "error": "invalid_format", "message": f"Invalid URL format: {indicator} ({e})"}
            except Exception as e:
                 logger.error(f"Error processing URL for VT check '{indicator}': {e}")
                 return {**base_result, "error": "processing_error", "message": f"Error processing URL: {e}"}

        elif indicator_type == 'hash':
             if not re.fullmatch(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator):
                 logger.warning(f"Invalid hash format provided for VT check: {indicator}")
                 return {**base_result, "error": "invalid_format", "message": f"Invalid hash format (MD5/SHA1/SHA256 expected): {indicator}"}
             api_id_for_get = indicator.lower()
             get_endpoint = f"/files/{api_id_for_get}"
        else:
            logger.error(f"Unknown indicator type specified for VT check: {indicator_type}")
            return {**base_result, "error": "invalid_type", "message": f"Unsupported indicator type: {indicator_type}"}


        # 3. Make the initial GET API Call
        vt_get_response = await self._request(session, get_endpoint, method='GET')

        # 4. Process the GET API response
        if vt_get_response and isinstance(vt_get_response, dict):
            if "data" in vt_get_response and isinstance(vt_get_response["data"], dict) and "attributes" in vt_get_response["data"]:
                attributes = vt_get_response["data"].get("attributes", {})
                if not isinstance(attributes, dict):
                     logger.warning(f"VT GET response 'data.attributes' is not a dict for {indicator_type} {indicator}. Resp: {vt_get_response}")
                     attributes = {"error": "malformed_attributes"}

                await self.db_manager.store_result(indicator, indicator_type, attributes)
                logger.debug(f"VT GET check successful for {indicator_type}: {indicator}")
                return {**base_result, "attributes": attributes}

            elif indicator_type == 'url' and vt_get_response.get("_get_status") == 404:
                logger.info(f"URL '{indicator}' not found via GET /urls/{api_id_for_get}. Attempting submission via POST /urls.")

                post_data = {'url': indicator}
                vt_post_response = await self._request(session, "/urls", method='POST', data=post_data)

                if vt_post_response and isinstance(vt_post_response, dict):
                     if vt_post_response.get("_post_status") == 200 or ("data" in vt_post_response and vt_post_response["data"].get("type") == "analysis"):
                         logger.info(f"Successfully submitted URL '{indicator}' to VirusTotal for analysis.")
                         return {**base_result,
                                 "error": "not_found_but_submitted",
                                 "message": "URL not found in VT, submitted for analysis.",
                                 "submitted_for_analysis": True}
                     elif "error" in vt_post_response:
                         post_error = vt_post_response.get("error", "unknown_post_error")
                         post_msg = vt_post_response.get("message", "POST submission failed")
                         logger.error(f"Failed to submit URL '{indicator}' to VT via POST: {post_error} - {post_msg}")
                         original_get_message = vt_get_response.get("message", "URL not found in VT.")
                         return {**base_result, "error": "not_found", "message": f"{original_get_message} (POST submission also failed: {post_msg})"}
                     else:
                         logger.warning(f"Unexpected successful POST response struct for URL '{indicator}': {vt_post_response}")
                         return {**base_result, "error": "not_found", "message": "URL not found in VT. POST submission returned unexpected response."}
                else:
                    logger.error(f"Internal error or invalid response during POST submission for URL '{indicator}'")
                    return {**base_result, "error": "not_found", "message": "URL not found in VT. Internal error during POST submission."}

            elif "error" in vt_get_response:
                error_code = vt_get_response.get("error")
                error_message = vt_get_response.get("message", "No error message provided.")
                log_level = logging.INFO if error_code == "not_found" else logging.WARNING
                logger.log(log_level, f"VT GET check for {indicator_type} {indicator} failed with '{error_code}': {error_message}")
                return {**base_result, "error": error_code, "message": error_message}

            else:
                logger.error(f"Unexpected VT GET response structure for {indicator_type} {indicator}. Resp: {vt_get_response}")
                return {**base_result, "error": "unexpected_response", "message": "Unexpected API GET response structure."}
        else:
             logger.error(f"Internal error: _request returned invalid data type for GET {indicator_type} {indicator}. Got: {type(vt_get_response)}")
             return {**base_result, "error": "internal_error", "message": "Internal error processing VT GET response."}


# --- Core Analysis Functions ---

def analyze_authentication_headers(msg: EmailMessage) -> Dict[str, Any]:
    """
    Parses key email authentication headers (SPF, DKIM, DMARC) primarily from the
    'Authentication-Results' header, with fallbacks to 'Received-SPF' and 'DKIM-Signature'.

    Note: DMARC policy verification requires DNS lookups (handled separately if enabled).

    Args:
        msg (EmailMessage): The parsed email message object.

    Returns:
        Dict[str, Any]: Dictionary containing parsed results under keys 'spf', 'dkim', 'dmarc'.
                        Each contains 'result', 'domain' (where applicable), etc.
                        Also includes an 'errors' list for parsing issues.
    """
    results = {
        # Initialize with default 'not_found' or appropriate states
        'spf': {'result': 'not_found', 'domain': None, 'source': None},
        'dkim': {'result': 'not_found', 'domain': None, 'selector': None, 'source': None},
        'dmarc': {'result': 'checking_disabled', 'policy': None, 'domain_to_check': None, 'source': None},
        'errors': []
    }

    from_header_decoded = decode_email_header(msg.get('From'))
    from_domain = extract_domain(from_header_decoded)
    if from_domain:
        results['dmarc']['domain_to_check'] = from_domain
        if dns is None:
             results['dmarc']['result'] = 'checking_disabled_dnspython_missing'
        elif not from_domain:
             results['dmarc']['result'] = 'checking_disabled_no_from_domain'
        else:
             results['dmarc']['result'] = 'not_checked_yet'


    # 1. Prioritize 'Authentication-Results' header (most reliable source)
    auth_results_header = msg.get('Authentication-Results')
    if auth_results_header:
        results['spf']['source'] = 'auth_results'
        results['dkim']['source'] = 'auth_results'
        results['dmarc']['source'] = 'auth_results'

        # Extract SPF result and domain
        spf_match = re.search(r'spf=(\w+)\s*(?:\(([^)]+)\))?.*?smtp\.mailfrom=([\S]+)', auth_results_header, re.IGNORECASE)
        if not spf_match: 
             spf_match = re.search(r'spf=(\w+)\s+\(.*\bdomain of\b\s+([\S]+)\)', auth_results_header, re.IGNORECASE)
        if not spf_match: 
            spf_match = re.search(r'spf=(\w+)', auth_results_header, re.IGNORECASE)

        if spf_match:
            results['spf']['result'] = spf_match.group(1).lower()
            spf_domain_source = spf_match.group(3) if len(spf_match.groups()) >= 3 and spf_match.group(3) else \
                                spf_match.group(2) if len(spf_match.groups()) >= 2 and spf_match.group(2) else None
            if spf_domain_source:
                results['spf']['domain'] = extract_domain(spf_domain_source)
            else:
                 if results['spf']['result'] == 'pass' and from_domain:
                     results['spf']['domain'] = from_domain


        dkim_match = re.search(r'dkim=(\w+).*?header\.i=@?([\w.\-]+).*?header\.s=([\w.\-]+)', auth_results_header, re.IGNORECASE)
        if not dkim_match: 
             dkim_match = re.search(r'dkim=(\w+).*?header\.d=([\w.\-]+).*?header\.s=([\w.\-]+)', auth_results_header, re.IGNORECASE)
        if not dkim_match: 
             dkim_match = re.search(r'dkim=(\w+)', auth_results_header, re.IGNORECASE)

        if dkim_match:
            results['dkim']['result'] = dkim_match.group(1).lower()
            if len(dkim_match.groups()) >= 3:
                results['dkim']['domain'] = dkim_match.group(2).lower()
                results['dkim']['selector'] = dkim_match.group(3) 


        # Extract DMARC result and policy (p=)
        dmarc_match = re.search(r'dmarc=(\w+)\s*(?:\(([^)]+)\))?.*?header\.from=([\w.\-]+)', auth_results_header, re.IGNORECASE)
        if not dmarc_match: 
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header, re.IGNORECASE)

        if dmarc_match:
            results['dmarc']['result'] = dmarc_match.group(1).lower()
            dmarc_policy_info = dmarc_match.group(2) if len(dmarc_match.groups()) >= 2 and dmarc_match.group(2) else ''
            policy_match = re.search(r'p=(\w+)', dmarc_policy_info, re.IGNORECASE)
            if policy_match:
                results['dmarc']['policy'] = policy_match.group(1).lower()
            dmarc_header_from = dmarc_match.group(3).lower() if len(dmarc_match.groups()) >= 3 and dmarc_match.group(3) else None
            if from_domain and dmarc_header_from and from_domain != dmarc_header_from:
                 results['errors'].append(f"DMARC check in Authentication-Results used domain '{dmarc_header_from}' which differs from message From domain '{from_domain}'.")
            elif dmarc_header_from:
                results['dmarc']['domain_to_check'] = dmarc_header_from


    # 2. Fallback to 'Received-SPF' if SPF not found in Auth-Results
    if results['spf']['result'] == 'not_found':
        received_spf = msg.get('Received-SPF')
        if received_spf:
            results['spf']['source'] = 'received_spf'
            match = re.match(r'(\w+)\s*(?:\((.*?)\))?', received_spf.strip(), re.IGNORECASE)
            if match:
                results['spf']['result'] = match.group(1).lower()
                reason_part = match.group(2)
                if reason_part:
                    domain_match = re.search(r'(?:google\.com|microsoft\.com|domain of|sender is)\s+([\w.\-]+)', reason_part, re.IGNORECASE)
                    if domain_match:
                         results['spf']['domain'] = extract_domain(domain_match.group(1))

            else:
                results['errors'].append(f"Could not parse Received-SPF header: {received_spf}")

    # 3. Fallback to 'DKIM-Signature' presence if DKIM not found in Auth-Results
    if results['dkim']['result'] == 'not_found':
        dkim_sig = msg.get('DKIM-Signature')
        if dkim_sig:
             results['dkim']['source'] = 'dkim_signature'
             results['dkim']['result'] = 'signature_present_needs_verification' 
             # Extract domain (d=) and selector (s=) tags from the signature header
             domain_match = re.search(r'[;\s]d=([\S]+);?', dkim_sig)
             selector_match = re.search(r'[;\s]s=([\S]+);?', dkim_sig)
             if domain_match:
                 results['dkim']['domain'] = extract_domain(domain_match.group(1).strip())
             if selector_match:
                 results['dkim']['selector'] = selector_match.group(1).strip()


    # 4. DMARC DNS Check
    if dns and results['dmarc']['domain_to_check'] and results['dmarc']['result'] not in ['checking_disabled_dnspython_missing', 'checking_disabled_no_from_domain']:
         dmarc_domain = results['dmarc']['domain_to_check']
         try:
             dmarc_query = f"_dmarc.{dmarc_domain}"
             logger.debug(f"Performing DMARC DNS query for: {dmarc_query}")
             resolver = dns.resolver.Resolver()
             # Configure resolver timeout
             resolver.timeout = 5
             resolver.lifetime = 5
             txt_records = resolver.resolve(dmarc_query, 'TXT')
             dmarc_record = None
             for record in txt_records:
                 record_text = b"".join(record.strings).decode('utf-8')
                 if record_text.lower().startswith("v=dmarc1"):
                     dmarc_record = record_text
                     break

             if dmarc_record:
                 results['dmarc']['source'] = 'dns_lookup'
                 logger.info(f"Found DMARC record for {dmarc_domain}: {dmarc_record}")
                 # Parse the policy (p=) tag
                 policy_match = re.search(r'[;\s]p=(\w+)', dmarc_record, re.IGNORECASE)
                 if policy_match:
                     results['dmarc']['policy'] = policy_match.group(1).lower()
                     
                     if results['dmarc']['result'] == 'not_checked_yet':
                          results['dmarc']['result'] = 'policy_found_in_dns' 
                 else:
                      results['errors'].append(f"DMARC record found but missing 'p=' policy tag: {dmarc_record}")
                      if results['dmarc']['result'] == 'not_checked_yet':
                          results['dmarc']['result'] = 'policy_missing_tag'

             else:
                 logger.info(f"No DMARC record found for {dmarc_domain} (or record invalid).")
                 if results['dmarc']['result'] == 'not_checked_yet':
                      results['dmarc']['result'] = 'no_dns_record'


         except dns.resolver.NXDOMAIN:
             logger.info(f"DMARC DNS query failed: NXDOMAIN for {dmarc_query}")
             if results['dmarc']['result'] == 'not_checked_yet':
                results['dmarc']['result'] = 'dns_nxdomain'
         except dns.resolver.NoAnswer:
              logger.info(f"DMARC DNS query failed: No TXT answer for {dmarc_query}")
              if results['dmarc']['result'] == 'not_checked_yet':
                 results['dmarc']['result'] = 'dns_no_answer'
         except dns.exception.Timeout:
              logger.warning(f"DMARC DNS query timed out for {dmarc_query}")
              if results['dmarc']['result'] == 'not_checked_yet':
                 results['dmarc']['result'] = 'dns_timeout'
                 results['errors'].append("DMARC DNS check timed out.")
         except Exception as e:
              logger.error(f"Unexpected error during DMARC DNS query for {dmarc_query}: {e}")
              if results['dmarc']['result'] == 'not_checked_yet':
                  results['dmarc']['result'] = 'dns_error'
                  results['errors'].append(f"DMARC DNS check error: {e}")

    if results['dmarc']['result'] == 'not_checked_yet':
        if results['dmarc']['source'] == 'auth_results' and results['dmarc']['policy'] is None:
             results['dmarc']['result'] = 'found_in_auth_results_no_policy'
        else:
             results['dmarc']['result'] = 'not_found'


    return results

def check_typosquatting(domain_to_check: str, known_domains: Set[str], threshold: int = 2) -> Optional[Dict[str, Any]]:
    """
    Checks a domain for potential typosquatting against a set of known legitimate domains
    using Levenshtein distance.

    Args:
        domain_to_check (str): The domain name to check (e.g., "paypa1.com").
        known_domains (Set[str]): A set of known legitimate domains (e.g., {"paypal.com", "google.com"}).
        threshold (int): The maximum Levenshtein distance to consider suspicious (inclusive). Defaults to 2.

    Returns:
        Optional[Dict[str, Any]]: A dictionary {'similar_to': known_domain, 'distance': dist}
                                  if a potential typo is found within the threshold, otherwise None.
                                  Returns None if Levenshtein library is missing.
    """
    if not domain_to_check or not levenshtein_distance:
        if not levenshtein_distance:
             logger.debug("Levenshtein library not available, skipping typosquatting check.")
        return None

    normalized_domain = domain_to_check.lower()
    if normalized_domain.startswith('www.'):
        normalized_domain = normalized_domain[4:]

    domain_base = normalized_domain.split('.')[0] if '.' in normalized_domain else normalized_domain

    min_dist = float('inf')
    closest_match_known_domain = None

    for known in known_domains:
        normalized_known = known.lower()
        if normalized_known.startswith('www.'):
             normalized_known = normalized_known[4:]

        known_base = normalized_known.split('.')[0] if '.' in normalized_known else normalized_known

        dist = levenshtein_distance(domain_base, known_base)

        if dist < min_dist:
            min_dist = dist
            closest_match_known_domain = known

    if closest_match_known_domain and 0 < min_dist <= threshold:
        logger.info(f"Potential typosquatting detected: '{domain_to_check}' (base:'{domain_base}') is distance {min_dist} from known domain '{closest_match_known_domain}' (base:'{normalized_known.split('.')[0]}')")
        return {"similar_to": closest_match_known_domain, "distance": min_dist}

    return None 


async def analyze_headers(msg: EmailMessage, vt_client: VirusTotalClient, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Analyzes email headers for standard information, authentication results,
    suspicious indicators, and checks originating IPs via VirusTotal.

    Args:
        msg (EmailMessage): The parsed email message object.
        vt_client (VirusTotalClient): The initialized VirusTotal client for API calls.
        session (aiohttp.ClientSession): The active aiohttp session for VT checks.

    Returns:
        Dict[str, Any]: Dictionary containing header analysis results, including:
                        - Decoded standard headers (Subject, From, To, Reply-To, Date, Message-ID)
                        - Parsed Authentication results ('Authentication' key)
                        - Received header chain ('Received_Chain') with parsed IPs
                        - VirusTotal results for public IPs ('IP_Analysis')
                        - List of identified suspicious header patterns ('Suspicious_Headers')
                        - From domain analysis ('From_Domain', 'Typosquatting_From')
    """
    headers_analysis = {
        "Subject": decode_email_header(msg.get("Subject")),
        "From": decode_email_header(msg.get("From")),
        "To": decode_email_header(msg.get("To")), # Can be multiple, decode_header handles it reasonably
        "Reply-To": decode_email_header(msg.get("Reply-To")),
        "Date": decode_email_header(msg.get("Date")),
        "Message-ID": msg.get("Message-ID"), # Typically ASCII, no decoding needed but get raw value
        "Authentication": {}, # Placeholder, filled below
        "Received_Chain": [], # List to store raw Received headers and parsed IPs
        "IP_Analysis": {}, # Store VT results for unique public IPs found
        "Suspicious_Headers": [], # List of strings describing suspicious findings
        "From_Domain": None, # Store extracted From domain
        "Typosquatting_From": None # Store typosquatting result for From domain
    }
    logger.info("Starting header analysis...")

    # 1. Analyze Authentication Headers
    headers_analysis["Authentication"] = analyze_authentication_headers(msg)

    # 2. Analyze Received Headers and Extract IPs
    received_headers = msg.get_all('Received', [])
    unique_public_ips: Set[str] = set()
    for header_value in reversed(received_headers): 
        
        decoded_header = decode_email_header(header_value)
        header_info = {"raw": decoded_header, "parsed_ips": []} 

        # Extract all potential IPv4 addresses using regex
        potential_ips = re.findall(IPV4_REGEX, decoded_header)
        for ip_str in potential_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                # Filter out private, loopback, link-local, and unspecified IPs
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_multicast):
                    unique_public_ips.add(ip_str)
                    if ip_str not in header_info["parsed_ips"]: 
                         header_info["parsed_ips"].append(ip_str)
            except ValueError:
                logger.debug(f"Ignoring invalid IP address '{ip_str}' found in Received header.")
                continue 

        headers_analysis["Received_Chain"].append(header_info)

    # 3. Check Extracted Public IPs with VirusTotal (concurrently)
    ip_check_tasks = []
    if unique_public_ips:
        logger.info(f"Found {len(unique_public_ips)} unique public IPs in headers. Checking via VirusTotal...")
        for ip in unique_public_ips:
            task = asyncio.create_task(vt_client.check_indicator(session, ip, 'ip'), name=f"vt_ip_{ip}")
            ip_check_tasks.append(task)

        # Wait for all VT IP check tasks to complete
        ip_vt_results = await asyncio.gather(*ip_check_tasks)

        for result in ip_vt_results:
             if result and isinstance(result, dict) and 'indicator' in result:
                 headers_analysis["IP_Analysis"][result['indicator']] = result
             else:
                  logger.error(f"Received unexpected result format from VT IP check: {result}")

    else:
        logger.info("No unique public IPs found in Received headers to check via VirusTotal.")


    # 4. Check for Other Suspicious Header Patterns
    # From/Reply-To Mismatch
    if headers_analysis["Reply-To"] and headers_analysis["From"] and \
       headers_analysis["Reply-To"].lower() != headers_analysis["From"].lower():
        from_domain_reply = extract_domain(headers_analysis["Reply-To"])
        from_domain_from = extract_domain(headers_analysis["From"])
        if from_domain_reply != from_domain_from:
            note = f"Mismatch between From domain ('{from_domain_from or 'N/A'}') and Reply-To domain ('{from_domain_reply or 'N/A'}')."
            headers_analysis["Suspicious_Headers"].append(note)
            logger.debug(note)
        else:
             logger.debug(f"From and Reply-To addresses differ but domains match: From='{headers_analysis['From']}', Reply-To='{headers_analysis['Reply-To']}'")


    mailer_headers = ['X-Mailer', 'User-Agent', 'X-Sender', 'List-Unsubscribe']
    bulk_keywords = ['bulk', 'mailer', 'marketing', 'campaign', 'esp', 'smtp.com', 'sendgrid', 'mailchimp'] 
    for header_name in mailer_headers:
        header_value = decode_email_header(msg.get(header_name))
        if header_value:
             header_lower = header_value.lower()
             for keyword in bulk_keywords:
                 if keyword in header_lower:
                     note = f"Header '{header_name}' suggests potential bulk/marketing email source: '{header_value[:60]}...'"
                     if note not in headers_analysis["Suspicious_Headers"]: 
                         headers_analysis["Suspicious_Headers"].append(note)
                     logger.debug(note)
                     break 

    if not headers_analysis["Date"]:
         headers_analysis["Suspicious_Headers"].append("Missing standard 'Date' header.")
    if not headers_analysis["Message-ID"]:
         headers_analysis["Suspicious_Headers"].append("Missing standard 'Message-ID' header.")
    if not headers_analysis["From"]:
         headers_analysis["Suspicious_Headers"].append("Missing standard 'From' header.")

    # 5. Analyze 'From' Domain
    from_domain = extract_domain(headers_analysis["From"])
    if from_domain:
         headers_analysis["From_Domain"] = from_domain
         logger.debug(f"Extracted From domain: {from_domain}")

         
         if is_suspicious_tld(from_domain):
             headers_analysis["Suspicious_Headers"].append(f"From address domain '{from_domain}' uses a potentially suspicious TLD.")

         # Check for alignment with SPF/DKIM domains (if available and pass)
         spf_info = headers_analysis["Authentication"]["spf"]
         dkim_info = headers_analysis["Authentication"]["dkim"]
         if spf_info.get("result") == 'pass' and spf_info.get("domain") and from_domain != spf_info["domain"]:
              headers_analysis["Suspicious_Headers"].append(f"From domain ('{from_domain}') does not align with verified SPF domain ('{spf_info['domain']}').")
         if dkim_info.get("result") == 'pass' and dkim_info.get("domain") and from_domain != dkim_info["domain"]:
              headers_analysis["Suspicious_Headers"].append(f"From domain ('{from_domain}') does not align with verified DKIM domain ('{dkim_info['domain']}').")

         # Check for typosquatting against known brand domains
         typo_result = check_typosquatting(from_domain, KNOWN_BRAND_DOMAINS, threshold=CONFIG.get("TYPOSQUATTING_THRESHOLD", 2))
         if typo_result:
              note = f"From domain '{from_domain}' may be typosquatting known brand '{typo_result['similar_to']}' (distance: {typo_result['distance']})."
              headers_analysis["Suspicious_Headers"].append(note)
              headers_analysis["Typosquatting_From"] = typo_result
              logger.warning(note) 

    else:
         if headers_analysis["From"]: 
             headers_analysis["Suspicious_Headers"].append(f"Could not extract a valid domain from the From header: '{headers_analysis['From']}'")


    logger.info(f"Header analysis complete. Found {len(headers_analysis['Suspicious_Headers'])} suspicious indicators.")
    return headers_analysis


async def analyze_body(msg: EmailMessage, vt_client: VirusTotalClient, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Analyzes the email body (plain text and HTML parts) for content, links,
    potential credential harvesting forms, obfuscation techniques, brand impersonation,
    and checks extracted URLs via VirusTotal.

    Args:
        msg (EmailMessage): The parsed email message object.
        vt_client (VirusTotalClient): The initialized VirusTotal client for API calls.
        session (aiohttp.ClientSession): The active aiohttp session for VT checks.

    Returns:
        Dict[str, Any]: Dictionary containing body analysis results:
                        - 'Text': Plain text content snippet (str or None).
                        - 'HTML': HTML content snippet (str or None).
                        - 'Links': List of unique URLs found (List[str]).
                        - 'URL_Analysis': VT results for checked URLs (Dict[str, Dict]).
                        - 'Suspicious_Elements': List of suspicious findings (List[str]).
                        - 'Brand_Info': Brand detection results (List[Dict]).
                        - 'Typosquatting_Links': Typosquatting results for link domains (Dict[str, Dict]).
    """
    body_analysis = {
        "Text": None,
        "HTML": None,
        "Links": [], # Unique URLs found in text/html
        "URL_Analysis": {}, # Store VT results for URLs, keyed by URL
        "Suspicious_Elements": [], # List of strings describing findings
        "Brand_Info": [], # Store info about potential brand mentions/impersonation
        "Typosquatting_Links": {} # Store typosquatting results, keyed by URL
    }
    urls_found_in_body: Set[str] = set()
    html_content: Optional[str] = None
    text_content: Optional[str] = None
    logger.info("Starting body analysis...")

    # 1. Extract Text and HTML Content Parts
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                disposition_header = part.get("Content-Disposition")

                
                content_disposition_str = str(disposition_header).lower() if disposition_header else "" 
                filename = part.get_filename()

                is_likely_attachment = "attachment" in content_disposition_str or bool(filename) 

                if part.is_multipart() or is_likely_attachment: 
                    continue

                if content_type == "text/plain" and text_content is None: 
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8' 
                        text_content = payload_bytes.decode(charset, errors='replace')
                        # Store a snippet for analysis/reporting (e.g., first 2000 chars)
                        body_analysis["Text"] = text_content[:2000] + ('...' if len(text_content) > 2000 else '')
                        logger.debug(f"Extracted text part ({len(text_content)} chars, using charset {charset}).")
                    except Exception as e:
                        logger.warning(f"Failed to decode text part (charset: {part.get_content_charset()}): {e}")
                        body_analysis["Suspicious_Elements"].append(f"Error decoding text part: {e}")
                elif content_type == "text/html" and html_content is None: 
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html_content = payload_bytes.decode(charset, errors='replace')

                        body_analysis["HTML"] = html_content[:4000] + ('...' if len(html_content) > 4000 else '')
                        logger.debug(f"Extracted HTML part ({len(html_content)} chars, using charset {charset}).")
                    except Exception as e:
                        logger.warning(f"Failed to decode HTML part (charset: {part.get_content_charset()}): {e}")
                        body_analysis["Suspicious_Elements"].append(f"Error decoding HTML part: {e}")
        else: # Handle non-multipart messages
            content_type = msg.get_content_type()
            if content_type == 'text/plain':
                 payload_bytes = msg.get_payload(decode=True)
                 charset = msg.get_content_charset() or 'utf-8'
                 text_content = payload_bytes.decode(charset, errors='replace')
                 body_analysis["Text"] = text_content[:2000] + ('...' if len(text_content) > 2000 else '')
                 logger.debug(f"Extracted single text part ({len(text_content)} chars, using charset {charset}).")
            elif content_type == 'text/html':
                 payload_bytes = msg.get_payload(decode=True)
                 charset = msg.get_content_charset() or 'utf-8'
                 html_content = payload_bytes.decode(charset, errors='replace')
                 body_analysis["HTML"] = html_content[:4000] + ('...' if len(html_content) > 4000 else '')
                 logger.debug(f"Extracted single HTML part ({len(html_content)} chars, using charset {charset}).")

        if not text_content and not html_content:
             logger.warning("Could not find a readable text/plain or text/html body part.")
             body_analysis["Suspicious_Elements"].append("No standard text or HTML body content found.")

    except Exception as e:
         logger.exception(f"Error occurred while processing message parts for body content: {e}")
         body_analysis["Suspicious_Elements"].append(f"Error processing body parts: {e}")


    # 2. Extract URLs from Text and HTML Content
    try:
        combined_text_for_urls = (text_content or "") + "\n" + (html_content or "")

        # Use regex to find potential URLs in the combined content
        raw_urls_from_regex = re.findall(URL_REGEX, combined_text_for_urls)
        for url in raw_urls_from_regex:
            cleaned_url = url.rstrip('.,;!?)>"\']')
            try:
                 parsed = urlparse(cleaned_url)
                 if parsed.scheme and parsed.netloc:
                     normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}{';' + parsed.params if parsed.params else ''}{'?' + parsed.query if parsed.query else ''}{'#' + parsed.fragment if parsed.fragment else ''}"
                     urls_found_in_body.add(normalized_url)
            except ValueError:
                logger.debug(f"Ignoring invalid URL found by regex: {url}")


        if html_content:
            href_links = re.findall(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(http[s]?://[^"\']+)\1', html_content, re.IGNORECASE)
            for _, url in href_links: 
                 try:
                     parsed = urlparse(url)
                     if parsed.scheme in ['http', 'https'] and parsed.netloc:
                        normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}{';' + parsed.params if parsed.params else ''}{'?' + parsed.query if parsed.query else ''}{'#' + parsed.fragment if parsed.fragment else ''}"
                        urls_found_in_body.add(normalized_url)
                 except ValueError:
                      logger.debug(f"Ignoring invalid URL found in href: {url}")

        body_analysis["Links"] = sorted(list(urls_found_in_body))
        logger.info(f"Found {len(body_analysis['Links'])} unique URLs in body content.")

    except Exception as e:
         logger.exception(f"Error occurred during URL extraction from body: {e}")
         body_analysis["Suspicious_Elements"].append(f"Error extracting URLs: {e}")


    # 3. Analyze HTML Content for Suspicious Elements (if HTML exists)
    if html_content:
        try:
            if re.search(r'<input[^>]+type=["\']?(?:password|text|email|tel|number)["\']?', html_content, re.IGNORECASE):
                body_analysis["Suspicious_Elements"].append("HTML body contains input fields (potential credential harvesting).")
                logger.debug("Found input fields in HTML.")

            if re.search(r'<form[^>]+action=', html_content, re.IGNORECASE):
                 body_analysis["Suspicious_Elements"].append("HTML body contains <form> tag(s).")
                 logger.debug("Found form tag in HTML.")

            # Check for common URL shortener domains
            shortener_domains = {'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'} 
            found_shorteners = set()
            for url in body_analysis["Links"]:
                 domain = extract_domain(url)
                 if domain in shortener_domains:
                     found_shorteners.add(domain)
            if found_shorteners:
                 body_analysis["Suspicious_Elements"].append(f"Contains links using known URL shorteners: {', '.join(found_shorteners)}.")
                 logger.debug(f"Found URL shorteners: {found_shorteners}")


            # Check for potential hidden text (basic checks for common techniques)
            # - Text matching background color (e.g., white on white)
            # - Text with display:none or visibility:hidden
            # - Font size zero or very small
            hidden_text_patterns = [
                r'style=["\'][^"\']*(?:color\s*:\s*#(?:FFF|FFFFFF|fff|ffffff)|color\s*:\s*white)[^"\']*["\']', # White text color
                r'style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\']', # Hidden styles
                r'font-size\s*:\s*(?:0|1)px' # Zero or 1px font size
            ]
            for pattern in hidden_text_patterns:
                 if re.search(pattern, html_content, re.IGNORECASE):
                     body_analysis["Suspicious_Elements"].append("Potential hidden text techniques detected in HTML styles.")
                     logger.debug(f"Found potential hidden text pattern: {pattern}")
                     break # Found one type, no need to report others redundantly

            # Check for embedded Javascript (can be benign but often used maliciously)
            # Simple check for <script> tags;
            if re.search(r'<script.*?>.*?</script>', html_content, re.IGNORECASE | re.DOTALL):
                body_analysis["Suspicious_Elements"].append("Embedded Javascript (<script> tags) found in HTML body.")
                logger.debug("Found script tags in HTML.")

            # Check for meta refresh tag used for redirection
            if re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']+url=([^"\'>]+)["\']', html_content, re.IGNORECASE):
                 body_analysis["Suspicious_Elements"].append("HTML contains meta refresh tag (potential redirection).")
                 logger.debug("Found meta refresh tag in HTML.")

        except Exception as e:
             logger.exception(f"Error occurred during HTML suspicious element analysis: {e}")
             body_analysis["Suspicious_Elements"].append(f"Error analyzing HTML elements: {e}")


    # 4. Analyze Links: VirusTotal Checks and Typosquatting
    url_check_tasks = []
    unique_domains_in_links: Set[str] = set()
    if body_analysis["Links"]:
        logger.info(f"Analyzing {len(body_analysis['Links'])} URLs from body (VT checks, typosquatting)...")
        for url in body_analysis["Links"]:
             domain = extract_domain(url)
             if domain:
                  unique_domains_in_links.add(domain)
                  typo_result = check_typosquatting(domain, KNOWN_BRAND_DOMAINS, threshold=CONFIG.get("TYPOSQUATTING_THRESHOLD", 2))
                  if typo_result:
                      body_analysis["Typosquatting_Links"][url] = typo_result 
                      note = f"Link URL '{url}' (domain: '{domain}') may be typosquatting known brand '{typo_result['similar_to']}' (distance: {typo_result['distance']})."
                      body_analysis["Suspicious_Elements"].append(note)
                      logger.warning(note) 

             task = asyncio.create_task(vt_client.check_indicator(session, url, 'url'), name=f"vt_url_{url[:30]}")
             url_check_tasks.append(task)

        url_vt_results = await asyncio.gather(*url_check_tasks)

        # Process and store the VT results, keyed by URL
        for result in url_vt_results:
             if result and isinstance(result, dict) and 'indicator' in result:
                 body_analysis["URL_Analysis"][result['indicator']] = result
             else:
                  logger.error(f"Received unexpected result format from VT URL check: {result}")

    else:
        logger.info("No links found in body to analyze.")


    # 5. Basic Brand Impersonation Analysis
    try:
        email_content_lower = (text_content or "").lower() + "\n" + (html_content or "").lower()
        mentioned_brands: Set[str] = set() 

        for brand_domain in KNOWN_BRAND_DOMAINS:
            brand_name = brand_domain.split('.')[0] 
            # Use word boundaries to avoid partial matches (e.g., 'apple' in 'applesauce')
            if re.search(r'\b' + re.escape(brand_name) + r'\b', email_content_lower):
                 mentioned_brands.add(brand_domain)

        if mentioned_brands:
            logger.info(f"Email content mentions potential brands: {mentioned_brands}")
            brand_analysis_result = {
                "mentioned_brands": sorted(list(mentioned_brands)),
                "link_domains_match_status": "no_links_to_check", 
                "notes": []
            }

            if unique_domains_in_links:
                match_found = False
                mismatch_found = False
                suspicious_mismatched_domains = set()

                for link_domain in unique_domains_in_links:
                    is_mentioned_brand_domain = False
                    is_any_known_brand_domain = False

                    for brand_dom in mentioned_brands:
                        if link_domain == brand_dom or link_domain.endswith('.' + brand_dom):
                            is_mentioned_brand_domain = True
                            break
                    # Check if link domain matches *any* known brand (even if not mentioned)
                    for brand_dom in KNOWN_BRAND_DOMAINS:
                        if link_domain == brand_dom or link_domain.endswith('.' + brand_dom):
                            is_any_known_brand_domain = True
                            break

                    if is_mentioned_brand_domain:
                        match_found = True # Found a link matching a mentioned brand
                    elif not is_any_known_brand_domain:
                        mismatch_found = True
                        suspicious_mismatched_domains.add(link_domain)


                # Determine overall status based on findings
                if match_found and not mismatch_found:
                    brand_analysis_result["link_domains_match_status"] = "match" 
                elif mismatch_found:
                    brand_analysis_result["link_domains_match_status"] = "mismatch" 
                    note = f"Email mentions brand(s) ({', '.join(mentioned_brands)}) but contains links to potentially unrelated or suspicious domains: {', '.join(suspicious_mismatched_domains)}."
                    brand_analysis_result["notes"].append(note)
                    body_analysis["Suspicious_Elements"].append(note) 
                elif not match_found and unique_domains_in_links:
                    
                     brand_analysis_result["link_domains_match_status"] = "no_mentioned_brand_links"

            body_analysis["Brand_Info"].append(brand_analysis_result)

    except Exception as e:
         logger.exception(f"Error occurred during brand impersonation analysis: {e}")
         body_analysis["Suspicious_Elements"].append(f"Error analyzing brand impersonation: {e}")


    logger.info(f"Body analysis complete. Found {len(body_analysis['Suspicious_Elements'])} suspicious elements.")
    return body_analysis


async def analyze_attachments(msg: EmailMessage, vt_client: VirusTotalClient, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Analyzes email attachments: extracts metadata (name, size, type), generates hashes,
    performs OCR on images (if enabled), and checks file hashes via VirusTotal.

    Args:
        msg (EmailMessage): The parsed email message object.
        vt_client (VirusTotalClient): The initialized VirusTotal client for API calls.
        session (aiohttp.ClientSession): The active aiohttp session for VT checks.

    Returns:
        Dict[str, Any]: Dictionary containing attachment analysis results:
                        - 'Data': Dict mapping filename to attachment info (size, type, hashes, ocr_text, ocr_error).
                        - 'Hash_Analysis': VT results keyed by filename.
                        - 'Suspicious_Indicators': List of suspicious findings (List[str]).
    """
    attachments_analysis = {
        "Data": {}, # Key: filename, Value: Dict{size, content_type, hashes, ocr_text, ocr_error}
        "Hash_Analysis": {}, # Key: filename, Value: VT result for SHA256 hash
        "Suspicious_Indicators": [] # List of strings
    }
    attachment_payloads: Dict[str, bytes] = {} # Store payload bytes temporarily for hashing/OCR, keyed by filename
    logger.info("Starting attachment analysis...")

    # 1. Iterate through message parts to find attachments
    try:
        for part in msg.walk():
            # Check if part is likely an attachment using filename or content-disposition
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", "")).lower()

            # Criteria for being an attachment: has filename OR content-disposition is 'attachment'
            is_attachment_candidate = bool(filename) or "attachment" in content_disposition

            # Skip parts that are containers or clearly not attachments (e.g., inline text without filename)
            if part.get_content_maintype() == 'multipart' or not is_attachment_candidate:
                continue

            # Decode filename if necessary (can be RFC 2047 encoded)
            if filename:
                filename = decode_email_header(filename)
            else:
                ext = part.get_content_subtype() or 'bin'
                filename = f"attachment_{len(attachments_analysis['Data']) + 1}.{ext}"
                logger.warning(f"Attachment part missing filename, using generated name: {filename}")

            # Ensure unique filenames if duplicates occur
            original_filename = filename
            counter = 1
            while filename in attachments_analysis["Data"]:
                 name, ext = os.path.splitext(original_filename)
                 filename = f"{name}_{counter}{ext}"
                 counter += 1
            if original_filename != filename:
                 logger.warning(f"Duplicate attachment filename '{original_filename}', renamed to '{filename}'.")


            logger.debug(f"Processing attachment candidate: {filename} (Type: {part.get_content_type()})")

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                     logger.warning(f"Attachment '{filename}' has None payload after decoding. Skipping.")
                     attachments_analysis["Data"][filename] = {"error": "Failed to decode payload (payload is None)."}
                     continue
                if not isinstance(payload, bytes):
                     logger.error(f"Attachment '{filename}' payload is not bytes after decoding (Type: {type(payload)}). Skipping.")
                     attachments_analysis["Data"][filename] = {"error": f"Decoded payload is not bytes (type: {type(payload)})."}
                     continue

                attachment_payloads[filename] = payload 
                content_type = part.get_content_type()
                file_size = len(payload)

                # Initialize data entry for this attachment
                attachments_analysis["Data"][filename] = {
                    "size": file_size,
                    "content_type": content_type,
                    "hashes": {}, 
                    "ocr_text": None,
                    "ocr_error": None,
                }

                
                hashes = generate_hashes(payload)
                attachments_analysis["Data"][filename]["hashes"] = hashes
                logger.debug(f"Generated hashes for {filename}: MD5={hashes.get('md5', 'N/A')[:8]}..., SHA256={hashes.get('sha256', 'N/A')[:8]}...")

                # Perform OCR if it's an image type and OCR is enabled
                if CONFIG.get("OCR_ENABLED") and content_type in OCR_IMAGE_CONTENT_TYPES:
                     logger.debug(f"Performing OCR on image attachment: {filename}")
                     ocr_text, ocr_error = await perform_ocr(payload)
                     attachments_analysis["Data"][filename]["ocr_text"] = ocr_text
                     attachments_analysis["Data"][filename]["ocr_error"] = ocr_error
                     if ocr_error:
                          logger.warning(f"OCR failed for {filename}: {ocr_error}")
                     elif ocr_text:
                           logger.info(f"OCR extracted {len(ocr_text)} chars from {filename}")
                           suspicious_keywords = ['password', 'urgent', 'invoice', 'payment', 'account', 'verify']
                           for keyword in suspicious_keywords:
                               if keyword in ocr_text.lower():
                                   note = f"Suspicious keyword '{keyword}' found in OCR text of image attachment '{filename}'."
                                   if note not in attachments_analysis["Suspicious_Indicators"]:
                                        attachments_analysis["Suspicious_Indicators"].append(note)


                # Check for common suspicious indicators based on filename/type
                file_ext_lower = os.path.splitext(filename)[1].lower()
                # Executables/Scripts (High Risk)
                if file_ext_lower in ['.exe', '.scr', '.bat', '.vbs', '.js', '.ps1', '.jar', '.msi', '.cmd', '.com', '.cpl']:
                     attachments_analysis["Suspicious_Indicators"].append(f"Executable or script attachment found: '{filename}'. High risk.")
                # Archives (Potential Malware Container)
                elif file_ext_lower in ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso']:
                     attachments_analysis["Suspicious_Indicators"].append(f"Archive attachment found: '{filename}' (potential malware container).")
                # Office Docs with Macros 
                elif file_ext_lower in ['.docm', '.xlsm', '.pptm']:
                    attachments_analysis["Suspicious_Indicators"].append(f"Office document with potential macros found: '{filename}'.")
                elif content_type == 'application/vnd.ms-office' and file_ext_lower in ['.doc', '.xls', '.ppt']:
                     # Older formats that can contain macros
                     attachments_analysis["Suspicious_Indicators"].append(f"Legacy Office document found: '{filename}' (may contain macros).")

                # Large PDF check 
                if content_type == 'application/pdf' and file_size > (2 * 1024 * 1024): # e.g., > 2MB
                     attachments_analysis["Suspicious_Indicators"].append(f"Large PDF attachment found: '{filename}' ({file_size / (1024):.0f} KB).")

                # Double Extension Check 
                name_part = os.path.splitext(filename)[0]
                if '.' in name_part: 
                     common_non_exec = ['.pdf', '.docx', '.xlsx', '.jpg', '.png', '.txt', '.html']
                     parts = filename.lower().split('.')
                     if len(parts) > 2 and f'.{parts[-2]}' in common_non_exec and f'.{parts[-1]}' in ['.exe', '.scr', '.bat', '.js', '.vbs']:
                          attachments_analysis["Suspicious_Indicators"].append(f"Potential deceptive double extension detected: '{filename}'. High risk.")


            except Exception as e:
                logger.exception(f"Failed to process attachment part identified as '{filename}': {e}")
                if filename not in attachments_analysis["Data"]:
                    attachments_analysis["Data"][filename] = {}
                attachments_analysis["Data"][filename]["error"] = f"Failed to process: {e}"

    except Exception as e:
         logger.exception(f"Error occurred while walking message parts for attachments: {e}")
         attachments_analysis["Suspicious_Indicators"].append(f"Error processing attachments: {e}")


    # 2. Check Attachment Hashes with VirusTotal 
    hash_check_tasks = []
    filenames_with_hashes = [] 

    for filename, data in attachments_analysis["Data"].items():
        if "hashes" in data and isinstance(data["hashes"], dict) and data["hashes"].get("sha256") and "error" not in data:
            filenames_with_hashes.append(filename)

    if filenames_with_hashes:
        logger.info(f"Checking {len(filenames_with_hashes)} unique attachment hashes via VirusTotal...")
        for filename in filenames_with_hashes:
            sha256_hash = attachments_analysis["Data"][filename]["hashes"]["sha256"]
            task = asyncio.create_task(vt_client.check_indicator(session, sha256_hash, 'hash'), name=f"vt_hash_{filename[:20]}")
            hash_check_tasks.append(task)

        # Wait for all hash checks to complete
        hash_vt_results = await asyncio.gather(*hash_check_tasks)

        # Process results, mapping back to filename based on the order (or hash if needed)
        for i, filename in enumerate(filenames_with_hashes):
            result = hash_vt_results[i]
            if result and isinstance(result, dict):
                 attachments_analysis["Hash_Analysis"][filename] = result
                 # Check if VT result itself indicates an error
                 if result.get("error"):
                      logger.warning(f"VT check failed for hash of '{filename}': {result.get('error')} - {result.get('message')}")
                 attributes = result.get("attributes", {})
                 stats = attributes.get("last_analysis_stats", {})
                 malicious = stats.get("malicious", 0)
                 suspicious = stats.get("suspicious", 0)
                 if malicious > 0:
                      note = f"VirusTotal detected malicious indicators ({malicious}) for attachment '{filename}' hash."
                      attachments_analysis["Suspicious_Indicators"].append(note)
                      logger.warning(note)
                 elif suspicious > 0:
                      note = f"VirusTotal detected suspicious indicators ({suspicious}) for attachment '{filename}' hash."
                      attachments_analysis["Suspicious_Indicators"].append(note)
                      logger.warning(note)

            else:
                  logger.error(f"Received unexpected result format from VT hash check for {filename}: {result}")
                  attachments_analysis["Hash_Analysis"][filename] = {"error": "internal_error", "message": "Invalid result format from VT check."}

    else:
        logger.info("No valid attachment hashes found to check via VirusTotal.")

    # Cleanup temporary payload storage
    del attachment_payloads

    logger.info(f"Attachment analysis complete. Found {len(attachments_analysis['Suspicious_Indicators'])} suspicious indicators.")
    return attachments_analysis