# src/report_generator.py

import json
from typing import Dict, Any, Optional, List
import textwrap
import logging
import os 
from config.config import CONFIG
import ipaddress
import re

# Use colorama for cross-platform colored terminal output
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True) # Initialize colorama to automatically reset styles
except ImportError:
    # Define dummy color objects if colorama is not installed
    logging.getLogger(__name__).warning("colorama library not found. Console report will lack colors.")
    class DummyStyle:
        def __getattr__(self, name):
            return "" # Return empty string for any color attribute
    Fore = Back = Style = DummyStyle() # Assign dummy class to all color objects

logger = logging.getLogger(__name__)

# --- Enhanced Color Scheme ---
# Define colors for different elements of the report for better readability
COLORS = {
    "header": Fore.MAGENTA + Style.BRIGHT,       # Main section titles
    "section": Fore.CYAN + Style.BRIGHT,         # Sub-section titles
    "subsection": Fore.BLUE + Style.BRIGHT,      # Lower-level titles
    "key": Fore.GREEN,                          # Keys in key-value pairs
    "value": Fore.WHITE,                        # Values in key-value pairs
    "value_bright": Fore.WHITE + Style.BRIGHT,  # Important values
    "verdict_clean": Fore.GREEN + Style.BRIGHT,  # Clean verdict
    "verdict_suspicious": Fore.YELLOW + Style.BRIGHT, # Suspicious verdict
    "verdict_malicious": Fore.RED + Style.BRIGHT,   # Malicious verdict
    "error": Fore.RED + Style.BRIGHT,           # Error messages
    "warning": Fore.YELLOW,                     # Warning messages/indicators
    "info": Fore.BLUE,                          # Informational text (like VT cache status)
    "highlight": Back.YELLOW + Fore.BLACK + Style.BRIGHT, # Highlighting specific text
    "dim": Style.DIM,                           # Less important details
    "reset": Style.RESET_ALL                    # Reset all styles (handled by autoreset=True now)
}

# --- Helper Functions for Formatting ---

def draw_box(title: str, color: str = COLORS["header"], width: int = 80) -> str:
    """Draws a decorative box around a title with specified color."""
    padding = 2
    title_text = f" {title} "
    line_len = width - (padding * 2)
    if len(title_text) > line_len:
        # Truncate title if too long for the box width
        title_text = title_text[:line_len - 3] + "... "

    side_len = (line_len - len(title_text)) // 2
    left_border = "═" * side_len
    right_border = "═" * (line_len - len(title_text) - side_len)

    top_border = f"╔{'═' * line_len}╗"
    middle = f"║{left_border}{Style.BRIGHT}{title_text}{Style.NORMAL}{right_border}║"
    bottom_border = f"╚{'═' * line_len}╝"

    return f"\n{color}{top_border}\n{color}{middle}\n{color}{bottom_border}{COLORS['reset']}"


def wrap_text(text: str, width: int = 78, indent: str = '  ', subsequent_indent: Optional[str] = None) -> str:
    """Wraps text neatly for console output with indentation."""
    if not isinstance(text, str):
        text = str(text) # Ensure input is string

    if subsequent_indent is None:
        subsequent_indent = indent # Default subsequent indent to match initial indent

    # Use textwrap for reliable wrapping
    wrapper = textwrap.TextWrapper(
        width=width,
        initial_indent=indent,
        subsequent_indent=subsequent_indent,
        replace_whitespace=False, 
        drop_whitespace=True, 
        break_long_words=False 
    )
    wrapped_lines = wrapper.wrap(text)
    return '\n'.join(wrapped_lines)

def format_key_value(key: str, value: Any, indent: str = '  ', key_width: int = 25) -> str:
    """Formats a key-value pair for aligned output."""
    key_str = f"{indent}{COLORS['key']}{key+':':<{key_width}}{COLORS['reset']}"
    value_str = f"{COLORS['value']}{value}{COLORS['reset']}"
    return f"{key_str} {value_str}"

def format_vt_result(result: Optional[Dict[str, Any]]) -> str:
    """Formats VirusTotal result dictionary into a concise colored summary string."""
    if result is None:
         return f"{COLORS['dim']}N/A{COLORS['reset']}"
    if "error" in result:
        error_msg = result.get("message", "Unknown error")
        error_code = result.get("error", "unknown")
        # Dim 'not_found' errors, highlight others
        color = COLORS['dim'] if error_code == 'not_found' else COLORS['error']
        return f"{color}VT Error: {error_msg}{COLORS['reset']}"

    attributes = result.get("attributes", {})
    if not attributes: # Handle case where attributes might be empty but no error reported
        return f"{COLORS['warning']}VT Warning: No attributes found{COLORS['reset']}"

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_votes = attributes.get("total_votes", {}).get("harmless", 0) + attributes.get("total_votes", {}).get("malicious", 0)

    # Determine color based on malicious/suspicious count
    if malicious > 5: # High confidence malicious
        verdict_color = COLORS['verdict_malicious']
    elif malicious > 0: # Malicious
        verdict_color = COLORS['verdict_malicious']
    elif suspicious > 2: # High confidence suspicious
        verdict_color = COLORS['verdict_suspicious']
    elif suspicious > 0: # Suspicious
        verdict_color = COLORS['verdict_suspicious']
    else: # Clean
        verdict_color = COLORS['verdict_clean']

    summary = f"M:{malicious} S:{suspicious}" # H:{harmless} U:{undetected}

    # Add reputation score if available (useful for IPs/Domains)
    reputation = attributes.get("reputation")
    rep_str = ""
    if reputation is not None:
         rep_color = COLORS['success'] if reputation > 0 else COLORS['warning'] if reputation == 0 else COLORS['error']
         rep_str = f" Rep:{rep_color}{reputation}{verdict_color}" # Use verdict color for context

    # Add total votes if available (useful for URLs)
    votes_str = f" Votes:{total_votes}" if total_votes > 0 else ""


    cached = result.get("cached", False)
    cache_str = f" {COLORS['dim']}(Cached){verdict_color}" if cached else ""

    return f"{verdict_color}{summary}{rep_str}{votes_str}{cache_str}{COLORS['reset']}"


def format_auth_result(auth_type: str, result: Dict[str, Any]) -> str:
    """Formats SPF, DKIM, or DMARC result dictionary into a colored string."""
    status = result.get('result', 'unknown').lower()
    domain = result.get('domain', result.get('domain_to_check', 'N/A')) # Get relevant domain
    source = result.get('source', None)
    policy = result.get('policy', None) # For DMARC

    # Determine color based on status
    if status == 'pass':
        #color = COLORS['success']
        color = COLORS['verdict_clean']
    elif status in ['fail', 'permerror', 'temperror', 'policy_override', 'invalid', 'error']:
        color = COLORS['error']
    elif status in ['softfail', 'neutral', 'none', 'signature_present_needs_verification', 'policy_missing_tag', 'dns_error', 'dns_timeout']:
        color = COLORS['warning']
    elif status in ['not_found', 'checking_disabled_dnspython_missing', 'checking_disabled_no_from_domain', 'not_checked_yet', 'no_dns_record', 'dns_nxdomain', 'dns_no_answer']:
        color = COLORS['dim']
    else: # Unknown status
        color = COLORS['value_bright']

    # Build the string
    output = f"{color}{status.upper()}{COLORS['reset']}"
    if domain and domain != 'N/A':
        output += f" (Domain: {COLORS['value_bright']}{domain}{COLORS['reset']}"
        # Add selector for DKIM
        if auth_type == 'DKIM' and result.get('selector'):
            output += f", Sel: {result['selector']}"
        output += ")"
    if auth_type == 'DMARC' and policy:
         output += f" (Policy: {COLORS['value_bright']}{policy.upper()}{COLORS['reset']})"
    if source and source not in ['auth_results']: # Optionally show non-standard source
         output += f" {COLORS['dim']}[{source}]{COLORS['reset']}"

    return output

# --- Printing Functions for Report Sections ---

def print_information(info: Dict[str, Any]) -> None:
    """Prints the general information section."""
    print(draw_box('General Information', color=COLORS["section"]))
    print(format_key_value("Filename", info.get('Filename', 'N/A')))
    print(format_key_value("Analysis Date", info.get('AnalysisDate', 'N/A')))
    print(format_key_value("Status", info.get('Status', 'N/A')))
    print(format_key_value("Duration", f"{info.get('DurationSeconds', 'N/A')} seconds"))
    print(format_key_value("AI Enabled", info.get('AI_Enabled', False)))
    print(format_key_value("VirusTotal Enabled", info.get('VT_Enabled', False)))
    print(format_key_value("OCR Enabled", CONFIG.get("OCR_ENABLED", False))) # Show OCR status from config
    if info.get('Error'):
        print(format_key_value(f"{COLORS['error']}Analysis Error", info['Error']))

def print_hashes(hashes: Optional[Dict[str, str]]) -> None:
    """Prints file hashes if available."""
    if not hashes or hashes.get('md5') == 'error': # Check if hashing failed
         print(draw_box('File Hashes', color=COLORS["warning"]))
         print(f"  {COLORS['warning']}Hashing failed or no data to hash.{COLORS['reset']}")
         return

    if not hashes.get('md5'): # Check if hashes are empty (e.g. empty file)
         print(draw_box('File Hashes', color=COLORS["info"]))
         print(f"  {COLORS['info']}No hashes generated (likely empty file).{COLORS['reset']}")
         return

    print(draw_box('File Hashes', color=COLORS["section"]))
    print(format_key_value("MD5", hashes.get('md5', 'N/A'), key_width=10))
    print(format_key_value("SHA1", hashes.get('sha1', 'N/A'), key_width=10))
    print(format_key_value("SHA256", hashes.get('sha256', 'N/A'), key_width=10))

def print_headers(headers: Optional[Dict[str, Any]], verbose: bool) -> None:
    """Prints the header analysis section."""
    if not headers:
        print(draw_box('Header Analysis', color=COLORS["warning"]))
        print(f"  {COLORS['warning']}Header analysis data is missing.{COLORS['reset']}")
        return

    print(draw_box('Header Analysis'))
    if headers.get("error"):
         print(f"  {COLORS['error']}Header analysis failed: {headers['error']}{COLORS['reset']}")
         # Print basic headers even if full analysis failed
         # print(format_key_value("Subject", headers.get('Subject', 'N/A')))
         return # Stop here if analysis failed

    # Basic Info
    print(format_key_value("Subject", headers.get('Subject', 'N/A')))
    print(format_key_value("From", headers.get('From', 'N/A')))
    print(format_key_value("From Domain", headers.get('From_Domain', 'N/A')))
    print(format_key_value("Reply-To", headers.get('Reply-To', 'N/A')))
    print(format_key_value("To", headers.get('To', 'N/A')))
    if verbose:
        print(format_key_value("Date", headers.get('Date', 'N/A')))
        print(format_key_value("Message-ID", headers.get('Message-ID', 'N/A')))

    # Authentication Results
    auth = headers.get("Authentication", {})
    print(f"\n{COLORS['subsection']}  Authentication Results:{COLORS['reset']}")
    print(f"    {'SPF:':<8} {format_auth_result('SPF', auth.get('spf', {}))}")
    print(f"    {'DKIM:':<8} {format_auth_result('DKIM', auth.get('dkim', {}))}")
    print(f"    {'DMARC:':<8} {format_auth_result('DMARC', auth.get('dmarc', {}))}")
    if auth.get('errors'):
        print(f"    {COLORS['warning']}Auth Parsing Issues:{COLORS['reset']}")
        for err in auth['errors']:
            print(wrap_text(f"- {err}", width=74, indent='      '))

    # IP Analysis (VirusTotal)
    ip_analysis = headers.get("IP_Analysis", {})
    if ip_analysis:
        print(f"\n{COLORS['subsection']}  Received IP Address Checks (VirusTotal):{COLORS['reset']}")
        sorted_ips = sorted(ip_analysis.keys(), key=lambda ip: ipaddress.ip_address(ip)) # Sort IPs for readability
        for ip in sorted_ips:
             result = ip_analysis[ip]
             print(f"    {COLORS['value_bright']}{ip:<18}{COLORS['reset']} {format_vt_result(result)}")

    # Suspicious Header Indicators
    suspicious = headers.get("Suspicious_Headers", [])
    if suspicious:
        print(f"\n{COLORS['warning']}  ⚠️ Suspicious Header Indicators Found:{COLORS['reset']}")
        for item in suspicious:
            print(wrap_text(f"- {item}", width=76, indent='    ', subsequent_indent='      '))

    # From Domain Typosquatting Check Result
    typo_from = headers.get("Typosquatting_From")
    if typo_from:
         print(f"\n{COLORS['warning']}  ⚠️ Typosquatting Alert (From Domain):{COLORS['reset']}")
         print(f"    Domain '{headers.get('From_Domain')}' looks similar to known brand '{COLORS['value_bright']}{typo_from.get('similar_to')}{COLORS['reset']}' (Distance: {typo_from.get('distance')})")


    if verbose and headers.get("Received_Chain"):
        print(f"\n{COLORS['subsection']}  Received Header Chain (Newest to Oldest):{COLORS['reset']}")
        for i, item in enumerate(headers["Received_Chain"]):
            ips = ', '.join(item.get('parsed_ips', []))
            ips_str = f" (IPs: {COLORS['value_bright']}{ips}{COLORS['reset']})" if ips else ""
            print(wrap_text(f"{i+1}: {item.get('raw', 'N/A')}{ips_str}", width=78, indent='    ', subsequent_indent='       '))


def print_body(body: Optional[Dict[str, Any]], verbose: bool) -> None:
    """Prints the body analysis section."""
    if not body:
        print(draw_box('Body Analysis', color=COLORS["warning"]))
        print(f"  {COLORS['warning']}Body analysis data is missing.{COLORS['reset']}")
        return

    print(draw_box('Body Analysis'))
    if body.get("error"):
        print(f"  {COLORS['error']}Body analysis failed: {body['error']}{COLORS['reset']}")
        return

    # Content Snippets
    if verbose:
        if body.get("Text"):
            print(f"\n{COLORS['subsection']}  Plain Text Snippet:{COLORS['reset']}")
            print(wrap_text(body["Text"], width=76, indent='  > '))
        if body.get("HTML"):
            print(f"\n{COLORS['subsection']}  HTML Snippet:{COLORS['reset']}")
            html_snippet = body["HTML"]
            html_snippet = re.sub('<style.*?</style>', '', html_snippet, flags=re.DOTALL | re.IGNORECASE)
            html_snippet = re.sub('<script.*?</script>', '', html_snippet, flags=re.DOTALL | re.IGNORECASE)
            html_snippet = re.sub('<[^>]+>', ' ', html_snippet) # Replace tags with space
            html_snippet = ' '.join(html_snippet.split()) # Normalize whitespace
            print(wrap_text(html_snippet[:1000] + ('...' if len(html_snippet)>1000 else ''), width=76, indent='  > '))

    # Link Analysis (URLs, VT, Typosquatting)
    links = body.get("Links", [])
    url_analysis = body.get("URL_Analysis", {})
    typo_links = body.get("Typosquatting_Links", {})
    if links:
        print(f"\n{COLORS['subsection']}  Links Found ({len(links)} URLs):{COLORS['reset']}")
        links_to_show = links[:20] # Limit displayed links
        for url in links_to_show:
            vt_result = url_analysis.get(url)
            typo_info = ""
            if url in typo_links:
                typo = typo_links[url]
                typo_info = f" {COLORS['warning']}⚠️ [Typosquatting Alert: ~'{typo.get('similar_to')}', Dist:{typo.get('distance')}]{COLORS['reset']}"

            # Wrap long URLs
            url_display = wrap_text(url, width=74, indent='    ', subsequent_indent='      ')
            print(f"{url_display}{typo_info}")
            print(f"      {COLORS['key']}VT:{COLORS['reset']} {format_vt_result(vt_result)}")
        if len(links) > len(links_to_show):
            print(f"    {COLORS['dim']}... (and {len(links) - len(links_to_show)} more links){COLORS['reset']}")


    # Brand Impersonation Analysis
    brand_info_list = body.get("Brand_Info", [])
    if brand_info_list:
        print(f"\n{COLORS['subsection']}  Brand Impersonation Analysis:{COLORS['reset']}")
        for info in brand_info_list: 
            print(f"    {COLORS['key']}Mentioned Brands:{COLORS['reset']} {COLORS['value_bright']}{', '.join(info.get('mentioned_brands', ['None']))}{COLORS['reset']}")
            status = info.get('link_domains_match_status', 'N/A')
            # Color code status
            if status == 'match':
                status_color = COLORS['success']
            elif status == 'mismatch':
                status_color = COLORS['error']
            elif status in ['no_mentioned_brand_links', 'no_links_to_check']:
                status_color = COLORS['info']
            else:
                status_color = COLORS['warning']
            print(f"    {COLORS['key']}Link Domain Match Status:{COLORS['reset']} {status_color}{status}{COLORS['reset']}")
            if info.get('notes'):
                print(f"    {COLORS['warning']}Brand Analysis Notes:{COLORS['reset']}")
                for note in info['notes']:
                    print(wrap_text(f"- {note}", width=74, indent='      '))

    # Suspicious Body Elements
    suspicious = body.get("Suspicious_Elements", [])
    if suspicious:
        print(f"\n{COLORS['warning']}  ⚠️ Suspicious Body Elements Found:{COLORS['reset']}")
        for item in suspicious:
            print(wrap_text(f"- {item}", width=76, indent='    ', subsequent_indent='      '))


def print_attachments(attachments: Optional[Dict[str, Any]], verbose: bool) -> None:
    """Prints the attachment analysis section, including OCR results."""
    if not attachments:
        return

    if not attachments.get("Data"):
        print(draw_box('Attachments Analysis', color=COLORS["info"]))
        print(f"  {COLORS['info']}No attachments found in the email.{COLORS['reset']}")
        return

    print(draw_box('Attachments Analysis'))
    if attachments.get("error"): 
        print(f"  {COLORS['error']}Attachment analysis failed: {attachments['error']}{COLORS['reset']}")
        return

    attachment_data = attachments.get("Data", {})
    hash_analysis = attachments.get("Hash_Analysis", {})
    print(f"{COLORS['subsection']}  Found {len(attachment_data)} Attachment(s):{COLORS['reset']}")

    for i, (name, data) in enumerate(attachment_data.items()):
        print(f"\n  {COLORS['value_bright']}Attachment {i+1}:{COLORS['reset']}")
        print(format_key_value("Filename", name))

        if "error" in data:
            print(format_key_value(f"{COLORS['error']}Processing Error", data['error']))
            continue 

        size_kb = data.get('size', 0) / 1024
        ctype = data.get('content_type', 'unknown/unknown')
        print(format_key_value("Content Type", ctype))
        print(format_key_value("Size", f"{size_kb:.2f} KB"))

        # Display Hashes (verbose or just SHA256)
        hashes = data.get("hashes", {})
        if verbose and hashes:
            print(format_key_value("MD5", hashes.get('md5', 'N/A')))
            print(format_key_value("SHA1", hashes.get('sha1', 'N/A')))
            print(format_key_value("SHA256", hashes.get('sha256', 'N/A')))
        elif hashes and hashes.get("sha256"):
             print(format_key_value("SHA256", hashes.get('sha256', 'N/A')))

        # VirusTotal Hash Check Result
        vt_result = hash_analysis.get(name) # VT result is keyed by filename
        print(f"    {COLORS['key']}{'VT (Hash):':<25}{COLORS['reset']} {format_vt_result(vt_result)}")

        # OCR Result (if present)
        if data.get("ocr_error"):
             print(format_key_value(f"{COLORS['warning']}OCR Error", data["ocr_error"]))
        elif data.get("ocr_text") is not None: # Check for None explicitly, empty string is valid
             ocr_text = data["ocr_text"]
             print(f"    {COLORS['key']}{'OCR Text Extracted:':<25}{COLORS['reset']} ({len(ocr_text)} chars)")
             if verbose or len(ocr_text) < 500: # Show full text if short or verbose
                 if ocr_text:
                    print(wrap_text(ocr_text, width=72, indent='      > '))
                 else:
                     print(f"      {COLORS['dim']}(No text content detected by OCR){COLORS['reset']}")
             elif ocr_text: # Show snippet if long and not verbose
                 snippet = ocr_text[:400]
                 print(wrap_text(f"{snippet}...", width=72, indent='      > ', subsequent_indent='      > '))


    # Overall Suspicious Attachment Indicators
    suspicious = attachments.get("Suspicious_Indicators", [])
    if suspicious:
        print(f"\n{COLORS['warning']}  ⚠️ Suspicious Attachment Indicators Found:{COLORS['reset']}")
        for item in suspicious:
            print(wrap_text(f"- {item}", width=76, indent='    ', subsequent_indent='      '))


def print_ai_analysis(ai_data: Optional[Dict[str, Any]]) -> None:
    """Prints the AI analysis results section."""
    if not ai_data:
        # AI analysis was likely skipped or not requested
        print(draw_box('AI Analysis Summary', color=COLORS["info"]))
        print(f"  {COLORS['info']}AI analysis was not performed.{COLORS['reset']}")
        return

    print(draw_box('AI Analysis Summary'))

    if "error" in ai_data:
        print(f"  {COLORS['error']}AI Analysis Failed: {ai_data.get('message', 'Unknown AI error')}{COLORS['reset']}")
        return

    # Extract key AI findings
    verdict = ai_data.get('verdict', 'UNKNOWN').upper()
    try:
         confidence_val = float(ai_data.get('confidence', 0))
         confidence = f"{confidence_val * 100:.1f}%"
    except (ValueError, TypeError):
         confidence = f"{ai_data.get('confidence', 'N/A')} (invalid format)" # Handle non-float confidence

    try:
         score_val = int(ai_data.get('phishing_score', -1))
         phishing_score = f"{score_val}/10" if 0 <= score_val <= 10 else f"{ai_data.get('phishing_score', 'N/A')} (invalid)"
    except (ValueError, TypeError):
         phishing_score = f"{ai_data.get('phishing_score', 'N/A')} (invalid format)"

    brands = ai_data.get('identified_brands', [])
    susp_elements = ai_data.get('suspicious_elements', [])
    explanation = ai_data.get('explanation', 'No explanation provided.')

    # Determine color based on verdict
    if verdict == 'MALICIOUS':
        verdict_color = COLORS['verdict_malicious']
    elif verdict == 'SUSPICIOUS':
        verdict_color = COLORS['verdict_suspicious']
    elif verdict == 'CLEAN':
        verdict_color = COLORS['verdict_clean']
    else: # Unknown or other verdict
        verdict_color = COLORS['warning']

    # Print Summary Block
    print(format_key_value("AI Verdict", f"{verdict_color}{verdict}{COLORS['reset']}", key_width=28))
    print(format_key_value("AI Confidence", confidence, key_width=28))
    print(format_key_value("AI Phishing Score (0-10)", phishing_score, key_width=28))
    print(format_key_value("AI Identified Brands", f"{COLORS['value_bright']}{', '.join(brands) if brands else 'None'}{COLORS['reset']}", key_width=28))


    # Print Key Suspicious Elements cited by AI
    if susp_elements:
        print(f"\n{COLORS['warning']}  Key Suspicious Elements Cited by AI:{COLORS['reset']}")
        for item in susp_elements:
            print(wrap_text(f"- {item}", width=76, indent='    ', subsequent_indent='      '))

    # Print AI Explanation
    print(f"\n{COLORS['subsection']}  AI Explanation:{COLORS['reset']}")
    print(wrap_text(explanation, width=76, indent='  > '))


# --- Main Report Generation Function ---

def generate_report(results: Dict[str, Any], verbose: bool = False) -> None:
    """
    Generates and prints the full analysis report to the console using enhanced formatting.

    Args:
        results (Dict[str, Any]): The comprehensive analysis results dictionary from main.py.
        verbose (bool): Flag to control the level of detail in the report.
    """
    if not results:
        print(f"{COLORS['error']}Error: No analysis results provided to generate report.{COLORS['reset']}")
        return

    # --- Print Report Sections in Order ---
    # 1. General Information
    print_information(results.get("Information", {}))

    # Handle case where analysis failed early (e.g., parsing error)
    analysis = results.get("Analysis", {})
    if not analysis and results.get("Error"):
        print(draw_box('Analysis Failed', color=COLORS['error']))
        print(f"  {COLORS['error']}Core analysis could not be performed due to error reported above.{COLORS['reset']}")
        print(f"\n{draw_box('End of Report', color=COLORS['section'])}")
        return

    # 2. File Hashes
    print_hashes(analysis.get("FileHashes"))

    # 3. Header Analysis
    print_headers(analysis.get("Headers"), verbose)

    # 4. Body Analysis
    print_body(analysis.get("Body"), verbose)

    # 5. Attachment Analysis
    print_attachments(analysis.get("Attachments"), verbose)

    # 6. AI Analysis Summary (if performed)
    print_ai_analysis(analysis.get("AI_Analysis"))

    # --- End of Report ---
    print(f"\n{draw_box('End of Report', color=COLORS['section'])}")