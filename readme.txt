# Advanced Email Phishing Detector

This tool analyzes email files (.eml, .msg) to detect potential phishing attempts using a multi-faceted approach including header analysis, content inspection, external threat intelligence (VirusTotal), Optical Character Recognition (OCR) for images, and optional AI-powered assessment.

## Features

*   **Comprehensive Parsing:** Extracts headers, body (text/html), attachments, and structure from `.eml` and `.msg` files.
*   **Header Analysis:**
    *   Decodes standard headers (Subject, From, To, Reply-To).
    *   Parses authentication results (SPF, DKIM, DMARC) from headers.
    *   Performs DNS lookup for DMARC policy (requires `dnspython`).
    *   Identifies suspicious patterns (e.g., From/Reply-To mismatch).
    *   Extracts originating IP addresses from `Received` headers.
*   **Body Analysis:**
    *   Extracts plain text and HTML content.
    *   Identifies and extracts URLs.
    *   Detects suspicious elements in HTML (forms, hidden text, javascript, shorteners).
    *   Analyzes links for potential brand impersonation and typosquatting (requires `python-Levenshtein`).
*   **Attachment Analysis:**
    *   Extracts attachment metadata (filename, size, content type).
    *   Generates MD5, SHA1, SHA256 hashes.
    *   Identifies suspicious attachment types/names (executables, archives, double extensions).
    *   **OCR Integration:** Extracts text from image attachments (requires Tesseract, `Pillow`, `pytesseract`).
*   **VirusTotal Integration:**
    *   Checks extracted IPs, URLs, and attachment hashes against VirusTotal API v3.
    *   Uses asynchronous requests (`aiohttp`) for efficiency.
    *   Caches VT results in a local SQLite database (`aiosqlite`) to reduce API calls and speed up re-analysis.
*   **AI-Powered Assessment (Optional):**
    *   Sends a detailed report of all findings to a configured AI model (e.g., via OpenRouter).
    *   Prompts the AI to provide a structured JSON response including:
        *   Phishing Score (0-10)
        *   Verdict (CLEAN, SUSPICIOUS, MALICIOUS)
        *   Confidence Score
        *   Detailed Explanation
        *   List of Suspicious Elements
        *   Identified Brands
*   **Reporting:**
    *   Generates a detailed, colorized report on the console (`colorama`).
    *   Optionally saves the full analysis results (including AI response) to a JSON file.

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Tesseract OCR Engine:**
    *   This tool relies on Google's Tesseract OCR engine, which must be installed separately.
    *   **Ubuntu/Debian:** `sudo apt update && sudo apt install tesseract-ocr tesseract-ocr-eng` (install other language packs like `tesseract-ocr-fra` as needed).
    *   **macOS:** `brew install tesseract tesseract-lang`
    *   **Windows:** Download installer from the official Tesseract repository: [https://github.com/tesseract-ocr/tessdoc](https://github.com/tesseract-ocr/tessdoc). **Ensure Tesseract is added to your system's PATH during installation**, or update `TESSERACT_CMD` in `config/config.py` with the full path to `tesseract.exe`.
    *   **Install Language Packs:** Make sure you install the language packs corresponding to the `OCR_LANGUAGES` setting in `config/config.py`.

5.  **Configure API Keys:**
    *   **VirusTotal:** Obtain an API key from [VirusTotal](https://www.virustotal.com/). Set it as an environment variable:
        ```bash
        export VIRUSTOTAL_API_KEY="your_vt_api_key"
        # On Windows use `set VIRUSTOTAL_API_KEY=your_vt_api_key` (cmd)
        # or `$env:VIRUSTOTAL_API_KEY="your_vt_api_key"` (PowerShell)
        ```
        Alternatively, you can hardcode it in `config/config.py` (NOT RECOMMENDED).
    *   **AI Provider (e.g., OpenRouter):** Obtain an API key from your chosen AI provider compatible with the OpenAI API standard (like OpenRouter.ai). Set it as an environment variable:
        ```bash
        export OPENROUTER_API_KEY="your_ai_api_key"
        # Or equivalent set command for Windows
        ```
        Alternatively, edit `config/config.py`.

6.  **Review Configuration:**
    *   Check `config/config.py` for other settings like:
        *   `AI_MODEL`: Ensure the chosen model is available via your API provider/URL.
        *   `DATABASE_PATH`: Location for the VT cache database. The directory will be created if it doesn't exist.
        *   `CACHE_DURATION_SECONDS`: How long VT results are cached.
        *   `OCR_ENABLED`, `OCR_LANGUAGES`, `TESSERACT_CMD`.
        *   `LOG_LEVEL`.

## Usage

Run the analysis from the command line:

```bash
python main.py -f <path_to_email_file.eml> [options]

Arguments:

-f, --file (Required): Path to the email file (.eml or .msg) to analyze.

--ai (Optional): Enable AI-based analysis. Requires AI_API_KEY to be configured.

-o, --output (Optional): Path to save the full analysis results as a JSON file.

-v, --verbose (Optional): Enable verbose console report output (shows more details like content snippets).

Examples:

Basic analysis:

python main.py -f suspicious_email.eml
Use code with caution.
Bash
Analysis with AI enabled and save results to JSON:

python main.py -f urgent_invoice.msg --ai -o report.json
Use code with caution.
Bash
Verbose console report:

python main.py -f newsletter.eml -v
Use code with caution.


# flowchart

+-------------------------+      +-------------------------+      +-----------------------+
|   Start (main.py)       | ---> |  Parse Command Line Args| ---> | Validate Input File   |
| (Input: email file path)|      | (file, --ai, -o, -v)    |      | (Exists? Size? Ext?)  |
+-------------------------+      +------------+------------+      +-----------+-----------+
                                              |                              | (Error -> Exit)
                                              |                              |
                                              v                              v (OK)
+-------------------------+      +------------+------------+      +-----------+-----------+
|  Initialize Components  | <--+ | Run Full Analysis Async |      |  Parse Email File     |
| (DB Manager, VT Client)|      | (run_full_email_analysis)| ---> | (email_parser.py)     |
+-------------------------+      +------------+------------+      +-----------+-----------+
                                              |                              | (Error -> Exit)
                                              |                              |
                                              v                              v (OK)
+-------------------------+      +-------------------------+      +-----------+-----------+
| Generate File Hashes    |      | Start Concurrent Tasks  |      |   EmailMessage Obj    |
| (security_analyzer)     | <--- |  (analyze_headers,     |      |   Raw Content String  |
+-------------------------+      |   analyze_body,         |      +-----------------------+
                               |   analyze_attachments)  |
                               +------------+------------+
                                            |
                                            v (Await Tasks)
+---------------------------+      +-------------------------+      +-------------------------+
|    Analyze Attachments    | <---|                         | ---> |     Analyze Headers     |
| - Metadata, Hashes        |      |   Gather Task Results   |      | - Decode, Auth, IPs     |
| - OCR (if image, enabled) |      | (Handle Exceptions)     |      | - VT IP Checks          |
| - VT Hash Checks          |      +-----------+-------------+      | - Suspicious Indicators |
| (security_analyzer)       |                  |                    | (security_analyzer)       |
+---------------------------+                  |                    +-------------------------+
          |                                    |                                    |
          |------------------------------------|------------------------------------|
                                               |
                                               v
+-------------------------+      +-------------+-----------+      +-------------------------+
|   Analyze Body          | <----|  Combine Analysis Data  |      | AI Analysis (Optional)  |
| - Text/HTML Content     |      +-------------------------+ ---> | - Build Prompt          |
| - Links, URL Checks (VT)|                  |                    | - Call AI API           |
| - Typosquatting         |                  |                    | - Parse JSON Response   |
| - Brand Impersonation   |                  |                    | (ai_integration.py)     |
| (security_analyzer)       |                  |                    +-----------+-------------+
+-------------------------+                  |                                | (Store AI Result)
                                               v
+-------------------------+      +-------------------------+      +-----------+-----------+
|  Generate Console Report| <--- |   Finalize Results Dict |      | Save Results to JSON? |
| (report_generator.py)   |      | (Set Status, Duration)  | ---> | (If -o specified)     |
+-------------+-----------+      +------------+------------+      +-----------------------+
              |                             |
              v                             v
+-------------+-----------+      +----------+----------+
| Display Report to User  |      | Prune Database Cache|
+-------------------------+      +---------------------+
              |
              v
+-------------+-----------+
|      End (Exit Code)    |
+-------------------------+


Key Components
main.py: Orchestrates the analysis workflow, handles arguments, calls other modules.

config/config.py: Manages configuration settings (API keys, paths, timeouts, features).

src/email_parser.py: Parses .eml and .msg files into usable EmailMessage objects.

src/database_manager.py: Handles SQLite database interaction for caching VT results asynchronously.

src/security_analyzer.py: Contains the core logic for analyzing headers, body, and attachments, including VT checks, OCR, and indicator extraction. Defines the VirusTotalClient.

src/ai_integration.py: Builds the prompt for the AI model and handles the API interaction.

src/report_generator.py: Formats the analysis results into a human-readable console report.

TODO / Potential Improvements
DMARC Alignment Check: Implement full DMARC alignment verification based on SPF/DKIM results and domains, not just DNS policy lookup.

URL Unshortening: Integrate a service or library to resolve shortened URLs before VT checks.

Sandbox Integration: Add capability to submit attachments to a sandbox environment (e.g., Cuckoo, ANY.RUN) for dynamic analysis.

HTML Rendering: Use libraries like BeautifulSoup and html2text for more sophisticated HTML analysis and cleaner text extraction.

Configuration: Move KNOWN_BRAND_DOMAINS and SUSPICIOUS_TLDS to external configuration files (e.g., JSON, YAML) for easier updates.

Error Handling: More granular error handling and potentially allow analysis to continue even if one minor component fails.

Testing: Add unit and integration tests.