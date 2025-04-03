# Advanced Email Phishing Detector V3 

This tool analyzes email files (.eml, .msg) to detect potential phishing attempts using a multi-faceted approach including header analysis, content inspection, external threat intelligence (VirusTotal), Optical Character Recognition (OCR) for images, and optional AI-powered assessment.
v2 link: https://github.com/hithamO/email-phishing-detector-test

## Features

### Comprehensive Parsing
- Extracts headers, body (text/html), attachments, and structure from `.eml` and `.msg` files.

### Header Analysis
- Decodes standard headers (Subject, From, To, Reply-To).
- Parses authentication results (SPF, DKIM, DMARC) from headers.
- Performs DNS lookup for DMARC policy (requires `dnspython`).
- Identifies suspicious patterns (e.g., From/Reply-To mismatch).
- Extracts originating IP addresses from `Received` headers.

### Body Analysis
- Extracts plain text and HTML content.
- Identifies and extracts URLs.
- Detects suspicious elements in HTML (forms, hidden text, JavaScript, shorteners).
- Analyzes links for potential brand impersonation and typosquatting (requires `python-Levenshtein`).

### Attachment Analysis
- Extracts attachment metadata (filename, size, content type).
- Generates MD5, SHA1, SHA256 hashes.
- Identifies suspicious attachment types/names (executables, archives, double extensions).
- **OCR Integration:** Extracts text from image attachments (requires Tesseract, `Pillow`, `pytesseract`).

### VirusTotal Integration
- Checks extracted IPs, URLs, and attachment hashes against VirusTotal API v3.
- Uses asynchronous requests (`aiohttp`) for efficiency.
- Caches VT results in a local SQLite database (`aiosqlite`) to reduce API calls and speed up re-analysis.

### AI-Powered Assessment (Optional)
- Sends a detailed report of all findings to a configured AI model (e.g., via OpenRouter).
- Prompts the AI to provide a structured JSON response including:
  - Phishing Score (0-10)
  - Verdict (CLEAN, SUSPICIOUS, MALICIOUS)
  - Confidence Score
  - Detailed Explanation
  - List of Suspicious Elements
  - Identified Brands

### Reporting
- Generates a detailed, colorized report on the console (`colorama`).
- Optionally saves the full analysis results (including AI response) to a JSON file.

## Setup

### 1. Clone the Repository
```bash
git clone <repository_url>
cd <repository_directory>
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Tesseract OCR Engine

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install tesseract-ocr tesseract-ocr-eng
```

**macOS:**
```bash
brew install tesseract tesseract-lang
```

**Windows:** Download the installer from [Tesseract OCR GitHub](https://github.com/tesseract-ocr/tessdoc) and ensure Tesseract is added to your system's PATH during installation.

### 5. Configure API Keys

**VirusTotal API Key:**
```bash
export VIRUSTOTAL_API_KEY="your_vt_api_key"
# Windows (cmd): set VIRUSTOTAL_API_KEY=your_vt_api_key
# Windows (PowerShell): $env:VIRUSTOTAL_API_KEY="your_vt_api_key"
```

**AI Provider API Key (Optional, e.g., OpenRouter):**
```bash
export OPENROUTER_API_KEY="your_ai_api_key"
```

### 6. Review Configuration
Modify `config/config.py` for additional settings:
- `AI_MODEL`: Specify the AI model.
- `DATABASE_PATH`: Set database location.
- `CACHE_DURATION_SECONDS`: Set VirusTotal cache duration.
- `OCR_ENABLED`, `OCR_LANGUAGES`, `TESSERACT_CMD`.
- `LOG_LEVEL`.

## Usage

Run the analysis from the command line:
```bash
python main.py -f <path_to_email_file.eml> [options]
```

### Arguments
- `-f, --file`: (Required) Path to the email file (.eml or .msg) to analyze.
- `--ai`: (Optional) Enable AI-based analysis.
- `-o, --output`: (Optional) Save analysis results as a JSON file.
- `-v, --verbose`: (Optional) Enable verbose console output.

### Examples
Basic analysis:
```bash
python main.py -f suspicious_email.eml
```

Analysis with AI enabled and save results to JSON:
```bash
python main.py -f urgent_invoice.msg --ai -o report.json
```

Verbose console report:
```bash
python main.py -f newsletter.eml -v
```

## Flowchart
```plaintext
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

```

## Key Components

- **`main.py`**: Orchestrates the analysis workflow.
- **`config/config.py`**: Manages API keys and settings.
- **`src/email_parser.py`**: Parses `.eml` and `.msg` files.
- **`src/database_manager.py`**: Manages VirusTotal cache in SQLite.
- **`src/security_analyzer.py`**: Performs header, body, and attachment analysis.
- **`src/ai_integration.py`**: Handles AI-based assessment.
- **`src/report_generator.py`**: Generates console reports.

## TODO / Potential Improvements

- **DMARC Alignment Check**: Implement full DMARC verification.
- **URL Unshortening**: Integrate a service for resolving shortened URLs.
- **Sandbox Integration**: Submit attachments to a sandbox environment.
- **HTML Rendering**: Use BeautifulSoup and html2text for improved parsing.
- **Configuration Updates**: Move known domains and suspicious TLDs to external config files.
- **Error Handling**: Improve resilience in case of partial failures.
- **Testing**: Add unit and integration tests.
