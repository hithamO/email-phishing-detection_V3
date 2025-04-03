# config/config.py

# This is the V3.1 of code. So every edit here is an update of V2 code 
import os
from typing import Dict, List, Any, Tuple
import logging
import sys # Added for stderr output on critical errors

# Initialize logger early to catch issues during config load
logging.basicConfig(level="INFO", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Config:
    """
    Configuration management class for the Email Phishing Detector.

    Loads default settings and allows overriding them via environment variables
    or a dictionary. Includes basic validation for critical parameters.

    Access configuration values using CONFIG.get('KEY_NAME').
    """

    # Default configuration values
    DEFAULTS: Dict[str, Any] = {
        # AI Integration (e.g., OpenRouter supporting various models)
        # V2 was working for Openrouter only
        "AI_API_URL": "https://openrouter.ai/api/v1/chat/completions",
        "AI_API_KEY": os.getenv("OPENROUTER_API_KEY", ""), # Get API key from environment (security reasons)
        "AI_MODEL": "deepseek/deepseek-chat", # Specify the AI model (ensure compatibility with API_URL)
        "AI_TIMEOUT": (10, 60),  # Connect timeout (10s), read timeout (60s) for AI API
        "AI_MAX_TOKENS": 2000, # Max tokens for AI response generation
        "AI_TEMPERATURE": 0.2, # AI creativity setting (lower is more deterministic, higher is more creative)

        # VirusTotal Integration
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""), # Get VT key from environment (security reasons)
        "VT_TIMEOUT": (10, 30), # Connect timeout (10s), read timeout (30s) for VT API
        "VT_REQUEST_DELAY_SECONDS": 1.0, # Delay between VT requests (float, public API requires >= 1s for some endpoints)

        # Database Caching
        "DATABASE_PATH": "cache/vt_cache.db", # Path to the SQLite cache file (directory must exist or be creatable)
        "CACHE_DURATION_SECONDS": 6 * 3600, # Cache VT results for 6 hours (21600 seconds)

        # OCR (Optical Character Recognition) for Images in Attachments (New section)
        "OCR_ENABLED": True, # Enable/disable OCR processing for image attachments
        "OCR_LANGUAGES": ['eng'], # List of languages for Tesseract-OCR (e.g., ['eng', 'fra']) - Requires installing corresponding language packs for Tesseract | we will work with ENG for the prototype
        "TESSERACT_CMD": None, # Specify explicit path to tesseract executable if not in PATH (e.g., r'C:\Program Files\Tesseract-OCR\tesseract.exe')

        # File Handling
        "SUPPORTED_FILES": [".eml", ".msg"], # Allowed email file extensions (Just two for the prototype purpose)
        "MAX_FILE_SIZE": 10 * 1024 * 1024,  # Max email file size: 10MB

        # General
        "DATE_FORMAT": "%Y-%m-%d %H:%M:%S", # Date format used in reports and logging timestamps
        "USER_AGENT": "EmailPhishingDetector/1.1 (Async+OCR)", # User agent string for HTTP requests
        "LOG_LEVEL": "INFO", # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        "LOG_FORMAT": '%(asctime)s - %(name)s - %(levelname)s - %(message)s' # Log message format
    }

    def __init__(self, overrides: Dict = None):
        """
        Initializes the configuration object.

        Loads defaults, applies overrides if provided, and validates settings.

        Args:
            overrides (Dict, optional): Dictionary of settings to override defaults. Defaults to None.
        """
        self.config = self.DEFAULTS.copy()
        if overrides:
            # Ensure overrides are applied correctly
            for key, value in overrides.items():
                 if key in self.config:
                     self.config[key] = value
                 else:
                     logger.warning(f"Override provided for unknown config key: {key}")


        # Ensure API keys from environment are loaded if not present or empty after potential overrides
        if not self.config.get("AI_API_KEY"):
             self.config["AI_API_KEY"] = os.getenv("OPENROUTER_API_KEY", "")
        if not self.config.get("VIRUSTOTAL_API_KEY"):
            self.config["VIRUSTOTAL_API_KEY"] = os.getenv("VIRUSTOTAL_API_KEY", "")

        try:
            self.validate()
            logger.info("Configuration loaded and validated.")
            if not self.config.get("AI_API_KEY"):
                logger.warning("AI_API_KEY is not configured. AI analysis will be disabled or fail.")
            if not self.config.get("VIRUSTOTAL_API_KEY"):
                logger.warning("VIRUSTOTAL_API_KEY is not configured. VirusTotal checks will be disabled or fail.")
            if self.config.get("OCR_ENABLED"):
                 # Check if pytesseract command path needs setting (useful for Windows or non-standard installs)
                 tesseract_cmd_path = self.config.get("TESSERACT_CMD")
                 if tesseract_cmd_path:
                     try:
                         import pytesseract
                         pytesseract.pytesseract.tesseract_cmd = tesseract_cmd_path
                         logger.info(f"Set Tesseract command path to: {tesseract_cmd_path}")
                     except ImportError:
                         logger.warning("pytesseract library not found, cannot set Tesseract command path. OCR will fail.")
                     except Exception as e:
                          logger.error(f"Error setting Tesseract command path: {e}")


        except ValueError as e:
             logger.critical(f"CRITICAL CONFIGURATION ERROR: {e}")
             print(f"CRITICAL CONFIGURATION ERROR: {e}", file=sys.stderr)
             sys.exit(1) # Exit if configuration is fundamentally broken

        # Apply logging configuration after validation
        self._configure_logging()

    def _configure_logging(self):
         """Configures the root logger based on settings."""
         log_level = self.config.get("LOG_LEVEL", "INFO").upper()
         log_format = self.config.get("LOG_FORMAT")
         # Ensure the logger level is valid
         numeric_level = getattr(logging, log_level, None)
         if not isinstance(numeric_level, int):
             log_level = "INFO" # Default to INFO if invalid level specified
             numeric_level = getattr(logging, log_level, None)
             logger.warning(f"Invalid LOG_LEVEL configured. Defaulting to {log_level}.")

         # Reconfigure the root logger
         # Use force=True if running in environments like Jupyter where basicConfig might have run already
         logging.basicConfig(level=numeric_level, format=log_format, force=True)
         logger.info(f"Logging configured to level {log_level}.")


    def validate(self) -> None:
        """
        Performs basic validation on critical configuration parameters.

        Raises:
            ValueError: If a configuration value is invalid.
        """
        if not isinstance(self.config["SUPPORTED_FILES"], list) or not all(isinstance(ext, str) and ext.startswith('.') for ext in self.config["SUPPORTED_FILES"]):
            raise ValueError("CONFIG: SUPPORTED_FILES must be a list of strings starting with '.'.")
        if not isinstance(self.config["MAX_FILE_SIZE"], int) or self.config["MAX_FILE_SIZE"] <= 0:
            raise ValueError("CONFIG: MAX_FILE_SIZE must be a positive integer.")

        # Timeout Validations
        for key in ["AI_TIMEOUT", "VT_TIMEOUT"]:
            timeout = self.config[key]
            if not isinstance(timeout, tuple) or len(timeout) != 2 or not all(isinstance(t, (int, float)) and t >= 0 for t in timeout):
                raise ValueError(f"CONFIG: {key} must be a tuple of two non-negative numbers (connect_timeout, read_timeout). Found: {timeout}")

        if not isinstance(self.config["VT_REQUEST_DELAY_SECONDS"], (int, float)) or self.config["VT_REQUEST_DELAY_SECONDS"] < 0:
             raise ValueError("CONFIG: VT_REQUEST_DELAY_SECONDS must be a non-negative number.")
        if not isinstance(self.config["CACHE_DURATION_SECONDS"], int) or self.config["CACHE_DURATION_SECONDS"] < 0:
             raise ValueError("CONFIG: CACHE_DURATION_SECONDS must be a non-negative integer.")
        if not isinstance(self.config["DATABASE_PATH"], str) or not self.config["DATABASE_PATH"]:
             raise ValueError("CONFIG: DATABASE_PATH must be a non-empty string.")

        # Validate Logging Level string before trying to use it
        log_level_str = self.config["LOG_LEVEL"].upper()
        if log_level_str not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
             # Log a warning here, but allow fallback in _configure_logging
             logger.warning(f"CONFIG: Invalid LOG_LEVEL '{self.config['LOG_LEVEL']}'. Will default to INFO.")
             # raise ValueError("CONFIG: LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.") # Making this non-fatal

        # Validate OCR settings if enabled
        if self.config["OCR_ENABLED"]:
             if not isinstance(self.config["OCR_LANGUAGES"], list) or not all(isinstance(lang, str) and len(lang) == 3 for lang in self.config["OCR_LANGUAGES"]):
                 raise ValueError("CONFIG: OCR_LANGUAGES must be a list of 3-letter language codes (e.g., ['eng', 'fra']).")
             if self.config["TESSERACT_CMD"] is not None and not isinstance(self.config["TESSERACT_CMD"], str):
                  raise ValueError("CONFIG: TESSERACT_CMD must be a string (path) or None.")


        if not isinstance(self.config["AI_API_URL"], str) or not self.config["AI_API_URL"].startswith("http"):
            logger.warning(f"CONFIG: AI_API_URL '{self.config['AI_API_URL']}' doesn't look like a valid URL.")


    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieves a configuration value by key.

        Args:
            key (str): The configuration key name.
            default (Any, optional): The value to return if the key is not found. Defaults to None.

        Returns:
            Any: The configuration value or the default.
        """
        return self.config.get(key, default)

# --- Global Instance ---
# Create a global CONFIG instance for easy access throughout the application.
# This instance is created when the module is first imported.
try:
    CONFIG = Config()
except Exception as e:
     # Catch potential errors during Config instantiation itself (e.g., file system issues if defaults involved paths)
     logger.critical(f"Failed to initialize configuration: {e}", exc_info=True)
     print(f"CRITICAL ERROR: Failed to initialize configuration: {e}", file=sys.stderr)
     sys.exit(1)