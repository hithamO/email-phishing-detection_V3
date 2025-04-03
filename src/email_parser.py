# src/email_parser.py
import email
from email.message import EmailMessage
import logging
from typing import Dict, Any
import os

# Local imports (assuming config is accessible)
# Need to import CONFIG to check MAX_FILE_SIZE
try:
    from config.config import CONFIG
except ImportError:
    # Fallback or default if config is unavailable in this context
    class MockConfig:
        def get(self, key, default=None):
            if key == "MAX_FILE_SIZE":
                return 10 * 1024 * 1024 # Default 10MB
            return default
    CONFIG = MockConfig()
    print("Warning: Could not import config. Using default max file size.")


logger = logging.getLogger(__name__)

class EmailAnalysisError(Exception):
    """Custom exception for errors encountered during email parsing."""
    pass

def parse_email(file_path: str) -> Dict[str, Any]:
    """
    Parses an email file (.eml or .msg), validates basic properties,
    and returns its content structure.

    Args:
        file_path (str): Path to the email file.

    Returns:
        Dict[str, Any]: Dictionary containing:
                        'message' (email.message.EmailMessage object),
                        'raw_content' (str, decoded content for hashing/reference),
                        'filename' (str, base name of the input file).

    Raises:
        EmailAnalysisError: If the file is not found, has an unsupported extension,
                            exceeds the maximum size, or fails during parsing.
        ImportError: If the 'extract-msg' library is needed for .msg files but not installed.
    """
    logger.debug(f"Attempting to parse email file: {file_path}")

    # 1. Validate File Existence
    if not os.path.exists(file_path):
        raise EmailAnalysisError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
         raise EmailAnalysisError(f"Path is not a file: {file_path}")

    # 2. Validate File Size
    try:
        file_size = os.path.getsize(file_path)
        max_size = CONFIG.get("MAX_FILE_SIZE", 10 * 1024 * 1024) # Default 10MB
        if file_size > max_size:
            raise EmailAnalysisError(f"File exceeds maximum size: {file_size / (1024*1024):.2f} MB > {max_size / (1024*1024):.2f} MB")
        if file_size == 0:
             raise EmailAnalysisError(f"File is empty: {file_path}")
    except OSError as e:
         raise EmailAnalysisError(f"Error accessing file properties for {file_path}: {e}")

    # 3. Validate File Extension
    filename_base = os.path.basename(file_path)
    _, ext = os.path.splitext(filename_base.lower())
    supported_extensions = CONFIG.get("SUPPORTED_FILES", [".eml", ".msg"])
    if ext not in supported_extensions:
        raise EmailAnalysisError(f"Unsupported file extension: '{ext}'. Supported: {', '.join(supported_extensions)}")

    # 4. Parse based on extension
    try:
        if ext == ".eml":
            # Read as bytes first for accurate parsing
            with open(file_path, 'rb') as f:
                raw_bytes = f.read()
            # Parse using email library, specifying EmailMessage class for modern features
            msg = email.message_from_bytes(raw_bytes, _class=EmailMessage)
            # Decode the raw bytes to string for hashing/reference, replacing errors
            # Use 'utf-8' as a common default, but email encoding can be complex.
            # The `email` library handles internal decoding of parts better.
            raw_content_str = raw_bytes.decode('utf-8', errors='replace')

        elif ext == ".msg":
            # Requires 'extract-msg' library
            try:
                import extract_msg
            except ImportError as e:
                logger.error("The 'extract-msg' library is required to parse .msg files.")
                raise ImportError("MSG parsing requires 'extract-msg' library. Install with: pip install extract-msg") from e

            try:
                 # Use extract_msg to get the email content as a string dump
                 msg_file_data = extract_msg.Message(file_path)
                 # Get the raw email data, hopefully in RFC822 format
                 raw_content_str = msg_file_data.body # Or potentially .get_email() if that exists and is better
                 # Ensure raw_content_str is a string; it might be bytes
                 if isinstance(raw_content_str, bytes):
                     raw_content_str = raw_content_str.decode('utf-8', errors='replace')

                 # Parse the extracted string content using the email library
                 msg = email.message_from_string(raw_content_str, _class=EmailMessage)
                 msg_file_data.close() # Close the .msg file handle

                 # Raw_content_str here is the *output* of extract-msg, not the original file bytes.

            except Exception as e:
                logger.exception(f"Failed to parse .msg file '{filename_base}' using extract-msg: {e}")
                raise EmailAnalysisError(f"Failed to parse .msg file: {e}")

        else:

                raise EmailAnalysisError(f"Internal error: Reached parsing logic for unsupported extension '{ext}'.")

        # Basic validation of the parsed message
        if not msg:
            raise EmailAnalysisError("Parsing resulted in an empty message object.")

        logger.info(f"Successfully parsed email file: {filename_base}")
        return {
            "message": msg,             # The parsed EmailMessage object
            "raw_content": raw_content_str, # The decoded string content (primarily for hashing)
            "filename": filename_base   # Original filename
        }

    except EmailAnalysisError:
        # Re-raise known parsing errors directly
        raise
    except ImportError:
         # Re-raise import errors (like for extract-msg)
         raise
    except Exception as e:
        # Catch any other unexpected errors during parsing
        logger.exception(f"An unexpected error occurred while parsing email file {file_path}: {e}")
        # Wrap the unexpected error in our custom exception type
        raise EmailAnalysisError(f"Unexpected email parsing error: {e}") from e