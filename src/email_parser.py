# src/email_parser.py
import email
from email.message import EmailMessage
import logging
from typing import Dict, Any
import os

# Local imports 
try:
    from config.config import CONFIG
except ImportError:
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
            with open(file_path, 'rb') as f:
                raw_bytes = f.read()
            msg = email.message_from_bytes(raw_bytes, _class=EmailMessage)
            raw_content_str = raw_bytes.decode('utf-8', errors='replace')

        elif ext == ".msg":
            try:
                import extract_msg
            except ImportError as e:
                logger.error("The 'extract-msg' library is required to parse .msg files.")
                raise ImportError("MSG parsing requires 'extract-msg' library. Install with: pip install extract-msg") from e

            try:
                 msg_file_data = extract_msg.Message(file_path)
                 # Get the raw email data, hopefully in RFC822 format
                 raw_content_str = msg_file_data.body
                 if isinstance(raw_content_str, bytes):
                     raw_content_str = raw_content_str.decode('utf-8', errors='replace')

                 msg = email.message_from_string(raw_content_str, _class=EmailMessage)
                 msg_file_data.close() 


            except Exception as e:
                logger.exception(f"Failed to parse .msg file '{filename_base}' using extract-msg: {e}")
                raise EmailAnalysisError(f"Failed to parse .msg file: {e}")

        else:

                raise EmailAnalysisError(f"Internal error: Reached parsing logic for unsupported extension '{ext}'.")

        if not msg:
            raise EmailAnalysisError("Parsing resulted in an empty message object.")

        logger.info(f"Successfully parsed email file: {filename_base}")
        return {
            "message": msg,             
            "raw_content": raw_content_str, 
            "filename": filename_base  
        }

    except EmailAnalysisError:
        raise
    except ImportError:
         raise
    except Exception as e:
        # Catch any other unexpected errors during parsing
        logger.exception(f"An unexpected error occurred while parsing email file {file_path}: {e}")
        raise EmailAnalysisError(f"Unexpected email parsing error: {e}") from e