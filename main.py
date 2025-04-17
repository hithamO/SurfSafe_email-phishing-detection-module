# main.py - Email Phishing Detector Orchestrator

import sys
import logging
import asyncio 
from datetime import datetime
from argparse import ArgumentParser
import json
import os 
import time

# External libraries
try:
    import aiohttp
except ImportError:
    aiohttp = None # Flag as missing
    logging.getLogger(__name__).critical("aiohttp library not found. Network operations (VT, AI) are impossible.")
    print("\nCRITICAL ERROR: The 'aiohttp' library is required but not installed.", file=sys.stderr)
    print("Please install it: pip install aiohttp", file=sys.stderr)
    
# Local imports 
try:
    from config.config import CONFIG 
    from src.email_parser import parse_email, EmailAnalysisError
    from src.security_analyzer import (
        analyze_headers,
        analyze_body,
        analyze_attachments,
        generate_hashes,
        VirusTotalClient
    )
    from src.ai_integration import analyze_with_ai
    from src.report_generator import generate_report
    from src.database_manager import DatabaseManager
except ImportError as e:
     logging.getLogger(__name__).critical(f"Failed to import local module: {e}. Check project structure and PYTHONPATH.", exc_info=True)
     print(f"\nCRITICAL ERROR: Failed to import local module: {e}.", file=sys.stderr)
     print("Ensure all source files (src/*) and config files (config/*) exist and the script is run from the project root.", file=sys.stderr)
     sys.exit(1)


logger = logging.getLogger(__name__)

# --- Core Analysis Orchestration (Async) ---

async def run_full_email_analysis(file_path: str, use_ai: bool = False) -> dict:
    """
    Performs the complete email analysis workflow asynchronously.

    Parses the email, analyzes headers, body, attachments (including async VT checks
    and OCR if enabled), optionally calls AI analysis, and returns structured results.

    Args:
        file_path (str): Path to the email file (.eml or .msg).
        use_ai (bool, optional): Whether to perform AI analysis. Defaults to False.

    Returns:
        dict: A dictionary containing the comprehensive analysis results.
              Includes an "Error" key in the top level if fatal errors occur during orchestration.
              The "Information" section tracks the overall status.
    """
    start_time = time.time()
    results = {
        "Information": {
            "Filename": os.path.basename(file_path),
            "FilePath": file_path,
            "AnalysisDate": datetime.now().strftime(CONFIG.get("DATE_FORMAT", "%Y-%m-%d %H:%M:%S")),
            "Status": "Analysis initiated",
            "DurationSeconds": 0,
            "AI_Enabled": use_ai and bool(CONFIG.get("AI_API_KEY")), 
            "VT_Enabled": bool(CONFIG.get("VIRUSTOTAL_API_KEY")), 
            "OCR_Enabled": bool(CONFIG.get("OCR_ENABLED", False))
        },
        "Analysis": {}, 
        "Error": None
    }

    if aiohttp is None:
         results["Error"] = "Missing dependency: aiohttp library is required for network operations (VT/AI)."
         results["Information"]["Status"] = "Failed (Missing Dependencies)"
         logger.critical(results["Error"])
         return results

    # Initialize Database Manager and VirusTotal Client
    try:
        db_manager = DatabaseManager(
            db_path=CONFIG.get("DATABASE_PATH"),
            cache_duration_seconds=CONFIG.get("CACHE_DURATION_SECONDS")
        )
        # Initialize DB schema asynchronously (creates table if needed)
        await db_manager.init_db()

        vt_client = VirusTotalClient(
            api_key=CONFIG.get("VIRUSTOTAL_API_KEY"),
            db_manager=db_manager
        )
        results["Information"]["VT_Enabled"] = bool(vt_client.api_key)

    except Exception as e:
         results["Error"] = f"Initialization failed: Error setting up Database or VirusTotal Client: {e}"
         results["Information"]["Status"] = "Failed (Initialization Error)"
         logger.critical(results["Error"], exc_info=True)
         return results

    async with aiohttp.ClientSession() as session:
        try:
            # 1. Parse Email File
            logger.info(f"Parsing email file: {file_path}")
            email_data = parse_email(file_path)
            msg = email_data["message"]
            raw_content_str = email_data["raw_content"]

            results["Information"]["Filename"] = email_data["filename"]
            logger.info(f"Email parsing successful for '{email_data['filename']}'.")

            # 2. Generate File Hashes (using the raw decoded content string)
            try:
                 raw_content_bytes = raw_content_str.encode('utf-8', errors='replace')
                 results["Analysis"]["FileHashes"] = generate_hashes(raw_content_bytes)
                 logger.debug("Generated file hashes for raw content.")
            except Exception as e:
                 logger.error(f"Failed to generate file hashes: {e}")
                 results["Analysis"]["FileHashes"] = {"error": f"Hashing failed: {e}"}


            results["Information"]["Status"] = "Analyzing components"

            # 3. Analyze Components Concurrently (Headers, Body, Attachments)
            logger.info("Starting concurrent analysis of headers, body, and attachments...")
            analysis_tasks = {
                "Headers": asyncio.create_task(analyze_headers(msg, vt_client, session), name="analyze_headers"),
                "Body": asyncio.create_task(analyze_body(msg, vt_client, session), name="analyze_body"),
                "Attachments": asyncio.create_task(analyze_attachments(msg, vt_client, session), name="analyze_attachments")
            }

            component_results = await asyncio.gather(*analysis_tasks.values(), return_exceptions=True)

            all_components_ok = True
            for i, name in enumerate(analysis_tasks.keys()):
                result_or_exception = component_results[i]
                if isinstance(result_or_exception, Exception):
                    logger.exception(f"Error during analysis component '{name}': {result_or_exception}", exc_info=result_or_exception)
                    results["Analysis"][name] = {"error": f"Analysis component failed: {result_or_exception}"}

   
                    all_components_ok = False 
                else:
                    results["Analysis"][name] = result_or_exception
                    logger.debug(f"Analysis component '{name}' completed successfully.")

            logger.info("Component analysis finished.")
            results["Information"]["Status"] = "Component analysis complete" if all_components_ok else "Component analysis completed with errors"


            # 4. AI Analysis 
            if use_ai and results["Information"]["AI_Enabled"]:
                logger.info("Performing AI analysis...")
                results["Information"]["Status"] = "AI analysis in progress"
                ai_task = asyncio.create_task(analyze_with_ai(results["Analysis"], session), name="analyze_with_ai")
                await ai_task

                try:
                    ai_result = ai_task.result()
                    results["Analysis"]["AI_Analysis"] = ai_result
                    if ai_result.get("error"):
                         logger.warning(f"AI analysis completed with errors: {ai_result.get('message')}")
                         results["Information"]["Status"] += " (AI errors)"
                    else:
                         logger.info("AI analysis finished successfully.")
                except Exception as e:
                     logger.exception(f"Critical error during AI analysis task execution: {e}")
                     results["Analysis"]["AI_Analysis"] = {"error": f"AI analysis task failed: {e}"}
                     results["Information"]["Status"] += " (AI failed)"

            elif use_ai: 
                 logger.warning("AI analysis requested (--ai) but AI_API_KEY is not configured or AI disabled.")
                 results["Analysis"]["AI_Analysis"] = {
                     "error": "configuration_missing",
                     "message": "AI analysis skipped: AI API Key not provided or AI disabled in config."
                     }
              

            # 5. Finalize Status
            if results["Error"]: 
                 pass 
            elif not all_components_ok or results["Analysis"].get("AI_Analysis", {}).get("error"):
                 results["Information"]["Status"] = "Analysis completed with errors"
            else:
                 results["Information"]["Status"] = "Analysis completed successfully"

            logger.info(f"Email analysis workflow ended with status: {results['Information']['Status']}")

        except EmailAnalysisError as e:
            logger.error(f"Email parsing failed: {e}")
            results["Error"] = f"Input Error: {e}"
            results["Information"]["Status"] = "Failed (Input Error)"
        except Exception as e:
            # Catch-all for unexpected errors during the main orchestration logic
            logger.exception(f"Unexpected error during email analysis workflow: {e}", exc_info=True)
            results["Error"] = f"Unexpected Workflow Error: {e}"
            results["Information"]["Status"] = "Failed (Unexpected Workflow Error)"
        finally:
            end_time = time.time()
            duration = round(end_time - start_time, 2)
            results["Information"]["DurationSeconds"] = duration
            logger.info(f"Total analysis duration: {duration} seconds.")

            # Prune old cache
            try:
                logger.debug("Pruning old database cache entries...")
                await db_manager.prune_old_cache()
            except Exception as e:
                 logger.error(f"Failed to prune database cache: {e}")

    return results


# --- Utility Functions ---

def save_results(results: dict, output_path: str) -> bool:
    """
    Saves the analysis results dictionary to a JSON file.

    Args:
        results (dict): The analysis results.
        output_path (str): The path where the JSON file should be saved.

    Returns:
        bool: True if saving was successful, False otherwise.
    """
    logger.info(f"Attempting to save analysis results to: {output_path}")
    try:
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Analysis results successfully saved to: {output_path}")
        return True
    except OSError as e:
        logger.error(f"Failed to create directory or write file at {output_path}: {e}", exc_info=True)
        print(f"[!] Error saving results: Could not write to path '{output_path}'. Check permissions and path validity.", file=sys.stderr)
    except TypeError as e:
        logger.error(f"Failed to serialize results to JSON for {output_path}: {e}", exc_info=True)
        print(f"[!] Error saving results: Data could not be serialized to JSON. {e}", file=sys.stderr)
    except Exception as e:
        logger.exception(f"An unexpected error occurred while saving results to {output_path}: {e}")
        print(f"[!] Error saving results: An unexpected error occurred: {e}", file=sys.stderr)

    return False

# --- Main Execution Block ---

async def async_main():
    """Asynchronous main function to handle argument parsing, run analysis, and report results."""
    parser = ArgumentParser(
        description="Advanced Email Phishing Detector (Async Version with OCR)",
        epilog="Example: python main.py -f /path/to/email.eml --ai -o results.json -v"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the email file (.eml or .msg) to analyze.")
    parser.add_argument("--ai", action="store_true", help="Enable AI-based analysis (requires configured AI_API_KEY).")
    parser.add_argument("-o", "--output", help="Optional path to save the full analysis results as a JSON file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose report output to console (shows more details like snippets).")
    args = parser.parse_args()

    # --- Initial Setup & Checks ---
    if aiohttp is None:
         sys.exit(1)

    if CONFIG.get("OCR_ENABLED"):
         try:
             import pytesseract
             try:
                 pytesseract.get_tesseract_version()
                 logger.info("Tesseract OCR detected.")
             except pytesseract.TesseractNotFoundError:
                 logger.warning("OCR is enabled in config, but Tesseract executable was not found. OCR will fail. Ensure Tesseract is installed and in PATH, or set TESSERACT_CMD in config.")
                 print("[!] Warning: OCR is enabled, but Tesseract not found. Image analysis may be incomplete.", file=sys.stderr)
         except ImportError:
              logger.warning("OCR is enabled in config, but 'pytesseract' library is not installed. OCR will be skipped.")
              print("[!] Warning: OCR is enabled, but 'pytesseract' library not installed.", file=sys.stderr)


    print(f"\n{'='*20} Email Phishing Analysis v1.1 {'='*20}")
    print(f"[*] Analyzing Email File: {args.file}")
    print(f"[*] AI Analysis: {'Enabled' if args.ai and CONFIG.get('AI_API_KEY') else 'Disabled'}{' (Requested but Key Missing!)' if args.ai and not CONFIG.get('AI_API_KEY') else ''}")
    print(f"[*] VirusTotal Checks: {'Enabled' if CONFIG.get('VIRUSTOTAL_API_KEY') else 'Disabled (No API Key)'}")
    print(f"[*] OCR Processing: {'Enabled' if CONFIG.get('OCR_ENABLED') else 'Disabled'}")
    print(f"[*] Output File: {args.output if args.output else 'None (Console Report Only)'}")
    print(f"[*] Verbose Report: {args.verbose}")
    print("-" * (40 + len(" Email Phishing Analysis v1.1 ")))
    print("[*] Starting analysis...")


    # --- Run the Core Analysis ---
    results = await run_full_email_analysis(args.file, args.ai)


    # --- Generate and Display Report ---
    print("\n" + "=" * 25 + " Analysis Report " + "=" * 25)
    try:
        generate_report(results, args.verbose)
    except Exception as e:
         logger.exception("Error generating console report: {e}")
         print(f"\n[!] CRITICAL ERROR: Failed to generate console report: {e}", file=sys.stderr)
    print("=" * (50 + len(" Analysis Report ")))


    # --- Save Results (if requested) ---
    if args.output:
        if save_results(results, args.output):
             print(f"\n[*] Full analysis results saved to: {args.output}")
        else:
             print(f"[!] Failed to save results to: {args.output}", file=sys.stderr)


    # --- Final Status and Exit ---
    exit_code = 0 if results.get("Error") is None else 1

    if exit_code != 0:
         print(f"\n[!] Analysis finished with errors: {results.get('Error')}", file=sys.stderr)
         logger.error(f"Analysis run failed. Error: {results.get('Error')}")
    else:
         final_status = results.get("Information", {}).get("Status", "Status Unknown")
         print(f"\n[*] Analysis finished. Final Status: {final_status}")
         logger.info(f"Analysis run completed. Final Status: {final_status}")

    sys.exit(exit_code)


if __name__ == "__main__":

    logging.basicConfig(level="INFO", format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)

    if aiohttp is None:
         sys.exit(1)

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n[*] Analysis interrupted by user (Ctrl+C). Exiting.", file=sys.stderr)
        logger.warning("Analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"A critical top-level error occurred: {e}", exc_info=True)
        print(f"\n[!] CRITICAL ERROR: An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)