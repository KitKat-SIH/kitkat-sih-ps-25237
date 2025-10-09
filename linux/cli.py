#!/usr/bin/env python3
"""
cli.py
Main entry point for MP-Hardener.
Handles command-line arguments and dispatches to internal modules.
"""

import argparse
import sys
import json
from pathlib import Path

# Internal imports
from hardn.modules import __main__ as hardn_main
import rollback
import report
from logger import SimpleLogger


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hardn",
        description="Multi-Platform System Hardening Tool (Linux edition)"
    )

    # Primary modes
    parser.add_argument("--audit", action="store_true",
                        help="Audit the system for compliance only (no changes).")
    parser.add_argument("--enforce", action="store_true",
                        help="Audit and then enforce compliance.")
    parser.add_argument("--rollback", metavar="<checkpoint>",
                        help="Restore configuration from a given checkpoint ID.")

    # Policy & privilege
    parser.add_argument("--policy", choices=["basic", "moderate", "strict"],
                        default="basic", help="Select hardening policy level.")
    parser.add_argument("--privileged", action="store_true",
                        help="Run with elevated privileges (requires sudo).")

    # Output options
    parser.add_argument("--json", metavar="FILE", nargs="?",
                        const="-",
                        help="Write JSON report to file (or stdout if '-')")
    parser.add_argument("--checkpoint", metavar="NAME",
                        help="Create a named checkpoint before enforcement.")
    parser.add_argument("--list-checkpoints", action="store_true",
                        help="List all available checkpoints.")
    parser.add_argument("--restore-checkpoint", metavar="ID",
                        help="Restore system to the specified checkpoint.")
    parser.add_argument("--version", action="store_true",
                        help="Show version and exit.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose (DEBUG) logging.")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print("hardn 1.0.0")
        sys.exit(0)

    # Determine mode
    if args.rollback:
        mode = "rollback"
    elif args.audit:
        mode = "audit"
    elif args.enforce:
        mode = "enforce"
    elif args.list_checkpoints:
        mode = "list"
    elif args.restore_checkpoint:
        mode = "restore"
    else:
        # default to audit if nothing specified
        mode = "audit"

    # Initialize logger
    log_path = Path("/var/log/hardn.log")
    logger = SimpleLogger(log_path, verbose=args.verbose)
    logger.log("INFO", f"Starting hardn in {mode} mode (policy={args.policy})")

    # Initialize shared context
    context = {
        "logger": logger,
        "report": [],
        "policy_level": args.policy,
        "mode": mode,
        "checkpoint": args.checkpoint,
        "privileged": args.privileged
    }

    try:
        if mode in ("audit", "enforce"):
            harden_main.run(context)
        elif mode == "rollback":
            rollback.create_checkpoint(args.rollback, logger)
        elif mode == "restore":
            rollback.restore_checkpoint(args.restore_checkpoint, logger)
        elif mode == "list":
            rollback.list_checkpoints(logger)
        else:
            parser.print_help()
            sys.exit(1)

        # Handle JSON output if requested
        if args.json:
            output = json.dumps(context["report"], indent=2)
            if args.json == "-" or args.json is None:
                print(output)
            else:
                Path(args.json).write_text(output)
                logger.log("INFO", f"JSON report written to {args.json}")

        # Generate PDF if enforcement mode succeeded
        if mode == "enforce" and context["report"]:
            report.generate_pdf(context["report"])

    except KeyboardInterrupt:
        logger.log("WARN", "Operation interrupted by user.")
    except Exception as e:
        logger.log("ERROR", f"Fatal error: {e}")
        sys.exit(1)
    finally:
        logger.log("INFO", "MP-Hardener finished.")


if __name__ == "__main__":
    main()
