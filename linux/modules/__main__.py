# modules/main.py
"""
Main orchestrator for MP-Hardener (Linux side).
Responsible for initializing all hardening modules based on CLI context.
"""

import importlib
from pathlib import Path

from firewall import FirewallModule

# List of all Linux module names (9 total, aligned with Annexure B)
MODULES: list = [
    FirewallModule
]
"""
    "filesystem",
    "boot_process",
    "network",
    "services",
    "accounts",
    "access_control",
    "auditd",
    "maintenance"
]
"""


def run(context):
    logger = context["logger"]
    policy = context["policy_level"]
    mode = context["mode"]

    logger.log("INFO", f"Policy level: {policy}")
    logger.log("INFO", f"Operating mode: {mode}")

    for module in MODULES:
        try:
            logger.log("INFO", f"Loaded module: {mod_name}")

            if not hasattr(module, f"apply_{policy}"):
                logger.log("WARN", f"{mod_name} does not define apply_{policy}()")
                continue

            # Run the appropriate policy application
            getattr(module, f"apply_{policy}")()
            logger.log("INFO", f"{mod_name}: {policy} policy applied successfully")

        except Exception as e:
            logger.log("ERROR", f"Module {mod_name} failed: {e}")

    # After all modules are done, finalize
    report_count = len(context["report"])
    logger.log("INFO", f"Completed all modules ({report_count} entries in report)")

    # Optionally dump raw JSON for debugging
    if context.get("debug_json"):
        import json
        debug_path = Path("/tmp/hardn-report.json")
        debug_path.write_text(json.dumps(context["report"], indent=2))
        logger.log("DEBUG", f"Report written to {debug_path}")

