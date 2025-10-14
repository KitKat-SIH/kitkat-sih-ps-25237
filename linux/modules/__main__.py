# modules/main.py
"""
Main orchestrator for hardn (Linux side).
Responsible for initializing all hardening modules based on CLI context.
"""

from pathlib import Path
from modules.base import Colors

from modules.firewall import FirewallModule
from modules.filesystem import FilesystemModule
from modules.boot_process import BootProcessModule
from modules.network import NetworkModule
from modules.services import ServicesModule
from modules.accounts import AccountsModule
from modules.access_control import AccessControlModule
from modules.auditd import AuditdModule
from modules.maintenance import MaintenanceModule


# List of all Linux module names (9 total, aligned with Annexure B)
MODULES: list = [
    FilesystemModule,
    # FirewallModule,
    # BootProcessModule,
    # NetworkModule,
    # ServicesModule,
    # AccountsModule,
    # AccessControlModule,
    # AuditdModule,
    # MaintenanceModule,
]


def run(context):
  logger = context["logger"]
  policy = context["policy_level"]
  mode = context["mode"]

  logger.log("INFO", f"Policy level: {policy}")
  logger.log("INFO", f"Operating mode: {mode}")

  for ModuleClass in MODULES:
    try:
      # Instantiate the module with context
      module_instance = ModuleClass(context)
      module_name = module_instance.id

      logger.log("INFO", f"Running module: {module_name}")
      start_index = len(context["report"])  # track start of this module's results

      # Run audit first
      if mode == "audit":
        module_instance.audit()
        logger.log("INFO", f"{module_name}: audit completed")

      # Run enforce if in enforce mode
      if mode == "enforce":
        module_instance.enforce()
        logger.log("INFO", f"{module_name}: enforcement completed")

      # Compute per-module score (passed/total)
      module_entries = [e for e in context["report"][start_index:] if e.get("module") == module_name]
      total_checks = len(module_entries)
      passed_checks = sum(1 for e in module_entries if e.get("ok", False))
      pct = (passed_checks / total_checks * 100.0) if total_checks else 0.0
      # Color thresholds (based on pass rate): red <50%, yellow <80%, else white
      if pct < 50.0:
        color = Colors.RED
      elif pct < 80.0:
        color = Colors.YELLOW
      else:
        color = Colors.WHITE
      print(f"{color}{passed_checks}/{total_checks} ({pct:.1f}%){Colors.END}")
      logger.log("INFO", f"{module_name} score: {passed_checks}/{total_checks} ({pct:.1f}%)")

    except Exception as e:
      logger.log("ERROR", f"Module {ModuleClass.__name__} failed: {e}")

  # After all modules are done, finalize
  report_count = len(context["report"])
  logger.log("INFO", f"Completed all modules ({report_count} entries in report)")

  # Final overall score (passed/total)
  total_checks = report_count
  passed_checks = sum(1 for e in context["report"] if e.get("ok", False))
  pct = (passed_checks / total_checks * 100.0) if total_checks else 0.0
  if pct < 50.0:
    color = Colors.RED
  elif pct < 80.0:
    color = Colors.YELLOW
  else:
    color = Colors.WHITE
  print(f"Final score: {color}{passed_checks}/{total_checks} ({pct:.1f}%){Colors.END}")
  logger.log("INFO", f"Final score: {passed_checks}/{total_checks} ({pct:.1f}%)")

  # Optionally dump raw JSON for debugging
  if context.get("debug_json"):
    import json
    debug_path = Path("/tmp/hardn-report.json")
    debug_path.write_text(json.dumps(context["report"], indent=2))
    logger.log("DEBUG", f"Report written to {debug_path}")
