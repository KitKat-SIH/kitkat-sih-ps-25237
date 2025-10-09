# modules/base.py
"""
Base class for all hardening modules in MP-Hardener.
Defines the standard interface (audit/enforce/rollback),
logging behavior, and the shared report mechanism.
"""

import datetime
from abc import ABC, abstractmethod


class BaseHardeningModule(ABC):
    """
    Abstract base class — acts like a 'pure virtual class' in C++.
    Every derived module must implement audit() and enforce().
    """

    # Common metadata, can be overridden by subclasses
    id = "base"
    name = "Base Hardening Module"
    description = "Abstract parent class for all hardening modules."
    supported_os = ["linux"]

    def __init__(self, context):
        """
        context: dict provided by orchestrator.
        Expected keys:
          - logger : logging object (must have .log(level, message))
          - policy_level : str ("basic" | "moderate" | "strict")
          - report : list() shared among modules
        """
        self.ctx = context
        self.logger = context.get("logger")
        self.policy = context.get("policy_level", "basic")
        self.report = context.get("report", [])

    @abstractmethod
    def audit(self):
        """Perform read-only checks and append results to the shared report."""
        pass

    @abstractmethod
    def enforce(self):
        """Apply fixes according to policy and append results to the report."""
        pass

    # BIG TODO
    def rollback(self, manifest_entry):
        """Optional per-module rollback; override if needed."""
        self.log_action("Rollback not implemented for this module.", "WARN")
        return {"status": "not_implemented"}

    def log_action(self, message, level="INFO"):
        """Simple wrapper for consistent logging output."""
        if self.logger:
            self.logger.log(level, f"[{self.id}] {message}")
        else:
            print(f"[{level}] [{self.id}] {message}")

    # ---------- Reporting ----------
    def add_result(self, check_id, status, ok):
        """
        Append one standardized result entry to the shared report.
        Fields (minimal schema):
          - module
          - check_id
          - status
          - ok
          - timestamp
        """
        entry = {
            "module": self.id,
            "check_id": check_id,
            "status": status,
            "ok": ok,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.report.append(entry)
        return entry
