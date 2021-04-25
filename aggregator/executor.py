import logging
from .check import Check

DEFAULT_CONFIG = {
    Check.Config.HOST: ''
}

class Executor(Check):
    """Collection of checks"""

    def __init__(self):
        """Constructor"""
        super().__init__(name='Executor', config=DEFAULT_CONFIG)
        self.checks = []

    def add_check(self, check: Check):
        """Registers a check for execution"""
        self.checks.append(check)

    def on_run(self):
        for c in self.checks:
            self.results += c.run()
