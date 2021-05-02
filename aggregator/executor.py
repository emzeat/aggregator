import datetime
import logging
import time

from .check import Check
from .output import Output

class Executor:
    """Collection of checks"""

    def __init__(self, interval=datetime.timedelta(seconds=15)):
        """Constructor"""
        self.outputs = []
        self.checks = []
        self.interval = interval
        self.logger = logging.getLogger("aggregator.executor")

    def add_check(self, check: Check):
        """Registers a check for execution"""
        self.checks.append(check)

    def add_output(self, output: Output):
        """Registers an output for result delivery"""
        self.outputs.append(output)

    def cycle(self):
        self.logger.debug("Running checks")
        results = []
        for c in self.checks:
            try:
                results += c.run()
            except Exception as e:
                c.logger.fatal(f'Run failure: {e}')
        for o in self.outputs:
            o.write(results)

    def run(self):
        self.logger.info(f"Will run checks every {self.interval}")
        while True:
            begin = datetime.datetime.now()
            self.cycle()
            end = datetime.datetime.now()
            remaining = self.interval - (end - begin)
            remaining_s = remaining.seconds + remaining.microseconds / (1000.0*1000.0)
            self.logger.info(f"{remaining} until next iteration")
            if remaining_s > 0:
                time.sleep(remaining_s)
