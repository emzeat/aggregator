"""
 executor.py

 Copyright (c) 2021 - 2022 Marius Zwicker
 All rights reserved.

 SPDX-License-Identifier: AGPL-3.0-only

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import datetime
import logging
import time

from .check import Check
from .output import Output


class Executor:
    """Collection of checks"""

    def __init__(self, interval=None, default_interval=30):
        """Constructor"""
        self.outputs = []
        self.checks = []
        self.default_interval = default_interval
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
            now = datetime.datetime.utcnow()
            try:
                if c.next_run_in(now, self.default_interval) <= 0:
                    results += c.run(now)
            except Exception as e:
                c.logger.fatal(f'Run failure: {e}')
                if c.logger.isEnabledFor(logging.DEBUG):
                    raise
        for o in self.outputs:
            try:
                o.write(results)
            except Exception as e:
                o.logger.fatal(f'Output failure: {e}')
                if o.logger.isEnabledFor(logging.DEBUG):
                    raise

    def next_cycle_in(self):
        now = datetime.datetime.utcnow()
        next = None
        for c in self.checks:
            c_next = c.next_run_in(now, self.default_interval)
            if next is None:
                next = c_next
            else:
                next = min(next, c_next)
        return next

    def run(self):
        self.logger.info(f"Beginning to run checks")
        while True:
            self.cycle()
            remaining_s = self.next_cycle_in()
            self.logger.info(
                f"{remaining_s:.3f}s until next iteration")
            if remaining_s > 0:
                time.sleep(remaining_s)
