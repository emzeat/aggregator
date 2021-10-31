"""
 executor.py

 Copyright (c) 2021 Marius Zwicker
 All rights reserved.

 SPDX-License-Identifier: GPL-2.0-or-later

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Library General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""

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
                if c.logger.isEnabledFor(logging.DEBUG):
                    raise
        for o in self.outputs:
            try:
                o.write(results)
            except Exception as e:
                o.logger.fatal(f'Output failure: {e}')
                if o.logger.isEnabledFor(logging.DEBUG):
                    raise

    def run(self):
        self.logger.info(f"Will run checks every {self.interval}")
        while True:
            begin = datetime.datetime.now()
            self.cycle()
            end = datetime.datetime.now()
            remaining = self.interval - (end - begin)
            remaining_s = remaining.total_seconds()
            self.logger.info(
                f"{remaining} ({remaining_s}s) until next iteration")
            if remaining_s > 0:
                time.sleep(remaining_s)
