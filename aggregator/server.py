"""
 server.py

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

import logging

from flask import Flask, request
import datetime


class Server:
    """Remote API"""

    def __init__(self, interface, port, checks):
        self.interface = interface
        self.port = port
        self.checks = checks
        self.app = Flask('aggregator API')

        @self.app.route("/api/v1", methods=['POST'])
        def run_checks():
            results = []
            requested_checks = request.get_json()
            now = datetime.datetime.utcnow()
            for entry in requested_checks:
                try:
                    entry_type = entry['type']
                except KeyError:
                    error = f"Missing 'type' in {entry}"
                    logging.fatal(error)
                    return {'check': entry, 'error': error}, 404
                try:
                    if entry_type in self.checks:
                        check = self.checks[entry_type](entry)
                        results += check.run(now)
                    else:
                        error = f"Unknown check '{entry_type}'"
                        logging.fatal(error)
                        return {'check': entry, 'error': error}, 404
                except KeyError as e:
                    error = f"Failed to create check of type '{entry_type}': Missing entry {e}"
                    logging.fatal(error)
                    return {'check': entry, 'error': error}, 404
            return {'checks': requested_checks, 'results': results}, 200

    def run(self):
        self.app.run(host=self.interface, port=self.port, ssl_context='adhoc',
                     threaded=False, use_reloader=False,
                     debug=logging.getLogger().isEnabledFor(logging.DEBUG))
