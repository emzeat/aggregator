import logging

from flask import Flask, request


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
                        results += check.run()
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
