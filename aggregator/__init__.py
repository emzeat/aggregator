import argparse
import logging
import json
import sys
import datetime

from .executor import Executor
from .check import Check, CHECKS
from .output import Output, OUTPUTS


def main():
    parser = argparse.ArgumentParser(description='Lightweight system monitoring daemon')
    parser.add_argument('-v', '--verbose', help='Enable verbose logging', action='store_true', default=False)
    parser.add_argument('-c', '--config', help='JSON config file to load', required=True)
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)

    logging.info(f"Reading configuration from {args.config}")
    with open(args.config, 'r') as configfile:
        lines = configfile.readlines()
        lines = [line if not line.lstrip().startswith('#') else '\n' for line in lines]
        config = json.loads(''.join(lines))

    if not isinstance(config, dict):
        logging.fatal(f"Malformed config file, expected 'list' but got '{config.__class__}'")
        sys.exit(1)

    engine = Executor(interval=datetime.timedelta(seconds=config.get('interval', 30)))
    for entry in config.get('checks', []):
        try:
            entry_type = entry[Check.Config.TYPE]
        except KeyError:
            logging.fatal(f"Missing {Check.Config.TYPE} in {entry}")
            sys.exit(1)
        try:
            if entry_type in CHECKS:
                engine.add_check(CHECKS[entry_type](entry))
            else:
                logging.fatal(f"Unknown check '{entry_type}'")
                sys.exit(1)
        except KeyError as e:
            logging.fatal(f"Failed to create check of type '{entry_type}': Missing entry {e}")
            sys.exit(1)

    for o in config.get('outputs', []):
        output_type = o.get('type')
        if output_type in OUTPUTS:
            engine.add_output(OUTPUTS[output_type](o))

    engine.run()
    sys.exit(0)
