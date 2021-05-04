import argparse
import logging
import json
import sys
import datetime

from .executor import Executor
from .check import Check, CHECKS, merge_dict, CheckAge
from .output import Output, OUTPUTS


def main():
    parser = argparse.ArgumentParser(description='Lightweight system monitoring daemon')
    parser.add_argument('-v', '--verbose', help='Enable verbose logging', action='store_true', default=False)
    parser.add_argument('-c', '--config', help='JSON config file to load', required=False)
    parser.add_argument('--touch', help='Updates the timestamp stored at the given path, compatible to the "age" check', required=False, default=None)
    parser.add_argument('--dump', help='Dump reference documentation with explanations for all entries to stdout',
                        action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)

    if args.dump:
        reference = {
            'interval': 'seconds: Seconds to sleep between running configured checks',
            'checks': [merge_dict({'type': key, 'desc': cls.__doc__}, cls.CONFIG) for key, cls in
                       CHECKS.items()],
            'outputs': [merge_dict({'type': key, 'desc': cls.__doc__}, cls.CONFIG) for key, cls in OUTPUTS.items()]
        }
        print(json.dumps(reference, indent=2))
        sys.exit(0)

    if args.touch:
        CheckAge.touch(args.touch)
        sys.exit(0)

    if not args.config:
        logging.fatal("Configuration file is required in this mode")

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
            entry_type = entry['type']
        except KeyError:
            logging.fatal(f"Missing 'type' in {entry}")
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
