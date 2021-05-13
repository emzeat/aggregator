import argparse
import logging
import json
import os
import sys
import datetime
import re
from dotenv import load_dotenv

from .executor import Executor
from .check import Check, CHECKS, merge_dict, CheckAge
from .output import Output, OUTPUTS
from .notification import MailNotification, NullNotification
from .server import Server


def handle_env(line: str):
    for match in re.findall(r'env:([A-Z0-9_]+)', line):
        variable = os.getenv(match)
        if variable:
            line = line.replace(f'env:{match}', variable)
    return line


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description='Lightweight system monitoring daemon')
    parser.add_argument('-v', '--verbose', help='Enable verbose logging', action='store_true', default=False)
    parser.add_argument('-c', '--config', help='JSON config file to load', required=False)
    parser.add_argument('-m', '--message', help='JSON string used to send a message with the given "contents" and '
                                                '"subject" using the configured notification channel',
                        required=False, default=None)
    parser.add_argument('--server', help='Runs a REST API server listening on interface and port',
                        required=False, default=None)
    parser.add_argument('--touch', help='Updates the timestamp stored at the given path, compatible to the "age" check',
                        required=False, default=None)
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

    if args.server:
        interface, port = args.server.split(':')
        api_server = Server(interface, port, CHECKS)
        api_server.run()
        sys.exit(0)

    if not args.config:
        logging.fatal("Configuration file is required in this mode")

    logging.info(f"Reading configuration from {args.config}")
    with open(args.config, 'r') as configfile:
        lines = configfile.readlines()
        lines = [line if not line.lstrip().startswith('#') else '\n' for line in lines]
        lines = [handle_env(line) for line in lines]
        config = json.loads(''.join(lines))

    if not isinstance(config, dict):
        logging.fatal(f"Malformed config file, expected 'list' but got '{config.__class__}'")
        sys.exit(1)

    if 'notification' in config:
        notifier = MailNotification(config['notification'])
    else:
        notifier = NullNotification()

    if args.message:
        try:
            message = json.loads(args.message)
            subject = message['subject']
            contents = message['contents']
        except json.JSONDecodeError:
            subject = args.message
            contents = args.message
        notifier.send_message(subject, contents)
        sys.exit(0)

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
