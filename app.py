#!/usr/bin/env python

import argparse
import ConfigParser
import logging
import os
import sys

from lbaas_arbor import mitigation

CONF = ConfigParser.ConfigParser()
CONF.read("lbaas_arbor.conf")

parser = argparse.ArgumentParser(
    description='DDoS Mitigation Manager for CLB 1.0'
)
parser.add_argument('--logfile', help="Full path for logfile.")
parser.add_argument('--loglevel', help="Logging level (INFO, DEBUG)")
parser.add_argument('--dryrun', action='store_true',
                    help="Full path for logfile.")
args = parser.parse_args()

if args.logfile:
    LOG_FILENAME = args.logfile
elif CONF.has_option('global', 'logfile'):
    LOG_FILENAME = CONF.get('global', 'logfile')
else:
    LOG_FILENAME = None
if args.loglevel:
    LOG_LEVEL = args.loglevel.upper()
else:
    LOG_LEVEL = CONF.get('global', 'loglevel').upper()

DRY_RUN = args.dryrun

logging.captureWarnings(True)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(LOG_LEVEL)

if LOG_FILENAME:
    try:
        os.makedirs(os.path.dirname(LOG_FILENAME))
    except TypeError:
        pass
    except OSError:
        pass
    logging.basicConfig(
        filename=LOG_FILENAME,
        level=LOG_LEVEL
    )

    if DRY_RUN:
        LOG = logging.getLogger('lbaas_arbor')
        LOG.addHandler(stdout_handler)
else:
    logging.basicConfig(
        stream=stdout_handler,
        level=LOG_LEVEL
    )
m = mitigation.MitigationManager(conf=CONF, dry_run=DRY_RUN)
m.run()
