#!/usr/bin/env python

import sys
import logging
import datetime
import shutil

from argparse import ArgumentParser
from configparser import ConfigParser
from urllib.parse import urlparse
from tempfile import NamedTemporaryFile
from OTXv2 import OTXv2Cached

## _APPNAME identifies the application running for logging purposes
_APPNAME = 'Zeek-OTX'

## _DEFAULT_CONFIG specifies default configuration values to allow
## for partially-defined configuration files
_DEFAULT_CONFIG = {
    'api_key': '',
    'days_of_history': '30',
    'outfile': 'otx.dat',
    'do_notice': 'F',
    'otx_cache': '.otx'
}

## _OTX_BASE_URL creates a base URL for pulse URLs to be built on
_OTX_BASE_URL = 'https://otx.alienvault.com/pulse'

## _SUPPORTED_IOC_TYPES specifies IOC types that are supported by
## Zeek, so that unsupported types can be skipped.
_SUPPORTED_IOC_TYPES = [
    'IPv4',
    'IPv6',
    'domain',
    'hostname',
    'email',
    'URL',
    'URI',
    'FileHash-MD5',
    'FileHash-SHA1',
    'FileHash-SHA256'
]

# Mapping of OTXv2 Indicator types to Zeek Intel types, additionally,
# identifies unsupported intel types to prevent errors in Zeek.
_MAP = {
    'IPv4': 'Intel::ADDR',
    'IPv6': 'Intel::ADDR',
    'domain': 'Intel::DOMAIN',
    'hostname': 'Intel::DOMAIN',
    'email': 'Intel::EMAIL',
    'URL': 'Intel::URL',
    'URI': 'Intel::URL',
    'FileHash-MD5': 'Intel::FILE_HASH',
    'FileHash-SHA1': 'Intel::FILE_HASH',
    'FileHash-SHA256': 'Intel::FILE_HASH',
}

# Zeek Intel file header format
_HEADER = '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\n'

def parse_args():
    '''Parse commandline arguments.

    Retrieves arguments from the commandline.

    Args:
        None
    Returns:
        Populated namespace with arguments.
    '''
    parser = ArgumentParser('AlienVault OTXv2 Zeek Client')
    parser.add_argument('-c', '--config',
                        help='configuration file path',
                        default='zeek_otx.conf')
    return parser.parse_args()

def parse_config(config_path):
    '''Parse configuration file.

    Args:
        config_path: A file path where the configuration file for this
            script is located.
    Returns:
        configuration values
    '''
    config = ConfigParser()
    config['DEFAULT'] = _DEFAULT_CONFIG
    logger = logging.getLogger(_APPNAME)
    files_read = config.read(config_path)
    if config_path not in files_read:
        logger.fatal('Failed to parse or open configuration file.')
        sys.exit(1)
    return config

def sync_otx_cache(api_key, days, otx_cache):
    '''Update and return the local otx cache.

    Args:
        api_key: the api key to authenticate to otx with
        days: the number of days to sync the cache for
        otx_cache: the local disk location to store the cache in
    Returns:
        A handle to the local otx cache.
    '''
    logger = logging.getLogger(_APPNAME)
    max_age = datetime.timedelta(days=days)

    # sync otx
    cache = OTXv2Cached(api_key, cache_dir=otx_cache, max_age=max_age)
    try:
        cache.update()
    except Exception as error:
        logger.fatal('Error while updating OTX cache: {0}'.format(error))
        sys.exit(1)
    return cache

def sanitize_url(url):
    '''Sanitize url for import in to Zeek intel framework.

    The Zeek intel framework does not support url scheme (http, https, etc.)
    and it must be stripped before adding the url into the intel framework.

    Args:
        url: a string url
    Returns
        A string of the sanitized url.
    '''
    parsed_url = urlparse(url)
    return parsed_url.geturl().replace('{0}://'.format(parsed_url.scheme), '')

def main(api_key, days, outfile, do_notice, otx_cache):
    '''Main runtime routine.'''

    cache = sync_otx_cache(api_key, days, otx_cache)

    iocs = set()
    # iterate through pulses, building the zeek intel file
    for pulse in cache.getall_iter():
        pulse_name = pulse.get('name')
        pulse_id = pulse.get('id')
        pulse_author = pulse.get('author_name')
        pulse_url = '{base_url}/{id}'.format(base_url=_OTX_BASE_URL,
                                             id=pulse_id)
        description = '{pulse_name} ({id})'.format(
            pulse_name=pulse_name,
            id=pulse_id)
        # sanitize description by removing tabs
        description = description.replace('\t', ' ')

        metadata = '\t'.join([pulse_author,
                              description,
                              pulse_url,
                              do_notice])

        for ioc in pulse.get('indicators'):
            if ioc.get('type') in _SUPPORTED_IOC_TYPES:
                indicator = ioc.get('indicator')
                indicator_type = ioc.get('type')
                # special handling for URL types
                if indicator_type == 'URL':
                    indicator = sanitize_url(indicator)

                iocs.add('\t'.join([indicator,
                                    _MAP.get(indicator_type),
                                    metadata]))

    tf_name = ''
    with NamedTemporaryFile(mode='w', delete=False) as tf:
        tf_name = tf.name
        tf.write(_HEADER)
        for ioc in iocs:
            tf.write(ioc + '\n')

    shutil.move(tf_name, outfile)


if __name__ == '__main__':

    logging.basicConfig(format='%(asctime)s\t%(name)s\t%(message)s')
    _LOGGER = logging.getLogger(_APPNAME)

    # Parse arguments from sys.argv
    args = parse_args()
    CONFIG = parse_config(args.config)

    # Validate configuration values
    API_KEY = CONFIG.get('otx', 'api_key')
    if not API_KEY:
        _LOGGER.fatal('api_key must be specififed!')
        sys.exit(1)

    try:
        DAYS = int(CONFIG.get('otx', 'days_of_history'))
    except ValueError:
        _LOGGER.fatal('days_of_history is not a valid number')
        sys.exit(1)

    OUTFILE = CONFIG.get('otx', 'outfile')

    DO_NOTICE = CONFIG.get('otx', 'do_notice')
    if DO_NOTICE not in ['T', 'F']:
        DO_NOTICE = 'F'
        _LOGGER.warning('do_notice must be "T" or "F", defaulting to "F"')

    OTX_CACHE = CONFIG.get('otx', 'otx_cache')

    main(API_KEY, DAYS, OUTFILE, DO_NOTICE, OTX_CACHE)
