#!/usr/bin/env python

import requests
import sys
import os

from argparse import ArgumentParser
from ConfigParser import ConfigParser
from datetime import datetime, timedelta
from urlparse import urlparse

# The URL is hard coded. I'm comfortable doing this since it's unlikely that
# the URL will change without resulting in an API change that will require
# changes to this script.
_URL = 'http://otx.alienvault.com/api/v1/pulses/subscribed'

# Bro Intel file header format
_HEADER = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\n"

# Mapping of OTXv2 Indicator types to Bro Intel types, additionally,
# identifies unsupported intel types to prevent errors in Bro.
_MAP = {
    "IPv4": "Intel::ADDR",
    "IPv6": "Intel::ADDR",
    "domain": "Intel::DOMAIN",
    "hostname": "Intel::DOMAIN",
    "email": "Intel::EMAIL",
    "URL": "Intel::URL",
    "URI": "Intel::URL",
    "FileHash-MD5": "Intel::FILE_HASH",
    "FileHash-SHA1": "Intel::FILE_HASH",
    "FileHash-SHA256": "Intel::FILE_HASH",
}

def to_unicode(obj, encoding='utf-8'):
    if isinstance(obj, basestring):
        if not isinstance(obj, unicode):
            obj = unicode(obj, encoding)
    return obj


def _get(key, mtime, limit=20, next_request=''):
    '''
    Retrieves a result set from the OTXv2 API using the restrictions of
    mtime as a date restriction.
    '''

    headers = {'X-OTX-API-KEY': key}
    params = {'limit': limit, 'modified_since': mtime}
    if next_request == '':
        r = requests.get(_URL, headers=headers, params=params)
    else:
        r = requests.get(next_request, headers=headers)

    # Depending on the response code, return the valid response.
    if r.status_code == 200:
        return r.json()
    if r.status_code == 403:
        print("An invalid API key was specified.")
        sys.exit(1)
    if r.status_code == 400:
        print("An invalid request was made.")
        sys.exit(1)

def iter_pulses(key, mtime, limit=20):
    '''
    Creates an iterator that steps through Pulses since mtime using key.
    '''

    # Populate an initial result set, after this the API will generate the next
    # request in the loop for every iteration.
    initial_results = _get(key, mtime, limit)
    for result in initial_results['results']:
        yield result

    next_request = initial_results['next']
    while next_request:
        json_data = _get(key, mtime, next_request=next_request)
        for result in json_data['results']:
            yield result
        next_request = json_data['next']

def map_indicator_type(indicator_type):
    '''
    Maps an OTXv2 indicator type to a Bro Intel Framework type.
    '''

    return _MAP.get(indicator_type)

def main():
    '''Retrieve intel from OTXv2 API.'''

    parser = ArgumentParser(description='AlienVault OTXv2 Bro Client')
    parser.add_argument('-c', '--config', 
                        help='configuration file path',
                        default='bro-otx.conf')
    args = parser.parse_args()

    config = ConfigParser()
    config.read(args.config)
    key = config.get('otx', 'api_key')
    days = int(config.get('otx', 'days_of_history'))
    outfile = config.get('otx', 'outfile')
    do_notice = config.get('otx', 'do_notice')

    mtime = (datetime.now() - timedelta(days=days)).isoformat()

    with open(outfile + '.tmp', 'wb') as f:
        f.write(_HEADER)
        for pulse in iter_pulses(key, mtime):
            # Intel description for notices
            description = 'AlienVault OTXv2 - %s ID: %s Author: %s' % (
                                pulse[u'name'], 
                                pulse[u'id'], 
                                pulse[u'author_name'])
            # A lot of care has to go into creating this description.
            # Tabs are removed to prevent Bro from throwing errors.
            description = description.replace('\t', ' ')
            for indicator in pulse[u'indicators']:
                bro_type = map_indicator_type(indicator[u'type'])
                if bro_type is None:
                    continue
                try:
                    url = pulse[u'references'][0]
                except IndexError:
                    url = 'https://otx.alienvault.com'
                fields = [to_unicode(indicator[u'indicator']),
                    to_unicode(bro_type),
                    to_unicode(description),
                    to_unicode(url),
                    to_unicode(do_notice) + to_unicode('\n')]
                if fields[1] == "Intel::URL":
                    url = urlparse(fields[0])
                    fields[0] = url.geturl().replace('{0}://'.format(url.scheme), '')
                f.write('\t'.join(fields).encode('utf-8'))

	os.rename(outfile + '.tmp', outfile)

if __name__ == '__main__':
    main()
