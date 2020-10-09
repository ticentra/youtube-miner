from __future__ import absolute_import

import logging
from pymisp import PyMISP

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)


_MISP_TO_MINEMELD = {
    'url': 'URL',
    'ip-dst': 'IPv4',
    'ip-src': 'IPv4',
    'domain': 'domain',
    'hostname': 'domain',
    'md5': 'md5',
    'sha256': 'sha256',
    'sha1': 'sha1',
    'sha512': 'sha512',
    'ssdeep': 'ssdeep',
    'mutex': 'mutex',
    'filename': 'file.name'
}


class MISPMiner(BasePollerFT):
    # this method sets all variables required by miner
    # including ones defined in config file
    # returns error if required value wasn't defined in config
    def configure(self):
        super(MISPMiner, self).configure()

        # get MISP credentials from config
        self.verify_cert = self.config.get('verify_cert', False)
        self.misp_url = self.config.get('misp_url', None)
        if self.misp_url is None:
            raise ValueError('%s - MISP URL is required' % self.name)
        self.misp_key = self.config.get('misp_key', None)
        if self.misp_key is None:
            raise ValueError('%s - MISP key is required' % self.name)

        # create MISP object
        self.misp = PyMISP(self.misp_url, self.misp_key, False)

        # get search values
        self.attr_tag = self.config.get('attr_tag', self.verify_cert)
        if self.attr_tag is None:
            raise ValueError('%s - Attribute teg is required' % self.name)

    def _process_item(self, item):
        # called on each item returned by _build_iterator
        # it should return a list of (indicator, value) pairs

        # each item is a dict in raw json format returned by misp, example:

        indicator = item['value']
        try:
            attr_type = _MISP_TO_MINEMELD[item['type']]
        except KeyError:
            attr_type = item['type']
        value = {
            'type': attr_type,
            'confidence': 100
        }

        return [[indicator, value]]

    def _build_iterator(self, now):
        # called at every polling interval
        # search wanted attributes and return them as lists
        search_result = self.misp.search(controller='attributes', tags=[self.attr_tag])
        try:
            return search_result['Attribute']
        except:
            LOG.debug('MISP response error:\n %s', search_result)
            return []
