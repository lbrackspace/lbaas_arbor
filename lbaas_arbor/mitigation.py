import base64
import logging
import mock
import os

import pymysql
import six
import suds.client
import suds.transport.https

from lbaas_arbor import arbor
from lbaas_arbor import regions

if six.PY3:
    import urllib as urllib2
    import urllib.parse as urlparse
else:
    import urlparse
    import urllib2

LOG = logging.getLogger('lbaas_arbor')


class MitigationManager(object):
    def __init__(self, conf, dry_run=False):
        self.conf = conf

        self.regions = regions.Region.load_regions(conf=conf)

        self.arbor_endpoint = self.conf.get('global', 'arbor_api_url')
        self._arbor_username = self.conf.get('global', 'arbor_api_user')
        self._arbor_password = self.conf.get('global', 'arbor_api_pass')
        self.arbor_wsdl = '/'.join(
            ['file:/', os.path.dirname(os.path.realpath(__file__)),
             'wsdl', 'PeakflowSP.wsdl']
        )
        if dry_run:
            self.arbor_client = mock.MagicMock()
        else:
            t = suds.transport.https.HttpAuthenticated(
                username=self._arbor_username, password=self._arbor_password
            )
            t.handler = urllib2.HTTPDigestAuthHandler(t.pm)
            t.urlopener = urllib2.build_opener(t.handler)
            self.arbor_client = suds.client.Client(
                self.arbor_wsdl,
                location=urlparse.urljoin(self.arbor_endpoint, "/soap/sp"),
                transport=t
            )

        self.default_replacements = {
            'arbor_api_key': conf.get('global', 'arbor_api_key'),
            'arbor_api_url': conf.get('global', 'arbor_api_url')
        }

        self._new_mitigations = None
        self._ongoing_mitigations = None
        self._expired_mitigations = None

    @staticmethod
    def _make_fcap_filter(lb_data):
        my_protocols = {combo['protocol'] for combo in lb_data}
        prot_ports = {protocol: [] for protocol in my_protocols}
        for combo in lb_data:
            prot_ports[combo['protocol']].append(str(combo['port']))
        my_list = [
            "({protocol} and not (dst port {ports}))".format(
                protocol=combo[0], ports=' or dst port '.join(combo[1])
            )
            for combo in six.iteritems(prot_ports)
        ]
        my_protocols.update({"ICMP"})
        my_protocols = sorted(list(my_protocols))
        fcap_filter = ("DROP not (" + " or ".join(my_protocols) + ") or "
                       + " or ".join(sorted(my_list)) + " or (ICMP and not"
                       " (icmptype icmp-echoreply or icmptype icmp-echo))")
        return fcap_filter

    @staticmethod
    def _make_arbor_filter_command(name, fcap_filter):
        command = (
            'services sp mitigation tms edit "{mit_name}" '
            'filter other_black_white set "{fcap_filter}"'
            .format(mit_name=name, fcap_filter=fcap_filter)
        )
        return command

    @staticmethod
    def _make_arbor_description_command(name, description):
        command = (
            'services sp mitigation tms edit "{mit_name}" '
            'description set "{description}"'
            .format(mit_name=name, description=description)
        )
        return command

    @staticmethod
    def _make_arbor_stop_command(name):
        command = (
            'services sp mitigation tms stop "{mit_name}"'
            .format(mit_name=name)
        )
        return command

    @property
    def new_mitigations(self):
        if self._new_mitigations is None:
            self._calculate_mitigation_list()
        return self._new_mitigations

    @property
    def ongoing_mitigations(self):
        if self._ongoing_mitigations is None:
            self._calculate_mitigation_list()
        return self._ongoing_mitigations

    @property
    def expired_mitigations(self):
        if self._expired_mitigations is None:
            self._calculate_mitigation_list()
        return self._expired_mitigations

    def _calculate_mitigation_list(self):
        my_mitigations = arbor.ArborMitigations(
            self.default_replacements
        ).get_results()

        # list of new mitigations (we will add filters to these)
        new_mitigations = []
        # list of ongoing mitigations (we won't touch these)
        ongoing_mitigations = []
        # list of expired mitigations (we will delete these)
        expired_mitigations = []
        for mit in my_mitigations:
            if not mit.done:
                if not mit.filter_applied:
                    new_mitigations.append(mit)
                else:
                    ongoing_mitigations.append(mit)
            else:
                expired_mitigations.append(mit)

        self._new_mitigations = new_mitigations
        self._ongoing_mitigations = ongoing_mitigations
        self._expired_mitigations = expired_mitigations

    @staticmethod
    def _translate_protocol(protocol):
        if protocol in ["UDP", "UDP_STREAM", "DNS_UDP"]:
            return "UDP"
        return "TCP"

    def _get_lb_data_for_ip(self, ip, region):
        query = (
            "SELECT LBVIP.port, LB.protocol"
            "  FROM virtual_ip_ipv4 AS VIP"
            "  JOIN loadbalancer_virtualip AS LBVIP"
            "    ON LBVIP.virtualip_id = VIP.id"
            "  JOIN loadbalancer AS LB"
            "    ON LB.id = LBVIP.loadbalancer_id"
            "  WHERE ip_address = '{ip}'"
        ).format(ip=ip)
        db = self.regions[region.upper()].get_db()
        c = db.cursor(pymysql.cursors.DictCursor)
        c.execute(query)
        data = [
            {
                "port": row.get("port"),
                "protocol": self._translate_protocol(row.get("protocol"))
            }
            for row in c
        ]
        return data

    def _arbor_mit_filter(self, mit):
        lb_data = self._get_lb_data_for_ip(ip=mit.ip, region=mit.region)
        fcap_filter = self._make_fcap_filter(lb_data)
        fcap_command = self._make_arbor_filter_command(mit.name, fcap_filter)
        fcap_command_b64 = base64.standard_b64encode(six.b(fcap_command))
        desc_command = self._make_arbor_description_command(mit.name,
                                                            arbor.FILTER_TAG)
        desc_command_b64 = base64.standard_b64encode(six.b(desc_command))
        LOG.debug(fcap_command)
        ret1 = self.arbor_client.service.cliRun(
            command=fcap_command_b64, timeout=5
        )
        LOG.debug(ret1)
        LOG.debug(desc_command)
        ret2 = self.arbor_client.service.cliRun(
            command=desc_command_b64, timeout=5
        )
        LOG.debug(ret2)

    def _arbor_mit_delete(self, mit):
        command = self._make_arbor_stop_command(mit.name)
        command_b64 = base64.standard_b64encode(six.b(command))
        LOG.debug(command)
        self.arbor_client.service.cliRun(
            command=command_b64, timeout=5
        )

    def add_filters_to_new_mitigations(self):
        for mit in self.new_mitigations:
            LOG.info("Adding filter to mitigation: {0}".format(mit))
            self._arbor_mit_filter(mit)

    def delete_expired_mitigations(self):
        for mit in self.expired_mitigations:
            LOG.info("Deleting mitigation: {0}".format(mit))
            self._arbor_mit_delete(mit)

    def run(self):
        self.add_filters_to_new_mitigations()
        self.delete_expired_mitigations()
        for mit in self.ongoing_mitigations:
            LOG.info("Ongoing mitigation untouched: {0}".format(mit))
