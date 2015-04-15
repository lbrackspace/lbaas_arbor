import logging

import requests
import six

from lbaas_arbor import exceptions

LOG = logging.getLogger('lbaas_arbor')
FILTER_TAG = "LBAASFILTERED"


class RESTQuery(object):
    # Method (GET / POST / etc), default is GET (string)
    method = "GET"
    # Full URI for the request (string)
    url = ""
    # Parameters for the request (dict)
    params = None
    # Body of the request (dict)
    body = None
    # Headers to include in the request (dict)
    headers = None
    # Replacements that will be applied to the above data (dict)
    replacements = {}

    def __init__(self, replacements=None):
        if replacements:
            self.replacements.update(replacements)

        self.url = self.url.format(**self.replacements)

        if self.params:
            self.params = {k: str(p).format(**self.replacements)
                           for k, p in six.iteritems(self.params)}
        if self.body:
            self.body = {k: str(b).format(**self.replacements)
                         for k, b in six.iteritems(self.body)}
        if self.headers:
            self.headers = {k: str(h).format(**self.replacements)
                            for k, h in six.iteritems(self.headers)}

    def _parse_response(self, resp):
        return resp

    def get_results(self):
        if self.method and self.url:
            try:
                resp = requests.request(
                    method=self.method,
                    url=self.url,
                    params=self.params,
                    data=self.body,
                    headers=self.headers,
                    verify=False
                )
                resp.raise_for_status()
                data = resp.json()
                return self._parse_response(data)
            except Exception:
                raise exceptions.MitigationException(
                    mitigation=self.__class__.__name__
                )


class LBaaSMitigation(object):
    def __init__(self, name, ip, alert_id, region, mitigation_id, description,
                 mo_name, annotations):
        self.name = name
        self.ip = ip
        self.alert_id = alert_id
        self.region = region
        self.mitigation_id = mitigation_id
        self.description = description
        self.mo_name = mo_name
        self.annotations = annotations

    @property
    def filter_applied(self):
        if self.description and FILTER_TAG in self.description:
            return True
        return False

    @property
    def done(self):
        for a in self.annotations:
            author = a.get("author")
            content = a.get("content")
            done_filter = "{0} done".format(self.mo_name)
            if author == "auto-annotation" and done_filter in content:
                return True
        return False

    def __str__(self):
        return "<LBaaSMitigation for {0}>".format(self.mitigation_id)

    def __repr__(self):
        return "LBaaSMitigation({0}, {1}, {2}, {3})".format(
            self.mitigation_id, self.region, self.filter_applied, self.done
        )


class ArborMitigations(RESTQuery):
    method = "POST"
    url = "{arbor_api_url}/arborws/mitigations/status"
    body = {
        "api_key": "{arbor_api_key}"
    }
    params = {
        "limit": 100,
        "filter": "Auto-Mitigation"
    }

    def _parse_response(self, resp):
        mitigations = []
        for p in resp:
            try:
                mo_name = p.get('managed_object_name')
                if 'LBaaS' not in mo_name:
                    continue
                alert_id = p.get('alert_id')
                auto_mit = p.get('is_automitigation')
                ongoing = p.get('ongoing')
                if not alert_id or not auto_mit or not ongoing:
                    continue
                mit_id = p.get('id')
                ip = p.get('prefix')
                if ip and '/32' in ip:
                    ip = ip.replace('/32', '')
                else:
                    LOG.warning("IP for Mitigation {0} not a /32: {1}"
                                .format(mit_id, ip))
                    continue
                name = p.get('name')
                region = mo_name.split('_')[0].upper()
                mit = LBaaSMitigation(
                    name=name,
                    mo_name=mo_name,
                    alert_id=alert_id,
                    mitigation_id=mit_id,
                    region=region,
                    ip=ip,
                    description=p.get('description'),
                    annotations=p.get('annotations')
                )
                mitigations.append(mit)
            except Exception:  # Pokemon!
                LOG.exception("Failed to handle mitigation: {0}".format(p))
        return mitigations
