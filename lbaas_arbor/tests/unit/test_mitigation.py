import logging

import mock
import six

from lbaas_arbor import arbor
from lbaas_arbor.tests.unit import base
from lbaas_arbor import mitigation


if six.PY2:
    import ConfigParser
else:
    import configparser as ConfigParser


example_return_mitigations = [
    {  # Expired mitigation
        "alert_id": "1255991",
        "annotations": [
            {
                "added": "2015-03-18T23:09:08",
                "author": "auto-annotation",
                "content": ("UDP Misuse attack #1255991 Incoming to "
                            "DFW_Cloud_LBaaS_304198 done")
            },
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": ("UDP Misuse attack #1255991 Incoming to "
                            "DFW_Cloud_LBaaS_304198 is now \"High\"")
            },
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": "Auto-mitigation for alert #1255991 Started."
            }
        ],
        "description": arbor.FILTER_TAG,
        "duration": "538.477199018002",
        "id": "1425",
        "ip_version": "4",
        "is_automitigation": True,
        "is_learning": False,
        "learning_cancelled": False,
        "managed_object_id": "1782",
        "managed_object_name": "DFW_Cloud_LBaaS_304198",
        "name": "Alert 1255991 Auto-Mitigation",
        "ongoing": True,
        "prefix": "162.242.141.132/32",
        "start": "2015-03-18T23:01:54",
        "type": "tms_mitigation",
        "user": "auto-mitigation"
    },
    {  # New mitigation
        "alert_id": "1255992",
        "annotations": [
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": ("UDP Misuse attack #1255992 Incoming to "
                            "DFW_Cloud_LBaaS_304199 is now \"High\"")
            },
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": "Auto-mitigation for alert #1255992 Started."
            }
        ],
        "duration": "538.477199018002",
        "id": "1426",
        "ip_version": "4",
        "is_automitigation": True,
        "is_learning": False,
        "learning_cancelled": False,
        "managed_object_id": "1783",
        "managed_object_name": "DFW_Cloud_LBaaS_304199",
        "name": "Alert 1255992 Auto-Mitigation",
        "ongoing": True,
        "prefix": "162.242.141.133/32",
        "start": "2015-03-18T23:01:54",
        "type": "tms_mitigation",
        "user": "auto-mitigation"
    },
    {  # Filtered mitigation
        "alert_id": "1255993",
        "annotations": [
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": ("UDP Misuse attack #1255993 Incoming to "
                            "DFW_Cloud_LBaaS_304200 is now \"High\"")
            },
            {
                "added": "2015-03-18T23:01:54",
                "author": "auto-annotation",
                "content": "Auto-mitigation for alert #1255993 Started."
            }
        ],
        "description": arbor.FILTER_TAG,
        "duration": "538.477199018002",
        "id": "1427",
        "ip_version": "4",
        "is_automitigation": True,
        "is_learning": False,
        "learning_cancelled": False,
        "managed_object_id": "1784",
        "managed_object_name": "DFW_Cloud_LBaaS_304199",
        "name": "Alert 1255993 Auto-Mitigation",
        "ongoing": True,
        "prefix": "162.242.141.134/32",
        "start": "2015-03-18T23:01:54",
        "type": "tms_mitigation",
        "user": "auto-mitigation"
    },
]


example_lbip_data = [
    {'protocol': 'UDP', 'port': 6777},
    {'protocol': 'UDP', 'port': 6778},
    {'protocol': 'TCP', 'port': 21},
    {'protocol': 'TCP', 'port': 443}
]


class TestMitigations(base.TestCase):
    def setUp(self):
        super(TestMitigations, self).setUp()
        conf = ConfigParser.ConfigParser()
        conf.add_section('global')
        conf.set('global', 'arbor_api_user', 'soap')
        conf.set('global', 'arbor_api_pass', '')
        conf.set('global', 'arbor_api_key', '')
        conf.set('global', 'arbor_api_url', 'https://myarbor.com/')
        conf.add_section('DFW')
        conf.set('DFW', 'host', 'dev.lbaas.com')
        conf.set('DFW', 'port', '3306')
        conf.set('DFW', 'user', 'DB_USER')
        conf.set('DFW', 'pass', 'DB_PASSWORD')
        conf.set('DFW', 'database', 'loadbalancing')
        self.conf = conf
        self.default_replacements = {
            'arbor_api_key': conf.get('global', 'arbor_api_key'),
            'arbor_api_url': conf.get('global', 'arbor_api_url')
        }
        logging.basicConfig(
            level="WARNING"
        )

    def test_fcap_filter(self):
        m = mitigation.MitigationManager(conf=self.conf, dry_run=True)
        lbip_mock = mock.MagicMock()
        lbip_mock.return_value = example_lbip_data
        m._get_lb_data_for_ip = lbip_mock
        data = m._get_lb_data_for_ip(
            ip='10.12.99.67',
            region="DEV"
        )
        fcap_filter = m._make_fcap_filter(data)
        expected_filter = (
            'DROP not (ICMP or TCP or UDP) or '
            '(TCP and not (dst port 21 or dst port 443)) or '
            '(UDP and not (dst port 6777 or dst port 6778)) or '
            '(ICMP and not (icmptype icmp-echoreply or icmptype icmp-echo))'
        )
        self.assertEqual(expected_filter, fcap_filter)

    def test_actually_get_mitigation_list(self):
        self.skip("Not a unit test.")
        m = mitigation.MitigationManager(conf=self.conf, dry_run=False)
        lbip_mock = mock.MagicMock()
        lbip_mock.return_value = example_lbip_data
        m._get_lb_data_for_ip = lbip_mock
        m.run()

    def test_get_mitigation_list(self):
        with mock.patch('requests.request') as request:
            m = mitigation.MitigationManager(conf=self.conf, dry_run=True)
            r_mock = mock.MagicMock()
            # r_mock.json.return_value = example_return_alerts
            # request.return_value = r_mock
            # alerts = arbor.ArborAlerts().get_results()
            r_mock.json.return_value = example_return_mitigations
            request.return_value = r_mock
            mitigations = arbor.ArborMitigations(
                replacements=self.default_replacements
            ).get_results()
            # arbor_alerts = mock.MagicMock()
            # mitigation.arbor.ArborAlerts.get_results = arbor_alerts
            arbor_mitigations = mock.MagicMock()
            mitigation.arbor.ArborMitigations.get_results = arbor_mitigations
            # arbor_alerts.return_value = alerts
            arbor_mitigations.return_value = mitigations

            lbip_mock = mock.MagicMock()
            lbip_mock.return_value = example_lbip_data
            m._get_lb_data_for_ip = lbip_mock

            m.run()

        self.assertEqual(type(m.new_mitigations), list)
        self.assertEqual(1, len(m.new_mitigations))
        self.assertEqual(type(m.ongoing_mitigations), list)
        self.assertEqual(1, len(m.ongoing_mitigations))
        self.assertEqual(type(m.expired_mitigations), list)
        self.assertEqual(1, len(m.expired_mitigations))

        new_mit = m.new_mitigations[0]
        self.assertEqual('1426', new_mit.mitigation_id)
        self.assertEqual('1255992', new_mit.alert_id)
        self.assertEqual('162.242.141.133', new_mit.ip)
        self.assertEqual('Alert 1255992 Auto-Mitigation', new_mit.name)
        self.assertEqual('DFW', new_mit.region)
        self.assertFalse(new_mit.done)
        self.assertFalse(new_mit.filter_applied)

        ongoing_mit = m.ongoing_mitigations[0]
        self.assertEqual('1427', ongoing_mit.mitigation_id)
        self.assertEqual('1255993', ongoing_mit.alert_id)
        self.assertEqual('162.242.141.134', ongoing_mit.ip)
        self.assertEqual('Alert 1255993 Auto-Mitigation', ongoing_mit.name)
        self.assertEqual('DFW', ongoing_mit.region)
        self.assertFalse(ongoing_mit.done)
        self.assertTrue(ongoing_mit.filter_applied)

        expired_mit = m.expired_mitigations[0]
        self.assertEqual('1425', expired_mit.mitigation_id)
        self.assertEqual('1255991', expired_mit.alert_id)
        self.assertEqual('162.242.141.132', expired_mit.ip)
        self.assertEqual('Alert 1255991 Auto-Mitigation', expired_mit.name)
        self.assertEqual('DFW', expired_mit.region)
        self.assertTrue(expired_mit.done)
        self.assertTrue(expired_mit.filter_applied)

    def test_mitigations_call(self):
        mitigations = arbor.ArborMitigations(
            replacements=self.default_replacements
        ).get_results()
        self.assertIsNotNone(mitigations)
