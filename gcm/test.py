import unittest
from gcm import *
import json


class GCMTest(unittest.TestCase):

    def setUp(self):
        self.gcm = GCM('123api')
        self.data = {
            'param1': '1',
            'param2': '2'
        }

    def test_construct_payload(self):
        res = self.gcm.construct_payload(
            registration_ids=['1', '2'], data=self.data, collapse_key='foo',
            delay_while_idle=True, time_to_live=3600, is_json=True
        )
        payload = json.loads(res)
        for arg in ['registration_ids', 'data', 'collapse_key', 'delay_while_idle', 'time_to_live']:
            self.assertIn(arg, payload)

    def test_require_collapse_key(self):
        with self.assertRaises(GCMNoCollapseKeyException):
            self.gcm.construct_payload(registration_ids='1234', data=self.data, time_to_live=3600)

    def test_json_payload(self):
        reg_ids = ['12', '145', '56']
        json_payload = self.gcm.construct_payload(registration_ids=reg_ids, data=self.data)
        payload = json.loads(json_payload)

        self.assertIn('registration_ids', payload)
        self.assertEqual(payload['data'], self.data)
        self.assertEqual(payload['registration_ids'], reg_ids)

    def test_plaintext_payload(self):
        result = self.gcm.construct_payload(registration_ids='1234', data=self.data, is_json=False)

        self.assertIn('registration_id', result)
        self.assertIn('data.param1', result)
        self.assertIn('data.param2', result)

    def test_limit_reg_ids(self):
        reg_ids = range(1003)
        self.assertTrue(len(reg_ids) > 1000)
        with self.assertRaises(GCMTooManyRegIdsException):
            self.gcm.json_request(registration_ids=reg_ids, data=self.data)

    def test_missing_reg_id(self):
        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.json_request(registration_ids=[], data=self.data)

        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.plaintext_request(registration_id=None, data=self.data)

    def test_invalid_ttl(self):
        with self.assertRaises(GCMInvalidTtlException):
            self.gcm.construct_payload(
                registration_ids='1234', data=self.data, is_json=False, time_to_live=5000000
            )

        with self.assertRaises(GCMInvalidTtlException):
            self.gcm.construct_payload(
                registration_ids='1234', data=self.data, is_json=False, time_to_live=-10
            )

    def test_handle_response(self):
        response = {
            'results': {'error': 'MissingRegistration'}
        }
        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.handle_response(response)

        response['results']['error'] = 'InvalidRegistration'
        with self.assertRaises(GCMMismatchSenderIdException):
            self.gcm.handle_response(response)

        response['results']['error'] = 'NotRegistered'
        with self.assertRaises(GCMNotRegisteredException):
            self.gcm.handle_response(response)

        response['results']['error'] = 'MessageTooBig'
        with self.assertRaises(GCMMessageTooBigException):
            self.gcm.handle_response(response)

if __name__ == '__main__':
    unittest.main()
