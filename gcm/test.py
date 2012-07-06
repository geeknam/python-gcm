import unittest
from gcm import *
import json


class GCMTest(unittest.TestCase):

    def setUp(self):
        self.gcm = GCM('123api')

    def test_json_payload(self):
        data = {
            'param1': '1',
            'param2': '2'
        }
        reg_ids = ['12', '145', '56']
        json_payload = self.gcm.construct_payload(registration_ids=reg_ids, data=data)
        payload = json.loads(json_payload)

        self.assertIn('registration_ids', payload)
        self.assertEqual(payload['data'], data)
        self.assertEqual(payload['registration_ids'], reg_ids)

    def test_plaintext_payload(self):
        data = {
            'param1': '1',
            'param2': '2'
        }
        result = self.gcm.construct_payload(registration_ids='1234', data=data, is_json=False)

        self.assertIn('registration_id', result)
        self.assertIn('data.param1', result)
        self.assertIn('data.param2', result)

    def test_limit_reg_ids(self):
        reg_ids = range(1003)
        data = {'key': 'value'}
        self.assertTrue(len(reg_ids) > 1000)
        with self.assertRaises(GCMTooManyRegIdsException):
            self.gcm.json_request(registration_ids=reg_ids, data=data)

    def test_missing_reg_id(self):
        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.json_request(registration_ids=[], data={'key': 'value'})

        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.plaintext_request(registration_id=None, data={'key': 'value'})

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
