import unittest
from gcm import *
import json
from mock import MagicMock, patch
import time


# Helper method to return a different value for each call.
def create_side_effect(returns):
    def side_effect(*args, **kwargs):
        result = returns.pop(0)
        if isinstance(result, Exception):
            raise result
        return result
    return side_effect


class GCMTest(unittest.TestCase):

    def setUp(self):
        self.gcm = GCM('123api')
        self.data = {
            'param1': '1',
            'param2': '2'
        }
        self.response = {
            'results': [
                {'error': 'InvalidRegistration'},
                {'error': 'NotRegistered'},
                {'message_id': '54749687859', 'registration_id': '6969'},
                {'message_id': '5456453453'},
                {'error': 'NotRegistered'},
                {'message_id': '123456778', 'registration_id': '07645'},
            ]
        }
        self.mock_response_1 = {
            'results': [
                {'error': 'Unavailable'},
                {'error': 'Unavailable'},
            ]
        }
        self.mock_response_2 = {
            'results': [
                {'error': 'Unavailable'},
                {'message_id': '1234'}
            ]
        }
        self.mock_response_3 = {
            'results': [
                {'message_id': '5678'},
                {'message_id': '1234'}
            ]
        }
        time.sleep = MagicMock()

    def test_gcm_proxy(self):
        self.gcm = GCM('123api', proxy='http://domain.com:8888')
        self.assertEqual(self.gcm.proxy, {
            'https': 'http://domain.com:8888'
        })

        self.gcm = GCM('123api', proxy={
            'http': 'http://domain.com:8888',
            'https': 'https://domain.com:8888'
        })
        self.assertEqual(self.gcm.proxy, {
            'http': 'http://domain.com:8888',
            'https': 'https://domain.com:8888'
        })

    def test_construct_payload(self):
        res = self.gcm.construct_payload(
            registration_ids=['1', '2'], data=self.data, collapse_key='foo',
            delay_while_idle=True, time_to_live=3600, is_json=True, dry_run = True
        )
        payload = json.loads(res)
        for arg in ['registration_ids', 'data', 'collapse_key', 'delay_while_idle', 'time_to_live', 'dry_run']:
            self.assertIn(arg, payload)

    def test_json_payload(self):
        reg_ids = ['12', '145', '56']
        json_payload = self.gcm.construct_payload(registration_ids=reg_ids, data=self.data)
        payload = json.loads(json_payload)

        self.assertIn('registration_ids', payload)
        self.assertEqual(payload['data'], self.data)
        self.assertEqual(payload['registration_ids'], reg_ids)

    def test_plaintext_payload(self):
        result = self.gcm.construct_payload(
            registration_ids='1234', data=self.data, is_json=False
        )
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

    def test_group_response(self):
        ids = ['123', '345', '678', '999', '1919', '5443']
        error_group = group_response(self.response, ids, 'error')
        self.assertEqual(error_group['NotRegistered'], ['345', '1919'])
        self.assertEqual(error_group['InvalidRegistration'], ['123'])

        canonical_group = group_response(self.response, ids, 'registration_id')
        self.assertEqual(canonical_group['678'], '6969')
        self.assertEqual(canonical_group['5443'], '07645')

    def test_group_response_no_error(self):
        ids = ['123', '345', '678']
        response = {
            'results': [
                {'message_id': '346547676'},
                {'message_id': '54749687859'},
                {'message_id': '5456453453'},
            ]
        }
        error_group = group_response(response, ids, 'error')
        canonical_group = group_response(response, ids, 'registration_id')
        self.assertEqual(error_group, None)
        self.assertEqual(canonical_group, None)

    def test_handle_json_response(self):
        ids = ['123', '345', '678', '999', '1919', '5443']
        res = self.gcm.handle_json_response(self.response, ids)

        self.assertIn('errors', res)
        self.assertIn('NotRegistered', res['errors'])
        self.assertIn('canonical', res)
        self.assertIn('678', res['canonical'])

    def test_handle_json_response_no_error(self):
        ids = ['123', '345', '678']
        response = {
            'results': [
                {'message_id': '346547676'},
                {'message_id': '54749687859'},
                {'message_id': '5456453453'},
            ]
        }
        res = self.gcm.handle_json_response(response, ids)

        self.assertNotIn('errors', res)
        self.assertNotIn('canonical', res)

    def test_handle_plaintext_response(self):
        response = 'Error=NotRegistered'
        with self.assertRaises(GCMNotRegisteredException):
            self.gcm.handle_plaintext_response(response)

        response = 'id=23436576'
        res = self.gcm.handle_plaintext_response(response)
        self.assertIsNone(res)

        response = 'id=23436576\nregistration_id=3456'
        res = self.gcm.handle_plaintext_response(response)
        self.assertEqual(res, '3456')

    @patch('requests.post')
    def test_make_request_header(self, mock_request):
        """ Test plaintext make_request. """

        mock_request.return_value.status_code = 200
        mock_request.return_value.content = "OK"
        # Perform request
        self.gcm.make_request(
            {'message': 'test'}, is_json=True
        )
        self.assertEqual(self.gcm.headers['Content-Type'],
            'application/json'
        )
        self.assertTrue(mock_request.return_value.json.called)


    @patch('requests.post')
    def test_make_request_plaintext(self, mock_request):
        """ Test plaintext make_request. """

        mock_request.return_value.status_code = 200
        mock_request.return_value.content = "OK"
        # Perform request
        response = self.gcm.make_request(
            {'message': 'test'}, is_json=False
        )
        self.assertEqual(response, "OK")

        mock_request.return_value.status_code = 400
        with self.assertRaises(GCMMalformedJsonException):
            response = self.gcm.make_request(
                {'message': 'test'}, is_json=False
            )

        mock_request.return_value.status_code = 401
        with self.assertRaises(GCMAuthenticationException):
            response = self.gcm.make_request(
                {'message': 'test'}, is_json=False
            )

        mock_request.return_value.status_code = 503
        with self.assertRaises(GCMUnavailableException):
            response = self.gcm.make_request(
                {'message': 'test'}, is_json=False
            )

    @patch('requests.api.request')
    def test_make_request_unicode(self, mock_request):
        """ Test make_request with unicode payload. """
        data = {
            'message': u'\x80abc'
        }
        try:
            self.gcm.make_request(data, is_json=False)
        except:
            pass
        self.assertTrue(mock_request.called)
        self.assertEqual(
            mock_request.call_args[1]['data'],
            'message=%C2%80abc'
        )

    def test_retry_plaintext_request_ok(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), 'id=123456789']

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        res = self.gcm.plaintext_request(registration_id='1234', data=self.data)

        self.assertIsNone(res)
        self.assertEqual(self.gcm.make_request.call_count, 3)

    def test_retry_plaintext_request_fail(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), GCMUnavailableException()]

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        with self.assertRaises(IOError):
            self.gcm.plaintext_request(registration_id='1234', data=self.data, retries=2)

        self.assertEqual(self.gcm.make_request.call_count, 2)

    def test_retry_json_request_ok(self):
        returns = [self.mock_response_1, self.mock_response_2, self.mock_response_3]

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        res = self.gcm.json_request(registration_ids=['1', '2'], data=self.data)

        self.assertEqual(self.gcm.make_request.call_count, 3)
        self.assertNotIn('errors', res)

    def test_retry_json_request_fail(self):
        returns = [self.mock_response_1, self.mock_response_2, self.mock_response_3]

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        res = self.gcm.json_request(registration_ids=['1', '2'], data=self.data, retries=2)

        self.assertEqual(self.gcm.make_request.call_count, 2)
        self.assertIn('Unavailable', res['errors'])
        self.assertEqual(res['errors']['Unavailable'][0], '1')

    def test_retry_exponential_backoff(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), 'id=123456789']

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        self.gcm.plaintext_request(registration_id='1234', data=self.data)

        # time.sleep is actually mock object.
        self.assertEqual(time.sleep.call_count, 2)
        backoff = self.gcm.BACKOFF_INITIAL_DELAY
        for arg in time.sleep.call_args_list:
            sleep_time = int(arg[0][0] * 1000)
            self.assertTrue(backoff / 2 <= sleep_time <= backoff * 3 / 2)
            if 2 * backoff < self.gcm.MAX_BACKOFF_DELAY:
                backoff *= 2

if __name__ == '__main__':
    unittest.main()
