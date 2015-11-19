import unittest
from gcm import *
import json
from mock import MagicMock, Mock, PropertyMock, patch, sentinel
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
        time.sleep = Mock()

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

        self.assertNotIn('priority', payload)

    def test_construct_payload_with_priority(self):
        res = self.gcm.construct_payload(
            registration_ids=['1', '2'], data=self.data, collapse_key='foo',
            delay_while_idle=True, time_to_live=3600, is_json=True, dry_run=True,
            priority=10
        )
        payload = json.loads(res)
        for arg in ['registration_ids', 'data', 'collapse_key', 'delay_while_idle', 'time_to_live', 'dry_run', 'priority']:
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

    def test_topic_payload(self):
        topic = 'foo'
        json_payload = self.gcm.construct_payload(topic=topic,
                                                  data=self.data)
        payload = json.loads(json_payload)

        self.assertEqual(payload['data'], self.data)
        self.assertEqual(payload.get('to'), '/topics/foo')

    def test_invalid_registration_ids_and_topic(self):
        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.construct_payload()

        with self.assertRaises(GCMInvalidInputException):
            reg_ids = ['12', '145', '56']
            topic = 'foo'
            self.gcm.construct_payload(registration_ids=reg_ids,
                                       topic=topic)

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

    def test_empty_topic(self):
        with self.assertRaises(GCMInvalidInputException):
            self.gcm.send_topic_message(topic='', data=self.data)

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

        success_group = group_response(self.response, ids, 'message_id')
        self.assertEqual(success_group['678'], '54749687859')
        self.assertEqual(success_group['999'], '5456453453')
        self.assertEqual(success_group['5443'], '123456778')

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
        success_group = group_response(response, ids, 'message_id')

        self.assertEqual(error_group, None)
        self.assertEqual(canonical_group, None)

        for id in ids:
            self.assertIn(id,success_group)

    def test_handle_json_response(self):
        ids = ['123', '345', '678', '999', '1919', '5443']
        res = self.gcm.handle_json_response(self.response, ids)

        self.assertIn('errors', res)
        self.assertIn('NotRegistered', res['errors'])
        self.assertIn('canonical', res)
        self.assertIn('678', res['canonical'])
        self.assertIn('678', res['success'])
        self.assertNotIn('123', res['success'])

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
        self.assertIn('success', res)

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

    def test_handle_topic_response(self):
        response = {'error': 'TopicsMessageRateExceeded'}
        with self.assertRaises(GCMTopicMessageException):
            self.gcm.handle_topic_response(response)

        response = {'message_id': '10'}
        res = self.gcm.handle_topic_response(response)
        self.assertEqual('10', res)

    @patch('requests.Session.post')
    def test_make_request_header(self, mock_request):
        """ Test plaintext make_request. """

        mock_request.return_value.status_code = 200
        mock_request.return_value.content = "OK"
        # Perform request
        self.gcm.make_request(
            {'message': 'test'}, is_json=True
        )
        self.assertTrue(mock_request.return_value.json.called)

    @patch('requests.Session.post')
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

    @patch('requests.Session.post')
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
            mock_request.call_args[1]['data']['message'],
            data['message']
        )

    @patch('requests.Session.post')
    def test_make_request_timeout(self, mock_request):
        """ Test make_request uses timeout. """
        mock_request.return_value.status_code = 200
        mock_request.return_value.content = "OK"
        gcm = GCM('123api', timeout=sentinel.timeout)

        gcm.make_request(
            {'message': 'test'}, is_json=True
        )
        mock_request.assert_called_once_with(
            GCM_URL, data={'message': 'test'},
            headers={'Authorization': 'key=123api', 'Content-Type': 'application/json'}, proxies=None,
            timeout=sentinel.timeout,
        )

    def test_plaintext_request_ok(self):
        returns = ['id=123456789']
        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        res = self.gcm.plaintext_request(registration_id='1234', data=self.data, retries=1)
        self.assertIsNone(res)
        self.assertEqual(self.gcm.make_request.call_count, 1)

    def test_retry_plaintext_request_ok(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), 'id=123456789']

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        with self.assertRaises(IOError):
            res = self.gcm.plaintext_request(registration_id='1234', data=self.data, retries=1)
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

    def test_retry_topic_request_ok(self):
        message_id = '123456789'
        returns = [GCMUnavailableException(), GCMUnavailableException(), {'message_id': message_id}]

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))
        res = self.gcm.send_topic_message(topic='foo', data=self.data)

        self.assertEqual(res, message_id)
        self.assertEqual(self.gcm.make_request.call_count, 3)

    def test_retry_topic_request_fail(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), GCMUnavailableException()]
        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))

        with self.assertRaises(IOError):
            self.gcm.send_topic_message(topic='foo', data=self.data, retries=2)

        self.assertEqual(self.gcm.make_request.call_count, 2)

    def test_retry_exponential_backoff(self):
        returns = [GCMUnavailableException(), GCMUnavailableException(), 'id=123456789']

        self.gcm.make_request = MagicMock(side_effect=create_side_effect(returns))

        with self.assertRaises(IOError):
            self.gcm.plaintext_request(registration_id='1234', data=self.data, retries=2)

        # time.sleep is actually mock object.
        self.assertEqual(time.sleep.call_count, 2)
        backoff = self.gcm.BACKOFF_INITIAL_DELAY
        for arg in time.sleep.call_args_list:
            sleep_time = int(arg[0][0] * 1000)
            self.assertTrue(backoff / 2 <= sleep_time <= backoff * 3 / 2)
            if 2 * backoff < self.gcm.MAX_BACKOFF_DELAY:
                backoff *= 2

    @patch('requests.Session.post')
    def test_retry_after_header_plaintext_request_with_varying_status(self, mock_request):
        retries = 2

        for index, status in enumerate([200, 500, 503]):
            mock_request.return_value.status_code = status
            mock_request.return_value.headers['Retry-After'] = 30

            self.gcm.make_request = MagicMock(return_value='Error=Unavailable')
            self.gcm.retry_after = PropertyMock(return_value=True)

            self.assertIsNotNone(self.gcm.retry_after)

            with self.assertRaises(IOError):
                res = self.gcm.plaintext_request(registration_id='123', data=self.data, retries=retries)

                self.assertIsNone(self.gcm.retry_after)
                self.assertEqual(time.sleep.call_count, retries + index)
                self.assertFalse(mock_request.return_value.content.called)
                self.assertEqual(self.gcm.make_request.call_count, retries)
                print(res)
                self.assertIn('errors', res)
                self.assertIn('Unavailable', res['errors'])
                self.assertEqual(res['errors']['Unavailable'][0], '1')
                self.assertEqual(res['errors']['Unavailable'][1], '2')

    @patch('requests.Session.post')
    def test_retry_after_header_json_request_with_varying_status(self, mock_request):
        retries = 1

        for index, status in enumerate([200, 500, 503]):
            mock_request.return_value.status_code = status
            mock_request.return_value.headers['Retry-After'] = 30

            self.gcm.make_request = MagicMock(return_value=self.mock_response_1)
            self.gcm.retry_after = PropertyMock(return_value=True)

            self.assertIsNotNone(self.gcm.retry_after)

            try:
                res = self.gcm.json_request(registration_ids=['1', '2'], data=self.data, retries=retries)
            except IOError:
                self.fail("json_request raised IOError")

            self.assertIsNone(self.gcm.retry_after)
            self.assertEqual(time.sleep.call_count, retries + index)
            self.assertFalse(mock_request.return_value.json.called)
            self.assertEqual(self.gcm.make_request.call_count, retries)
            self.assertIn('errors', res)
            self.assertIn('Unavailable', res['errors'])
            self.assertEqual(res['errors']['Unavailable'][0], '1')
            self.assertEqual(res['errors']['Unavailable'][1], '2')

    @patch('gcm.logging.getLogger')
    def test_logging_is_enabled(self, mock_logging):
        self.assertTrue(type(GCM.logger), MagicMock)
        GCM.enable_logging()
        self.assertEqual(GCM.logger.debug.call_count, 2)
        GCM.logger.debug.assert_any_call('Added a stderr logging handler to logger: gcm')
        GCM.logger.debug.assert_any_call('Added a stderr logging handler to logger: requests.packages.urllib3')

    @patch('gcm.logging.getLogger')
    def test_debug_enables_logging(self, mock_logging):
        self.assertTrue(type(GCM.logger), MagicMock)
        gcm = GCM('123api', debug=True)
        self.assertEqual(gcm.logger.debug.call_count, 2)
        gcm.logger.debug.assert_any_call('Added a stderr logging handler to logger: gcm')
        gcm.logger.debug.assert_any_call('Added a stderr logging handler to logger: requests.packages.urllib3')

    @patch('requests.Session.post')
    def test_make_request_uses_session(self, mock_request):
        mock_request.return_value.status_code = 500

        session = requests.Session()
        with patch.object(session, 'post') as mock_session_request:
            mock_session_request.return_value.status_code = 200
            mock_session_request.return_value.content = "OK"
            # Perform request
            with patch.object(session, 'close') as mock_session_close:
                self.gcm.make_request(
                    {'message': 'test'}, is_json=True, session=session
                )

                self.assertFalse(mock_session_close.called)
            self.assertTrue(mock_session_request.return_value.json.called)

    @patch('requests.Session.post')
    def test_make_request_closes_implicit_session(self, mock_request):
        mock_request.return_value.status_code = 200
        mock_request.return_value.content = "OK"
        # Perform request
        with patch('requests.Session.close') as mock_session_close:
            self.gcm.make_request(
                {'message': 'test'}, is_json=True
            )

            self.assertTrue(mock_session_close.called)

    def test_type_error_in_handle_plaintext_response(self):
        with self.assertRaises(TypeError):
            self.gcm.handle_plaintext_response(self.mock_response_1)

    def test_bytes_response_in_handle_plaintext_response(self):
        with self.assertRaises(GCMUnavailableException):
            self.gcm.handle_plaintext_response(b'Error=Unavailable')

    def test_missing_registration_exception_is_raised_in_handle_plaintext_response(self):
        with self.assertRaises(GCMMissingRegistrationException):
            self.gcm.handle_plaintext_response('Error=MissingRegistration')

    def test_invalid_registration_exception_is_raised_in_handle_plaintext_response(self):
        with self.assertRaises(GCMInvalidRegistrationException):
            self.gcm.handle_plaintext_response('Error=InvalidRegistration')

    def test_mismatch_senderid_exception_is_raised_in_handle_plaintext_response(self):
        with self.assertRaises(GCMMismatchSenderIdException):
            self.gcm.handle_plaintext_response('Error=MismatchSenderId')

    def test_messagetobig_registration_exception_is_raised_in_handle_plaintext_response(self):
        with self.assertRaises(GCMMessageTooBigException):
            self.gcm.handle_plaintext_response('Error=MessageTooBig')

    def test_payload_body_raises_not_implemented_exception(self):
        payload = Payload()
        with self.assertRaises(NotImplementedError):
            payload.body

    def test_retry_after_returns_int_when_int_given(self):
        retry_after = 21345
        res = get_retry_after({'Retry-After': retry_after})
        self.assertEqual(res, retry_after)

    def test_retry_after_returns_none_when_invalid_http_date_string_given(self):
        retry_after = '21345'
        res = get_retry_after({'Retry-After': retry_after})
        self.assertIsNone(res)

    def test_retry_after_returns_int_when_valid_http_date_string_given(self):
        retry_after = 'Fri, 31 Dec 1999 23:59:59 GMT'
        res = get_retry_after({'Retry-After': retry_after})
        self.assertIsNotNone(res)
        self.assertEqual(res, 946684799.0)
        self.assertTrue(type(res), float)

    def test_retry_after_returns_none_when_retry_after_is_missing(self):
        res = get_retry_after({})
        self.assertIsNone(res)

    def test_retry_after_returns_none_when_retry_after_is_empty(self):
        retry_after = ''
        res = get_retry_after({'Retry-After': retry_after})
        self.assertIsNone(res)

    def test_retry_after_returns_none_when_retry_after_is_zero(self):
        retry_after = 0
        res = get_retry_after({'Retry-After': retry_after})
        self.assertIsNone(res)

if __name__ == '__main__':
    unittest.main()
