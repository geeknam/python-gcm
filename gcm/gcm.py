import requests
import json
from collections import defaultdict
import time
import random
from sys import version_info
import logging
import re

if version_info.major == 2:
    from urllib2 import unquote
else:
    from urllib.parse import unquote

GCM_URL = 'https://gcm-http.googleapis.com/gcm/send'


class GCMException(Exception):
    pass


class GCMMalformedJsonException(GCMException):
    pass


class GCMConnectionException(GCMException):
    pass


class GCMAuthenticationException(GCMException):
    pass


class GCMTooManyRegIdsException(GCMException):
    pass


class GCMInvalidTtlException(GCMException):
    pass


class GCMTopicMessageException(GCMException):
    pass


# Exceptions from Google responses


class GCMMissingRegistrationException(GCMException):
    pass


class GCMMismatchSenderIdException(GCMException):
    pass


class GCMNotRegisteredException(GCMException):
    pass


class GCMMessageTooBigException(GCMException):
    pass


class GCMInvalidRegistrationException(GCMException):
    pass


class GCMUnavailableException(GCMException):
    pass


class GCMInvalidInputException(GCMException):
    pass


# TODO: Refactor this to be more human-readable
# TODO: Use OrderedDict for the result type to be able to preserve the order of the messages returned by GCM server
def group_response(response, registration_ids, key):
    # Pair up results and reg_ids
    mapping = zip(registration_ids, response['results'])
    # Filter by key
    filtered = ((reg_id, res[key]) for reg_id, res in mapping if key in res)
    # Grouping of errors and mapping of ids
    if key in ['registration_id', 'message_id']:
        grouping = dict(filtered)
    else:
        grouping = defaultdict(list)
        for k, v in filtered:
            grouping[v].append(k)

    return grouping or None


def get_retry_after(response_headers):
    retry_after = response_headers.get('Retry-After')

    if retry_after:
        # Parse from seconds (e.g. Retry-After: 120)
        if type(retry_after) is int:
            return retry_after
        # Parse from HTTP-Date (e.g. Retry-After: Fri, 31 Dec 1999 23:59:59 GMT)
        else:
            try:
                from email.utils import parsedate
                from calendar import timegm
                return timegm(parsedate(retry_after))
            except (TypeError, OverflowError, ValueError):
                return None

    return None


class Payload(object):
    """
    Base Payload class which prepares data for HTTP requests
    """

    # TTL in seconds
    GCM_TTL = 2419200

    topicPattern = re.compile('/topics/[a-zA-Z0-9-_.~%]+')

    def __init__(self, **kwargs):
        self.validate(kwargs)
        self.__dict__.update(**kwargs)

    def validate(self, options):
        """
        Allow adding validation on each payload key
        by defining `validate_{key_name}`
        """
        for key, value in options.items():
            validate_method = getattr(self, 'validate_%s' % key, None)
            if validate_method:
                validate_method(value)

    def validate_time_to_live(self, value):
        if not (0 <= value <= self.GCM_TTL):
            raise GCMInvalidTtlException("Invalid time to live value")

    def validate_registration_ids(self, registration_ids):

        if len(registration_ids) > 1000:
            raise GCMTooManyRegIdsException("Exceded number of registration_ids")

    def validate_to(self, value):
        if not re.match(Payload.topicPattern, value):
            raise GCMInvalidInputException(
                "Invalid topic name: {0}! Does not match the {1} pattern".format(value, Payload.topicPattern))

    @property
    def body(self):
        raise NotImplementedError


class PlaintextPayload(Payload):
    @property
    def body(self):
        # Safeguard for backwards compatibility
        if 'registration_id' not in self.__dict__:
            self.__dict__['registration_id'] = self.__dict__.pop(
                    'registration_ids', None
            )
        # Inline data for for plaintext request
        data = self.__dict__.pop('data')
        for key, value in data.items():
            self.__dict__['data.%s' % key] = value
        return self.__dict__


class JsonPayload(Payload):
    @property
    def body(self):
        return json.dumps(self.__dict__)


class GCM(object):
    # Timeunit is milliseconds.
    BACKOFF_INITIAL_DELAY = 1000
    MAX_BACKOFF_DELAY = 1024000
    logger = None
    logging_handler = None

    def __init__(self, api_key, proxy=None, timeout=None, debug=False):
        """ api_key : google api key
            url: url of gcm service.
            proxy: can be string "http://host:port" or dict {'https':'host:port'}
            timeout: timeout for every HTTP request, see 'requests' documentation for possible values.
        """
        self.api_key = api_key
        self.url = GCM_URL

        if isinstance(proxy, str):
            protocol = self.url.split(':')[0]
            self.proxy = {protocol: proxy}
        else:
            self.proxy = proxy

        self.timeout = timeout
        self.debug = debug
        self.retry_after = None

        if self.debug:
            GCM.enable_logging()

    @staticmethod
    def enable_logging(level=logging.DEBUG, handler=None):
        """
        Helper for quickly adding a StreamHandler to the logger. Useful for debugging.

        :param handler:
        :param level:
        :return: the handler after adding it
        """
        if not handler:
            # Use a singleton logging_handler instead of recreating it,
            # so we can remove-and-re-add safely without having duplicate handlers
            if GCM.logging_handler is None:
                GCM.logging_handler = logging.StreamHandler()
                GCM.logging_handler.setFormatter(logging.Formatter(
                    '[%(asctime)s - %(levelname)s - %(filename)s:%(lineno)s - %(funcName)s()] %(message)s'))
            handler = GCM.logging_handler

        GCM.logger = logging.getLogger(__name__)
        GCM.logger.removeHandler(handler)
        GCM.logger.addHandler(handler)
        GCM.logger.setLevel(level)
        GCM.log('Added a stderr logging handler to logger: {0}', __name__)

        # Enable requests logging
        requests_logger_name = 'requests.packages.urllib3'
        requests_logger = logging.getLogger(requests_logger_name)
        requests_logger.removeHandler(handler)
        requests_logger.addHandler(handler)
        requests_logger.setLevel(level)
        GCM.log('Added a stderr logging handler to logger: {0}', requests_logger_name)

    @staticmethod
    def log(message, *data):
        if GCM.logger and message:
            GCM.logger.debug(message.format(*data))

    @staticmethod
    def construct_payload(**kwargs):
        """
        Construct the dictionary mapping of parameters.
        Encodes the dictionary into JSON if for json requests.

        :return constructed dict or JSON payload
        :raises GCMInvalidTtlException: if time_to_live is invalid
        """

        is_json = kwargs.pop('is_json', True)

        if is_json:
            if 'topic' not in kwargs and 'registration_ids' not in kwargs:
                raise GCMMissingRegistrationException("Missing registration_ids or topic")
            elif 'topic' in kwargs and 'registration_ids' in kwargs:
                raise GCMInvalidInputException(
                    "Invalid parameters! Can't have both 'registration_ids' and 'to' as input parameters")

            if 'topic' in kwargs:
                kwargs['to'] = '/topics/{}'.format(kwargs.pop('topic'))
            elif 'registration_ids' not in kwargs:
                raise GCMMissingRegistrationException("Missing registration_ids")

            payload = JsonPayload(**kwargs).body
        else:
            payload = PlaintextPayload(**kwargs).body

        return payload

    def make_request(self, data, is_json=True, session=None):
        """
        Makes a HTTP request to GCM servers with the constructed payload

        :param data: return value from construct_payload method
        :param session: requests.Session object to use for request (optional)
        :raises GCMMalformedJsonException: if malformed JSON request found
        :raises GCMAuthenticationException: if there was a problem with authentication, invalid api key
        :raises GCMConnectionException: if GCM is screwed
        """

        headers = {
            'Authorization': 'key=%s' % self.api_key,
        }

        if is_json:
            headers['Content-Type'] = 'application/json'
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8'

        GCM.log('Request URL: {0}', self.url)
        GCM.log('Request headers: {0}', headers)
        GCM.log('Request proxy: {0}', self.proxy)
        GCM.log('Request timeout: {0}', self.timeout)
        GCM.log('Request data: {0}', data)
        GCM.log('Request is_json: {0}', is_json)

        new_session = None
        if not session:
            session = new_session = requests.Session()

        try:
            response = session.post(
                    self.url, data=data, headers=headers,
                    proxies=self.proxy, timeout=self.timeout,
            )
        finally:
            if new_session:
                new_session.close()

        GCM.log('Response status: {0} {1}', response.status_code, response.reason)
        GCM.log('Response headers: {0}', response.headers)
        GCM.log('Response data: {0}', response.text)

        # 5xx or 200 + error:Unavailable
        self.retry_after = get_retry_after(response.headers)

        # Successful response
        if response.status_code == 200:
            if is_json:
                response = response.json()
            else:
                response = response.content
            return response

        # Failures
        if response.status_code == 400:
            raise GCMMalformedJsonException(
                    "The request could not be parsed as JSON")
        elif response.status_code == 401:
            raise GCMAuthenticationException(
                    "There was an error authenticating the sender account")
        elif response.status_code == 503:
            raise GCMUnavailableException("GCM service is unavailable")
        else:
            error = "GCM service error: %d" % response.status_code
            raise GCMUnavailableException(error)

    @staticmethod
    def raise_error(error):
        if error == 'InvalidRegistration':
            raise GCMInvalidRegistrationException("Registration ID is invalid")
        elif error == 'Unavailable':
            # Plain-text requests will never return Unavailable as the error code.
            # http://developer.android.com/guide/google/gcm/gcm.html#error_codes
            raise GCMUnavailableException(
                    "Server unavailable. Resent the message")
        elif error == 'NotRegistered':
            raise GCMNotRegisteredException(
                    "Registration id is not valid anymore")
        elif error == 'MismatchSenderId':
            raise GCMMismatchSenderIdException(
                    "A Registration ID is tied to a certain group of senders")
        elif error == 'MessageTooBig':
            raise GCMMessageTooBigException("Message can't exceed 4096 bytes")
        elif error == 'MissingRegistration':
            raise GCMMissingRegistrationException("Missing registration")

    def handle_plaintext_response(self, response):
        if type(response) not in [bytes, str]:
            raise TypeError("Invalid type for response parameter! Expected: bytes or str. "
                            "Actual: {0}".format(type(response).__name__))

        # Split response by line
        if version_info.major == 3 and type(response) is bytes:
            response = response.decode("utf-8", "strict")

        response_lines = response.strip().split('\n')

        # Split the first line by =
        key, value = response_lines[0].split('=')

        # Error on first line
        if key == 'Error':
            self.raise_error(value)
        else:  # Canonical_id from the second line
            if len(response_lines) == 2:
                return unquote(response_lines[1].split('=')[1])
            return None  # TODO: Decide a way to return message id without breaking backwards compatibility
            # unquote(value)  # ID of the sent message (from the first line)

    @staticmethod
    def handle_json_response(response, registration_ids):
        errors = group_response(response, registration_ids, 'error')
        canonical = group_response(response, registration_ids, 'registration_id')
        success = group_response(response, registration_ids, 'message_id')

        info = {}

        if errors:
            info.update({'errors': errors})

        if canonical:
            info.update({'canonical': canonical})

        if success:
            info.update({'success': success})

        return info

    @staticmethod
    def handle_topic_response(response):
        error = response.get('error')
        if error:
            raise GCMTopicMessageException(error)
        return response['message_id']

    @staticmethod
    def extract_unsent_reg_ids(info):
        if 'errors' in info and 'Unavailable' in info['errors']:
            return info['errors']['Unavailable']
        return []

    def plaintext_request(self, **kwargs):
        """
        Makes a plaintext request to GCM servers

        :return dict of response body from Google including multicast_id, success, failure, canonical_ids, etc
        """
        if 'registration_id' not in kwargs:
            raise GCMMissingRegistrationException("Missing registration_id")
        elif not kwargs['registration_id']:
            raise GCMMissingRegistrationException("Empty registration_id")

        kwargs['is_json'] = False
        retries = kwargs.pop('retries', 5)
        session = kwargs.pop('session', None)
        payload = self.construct_payload(**kwargs)
        backoff = self.BACKOFF_INITIAL_DELAY
        info = None
        has_error = False

        for attempt in range(retries):
            try:
                response = self.make_request(payload, is_json=False, session=session)
                info = self.handle_plaintext_response(response)
                has_error = False
            except GCMUnavailableException:
                has_error = True

            if self.retry_after:
                GCM.log("[plaintext_request - Attempt #{0}] Retry-After ~> Sleeping for {1} seconds".format(attempt,
                                                                                                            self.retry_after))
                time.sleep(self.retry_after)
                self.retry_after = None
            elif has_error:
                sleep_time = backoff / 2 + random.randrange(backoff)
                nap_time = float(sleep_time) / 1000
                GCM.log(
                    "[plaintext_request - Attempt #{0}]Backoff ~> Sleeping for {1} seconds".format(attempt, nap_time))
                time.sleep(nap_time)
                if 2 * backoff < self.MAX_BACKOFF_DELAY:
                    backoff *= 2
            else:
                break

        if has_error:
            raise IOError("Could not make request after %d attempts" % retries)

        return info

    def json_request(self, **kwargs):
        """
        Makes a JSON request to GCM servers

        :param kwargs: dict mapping of key-value pairs of parameters
        :return dict of response body from Google including multicast_id, success, failure, canonical_ids, etc
        """
        if 'registration_ids' not in kwargs:
            raise GCMMissingRegistrationException("Missing registration_ids")
        elif not kwargs['registration_ids']:
            raise GCMMissingRegistrationException("Empty registration_ids")

        args = dict(**kwargs)

        retries = args.pop('retries', 5)
        session = args.pop('session', None)
        payload = self.construct_payload(**args)
        registration_ids = args['registration_ids']
        backoff = self.BACKOFF_INITIAL_DELAY
        info = None
        has_error = False

        for attempt in range(retries):
            try:
                response = self.make_request(payload, is_json=True, session=session)
                info = self.handle_json_response(response, registration_ids)
                unsent_reg_ids = self.extract_unsent_reg_ids(info)
                has_error = False
            except GCMUnavailableException:
                unsent_reg_ids = registration_ids
                has_error = True

            if unsent_reg_ids:
                registration_ids = unsent_reg_ids

                # Make the retry request with the unsent registration ids
                args['registration_ids'] = registration_ids
                payload = self.construct_payload(**args)

                if self.retry_after:
                    GCM.log("[json_request - Attempt #{0}] Retry-After ~> Sleeping for {1}".format(attempt,
                                                                                                   self.retry_after))
                    time.sleep(self.retry_after)
                    self.retry_after = None
                else:
                    sleep_time = backoff / 2 + random.randrange(backoff)
                    nap_time = float(sleep_time) / 1000
                    GCM.log("[json_request - Attempt #{0}] Backoff ~> Sleeping for {1}".format(attempt, nap_time))
                    time.sleep(nap_time)
                    if 2 * backoff < self.MAX_BACKOFF_DELAY:
                        backoff *= 2
            else:
                break

        if has_error:
            raise IOError("Could not make request after %d attempts" % retries)

        return info

    def send_downstream_message(self, **kwargs):
        return self.json_request(**kwargs)

    def send_topic_message(self, **kwargs):
        """
        Publish Topic Messaging to GCM servers
        Ref: https://developers.google.com/cloud-messaging/topic-messaging

        :param kwargs: dict mapping of key-value pairs of parameters
        :return message_id
        :raises GCMInvalidInputException: if the topic is empty
        """

        if 'topic' not in kwargs:
            raise GCMInvalidInputException("Topic name missing!")
        elif not kwargs['topic']:
            raise GCMInvalidInputException("Topic name cannot be empty!")

        retries = kwargs.pop('retries', 5)
        session = kwargs.pop('session', None)
        payload = self.construct_payload(**kwargs)
        backoff = self.BACKOFF_INITIAL_DELAY

        for attempt in range(retries):
            try:
                response = self.make_request(payload, is_json=True, session=session)
                return self.handle_topic_response(response)
            except (GCMUnavailableException, GCMTopicMessageException):
                if self.retry_after:
                    GCM.log("[send_topic_message - Attempt #{0}] Retry-After ~> Sleeping for {1}"
                            .format(attempt, self.retry_after))

                    time.sleep(self.retry_after)
                    self.retry_after = None
                else:
                    sleep_time = backoff / 2 + random.randrange(backoff)
                    nap_time = float(sleep_time) / 1000
                    GCM.log("[send_topic_message - Attempt #{0}] Backoff ~> Sleeping for {1}".format(attempt, nap_time))
                    time.sleep(nap_time)
                    if 2 * backoff < self.MAX_BACKOFF_DELAY:
                        backoff *= 2

        raise IOError("Could not make request after %d attempts" % retries)
