import requests
import json
from collections import defaultdict
import time
import random
from sys import version_info

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


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


# TODO: Refactor this to be more human-readable
def group_response(response, registration_ids, key):
    # Pair up results and reg_ids
    mapping = zip(registration_ids, response['results'])
    # Filter by key
    filtered = ((reg_id, res[key]) for reg_id, res in mapping if key in res)
    # Grouping of errors and mapping of ids
    if key is 'registration_id':
        grouping = dict(filtered)
    else:
        grouping = defaultdict(list)
        for k, v in filtered:
            grouping[v].append(k)

    return grouping or None


class Payload(object):
    """
    Base Payload class which prepares data for HTTP requests
    """

    # TTL in seconds
    GCM_TTL = 2419200

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

    def __init__(self, api_key, url=GCM_URL, proxy=None):
        """ api_key : google api key
            url: url of gcm service.
            proxy: can be string "http://host:port" or dict {'https':'host:port'}
        """
        self.api_key = api_key
        self.url = url

        if isinstance(proxy, str):
            protocol = url.split(':')[0]
            self.proxy = {protocol: proxy}
        else:
            self.proxy = proxy

    def construct_payload(self, **kwargs):
        """
        Construct the dictionary mapping of parameters.
        Encodes the dictionary into JSON if for json requests.

        :return constructed dict or JSON payload
        :raises GCMInvalidTtlException: if time_to_live is invalid
        """

        is_json = kwargs.pop('is_json', True)

        if is_json:
            payload = JsonPayload(**kwargs).body
        else:
            payload = PlaintextPayload(**kwargs).body

        return payload

    def make_request(self, data, is_json=True):
        """
        Makes a HTTP request to GCM servers with the constructed payload

        :param data: return value from construct_payload method
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


        response = requests.post(
            self.url, data=data, headers=headers,
            proxies=self.proxy
        )

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

    def raise_error(self, error):
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

    def handle_plaintext_response(self, response):
        # Split response by line
        if version_info.major == 3 and type(response) is bytes:
            response = response.decode("utf-8", "strict")

        response_lines = response.strip().split('\n')

        # Split the first line by =
        key, value = response_lines[0].split('=')
        if key == 'Error':
            self.raise_error(value)
        else:
            if len(response_lines) == 2:
                return response_lines[1].split('=')[1]
            return

    def handle_json_response(self, response, registration_ids):
        errors = group_response(response, registration_ids, 'error')
        canonical = group_response(
            response, registration_ids, 'registration_id')

        info = {}
        if errors:
            info.update({'errors': errors})
        if canonical:
            info.update({'canonical': canonical})

        return info

    def extract_unsent_reg_ids(self, info):
        if 'errors' in info and 'Unavailable' in info['errors']:
            return info['errors']['Unavailable']
        return []

    def plaintext_request(self, **kwargs):
        """
        Makes a plaintext request to GCM servers

        :param registration_id: string of the registration id
        :param data: dict mapping of key-value pairs of messages
        :return dict of response body from Google including multicast_id, success, failure, canonical_ids, etc
        """

        kwargs['is_json'] = False
        retries = kwargs.pop('retries', 5)
        payload = self.construct_payload(**kwargs)

        attempt = 0
        backoff = self.BACKOFF_INITIAL_DELAY

        if retries:
            for attempt in range(retries):
                try:
                    response = self.make_request(payload, is_json=False)
                    return self.handle_plaintext_response(response)
                except GCMUnavailableException:
                    sleep_time = backoff / 2 + random.randrange(backoff)
                    time.sleep(float(sleep_time) / 1000)
                    if 2 * backoff < self.MAX_BACKOFF_DELAY:
                        backoff *= 2

        raise IOError("Could not make request after %d attempts" % attempt)

    def json_request(self, **kwargs):
        """
        Makes a JSON request to GCM servers

        :param registration_ids: list of the registration ids
        :param data: dict mapping of key-value pairs of messages
        :return dict of response body from Google including multicast_id, success, failure, canonical_ids, etc
        """
        retries = kwargs.pop('retries', 5)
        payload = self.construct_payload(**kwargs)

        backoff = self.BACKOFF_INITIAL_DELAY

        registration_ids = kwargs['registration_ids']
        for attempt in range(retries):

            response = self.make_request(payload, is_json=True)
            info = self.handle_json_response(response, registration_ids)

            unsent_reg_ids = self.extract_unsent_reg_ids(info)
            if unsent_reg_ids:
                registration_ids = unsent_reg_ids
                sleep_time = backoff / 2 + random.randrange(backoff)
                time.sleep(float(sleep_time) / 1000)
                if 2 * backoff < self.MAX_BACKOFF_DELAY:
                    backoff *= 2
            else:
                break
        return info
