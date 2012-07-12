import urllib
import urllib2
import json

GCM_URL = 'https://android.googleapis.com/gcm/send'


class GCMException(Exception): pass
class GCMMalformedJsonException(GCMException): pass
class GCMConnectionException(GCMException): pass
class GCMAuthenticationException(GCMException): pass
class GCMTooManyRegIdsException(GCMException): pass
class GCMNoCollapseKey(GCMException): pass

# Exceptions from Google responses
class GCMMissingRegistrationException(GCMException): pass
class GCMMismatchSenderIdException(GCMException): pass
class GCMNotRegisteredException(GCMException): pass
class GCMMessageTooBigException(GCMException): pass


class GCM(object):

    def __init__(self, api_key):
        self.api_key = api_key

    def construct_payload(self, registration_ids, data=None, collapse_key=None,
                            delay_while_idle=False, time_to_live=None, is_json=True):
        if is_json:
            payload = {'registration_ids': registration_ids}
            if data:
                payload['data'] = data
        else:
            payload = {'registration_id': registration_ids}
            if data:
                for k in data.keys():
                    data['data.%s' % k] = data.pop(k)
                payload.update(data)

        if delay_while_idle:
            payload['delay_while_idle'] = delay_while_idle

        if time_to_live:
            payload['time_to_live'] = time_to_live
            if collapse_key is None:
                raise GCMNoCollapseKey("collapse_key is required when time_to_live is provided")

        if collapse_key:
            payload['collapse_key'] = collapse_key

        if json:
            payload = json.dumps(payload)

        return payload

    def make_request(self, data, is_json=True):
        headers = {
            'Authorization': 'key=%s' % self.api_key,
        }
        # Default Content-Type is defaulted to application/x-www-form-urlencoded;charset=UTF-8
        if is_json:
            headers['Content-Type'] = 'application/json'

        if not is_json:
            data = urllib.urlencode(data)
        req = urllib2.Request(GCM_URL, data, headers)

        try:
            response = urllib2.urlopen(req).read()
        except urllib2.HTTPError as e:
            if e.code == 400:
                raise GCMMalformedJsonException("The request could not be parsed as JSON")
            elif e.code == 401:
                raise GCMAuthenticationException("There was an error authenticating the sender account")
            # TODO: handle 503 and Retry-After
        except urllib2.URLError as e:
            raise GCMConnectionException("There was an internal error in the GCM server while trying to process the request")

        if is_json:
            response = json.loads(response)
        return response

    def handle_response(self, response):
        error = response['results']['error']

        if error == 'MissingRegistration':
            raise GCMMissingRegistrationException("Missing registration_ids")
        elif error == 'InvalidRegistration':
            raise GCMMismatchSenderIdException("A registration ID is tied to a certain group of senders")
        elif error == 'NotRegistered':
            raise GCMNotRegisteredException("Registration id is not valid anymore")
        elif error == 'MessageTooBig':
            raise GCMMessageTooBigException("Message can't exceed 4096 bytes")

    def plaintext_request(self, registration_id, data=None, collapse_key=None,
                            delay_while_idle=False, time_to_live=None):

        if not registration_id:
            raise GCMMissingRegistrationException("Missing registration_id")

        payload = self.construct_payload(
            registration_id, data, collapse_key,
            delay_while_idle, time_to_live, False
        )

        return self.make_request(payload, json=False)

    def json_request(self, registration_ids, data=None, collapse_key=None,
                        delay_while_idle=False, time_to_live=None):

        if not registration_ids:
            raise GCMMissingRegistrationException("Missing registration_ids")
        if len(registration_ids) > 1000:
            raise GCMTooManyRegIdsException("Exceded number of registration_ids")

        payload = self.construct_payload(
            registration_ids, data, collapse_key,
            delay_while_idle, time_to_live
        )

        return self.make_request(payload, is_json=True)
