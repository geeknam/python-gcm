#!/usr/bin/env python3

from gcm import GCM

# Plain text request

API_KEY = "your api key"

gcm = GCM(API_KEY, debug=True)

registration_id = 'your push token'

data = {'param1': 'value1', 'param2': 'value2'}

response = gcm.plaintext_request(registration_id=registration_id, data=data)

print(response)
