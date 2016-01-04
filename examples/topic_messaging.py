#!/usr/bin/env python3

from gcm import GCM

# Topic Messaging

API_KEY = "your api key"

gcm = GCM('api key')
data = {'param1': 'value1', 'param2': 'value2'}
topic = 'your topic name'

response = gcm.send_topic_message(topic=topic, data=data)

print(response)
