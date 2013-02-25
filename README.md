python-gcm
======================
[![Build Status](https://secure.travis-ci.org/geeknam/python-gcm.png?branch=master)](http://travis-ci.org/geeknam/python-gcm)

Python client for Google Cloud Messaging for Android (GCM)

Installation
-------------
```bash
pip install python-gcm
```

Features
------------
* Supports multicast message
* Resend messages using exponential back-off
* Proxy support
* Easily handle errors

Usage
------------
RTFM [here](http://developer.android.com/guide/google/gcm/gcm.html)
        
Basic
```python
from gcm import GCM

gcm = GCM(API_KEY)
data = {'param1': 'value1', 'param2': 'value2'}

# Plaintext request
reg_id = '12'
gcm.plaintext_request(registration_id=reg_id, data=data)

# JSON request
reg_ids = ['12', '34', '69']
response = gcm.json_request(registration_ids=reg_ids, data=data)

# Extra arguments
res = gcm.json_request(
    registration_ids=reg_ids, data=data,
    collapse_key='uptoyou', delay_while_idle=True, time_to_live=3600
)
```

Error handling
```python
# Plaintext request
reg_id = '12345'
try:
    canonical_id = gcm.plaintext_request(registration_id=reg_id, data=data)
    if canonical_id:
        # Repace reg_id with canonical_id in your database
        entry = entity.filter(registration_id=reg_id)
        entry.registration_id = canonical_id
        entry.save()
except GCMNotRegisteredException:
    # Remove this reg_id from database
    entity.filter(registration_id=reg_id).delete()
except GCMUnavailableException:
    # Resent the message

# JSON request
reg_ids = ['12', '34', '69']
response = gcm.json_request(registration_ids=reg_ids, data=data)

# Handling errors
if 'errors' in response:
    for error, reg_ids in response['errors'].items():
        # Check for errors and act accordingly
        if error is 'NotRegistered':
            # Remove reg_ids from database
            for reg_id in reg_ids:
                entity.filter(registration_id=reg_id).delete()
if 'canonical' in response:
    for reg_id, canonical_id in response['canonical'].items():
        # Repace reg_id with canonical_id in your database
        entry = entity.filter(registration_id=reg_id)
        entry.registration_id = canonical_id
        entry.save()
```

Exceptions
------------
Read more on response errors [here](http://developer.android.com/guide/google/gcm/gcm.html#success)


* GCMMalformedJsonException
* GCMConnectionException
* GCMAuthenticationException
* GCMTooManyRegIdsException
* GCMNoCollapseKeyException
* GCMInvalidTtlException
* GCMMissingRegistrationException
* GCMMismatchSenderIdException
* GCMNotRegisteredException
* GCMMessageTooBigException
* GCMInvalidRegistrationException
* GCMUnavailableException

![Gotta catch them all](http://t.qkme.me/35gjhs.jpg)
