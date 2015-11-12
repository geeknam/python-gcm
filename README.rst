python-gcm
======================

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/geeknam/python-gcm
   :target: https://gitter.im/geeknam/python-gcm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge
.. image:: https://img.shields.io/pypi/v/python-gcm.svg
   :target: https://pypi.python.org/pypi/python-gcm
.. image:: https://img.shields.io/pypi/dm/python-gcm.svg
   :target: https://pypi.python.org/pypi/python-gcm
.. image:: https://secure.travis-ci.org/geeknam/python-gcm.png?branch=master
   :alt: Build Status
   :target: http://travis-ci.org/geeknam/python-gcm
.. image:: https://landscape.io/github/geeknam/python-gcm/master/landscape.png
   :target: https://landscape.io/github/geeknam/python-gcm/master
   :alt: Code Health
.. image:: https://coveralls.io/repos/geeknam/python-gcm/badge.svg?branch=master
   :target: https://coveralls.io/r/geeknam/python-gcm
.. image:: https://img.shields.io/gratipay/geeknam.svg
   :target: https://gratipay.com/geeknam/

Python client for Google Cloud Messaging for Android (GCM)

Installation
-------------

.. code-block:: bash

   pip install python-gcm

Features
------------

* Supports multicast message
* Resend messages using exponential back-off
* Proxy support
* Easily handle errors
* Uses `requests` from version > 0.2
* Topic Messaging `Reference <https://developers.google.com/cloud-messaging/topic-messaging>`__

Usage
------------

RTFM about `Google Cloud Messaging <https://developers.google.com/cloud-messaging>`__
        
Basic

.. code-block:: python

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

   # Topic Messaging
   topic = 'foo'
   gcm.send_topic_message(topic=topic, data=data)


Error handling

.. code-block:: python

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

   # Successfully handled registration_ids
   # Keep in mind that a registration id listed in response['success'] can also be in response['canonical'] if the registration id has changed
   if response and 'success' in response:
        for reg_id, success_id in response['success'].items():
            print('SUCCESS for reg_id %s' % reg_id)

   # Handling errors
   if 'errors' in response:
       for error, reg_ids in response['errors'].items():
           # Check for errors and act accordingly
           if error in ['NotRegistered', 'InvalidRegistration']:
               # Remove reg_ids from database
               for reg_id in reg_ids:
                   entity.filter(registration_id=reg_id).delete()

   if 'canonical' in response:
       for reg_id, canonical_id in response['canonical'].items():
           # Repace reg_id with canonical_id in your database
           entry = entity.filter(registration_id=reg_id)
           entry.registration_id = canonical_id
           entry.save()

Exceptions
------------
Read more on response errors `here
<https://developers.google.com/cloud-messaging/http-server-ref#error-codes>`__


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

Contributing
==========
See `CONTRIBUTING.md <CONTRIBUTING.md>`_

Licensing
=======
See `LICENSE <LICENSE>`_
