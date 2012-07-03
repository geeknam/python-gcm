Python client for Google Cloud Messaging for Android (GCM)
======================

Usage
------------
RTFM [here](http://developer.android.com/guide/google/gcm/gcm.html)


        gcm = GCM(API_KEY)
        data = {'param1': 'value1', 'param2': 'value2'}
        
        # Plaintext request
        reg_id = '12345'
        res = gcm.plaintext_request(registration_id=reg_id, data=data)

        # JSON request
        reg_ids = ['12', '34', '69']
        res = gcm.json_request(registration_ids=reg_ids, data=data)

        # Extra arguments
        res = gcm.json_request(
            registration_ids=reg_ids, data=data,
            collapse_key='uptoyou', delay_while_idle=True, time_to_live=3600
        )

        # Handle responses. This raises exceptions when GCM servers return errors 
        gcm.handle_response(res)


Exceptions
------------
Read more on response errors [here](http://developer.android.com/guide/google/gcm/gcm.html#success)


* GCMMalformedJsonException
* GCMConnectionException
* GCMAuthenticationException
* GCMTooManyRegIdsException
* GCMMissingRegistrationException
* GCMMismatchSenderIdException
* GCMNotRegisteredException
* GCMMessageTooBigException