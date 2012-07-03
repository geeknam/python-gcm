Python client for Google Cloud Messaging for Android (GCM)
======================

Usage
------------

        gcm = GCM(API_KEY)
        data = {'param1': 'value1', 'param2': 'value2'}
        
        # Plaintext request
        reg_id = '12345'
        res = gcm.plaintext_request(reg_id, data)

        # JSON request
        reg_ids = ['12', '34', '69']
        res = gcm.json_request(reg_ids, data)

        # Handle responses. This raises exceptions when GCM servers return errors 
        gcm.handle_response(res)


Exceptions
------------

* GCMMalformedJsonException
* GCMConnectionException
* GCMAuthenticationException
* GCMTooManyRegIdsException
* C2DMCredentialException
* GCMMissingRegistrationException
* GCMMismatchSenderIdException
* GCMNotRegisteredException
* GCMMessageTooBigException