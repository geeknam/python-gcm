#!/usr/bin/env python3

from gcm import GCM

# JSON request

API_KEY = "your api key"

gcm = GCM(API_KEY)

registration_ids = ["your token 1", "your token 2"]

notification = {
    "title": "Awesome App Update",
    "body": "Tap here to start the update!",
    "icon": "myicon"
}

data = {
    "Nick": "Mario",
    "Room": "PortugalVSDenmark"
}

response = gcm.json_request(registration_ids=registration_ids,
                            notification=notification,
                            data=data,
                            collapse_key='awesomeapp_update',
                            restricted_package_name="gcm.play.android.samples.com.gcmquickstart",
                            priority='high',
                            delay_while_idle=False)

# Successfully handled registration_ids
if response and 'success' in response:
    for reg_id, success_id in response['success'].items():
        print('Successfully sent notification for reg_id {0}'.format(reg_id))

# Handling errors
if 'errors' in response:
    for error, reg_ids in response['errors'].items():
        # Check for errors and act accordingly
        if error in ['NotRegistered', 'InvalidRegistration']:
            # Remove reg_ids from database
            for reg_id in reg_ids:
                print("Removing reg_id: {0} from db".format(reg_id))

# Repace reg_id with canonical_id in your database
if 'canonical' in response:
    for reg_id, canonical_id in response['canonical'].items():
        print("Replacing reg_id: {0} with canonical_id: {1} in db".format(reg_id, canonical_id))
