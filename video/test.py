#-- coding:utf-8 --
from apns import APNs, Payload
import codecs
import time
apns = APNs( use_sandbox = True, cert_file = 'muyuncert.pem', key_file = 'muyunkey2.pem' )

# Send a notification
token_hex = 'aea23b4f8af477edb5ed701eb69b6a32489620fa34c0dbdfc8428170a68d2b08'
message = '令超小朋友！没事，就骚扰你一下'
for i in range(0,2):
    payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1)
#payload = Payload(alert="test!", sound="default",badge=1)
    apns.gateway_server.send_notification(token_hex, payload)
    time.sleep(1)

# Get feedback messages
for (token_hex, fail_time) in apns.feedback_server.items():
    # do stuff with token_hex and fail_time
    print "shit"
