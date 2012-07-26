import OpenTokSDK
import json
import urllib
import urllib2
import MySQLdb
from mod_python import apache
def handler(req):
        req.content_type='text/plain'
        req.write("Hello, world!")
        return apache.OK

api_key = '16693682' # Replace with your OpenTok API key.
api_secret = '672637d8e5ab9aff674ade175de1831c00c6e57a'  # Replace with your OpenTok API secret.
session_address = '127.0.0.1' # Replace with the representative URL of your session.

opentok_sdk = OpenTokSDK.OpenTokSDK(api_key, api_secret, staging=True)
session = opentok_sdk.create_session(session_address)

print session.session_id

connectionMetadata = 'username=Bob, userLevel=4'
#token = opentok_sdk.generate_token(session.session_id, 'PUBLISHER', None, connectionMetadata)
for i in range(0,3):
    token = opentok_sdk.generate_token(session.session_id)
    print token
    data = json.dumps({'sessionID':session.session_id, 'token':token})
