#-*- coding: UTF-8 -*-
import codecs
import time
import hashlib
import MySQLdb
import Queue
import logging

from django.shortcuts import render_to_response
from django.template import Context, loader, RequestContext
from django.http import HttpResponse, HttpResponseRedirect
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.views.generic.date_based import object_detail
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.backends.db import SessionStore
from django.utils import simplejson

from apns import APNs, Payload

import OpenTokSDK

from video.models import Users

# Initialize logging
logging.basicConfig(filename='server.log',level=logging.DEBUG)

# Initialize OpenTok
# TODO WRAP needed
#api_key = '16693682'
api_key = '16937882'
#api_secret = '672637d8e5ab9aff674ade175de1831c00c6e57a'
api_secret = 'fb8c4ec59099e592bd862f2c018f704c80a7eac3'
opentok_sdk = OpenTokSDK.OpenTokSDK(api_key, api_secret, staging=False)

# The container to record call requests
callDict = dict()

apns = APNs( use_sandbox = True, cert_file = 'muyuncert.pem', key_file = 'muyunkey2.pem' )
conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
cursor = conn.cursor()
#@csrf_exempt
def getMyInfo(username):
    cursor.execute("select uid, name, realname, company, language_id from users where name=%s", username)
    m = cursor.fetchall()
    nlist = ('uid', 'username', 'name', 'company', 'language' )
    vlist = m[0]
    rlist = dict(zip((nlist),(vlist)))
    return rlist

def sendNotification( message, token_hex, callType ):
    payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1,
                custom={'callType': callType,
                'callContact': getMyInfo(username)
            })
    apns.gateway_server.send_notification(token_hex, payload)
    for (token_hex, fail_time) in apns.feedback_server.items():
        print "shit"

InterpreterIdle = Queue.Queue(maxsize=0)
InterpreterUsing = Queue.Queue(maxsize=0)

def getInterpreter():
    now = InterpreterIdle.get()
    InterpreterUsing.put(now)
    return now
   
def putInterpreter():
    now = InterpreterUsing.get()
    InterpreterIdle.put(now)
    return now

    
# TODO It's a better idea to create a tokbox session id for him
# when logging in since it take quite a while to obtain it.
def requestLoginWithUsername(request):
    """
        Authenticate a login request.

        If it is a legal one, a push token(for iOS device) will also be generated
        and stored in the database.
    """

    if request.method == 'POST' :
        username = request.POST['username']
        password = request.POST['password']
        logging.info("login request: %s, %s", username, password)
        #
        cursor.execute("select * from users where name=%s and loginpassword=%s", ( username, password ) )
        m = cursor.fetchall()
        #
        if m[0][1]==username and m[0][4]==password:
            #
            # Generate a push token
            pushToken = ''
            try:
                # iOS front-end
                pushToken = request.POST['pushToken']
            except:
                # Web front-end
                pass
            print pushToken
            logging.debug("Generated pushToken: %s", pushToken)
            cursor.execute("update users set pushToken=%s where name=%s", (pushToken, username))
            #
            # Generate the login success mesage
            to_json = {
                    "requestType": "login",         # ca be banned since pushing is not necessary in this method
                    "username": username,
                    "message": "success",
                    "myInfo": getMyInfo(username) #TODO should be bannd. One method should do only one thing.
                    }
        else:
            #
            # Generate the login fail mesage
            to_json = {
                     "requestType": "login",
                     "message": "fail"
                     }
        #
        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        logging.info("response: %s", to_json)
    else:
        response = HttpResponse("Error!")
    #
    # TODO WRAP
    if request.META['HTTP_USER_AGENT'].find("iPhone") == -1:
        response['Access-Control-Allow-Origin']='*'
    return response

#
# NEW Method
#
def requestSessionWithUsername(request):
    """
        Generate and return the coresponding session ID and token.

    """
    #
    # generate a session and a token for him
    username = request.POST['username']
    logging.info("session and token request: %s", username)
    session_address = request.POST['address']
    logging.debug('IP address: %s', session_address)
    videoSession = opentok_sdk.create_session(session_address)
    videoToken = opentok_sdk.generate_token(videoSession.session_id)
    cursor.execute("update users set session_id=%s where name=%s", (videoSession.session_id, username))
    cursor.execute("update users set tokbox_token=%s where name=%s", (videoToken, username))
    logging.debug('session_id: %s', videoSession.session_id)
    logging.debug('token: %s', videoToken)
    #
    to_json = {
             "requestType": "session",
             "session_id": videoSession.session_id,
             "token": videoToken,
             }
    response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
    logging.info("response: %s", to_json)

    response['Access-Control-Allow-Origin']='*'
    return response

def requestContactsWithUsername(request):
    if request.method == 'POST':
        username = request.POST['username']
        print username
        cursor.execute("select uid from users where name=%s", username)
        mm = cursor.fetchall()
        id1 = mm[0][0]
        cursor.execute("select * from contacts where id1=%s", id1)
        member = cursor.fetchall()
        rlist=[]
        for item in member:
            cursor.execute("select uid, name, realname, language_id from users where uid=%s", item[2] )
            nlist = ('uid', 'username', 'name','language')
            vlist = cursor.fetchall()
            rlist.append(dict(zip((nlist),(vlist[0]))))
        to_json = {
                "requestType": "contacts",
                "contacts": rlist
                }
        print to_json
        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        if request.META['HTTP_USER_AGENT'].find("iPhone") == -1:
            response['Access-Control-Allow-Origin']='*'
        return response
    else:
        return HttpResponse("Error")

def requestRecentWithUsername(request):
    if request.method == 'POST':
        username = request.POST['username']
        print username
        cursor.execute("select uid from users where name=%s", username)
        mm = cursor.fetchall()
        id1 = mm[0][0]
        cursor.execute("select * from contacts where id1=%s and is_favourite=1", id1)
        member = cursor.fetchall()
        rlist=[]
        for item in member:
            cursor.execute("select uid, name, realname, language_id from users where uid=%s", item[2] )
            nlist = ('uid', 'username', 'name','language')
            vlist = cursor.fetchall()
            rlist.append(dict(zip((nlist),(vlist[0]))))
        to_json = {
                "requestType": "contacts",
                "contacts": rlist
                }
        print to_json
        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        response['Access-Control-Allow-Origin']='*'
        return response
    else:
        return HttpResponse("Error")

def requestMissedWithUsername(request):
    if request.method == 'POST':
        username = request.POST['username']
        print username
        cursor.execute("select uid from users where name=%s", username)
        mm = cursor.fetchall()
        id1 = mm[0][0]
        cursor.execute("select * from contacts where id1=%s", id1)
        member = cursor.fetchall()
        rlist=[]
        for item in member:
            cursor.execute("select uid, name, realname, language_id from users where uid=%s", item[2] )
            nlist = ('uid', 'username', 'name','language')
            vlist = cursor.fetchall()
            rlist.append(dict(zip((nlist),(vlist[0]))))
        to_json = {
                "requestType": "contacts",
                "contacts": rlist
                }
        print to_json
        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        response['Access-Control-Allow-Origin']='*'
        return response
    else:
        return HttpResponse("Error")

def requestVideoCallWithUsername(request):
    """
        This method is called when a user request a video conference.
        He may choose from translator-only, or with friend and translator
    """
    if request.method == 'POST':
        translator_only = False
        username = request.POST['username']
        callToUsername = request.POST['callToUsername']
        print callDict

        # check whether translator-only
        if username == '':
            # Then it reveals that he just need a translator
            translator_only = True

        # First find a proper translator
        # TODO
        # Then find the user he is calling
        if not translator_only:
            if callToUsername in callDict:
                # TODO
                # He is already called by others
                pass
            else:
                # Append to the dict
                logging.info("%s want to start a conference with %s", username, callToUsername)
                callDict[callToUsername] = username
            print request.META
            if request.META['HTTP_USER_AGENT'].find("iPhone") != -1:
                # Send a notification
                cursor.execute("select pushToken from users where name=%s", callToUsername)
                mm = cursor.fetchall()
                token_hex = mm[0][0]
                print token_hex
                message = '令超小朋友!接电话！'
                print "hahaha"
                payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1,
                custom={'callType':'videoCall', 
                        'callContact': {
                                        "uid": "101",
                                    "username": "test1",
                                    "name": "Chenyu Lan",
                                    "company": "SYSU",
                                    "language": "CHN",
                                }})
                apns.gateway_server.send_notification(token_hex, payload)
        to_json = {"message": "success"}
        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
    else:
        response = HttpResponse("Error!")

    if request.META['HTTP_USER_AGENT'].find("iPhone") == -1:
        response['Access-Control-Allow-Origin']='*'
    return response

def answerVideoCallWithUsername(request):
    """
        Call this method to check whether there's a coming call request. If so, anwser it.
        This method will be called quite often.
    """
    if request.method == 'POST':

        #if request.POST['message'] == 'accept':
        #    # Get SessionID and token from Opentok cloud server
        #    api_key = '16693682'
        #    api_secret = '672637d8e5ab9aff674ade175de1831c00c6e57a'
        #    session_address = '127.0.0.1'
        #    opentok_sdk = OpenTokSDK.OpenTokSDK(api_key, api_secret, staging=True)
        #    videoSession = opentok_sdk.create_session(session_address)
        #    #connectionMetadata = 'username=Bob, userLevel=4'
        #    for i in range(0,3):
        #        videoToken = opentok_sdk.generate_token(videoSession.session_id)
        #        print videoToken
        #        data = json.dumps({'sessionID':videoSession.session_id, 'token':videoToken})
        #        #push it!
        #else:
        #    #Push to User A telling it B reject!
        #    t = 1

        username = request.POST['username']
        print username
        print callDict
        if username in callDict:
            #
            # Then there's a call comming
            #
            # First obtain the caller's tokbox session id
            print "good"
            cursor.execute("select session_id from users where name=%s", callDict[username])
            m = cursor.fetchall()
            session_id = m[0][0]
            # generate a corresponding token
            token = opentok_sdk.generate_token(session_id)
            # Then response with it
            to_json = {'session_id':session_id, 'token':token}
            logging.info('%s get a comming call', username)
            del callDict[username]
        else:
            #
            # There's no comming call
            logging.debug('%s didn\'t get a comming call', username)
            to_json = {'session_id':'', 'token':''}

        response = HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
    else:
        response = HttpResponse("Error!")

    logging.info("response: %s", to_json)
    response['Access-Control-Allow-Origin']='*'
    return response

def deliberateToken():
    # Get SessionID and token from Opentok cloud server
    api_key = '16693682'
    api_secret = '672637d8e5ab9aff674ade175de1831c00c6e57a'
    session_address = '127.0.0.1'
    opentok_sdk = OpenTokSDK.OpenTokSDK(api_key, api_secret, staging=True)
    session = opentok_sdk.create_session(session_address)
    connectionMetadata = 'username=Bob, userLevel=4'
    for i in range(0,3):
        token = opentok_sdk.generate_token(session.session_id)
        print token
        data = json.dumps({'sessionID':session.session_id, 'token':token})
    return data

def updatePasswordWithUsername(request):
    if request.method=='POST':
        username = request.POST['username']
        newpassword = request.POST['newpassword']
        a = hashlib.md5()
        a.update(newpassword)
        newpassword = a.hexdigest()
        b = hashlib.sha1()
        b.update(newpassword)
        newpassword = b.hexdigest()
        print newpassword
        cursor.execute("update users set loginpassword=%s where name=%s", (newpassword, username))
        return HttpResponse("Update success!")
    else:
        return HttpResponse("Error!")
