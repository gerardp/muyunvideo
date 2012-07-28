# Create your views here.
#-*- coding: UTF-8 -*-
import codecs
from django.shortcuts import render_to_response
from django.template import Context, loader, RequestContext
#from read.models import Book,UserProfile
from django.http import HttpResponse, HttpResponseRedirect
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.views.generic.date_based import object_detail
from django.contrib.auth.decorators import login_required
from django.utils import simplejson
from apns import APNs, Payload
from video.models import Users
import time
import md5
import MySQLdb

apns = APNs( use_sandbox = True, cert_file = 'muyuncert.pem', key_file = 'muyunkey2.pem' )

#@csrf_exempt
if 0:
    def login_view(request):
        if request.method == 'POST' :
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(username = username, password = password)
            if user is not None:
                if user.is_active:
                    login(request,user)
                    print "login success"
                else:
                    return HttpResponse("disabled account")
        else:
            return render_to_response("login.html")
    def logout_view(request):  
        logout(request)  
        return store_view(request)  

    def push_request(uid):
        apns = APNs( use_sandbox = True, cert_file = 'muyuncert.pem', key_file = 'muyunkey2.pem' )
        # Send a notification
        #token_hex = 'aea23b4f8af477edb5ed701eb69b6a32489620fa34c0dbdfc8428170a68d2b08'
        token_hex = Users.pushtoken
        message = '您好，用户'+uid.name+'邀请您加入视频会议'
        payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1)
        #payload = Payload(alert="test!", sound="default",badge=1)
        apns.gateway_server.send_notification(token_hex, payload)


def requestLoginWithUsername(request):
    conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
    cursor = conn.cursor()
    if request.method == 'POST' :
        username = request.POST['username']
        password = request.POST['password']
        print username, password
        cursor.execute("select * from users where name=%s and loginpassword=%s", ( username, password ) )
        m = cursor.fetchall()
        if m[0][1]==username and m[0][4]==password:
            pushToken = request.POST['pushToken']
            print pushToken
            cursor.execute("update users set pushToken=%s where name=%s", (pushToken, username))
            cursor.execute("select uid, name, realname, company, language_id from users where name=%s", username)
            m = cursor.fetchall()
            nlist = ('uid', 'username', 'name', 'company', 'language' )
            vlist = m[0]
            print vlist
            rlist = dict(zip((nlist),(vlist)))
            print rlist
            to_json = {
                    "requestType": "login",
                    "message": "success",
                    "myInfo": rlist
                    }
            return HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        else:
            to_json = {
                     "requestType": "login",
                     "message": "fail"
                     }
            return HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
    else:
            return HttpResponse("Error!")

def requestContactsWithUsername(request):
    if request.method == 'POST':
        conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
        cursor = conn.cursor()
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
        return HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
    else:
        return HttpResponse("Error")

def requestVideoCallWithUsername(request):
    if request.method == 'POST':
        # Connect to database
        conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
        username = request.POST['username']
        callToUsername = request.POST['callToUsername']
        cursor = conn.cursor()
        n = cursor.execute("SELECT * FROM users WHERE name=%s", username)
        m = cursor.fetchall()
        uid_sender = m[0][0]
        # Send a notification
        message = 'haha'
        token_hex = 'aea23b4f8af477edb5ed701eb69b6a32489620fa34c0dbdfc8428170a68d2b08'
        payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1,
                    custom={'callType':'videoCall', 
	                'callContact': {
		  		 	"uid": "3",
					"username": "test1",
					"name": "Chenyu Lan",
					"company": "SYSU",
					"language": "CHN",
					#"portraitUrl": "http://it.kswchina.com/UploadFiles_9545/201106/2011062803172677.gif"
		    	}})
        apns.gateway_server.send_notification(token_hex, payload)
        #answerVideoCallWithUsername()
        to_json = {
                "requestType": "videoCall",
                "message": "accept"
                }
        return HttpResponse(simplejson.dumps(to_json), mimetype='application/json')
        
    else:
        return HttpResponse("Error!")

def answerVideoCallWithUsername(request2):
    if request2.method == 'POST':
        if request2.POST['message'] == 'accept':
            #do something
            s = 1
        else:
            #do something else
            t = 1
    else:
        return HttpResponse("Error!")

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
