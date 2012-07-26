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
    if request.method == 'POST' :
        username = request.POST['username']
        password = request.POST['password']
        if username == 'lancy' and password == 'test':
            to_json = {
                    "requestType": "login",
                    "message": "success",
                    "myInfo": {
                          "uid": "100",
                          "username": "lancy",
                          "name": "Chenyu Lan",
                          "company": "SYU",
                          "language": "CHN",
                          "portraitUrl": "http://it.kswchina.com/UploadFiles_9545/201106/2011062803172677.gif"
                          }
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

def requestVideoCallWithUsername(request):
    if request.method == 'POST':
        conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
        apns = APNs( use_sandbox = True, cert_file = 'muyuncert.pem', key_file = 'muyunkey2.pem' )
        username = request.POST['username']
        callToUsername = request.POST['callToUsername']
        n = cursor.execute("SELECT * FROM users WHERE name=%s", username)
        # Send a notification
        token_hex = 'aea23b4f8af477edb5ed701eb69b6a32489620fa34c0dbdfc8428170a68d2b08'
        #token_hex = .pushToken
        payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1,
                    custom={'callType':'videoCall', 
	                'callContact': {
		  		 	"uid": "101",
					"username": "test1",
					"name": "Chenyu Lan",
					"company": "SYSU",
					"language": "CHN",
					#"portraitUrl": "http://it.kswchina.com/UploadFiles_9545/201106/2011062803172677.gif"
		    	}})
        payload = Payload(alert=message.decode('utf-8'), sound="default", badge=1)
        apns.gateway_server.send_notification(token_hex, payload)
    else:
        return HttpResponse("Error!")


