# Create your views here.
#-*- coding: UTF-8 -*-
import codecs
from django.shortcuts import render_to_response
from django.template import Context, loader, RequestContext
#from read.models import Book,UserProfile
from django.http import HttpResponse, HttpResponseRedirect
from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import User, authenticate, login
from django.views.generic.date_based import object_detail
from django.contrib.auth.decorators import login_required
from django.utils import simplejson
from video.models import Users
from apns import APNs, Payload
import time

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
