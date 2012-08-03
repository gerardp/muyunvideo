from django.conf.urls import patterns, include, url
# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    #url(r'^$', 'muyunvideo.views.home', name='home'),
    # url(r'^muyunvideo/', include('muyunvideo.foo.urls')),
    url(r'^login/$', 'video.views.requestLoginWithUsername'),
    url(r'^session/$', 'video.views.requestSessionWithUsername'),
    url(r'^contacts/$', 'video.views.requestContactsWithUsername'),
    url(r'^updatePassword/$', 'video.views.updatePasswordWithUsername'),
    url(r'^videoCallTo/$', 'video.views.requestVideoCallWithUsername'),
    # Uncomment the admin/doc line below to enable admin documentation:
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^answerVideoCall/$','video.views.answerVideoCallWithUsername'), 
    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
       
)
