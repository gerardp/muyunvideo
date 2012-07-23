from django.conf.urls import patterns, include, url
# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

from video.views import login_view,logout_view  
urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'muyunvideo.views.home', name='home'),
    # url(r'^muyunvideo/', include('muyunvideo.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
     url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
     url(r'^admin/', include(admin.site.urls)),
     url(r'^accounts/login/$', login_view),  
     (r'^accounts/logout/$', logout_view),  
     )  
)
