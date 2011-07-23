from django.conf.urls.defaults import *
import djangpgapp.views

urlpatterns = patterns('djangpgapp.views',
        (r'^$', 'index_view'),
        (r'^newkey/$', 'keyinput_view'),
        (r'^addkey/$', 'keyinput_post'),
        (r'^login/$', 'login_view'),
        (r'^checkotp/$', 'login_post'),
        (r'^login_sign/$', 'login_sign_view'),
        (r'^check_signature/$', 'login_sign_post'),
        (r'^logout/$', 'logout_view'),
)
