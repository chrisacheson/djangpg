from django.conf.urls.defaults import *
import djangpgapp.views

urlpatterns = patterns('djangpgapp.views',
        (r'^$', 'index_view'),
        (r'^newkey/$', 'keyinput_view'),
        (r'^addkey/$', 'keyinput_post'),
        (r'^login/$', 'login_view'),
        (r'^login/checkotp/$', 'login_post'),
        (r'^login_sign/$', 'login_sign_view'),
        (r'^login_sign/check_signature/$', 'login_sign_post'),
        (r'^login_encrypt/$', 'login_key_view'),
        (r'^login_encrypt/key/$', 'login_key_post'),
        (r'^login_encrypt/challenge/$', 'login_encrypted_challenge_view'),
        (r'^login_encrypt/check_response/$', 'login_encrypted_challenge_post'),
        (r'^logout/$', 'logout_view'),
)
