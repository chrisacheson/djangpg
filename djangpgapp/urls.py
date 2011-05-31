from django.conf.urls.defaults import *
import djangpgapp.views

urlpatterns = patterns('', (r'newkey', djangpgapp.views.keyinput_view),
    (r'addkey', djangpgapp.views.addkey_view))
