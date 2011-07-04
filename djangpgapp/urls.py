from django.conf.urls.defaults import *
import djangpgapp.views

urlpatterns = patterns('djangpgapp.views',
        (r'^$', 'index'),
        (r'^newkey/$', 'keyinput'),
        (r'^addkey/$', 'addkey'),
        (r'^login/$', 'otplogin'),
        (r'^checkotp/$', 'checkotp'),
)
