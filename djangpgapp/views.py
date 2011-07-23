# Create your views here.
from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages

from djangpgapp.models import PublicKey, OneTimePassword
from randstring import randstring

def index_view(request):
    return render_to_response("index.html", context_instance=RequestContext(request))

def keyinput_view(request):
    return render_to_response("add_key.html", context_instance=RequestContext(request))

def keyinput_post(request):
    key = request.POST['key']
    key_objects = PublicKey.make_from_keydata(key)
    if len(key_objects) > 0:
        messages.success(request, "Your key has been imported.  Check your email for an encrypted list of one-time passwords.")
    else:
        messages.error(request, "Key import failed.")
    return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))

def login_view(request):
    return render_to_response("login.html", context_instance=RequestContext(request))

def login_post(request):
    user = authenticate(otp_string=request.POST['otp'])
    if user is not None:
        if user.is_active:
            login(request, user)
            messages.success(request, "You have successfully logged in.")
            return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))
        else:
            messages.error(request, "Your account is disabled.")
            return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))
    messages.error(request, "Login failed.")
    return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))

def login_sign_view(request):
    challenge = randstring(40)
    request.session['challenge'] = challenge
    return render_to_response("login_sign.html", {'challenge': challenge}, context_instance=RequestContext(request))

def login_sign_post(request):
    user = authenticate(challenge=request.session['challenge'], response=request.POST['response'])
    if user is not None:
        if user.is_active:
            login(request, user)
            messages.success(request, "You have successfully logged in.")
            return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))
        else:
            messages.error(request, "Your account is disabled.")
            return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))
    messages.error(request, "Login failed.")
    return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))

def logout_view(request):
    if request.user.is_authenticated():
        logout(request)
        messages.success(request, "You have successfully logged out.")
    return HttpResponseRedirect(reverse('djangpgapp.views.index_view'))
