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
    request.session['signature_challenge'] = challenge
    return render_to_response("login_sign.html", {'signature_challenge': challenge}, context_instance=RequestContext(request))

def login_sign_post(request):
    user = authenticate(signature_challenge=request.session['signature_challenge'], signed_response=request.POST['signed_response'])
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

def login_key_view(request):
    return render_to_response("login_key.html", context_instance=RequestContext(request))

def login_key_post(request):
    # Strip spaces from the fingerprint so that it can be pasted the same way GPG outputs it.
    key = PublicKey.objects.get(fingerprint=request.POST['fingerprint'].replace(" ", ""))
    request.session['public_key'] = key
    return HttpResponseRedirect(reverse('djangpgapp.views.login_encrypted_challenge_view'))

def login_encrypted_challenge_view(request):
    challenge = randstring(40)
    encrypted_challenge = request.session['public_key'].sign_and_encrypt(challenge)
    request.session['plaintext_challenge'] = challenge
    request.session['encrypted_challenge'] = encrypted_challenge
    return render_to_response("login_encrypt.html", {'encrypted_challenge': encrypted_challenge},
            context_instance=RequestContext(request))

def login_encrypted_challenge_post(request):
    user = authenticate(public_key=request.session['public_key'], plaintext_challenge=request.session['plaintext_challenge'],
            decrypted_response=request.POST['decrypted_response'])
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
