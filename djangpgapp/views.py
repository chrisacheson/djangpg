# Create your views here.
from django.http import HttpResponse
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login

from djangpgapp.gpg import GPG
from djangpgapp.models import PublicKey, OneTimePassword
gpg = GPG()

def index(request):
    return render_to_response("index.html")

def keyinput(request):
    return render_to_response("add_key.html", context_instance=RequestContext(request))

def addkey(request):
    key = request.POST['key']
    user_from_keydata(key)
    return HttpResponse("Success!")

def otplogin(request):
    return render_to_response("login.html", context_instance=RequestContext(request))

def checkotp(request):
    user = authenticate(otp_string=request.POST['otp'])
    if user is not None:
        if user.is_active:
            login(request, user)
            return HttpResponse("Success!")
        else:
            return HttpResponse("Account disabled.")
    return HttpResponse("Fail.")

# This should be part of the PublicKey model.
def user_from_keydata(keydata):
    results = gpg.add_key(keydata)
    assert len(results) == 1
    key = results[0]
    username, email = key.username, key.email
    # Create an active user with no usable password.
    user = User.objects.create_user(username, email)
    user.save()
    key.user = user
    key.save()
    OneTimePassword.make_new_batch(user)
    return user, key
