# Create your views here.
from django.http import HttpResponse
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext

from django.contrib.auth.models import User

from djangpgapp.gpg import GPG
from djangpgapp.models import PublicKey
gpg = GPG()

def keyinput_view(request):
    return render_to_response("add_key.html", context_instance=RequestContext(request))

def addkey_view(request):
    key = request.POST['key']
    user_from_keydata(key)
    return HttpResponse("Success!")

def user_from_keydata(keydata):
    results = gpg.add_key(keydata)
    assert len(results) == 1
    key = results[0]
    username, email = key.username, key.email
    user = User.objects.create_user(username, email, User.objects.make_random_password())
    user.is_active = False
    user.save()
    key.user = user
    key.save()
    return user, key
