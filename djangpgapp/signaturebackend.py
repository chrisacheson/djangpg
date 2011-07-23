from django.contrib.auth.models import User
from djangpgapp.models import PublicKey

class SignatureBackend:
    """
    Django auth backend for signature-based authentication.
    """

    def authenticate(self, challenge=None, response=None):
        if challenge and response and challenge in response:
            return PublicKey.verify(response).user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
