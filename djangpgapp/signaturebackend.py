from django.contrib.auth.models import User
from djangpgapp.models import PublicKey

class SignatureBackend:
    """
    Django auth backend for signature-based authentication.
    """

    def authenticate(self, signature_challenge=None, signed_response=None):
        if signature_challenge and signed_response and signature_challenge in signed_response:
            return PublicKey.verify(signed_response).user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
