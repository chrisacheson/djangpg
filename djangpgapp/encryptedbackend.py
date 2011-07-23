from django.contrib.auth.models import User
from djangpgapp.models import PublicKey

class EncryptedBackend:
    """
    Django auth backend for encryption-based authentication.
    """

    def authenticate(self, public_key=None, plaintext_challenge=None, decrypted_response=None):
        if public_key and plaintext_challenge and decrypted_response and plaintext_challenge in decrypted_response:
            return public_key.user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
