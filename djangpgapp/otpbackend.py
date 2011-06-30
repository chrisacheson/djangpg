from django.contrib.auth.models import User
from djangpgapp.models import OneTimePassword

class OTPBackend:
    """
    Hook our OneTimePassword model into Django's authentication system.
    """

    def authenticate(self, otp_string=None):
        if otp_string:
            return OneTimePassword.get_user_from_otpstring(otp_string)

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
