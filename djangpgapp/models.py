from django.db import models
from django.contrib.auth.models import User
import hashlib
from random import SystemRandom

class PublicKey(models.Model):
    fingerprint = models.CharField(max_length=40, unique=True)
    email = models.EmailField()
    username = models.CharField(max_length=64)
    user = models.ForeignKey(User, blank=True, null=True)

class OneTimePassword(models.Model):
    user = models.ForeignKey(User)
    hash = models.CharField(max_length=128)
    salt = models.CharField(max_length=16)
    expiration_counter = models.IntegerField()

    # Private: Separator to use between the OTP ID and raw password in the OTP string that is sent to the user.
    _separator = ":"

    @staticmethod
    def _make_hash(raw_password, salt):
        # Private: Do the actual hashing operation.
        iterations = 1000

        hash = hashlib.sha512(raw_password+salt)
        for i in range(iterations-1): hash = hashlib.sha512(hash.digest()+raw_password+salt)

        return hash.hexdigest()

    def generate(self):
        """
        Set the hash, salt, and expiration counter of the OneTimePassword object.
        Call this before calling save().

        Return the raw password as string.
        """
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        password_length = 40
        salt_length = 16
        raw_password = ""
        self.salt = ""
        rng = SystemRandom()

        for i in range(password_length): raw_password += rng.choice(alphabet)
        for i in range(salt_length): self.salt += rng.choice(alphabet)

        self.hash = OneTimePassword._make_hash(raw_password, self.salt)
        self.expiration_counter = 0

        return raw_password

    def get_otpstring(self, raw_password):
        """
        Return the one time password string to be sent to the user, given the raw password.
        Call this after calling save().
        """
        return str(self.id) + OneTimePassword._separator + raw_password

    @staticmethod
    def get_user_from_otpstring(otpstring):
        """
        Return the appropriate User object, given a valid one time password string, or None if invalid.
        """
        otp_id, separator, raw_password = otpstring.partition(OneTimePassword._separator)

        try: otp_object = OneTimePassword.objects.get(pk=otp_id)
        except: return None

        if otp_object.hash == OneTimePassword._make_hash(raw_password, otp_object.salt):
            return otp_object.user
            # TODO: We need to delete the used OTP and check if we need to create and send more of them.  Do that here?

        return None
