from django.db import models
from django.db.models import F
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
    algorithm = models.CharField(max_length=12)
    iterations = models.IntegerField()
    hash = models.CharField(max_length=128)
    salt = models.CharField(max_length=16)
    expiration_counter = models.IntegerField()

    # This is only set when the OTP object is first created, not when it is retreived from the database.
    raw_password = None

    # Private: Separator to use between the OTP ID and raw password in the OTP string that is sent to the user.
    _separator = ":"

    @staticmethod
    def _make_hash(algorithm, iterations, raw_password, salt):
        # Private: Do the actual hashing operation.

        hash = hashlib.new(algorithm, (raw_password+salt).encode())
        for i in range(iterations-1): hash = hashlib.new(algorithm, hash.digest()+(raw_password+salt).encode())

        return hash.hexdigest()

    @staticmethod
    def generate(user):
        """
        Given a User object, create a new OneTimePassword object and save it to the database.

        Return the newly created OneTimePassword object with the raw_password attribute set.
        """
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        password_length = 40
        salt_length = 16

        rng = SystemRandom()
        otp = OneTimePassword(user=user)
        otp.algorithm = "sha512"
        otp.iterations = 1000
        otp.raw_password = ""
        otp.salt = ""
        otp.expiration_counter = 0

        for i in range(password_length): otp.raw_password += rng.choice(alphabet)
        for i in range(salt_length): otp.salt += rng.choice(alphabet)

        otp.hash = OneTimePassword._make_hash(otp.algorithm, otp.iterations, otp.raw_password, otp.salt)
        otp.save()

        return otp

    def get_otpstring(self):
        """
        Return the one time password string to be sent to the user.  This only works if raw_password is set.
        """
        return str(self.id) + OneTimePassword._separator + self.raw_password

    @staticmethod
    def get_user_from_otpstring(otpstring):
        """
        Return the appropriate User object, given a valid one time password string, or None if invalid.
        Delete the OneTimePassword object afterwards, then check if we should create more.
        """
        minimum_otp_count = 3

        otp_id, separator, raw_password = otpstring.partition(OneTimePassword._separator)

        try: otp = OneTimePassword.objects.get(pk=otp_id)
        except: return None

        if otp.hash == OneTimePassword._make_hash(otp.algorithm, otp.iterations, raw_password, otp.salt):
            user = otp.user
            otp.delete()

            if len(user.onetimepassword_set.all()) < minimum_otp_count:
                OneTimePassword.make_new_batch(user)

            return user

        return None

    @staticmethod
    def make_new_batch(user):
        """
        Given a User object, make a new batch of one time passwords for them and send via encrypted email.
        Delete any expired OTPs.
        """
        otp_batch_size = 10
        expire_at_count = 2

        current_otps = user.onetimepassword_set.all()
        current_otps.update(expiration_counter=F("expiration_counter")+1)
        current_otps.filter(expiration_counter__gte=expire_at_count).delete()

        # Ugly workaround for circular dependency.
        # Consider getting rid of the gpg module and merging its methods into the PublicKey model.
        from gpg import GPG
        gpg = GPG()

        new_batch_strings = [OneTimePassword.generate(user).get_otpstring() for i in range(otp_batch_size)]

        mail_subject = "New one-time passwords"
        mail_body = "\n".join(new_batch_strings)
        gpg.send_mail(user, mail_subject, mail_body)
