from django.db import models
from django.db.models import F
from django.db import IntegrityError
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail

import hashlib
import gnupg
import re

from randstring import randstring

class GPGError(Exception):
    pass

class PublicKey(models.Model):
    fingerprint = models.CharField(max_length=40, unique=True)
    email = models.EmailField()
    username = models.CharField(max_length=64)
    user = models.ForeignKey(User, blank=True, null=True)

    # Private: Interface to python-gnupg.
    _gpg = gnupg.GPG(gnupghome = settings.GPG['HOMEDIR'])

    @staticmethod
    def make_from_keydata(keydata):
        """
        Given a public key block, import and create PublicKey models for any keys found.
        Create a new user and associate them with all the PublicKey objects created.

        Return a list of the new PublicKey objects.
        """
        gpg = PublicKey._gpg
        uid_parser = re.compile(r"(?P<username>.*?)( \((?P<comment>.*?)\))? \<(?P<email>.*)\>")

        import_result = gpg.import_keys(keydata)
        fingerprints = [result['fingerprint'] for result in import_result.results]
        keys = []
        ekeys = dict([[key['fingerprint'], uid_parser.match(key['uids'][0]).groupdict()] for key in gpg.list_keys() if key is not None and key != ""])

        for fingerprint in fingerprints:
            if not fingerprint in ekeys: raise GPGError("Error importing key " + str(fingerprint))
            key = ekeys[fingerprint]

            newkey = PublicKey(username=key['username'], fingerprint=fingerprint, email=key['email'])
            try:
                newkey.save()
            except IntegrityError:
                #Key exists already
                pass

            keys.append(newkey)

        if len(keys) > 0:
            # Create an active user with no usable password.
            # TODO: Currently we set the username from the name on the first key.  The other keys are saved but not used.
            # Consider letting the user pick their username and manage their keys.
            user = User.objects.create_user(keys[0].username, keys[0].email)
            user.save()

            for key in keys:
                key.user = user
                key.save()

            OneTimePassword.make_new_batch(user)

        return keys

    def sign_and_encrypt(self, plaintext):
        """
        Given plaintext data, sign it with the server key, encrypt it with this PublicKey.

        Return a PGP block with the signed and encrypted data.
        """
        keys = (self.fingerprint,)
        server_key = settings.GPG['SERVER_KEY']
        passphrase = settings.GPG['SERVER_PASSPHRASE']

        pgp_block = PublicKey._gpg.encrypt(plaintext, keys, sign=server_key, passphrase=passphrase, always_trust=True).data
        # Don't fail silently.
        assert(len(pgp_block) > 0)

        return pgp_block

    @staticmethod
    def verify(signed_data):
        """
        Given signed data, return the PublicKey that signed it, or None if the signature is invalid.
        """
        verified = PublicKey._gpg.verify(signed_data)

        if verified:
            return PublicKey.objects.get(fingerprint=verified.pubkey_fingerprint)
        else:
            return None

    def send_mail(self, subject, body):
        """
        Send encrypted email to the address on this PublicKey, signed with the server key.
        """
        encrypted_body = self.sign_and_encrypt(body)
        send_mail(subject, encrypted_body, settings.GPG['ENCMAIL_FROM'], (self.email,))

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

        otp = OneTimePassword(user=user)
        otp.algorithm = "sha512"
        otp.iterations = 1000
        otp.raw_password = randstring(40)
        otp.salt = randstring(16)
        otp.expiration_counter = 0

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

        new_batch_strings = [OneTimePassword.generate(user).get_otpstring() for i in range(otp_batch_size)]

        mail_subject = "New one-time passwords"
        mail_body = "\n".join(new_batch_strings)

        key = user.publickey_set.all()[0]
        key.send_mail(mail_subject, mail_body)
