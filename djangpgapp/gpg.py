#Wraps python-gnupg, adds convienience.

import gnupg
from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError

from models import PublicKey
import re

gpg = gnupg.GPG(gnupghome = settings.GPG['HOMEDIR'])
uid_parser = re.compile(r"(?P<username>.*?)( \((?P<comment>.*?)\))? \<(?P<email>.*)\>") 
class GPGError(Exception):
    pass

class GPG():
    def __init__(self):
        pass
    def sign_and_crypt(self, data, recipient):
        return gpg.encrypt(data, (recipient,), sign=settings.GPG['SERVER_KEY'],
                                     passphrase=settings.GPG['SERVER_PASSPHRASE']).data

    def decrypt_and_verify(self, data):
        '''Given PGP-signed and encrypted data
        return a 2-tuple (decrypted data, public key object)'''
        decrypted_data = gpg.decrypt(data, passphrase=settings.GPG['SERVER_PASSPHRASE'])
        logging.info(decrypted_data)
        if decrypted_data.key_id is None:            raise GPGError()

        else:
            fingerprint = decrypted_data.fingerprint
            key_model = PublicKey.objects.get(fingerprint=fingerprint)
            return decrypted_data.data, key_model

    def verify(self, data):
        '''Given signed data, return the public key object'''
        verified = gpg.verify(data)
        if verified.key_id is None:
            raise GPGError()
        else:
            fingerprint = verified.fingerprint
            key_model = PublicKey.objects.get(fingerprint=fingerprint)
            return key_model

    def add_key(self, keydata):
        '''Given a public key block create a key model.
        Return the key models.'''
        import_result = gpg.import_keys(keydata)
        fingerprints = [result['fingerprint'] for result in import_result.results]
        keys = []
        ekeys = dict([[key['fingerprint'], uid_parser.match(key['uids'][1]).groupdict()] for key in gpg.list_keys() if key is not None and key != ""])
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
        return keys

    def send_mail(self, user, subject, body):
        pubkey = PublicKey.objects.get(user__username__exact=user.username)
        encbody = self.sign_and_encrypt(body, pubkey.fingerprint)
        send_mail(encbody, settings.GPG['ENCMAIL_FROM'], (user.email,))
