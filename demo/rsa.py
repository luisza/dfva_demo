# encoding: utf-8


'''
Created on 16/4/2017

@author: luisza
'''
from __future__ import unicode_literals

from base64 import b64decode, b64encode
import hashlib
import json
import io

from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

import logging

logger = logging.getLogger('dfva_demo')


BLOCK_SIZE = 16


class AES_EAX:
    @staticmethod
    def decrypt(file_in, private_key, session_key=None):
        if session_key is None:
            private_key = RSA.import_key(private_key)

            enc_session_key, nonce, tag, ciphertext = \
                [file_in.read(x)
                 for x in (private_key.size_in_bytes(), BLOCK_SIZE, 16, -1)]

            cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def encrypt(message, session_key, file_out):
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message)
        [file_out.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]


class AES_256_CFB:

    @staticmethod
    def encrypt(message, session_key, file_out):
        # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
        IV = Random.new().read(BLOCK_SIZE)
        aes = AES.new(session_key, AES.MODE_CFB, IV,  segment_size=128)
        enc_message = aes.encrypt(message)
        [file_out.write(x) for x in (IV, enc_message)]

    @staticmethod
    def decrypt(file_in, private_key, session_key=None):
        if session_key is None:
            private_key = RSA.import_key(private_key)
            enc_session_key, iv, ciphertext = \
                [file_in.read(x)
                 for x in (private_key.size_in_bytes(), BLOCK_SIZE, -1)]

            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

        aes = AES.new(session_key, AES.MODE_CFB, iv, segment_size=128)
        return aes.decrypt(ciphertext)


Available_ciphers = {
    "aes_eax": AES_EAX,
    "aes-256-cfb": AES_256_CFB
}


def pem_to_base64(certificate):
    return certificate.replace("-----BEGIN CERTIFICATE-----\n", '').replace(
        '\n-----END CERTIFICATE-----', ''
    ).replace('\n', '')


def get_digest(digest_name):
    if 'sha256' == digest_name:
        return hashlib.sha256()
    elif 'sha384' == digest_name:
        return hashlib.sha384()
    elif 'sha512' == digest_name:
        return hashlib.sha512()


def get_hash_sum(data, algorithm):
    if type(data) == str:
        data = data.encode()
    digest = get_digest(algorithm)
    digest.update(data)
    hashsum = digest.hexdigest()
    return hashsum


def decrypt(private_key, cipher_text, as_str=True,
            session_key=None, method='aes_eax'):
    raw_cipher_data = b64decode(cipher_text)
    file_in = io.BytesIO(raw_cipher_data)
    file_in.seek(0)

    decrypted = Available_ciphers[method].decrypt(
        file_in, private_key, session_key=session_key)

    if as_str:
        return json.loads(decrypted.decode())
    return decrypted


def encrypt(public_key, message, method='aes_eax'):
    if type(message) == str:
        message = message.encode('utf-8')

    file_out = io.BytesIO()
    recipient_key = RSA.importKey(public_key)
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    file_out.write(cipher_rsa.encrypt(session_key))

    # Encrypt the data with the AES session key
    Available_ciphers[method].encrypt(message, session_key, file_out)

    file_out.seek(0)

    return b64encode(file_out.read())


def get_random_token():
    return get_random_bytes(16)


def validate_sign(public_certificate, key, cipher_text):

    cipher_text = b64decode(cipher_text)
    if hasattr(key, 'encode'):
        key = key.encode()

    digest = SHA512.new()
    digest.update(key)

    pub_key = RSA.importKey(public_certificate)
    verifier = PKCS1_v1_5.new(pub_key)
    result = verifier.verify(digest, cipher_text)
    logger.debug("validate_sign %i " % (result,))
    return result


def validate_sign_data(public_certificate, key, cipher_text):
    digest = SHA512.new()
    digest.update(key)

    raw_cipher_data = b64decode(cipher_text)
    file_in = io.BytesIO(raw_cipher_data)
    file_in.seek(0)
    pub_key = RSA.importKey(public_certificate)
    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x)
         for x in (pub_key.size_in_bytes(), 16, 16, -1)]

    verifier = PKCS1_v1_5.new(pub_key)
    result = verifier.verify(digest, enc_session_key)
    logger.debug("validate_sign_data %i " % (result,))
    return result