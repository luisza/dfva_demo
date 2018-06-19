'''
Created on 26 jul. 2017

@author: luis
'''
import json
import requests

from demo.rsa import encrypt, get_hash_sum, decrypt
from demo.requests_utils import get_requests_ssl_context
from django.conf import settings
from django.utils import timezone


class AuthenticatorClient(object):

    def __init__(self, institution, url_notify):
        self.institution = institution
        self.url_notify = url_notify

    def authenticate(self, identification):

        data = {
            'institution': str(self.institution.code),
            'notification_url': self.url_notify.url or 'N/D',
            'identification': identification,
            'request_datetime': timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        algorithm = 'sha512'
        str_data = json.dumps(data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': str(self.institution.code),
            "data": edata,
        }
        kwargs = {
            'json': params
        }
        kwargs.update(get_requests_ssl_context())

        result = requests.post(
            settings.DEMO_DFVA_SERVER_URL + '/authenticate/institution/', **kwargs)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'], as_str=True)

        return data
