'''
Created on 17 jun. 2018

@author: luis
'''
from cruds_adminlte.inline_crud import InlineAjaxCRUD
from demo.models import NotificationURL, Institution
from cruds_adminlte.crud import CRUDView
import logging
logger = logging.getLogger('dfva_demo')


class NotificationURLAjaxCRUD(InlineAjaxCRUD):
    model = NotificationURL
    base_model = Institution
    inline_field = 'institution'
    fields = ['description', 'url', 'not_webapp']
    title = "Direcciones de notificación"


class InstitutionCRUD(CRUDView):
    model = Institution
    check_login = True
    check_perms = True
    fields = ['name',
              'code',
              'active',
              'private_key',
              'public_certificate',
              'server_public_key']
    list_fields = ['name', 'active']
    display_fields = ['name', 'code', 'active', 'private_key', 'server_public_key',
                      'public_certificate']

    inlines = [NotificationURLAjaxCRUD]
