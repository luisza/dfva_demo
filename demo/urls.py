# encoding: utf-8

'''
Created on 26 jul. 2017

@author: luisza
'''

from django.conf.urls import url
from demo.views.authentication import send_notification,\
    AuthenticateDataRequestListView, AuthenticateDataRequestUpdate
from demo.views import show_simulate_bccr_request  # , PersonView
from demo.institution_views import InstitutionCRUD

urlpatterns = [
    url(r'simule/(?P<nform>auth|sign|validate|verify)$',
        show_simulate_bccr_request, name="simulate_bccr_request"),
    url(r'^authenticator/authenticatedatarequest/(?P<token>[^/]+)/update$',
        AuthenticateDataRequestUpdate.as_view(),
        name="authenticator_authenticatedatarequest_update"),
    url(r'^authenticator/authenticatedatarequest/list$', AuthenticateDataRequestListView.as_view(),
        name="authenticator_authenticatedatarequest_list"),
    url(r'^authenticator/authenticatedatarequest/list/(?P<token>[^/]+)/test$',
        send_notification, name="send_authrequest_notification"),
]

try:  # Needs to fix import
    urlpatterns += InstitutionCRUD().get_urls()
    #urlpatterns += PersonView().get_urls()
except:
    pass
