"""
Classes that describe different user roles
"""

import requests
import copy
import logging
from . import config


class AnonymousUser(object):
    """
    Class of the anonymous user
    """

    def __init__(self):
        self.api_base = config.API_BASE
        self.api_version = config.API_VERSION
        self.api_url = '{api_url}/{api_version}'.format(
            api_url=self.api_base,
            api_version=self.api_version
        )
    
    def get(self, *args, **kwargs):
        return requests.get(*self.update_args(args), **self.update_kwargs(kwargs))
    
    def post(self, *args, **kwargs):
        return requests.post(*self.update_args(args), **self.update_kwargs(kwargs))
    
    def put(self, *args, **kwargs):
        return requests.put(*self.update_args(args), **self.update_kwargs(kwargs))
    
    def options(self, *args, **kwargs):
        return requests.options(*self.update_args(args), **self.update_kwargs(kwargs))
    
    def update_args(self, args):
        args = list(args)
        if len(args) > 0:
            url = args[0]
            if not (url[0:4] == 'http' or url[0:2] == '//'):
                url = self.api_url + (url[0] == '/' and url or ('/' + url))
            args[0] = url
        return args
    
    def update_kwargs(self, kwargs):
        if 'headers' in kwargs:
            headers = kwargs['headers']
        else:
            headers = {}
            
        if hasattr(self, 'access_token') and self.access_token:
            headers['Authorization'] = headers.get('Authorization', 'Bearer:' + self.access_token)
        
        if headers:
            kwargs['headers'] = headers
        return kwargs
    
    def get_config(self, name):
        if hasattr(config, name):
            return copy.deepcopy(getattr(config, name))
        raise Exception('Non-existent config value: %s' % name)


class AuthenticatedUser(AnonymousUser):
    def __init__(self):
        AnonymousUser.__init__(self)
        self.access_token = config.AUTHENTICATED_USER_ACCESS_TOKEN

        
class BumblebeeAnonymousUser(AnonymousUser):
    def __init__(self):
        AnonymousUser.__init__(self)
        # dont want to fail tests 
        try:
            r = self.get('/accounts/bootstrap')
            self.access_token = r.json()['access_token']
        except:
            logging.error('Failed getting access_token for Bumblebee user!')