# encoding: utf-8
"""
Core tests of the ADS web services
"""

import time
import unittest

from ..user_roles import AnonymousUser, AuthenticatedUser, BumblebeeAnonymousUser


class TestCore(unittest.TestCase):
    """
    Base class for all tests
    """
    def setUp(self):
        """
        Generic setup
        """
        self.anonymous_user = AnonymousUser()
        self.authenticated_user = AuthenticatedUser()
        self.bumblebee_user = BumblebeeAnonymousUser()

    def test_status(self):
        """
        Tests that the service is online, and returns the expected message
        """
        r = self.anonymous_user.get(self.anonymous_user.api_base)
        self.assertEqual(
            r.json(),
            {'status': 'online', 'app': 'adsws.frontend'}
        )

    def test_resources(self):
        """
        Test that the expected resources are returned from the api
        """

        # /v1/resources doesn't exist (but I think it should exist)
        r = self.anonymous_user.get('/resources')
        self.assertEqual(404, r.status_code)

        # the response is organized from the perspective of the
        # ADS developer/ API maintainer
        # but API users probably expect to see something like:
        # {
        # '/v1': {
        #    'endpoints': [
        #       '/search/query'
        #        ...
        #     ]
        #  },
        # '/v2': {
        #    'endpoints': [
        #       '/search/newquery',
        #       ...
        #     ]
        #  }
        # }
        #
        # If we run two versions of the API alongside, I don't see
        # how the current structure can communicate two different
        # 'bases'

        # hack to get to the resources
        r = self.anonymous_user.get(self.anonymous_user.api_base + '/resources')
        resources = r.json()

        # check for presence of services in ['adsws.api']['endpoints']
        for endpoint in [
                "/citation_helper/resources", # is this necessary?
                "/recommender/resources",
                "/graphics/resources",
                "/biblib/resources",
                "/biblib/libraries",
                "/search/resources",
                "/export/resources",
                "/search/bigquery",
                "/export/endnote",
                "/search/status",
                "/export/aastex",
                "/export/bibtex",
                "/search/query",
                "/search/qtree",
                "/search/tvrh",
                "/orcid/exchangeOAuthCode",
                "/vault/configuration",
                "/oauth/authorize",
                "/vault/user-data",
                "/orcid/resources",
                "/oauth/invalid/",
                "/oauth/errors/",
                "/oauth/token",
                "/vault/query",
                "/oauth/ping/", # why is it duplicated in the response?
                "/oauth/ping/",
                "/oauth/info/",
                "/vis/author-network",
                "/vis/paper-network",
                "/vis/word-cloud",
                "/vis/resources",
                "/citation_helper/",
                "/protected",
                "/metrics/",
                "/status",
                "/biblib/permissions/<string:library>",
                "/biblib/libraries/<string:library>",
                "/biblib/documents/<string:library>",
                "/biblib/transfer/<string:library>",
                "/vault/execute_query/<queryid>",
                "/vault/configuration/<key>",
                "/vault/query2svg/<queryid>",
                "/vault/query/<queryid>",
                "/orcid/<orcid_id>/orcid-profile",
                "/orcid/<orcid_id>/orcid-works",
                "/recommender/<string:bibcode>",
                "/graphics/<string:bibcode>",
                "/metrics/<string:bibcode>",
                "/user/<string:identifier>"
        ]:
            self.assertIn(endpoint, resources['adsws.api']['endpoints'])

        #... and in adsws.accounts
        for endpoint in [
                "/oauth/authorize",
                "/oauth/invalid/",
                "/oauth/errors/",
                "/oauth/token",
                "/oauth/ping/",
                "/oauth/ping/",
                "/oauth/info/",
                "/user/delete",
                "/change-password",
                "/change-email",
                "/bootstrap",
                "/protected",
                "/register",
                "/status",
                "/logout",
                "/token",
                "/csrf",
                "/user",
                "/reset-password/<string:token>",
                "/verify/<string:token>"
        ]:
            self.assertIn(endpoint,  resources['adsws.accounts']['endpoints'])

        # ... and in adsws.feedback
        for endpoint in [
                "/oauth/authorize",
                "/oauth/invalid/",
                "/oauth/errors/",
                "/oauth/token",
                "/oauth/ping/",
                "/oauth/ping/",
                "/oauth/info/",
                "/slack"
        ]:
            self.assertIn(endpoint, resources['adsws.feedback']['endpoints'])

    def test_limits(self):
        """
        Check the response contains Headers and the limits are there
        """
        r = self.authenticated_user.get('/search/query', params={'q': 'title:"%s"' % time.time()})
        self.assertEqual('5000', r.headers['x-ratelimit-limit'])

        old_limit = int(r.headers['x-ratelimit-remaining'])
        r = self.authenticated_user.get('/search/query', params={'q': 'title:"%s"' % time.time()})

        self.assertEqual(str(old_limit-1), r.headers['x-ratelimit-remaining'])
        self.assertIn('x-ratelimit-reset', r.headers)

    def test_bootstrap(self):
        """
        Tests the bootstrap mechanism, and that the repeatability is idempotent
        XXX: the username for authenticated and anonymous users are the same.
        This is currently caught in a try/except clause, but still needs to be
        addressed.
        """
        # r = self.authenticated_user.get('/accounts/bootstrap')
        # a = r.json()

        r = self.anonymous_user.get('/accounts/bootstrap',
                                    headers={'cookie': 'session=.eJw1jbEKgzAABX-lvNnFDh2EbiFbYgspwS7BahoTo5WYICL-e4vQ9eDuNqh30HOHIoakMyjbothweqEAd3Tg8rFw0S_cNSsT5syJWUti8kqypRLUMuLdU7Ir9p876TDUox7jv_apU-xU4-3BMPmWlrfLnVhkSLMOxw059i_96Szg.CQLbdg.ffAhH5eYCI9D3kKMn9yIYSMneVI'})
        b = r.json()
        print b
        print r.headers

        # try:
        #     self.assertNotEqual(a['username'], b['username'])
        # except AssertionError:
        #     pass
        # except Exception as error:
        #     self.fail('Unknown failure: {}'.format(error))

        # self.assertNotEqual(a['access_token'], b['access_token'])

        # repeating the bootstrap request should give you the
        # same access token
        for x in xrange(5):
            r = self.anonymous_user.get('/accounts/bootstrap')
            self.assertEqual(r.json()['access_token'], b['access_token'])

        # for x in xrange(5):
        #     r = self.authenticated_user.get('/accounts/bootstrap')
        #     self.assertEqual(r.json()['access_token'], a['access_token'])




    def test_crossx_headers(self):
        """
        The microservices should test for headers that they require
        (e.g. Orcid-Authorizatio is tested in orcid)

        XXX: this should be improved
        """
        for endpoint in [
                         '/accounts/bootstrap'
                         ]:
            r = self.bumblebee_user.options(endpoint)

            # the value of this header will differ between staging/production
            self.assertIn('access-control-allow-origin', r.headers)
            self.assertIn('ui.adsabs.harvard.edu', r.headers['access-control-allow-origin'])
            self.assertIn('access-control-allow-headers', r.headers)
            self.assertTrue(r.headers['access-control-allow-headers'])
