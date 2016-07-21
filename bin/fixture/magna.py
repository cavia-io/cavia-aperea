# -*- coding: utf-8 -*-

from ngta import BaseTestFixture

import logging
import requests
import requests.auth
logger = logging.getLogger(__name__)


class Session(requests.Session):
    def __init__(self, resturl, username, password):
        requests.Session.__init__(self)
        self.resturl = resturl
        self.username = username
        self.password = password

    def send(self, request, **kwargs):
        def pformat(headers):
            return "\n".join(["%s: %s" % (key, value) for key, value in headers.items()])

        resp = requests.Session.send(self, request, **kwargs)
        logger.debug("Http Request: \n%s\n\n%s",
                     pformat(resp.request.headers),
                     resp.request.body if resp.request.body else "")
        logger.debug("Http Response: \n%s\n\n%s",
                     pformat(resp.headers),
                     resp.text if resp.text else "")
        return resp


class TestFixture(BaseTestFixture):
    def __init__(self, conf):
        # The conf should can be pickleable, otherwise it can't be attach with TestRunner in another process.
        self.conf = conf
        super(TestFixture, self).__init__(self.conf.get("name"))
        self.session = None

    def on_testrunner_start(self, testrunner):
        element = self.conf.find("MagnaSession")
        self.session = Session(**element.attrib)
        self.session.auth = requests.auth.HTTPBasicAuth(self.session.username, self.session.password)
        self.session.headers.update({"Content-Type": "application/json;charset=UTF-8"})

    def on_testrunner_stop(self, testrunner):
        # resource = TestContextManager.current_context().resource
        self.session.close()
