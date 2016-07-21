# -*- coding: utf-8 -*-

import six
import requests
from requests.compat import urljoin
from ngta import TestContextManager, parametrize, skip
from .base import RestBaseTestCase, RestNotFoundTestCase, randstr

import logging
logger = logging.getLogger(__name__)


testproject_json_schema = {
    "type": "object",
    "properties": {
        "id": {
            "type": "integer"
        },
        "name": {
            "type": "string"
        },
        "description": {
            "type": ["string", "null"]
        }
    },
    "required": ["id", "name", "description"]
}


class BaseTestCase(RestBaseTestCase):
    def _post_and_validate(self, url, data):
        resp = self.session.post(url, json=self.parameters)
        self.assertEqual(resp.status_code, requests.codes.created, msg="post response status code should be 201")

        json = resp.json()
        self._validate_json(json, testproject_json_schema, "json should be validated successfully by schema.")
        self.assertEqual(json["name"], data["name"], "name should be same.")
        if "description" not in data:
            self.assertIsNone(json["description"], "description should be None.")
        else:
            self.assertEqual(json["description"], data["description"], "description should be same.")
        return json

    def _get_and_validate(self, url, code, expected_data):
        resp = self.session.get(url)
        self.assertEqual(resp.status_code, code, msg="get response status code should be %s" % code)

        if resp.status_code == 200:
            json = resp.json()
            self._validate_json(json, testproject_json_schema, "json should be validated successfully by schema.")

            json.pop("id", None)
            self.assertEqual(json, expected_data, "name and description should be same.")

    def _delete_and_validate(self, url):
        resp = self.session.delete(url)
        self.assertEqual(resp.status_code, requests.codes.no_content, msg="delete response status code should be 204")
        self._get_and_validate(url, requests.codes.not_found, self.data)


class TestProjectsTestCase(BaseTestCase):
    def setUp(self):
        self.fixture = TestContextManager.current_context().fixture
        self.session = self.fixture.session
        self.url = urljoin(self.session.resturl, "testprojects")

    @parametrize("name", default=randstr())
    def test__post_without_description(self):
        self._post_and_validate(self.url, self.parameters)

    @parametrize("name", default=randstr())
    @parametrize("description", default=randstr())
    def test__post_with_description(self):
        self._post_and_validate(self.url, self.parameters)

    @skip("Not Implemented")
    def test__post_with_name_too_long(self):
        raise NotImplementedError

    def test__get(self):
        schema = {
            "type": "array",
            "items": testproject_json_schema
        }
        resp = self.session.get(self.url)
        self._validate_json(resp.json(), schema, "json should be validated successfully by schema.")


class TestProjectUpdateTestCase(BaseTestCase):
    def setUp(self):
        self.fixture = TestContextManager.current_context().fixture
        self.session = self.fixture.session

        self.data = {
            "name": randstr(),
            "description": randstr()
        }
        baseurl = urljoin(self.session.resturl, "testprojects")
        resp = self.session.post(baseurl, json=self.data)
        self._validate_post(self.data, resp)

        self.url = urljoin(baseurl+"/", str(resp.json().get("id")))

    @parametrize("name", type=six.text_type, default=randstr(length=5))
    @parametrize("description", type=six.text_type, default=randstr(length=5))
    def test__put(self):
        resp = self.session.put(self.url, json=self.parameters)
        self.assertEqual(resp.status_code, requests.codes.no_content, msg="put response status code should be 204")
        logger.debug("Check name and description have been modified by GET")
        self._get_and_validate(self.url, requests.codes.ok, self.parameters)

    def tearDown(self):
        self._delete_and_validate(self.url)


class TestProjectNotFoundTestCase(RestNotFoundTestCase):
    PATH = "testprojects"
