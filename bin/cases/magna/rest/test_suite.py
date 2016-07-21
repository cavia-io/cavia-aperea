# -*- coding: utf-8 -*-

import requests
from requests.compat import urljoin
from ngta import TestContextManager, parametrize, skip
from .base import RestBaseTestCase, RestNotFoundTestCase, randstr

import logging
logger = logging.getLogger(__name__)


testsuite_json_schema = {
    "type": "object",
    "properties": {
        "id": {
            "type": "integer"
        },
        "parent_id": {
            "type": "integer"
        },
        "name": {
            "type": "string"
        },
        "description": {
            "type": ["string", "null"]
        }
    },
    "required": ["id", "parent_id", "name", "description"]
}


class BaseTestCase(RestBaseTestCase):
    def _post_and_validate(self, url, data, schema=None):
        resp = self.session.post(url, json=self.parameters)
        self.assertEqual(resp.status_code, requests.codes.created, msg="post response status code should be 201")

        json = resp.json()
        if schema:
            self._validate_json(json, schema, "json should be validated successfully by schema.")
        self.assertEqual(json["name"], data["name"], "name should be same.")
        if "description" not in data:
            self.assertIsNone(json["description"], "description should be None.")
        else:
            self.assertEqual(json["description"], data["description"], "description should be same.")
        return json

    def _get_and_validate_200(self, url, schema, expected_data):
        resp = self.session.get(url)
        self.assertEqual(resp.status_code, requests.codes.ok, msg="get response status code should be 200")

        json = resp.json()
        self._validate_json(json, schema, "json should be validated successfully by schema.")

        json.pop("id", None)
        self.assertEqual(json, expected_data, "get response and expected data should be same.")

    def _get_and_validate_404(self, url, ):
        resp = self.session.get(url)
        self.assertEqual(resp.status_code, requests.codes.not_found, msg="get response status code should be 404")

    def _delete_and_validate(self, url):
        resp = self.session.delete(url)
        self.assertEqual(resp.status_code, requests.codes.no_content, msg="delete response status code should be 204")
        self._get_and_validate_404(url)


class TestSuitesTestCase(BaseTestCase):
    def setUp(self):
        self.fixture = TestContextManager.current_context().fixture
        self.session = self.fixture.session
        self.url = urljoin(self.session.resturl, "testsuites")

    def test__get(self):
        resp = self.session.get(self.url)
        self.assertEqual(resp.status_code, requests.codes.method_not_allowed,
                         msg="get response status code should be 405")

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


class TestSuiteNotFoundTestCase(RestNotFoundTestCase):
    PATH = "testsuites"
