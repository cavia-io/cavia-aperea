# -*- coding: utf-8 -*-

from jsonschema import validate, ValidationError
from ngta import TestCase

import random
import string
import collections

import requests
from abc import ABCMeta, abstractproperty
from six import add_metaclass
from requests.compat import urljoin
from ngta import TestContextManager, parametrize, skip


def randstr(chars=string.printable, length=None, exclude=None):
    # For chinese
    # common, rare = range(0x4e00, 0xa000), range(0x3400, 0x4e00)
    # chars = map(unichr, rare + common)
    if length is None:
        length = random.randint(0, 255)

    s = ""
    while len(s) != length:
        char = random.choice(chars)
        if isinstance(exclude, collections.Iterable) and char in exclude:
            continue
        else:
            s += char
    return s


class RestBaseTestCase(TestCase):
    def _validate_json(self, instance, schema, msg):
        try:
            validate(instance, schema)
        except ValidationError:
            self.fail_(msg)
        else:
            self.pass_(msg)


@add_metaclass(ABCMeta)
@parametrize("id", type=int, default=0)
class RestNotFoundTestCase(RestBaseTestCase):

    @abstractproperty
    def PATH(self):
        pass

    def setUp(self):
        self.session = TestContextManager.current_context().fixture.session
        self.url = urljoin(self.session.resturl, "%s/%d" % (self.PATH, self.parameters.get("id")))

    def test__get(self):
        resp = self.session.get(self.url)
        self.assertEqual(resp.status_code, requests.codes.not_found, msg="the status code should be 404")

    def test__put(self):
        resp = self.session.put(self.url, json={})
        self.assertEqual(resp.status_code, requests.codes.not_found, msg="the status code should be 404")

    def test__delete(self):
        resp = self.session.delete(self.url)
        self.assertEqual(resp.status_code, requests.codes.not_found, msg="the status code should be 404")
