# -*- coding: utf-8 -*-

from jsonschema import validate, ValidationError
from .base import RestBaseTestCase, RestNotFoundTestCase
from ngta import parametrize


testnode_json_schema = {
    "definitions": {
        "testnode": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer"
                },
                "parent_id": {
                    "type": ["integer", "null"]
                },
                "name": {
                    "type": "string"
                },
                "type": {
                    "type": "integer",
                    "enum": [1, 2, 3, 4, 5, 6]
                },
                "sequence": {
                    "type": "integer"
                },
                "children": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/testnode"}
                }
            },
            "required": ["id", "parent_id", "name", "type", "sequence"]
        }
    },

    "$ref": "#/definitions/testnode"
}


class BaseTestCase(RestBaseTestCase):
    pass


@parametrize("loop3", type=int, iteration=[7, 8, 9])
@parametrize("loop2", type=int, iteration=[4, 5, 6])
@parametrize("loop1", type=int, iteration=[1, 2, 3])
class TestNodeGetTestCase(BaseTestCase):
    def test_(self):
        pass


class TestNodePutTestCase(BaseTestCase):
    pass


class TestNodeNotFoundTestCase(RestNotFoundTestCase):
    PATH = "testnodes"
