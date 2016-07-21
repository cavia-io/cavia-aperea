# -*- coding: utf-8 -*-

import importlib

from ngta import BaseTestFixtureFactory
import logging
logger = logging.getLogger(__name__)


class TestFixtureFactory(BaseTestFixtureFactory):
    @classmethod
    def build_testfixture_by_element(cls, element):
        bench_type = element.get("type").lower()
        bench_module = importlib.import_module(cls.__module__ + "." + bench_type)
        return bench_module.TestFixture(element)
