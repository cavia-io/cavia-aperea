# -*- coding: utf-8 -*-

import os
import json
import time
import uuid
import datetime
import pydoc
import threading
import pprint
import collections
import multiprocessing
import sqlalchemy
import pysvn
import kombu

from xml.etree import ElementTree as etree
from contextlib import contextmanager
from multiprocessing import queues
from tornado import web, escape, gen, ioloop
from sqlalchemy import Column
from sqlalchemy import SmallInteger, Integer, Boolean, String, PickleType, Text, DateTime, TIMESTAMP
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from jsonschema import validate, ValidationError

import common
from ngta import ProcessTestRunner, TestContext, BaseTestFixture
from ngta.listener import TestRunnerLogFileInterceptor, TestCaseLogFileInterceptor, TestResultShelveInterceptor
from ngta.log import DEFAULT_LOG_LAYOUT
from ngta.util import generate_hierarchy_from_module
from coupling.util import ComplexJsonEncoder
from coupling.conf import XmlSetting
from fixture import TestFixtureFactory

import logging
import logging.config
logger = logging.getLogger(__name__)

CACHE_DIR = os.path.join(common.ROOT_DIR, "cache")
RES_CONF = os.path.join(common.CFG_DIR, "resconf.xml")
BaseModel = declarative_base()


class TextPickleType(PickleType):
    impl = Text


class Serializer(object):
    def as_dict(self, relative=True, excludes=()):
        fields = self.fields(relative)

        d = collections.OrderedDict()
        for field in fields:
            if field not in excludes:
                value = getattr(self, field)
                if isinstance(value, Serializer):
                    value = value.as_dict()
                d[field] = value
        return d

    def fields(self, relative=True):
        fields = [c.name for c in getattr(self.__class__, "__table__").columns]
        if relative:
            fields.extend(sqlalchemy.inspect(self.__class__).relationships.keys())
        return fields


class TestExecution(BaseModel, Serializer):
    class State(ProcessTestRunner.State):
        SUBMITTED = 2
        ASSIGNED = 3

    __tablename__ = 'testexecution'

    id = Column(Integer, primary_key=True)
    state = Column(SmallInteger, default=State.SUBMITTED)
    priority = Column(Integer, default=1)
    failfast = Column(Boolean, default=False)
    rsrcname = Column(String(255), ForeignKey('testfixture.name'), default=None)
    testsuites = Column(TextPickleType(pickler=json), nullable=False)
    local_creation_datetime = Column(DateTime, default=datetime.datetime.utcnow)
    start_datetime = Column(DateTime, default=None)
    stop_datetime = Column(DateTime, default=None)

    def __init__(self, id, testsuites, priority=None, failfast=None, rsrcname=None):
        self.id = id
        self.priority = priority
        self.failfast = failfast
        self.rsrcname = rsrcname
        self.testsuites = testsuites

    def __repr__(self):
        s = "<TestExecution(id='%s', state='%s', failfast='%s', rsrcname='%s')>"
        return s % (self.id, self.state, self.failfast, self.rsrcname)


class TestFixture(BaseModel, Serializer):
    __tablename__ = 'testfixture'
    name = Column(String(255), primary_key=True)
    state = Column(SmallInteger)

    def __init__(self, name, state=BaseTestFixture.State.IDLE.value):
        self.name = name
        self.state = state

    def __repr__(self):
        s = "<TestFixture(name='%s', state='%s')>"
        return s % (self.name, self.state)


class BaseResource(web.RequestHandler):
    def initialize(self):
        setattr(self.request, "json", self._json())

    def _json(self):
        content_type = self.request.headers.get("Content-Type", "")
        content_length = self.request.headers.get("Content-Length", -1)
        if 'application/json' in content_type and 0 < int(content_length):
            return escape.json_decode(self.request.body)
        return None

    def get_json(self):
        return self._json()

    @property
    def db(self):
        """"""
        return self.application.scoped_session

    def write(self, chunk):
        if self._finished:
            raise RuntimeError("Cannot write() after finish()")
        if isinstance(chunk, dict) or isinstance(chunk, list):
            chunk = json.dumps(chunk, cls=ComplexJsonEncoder).replace("</", "<\\/")
            self.set_header("Content-Type", "application/json; charset=UTF-8")
        chunk = escape.utf8(chunk)
        self._write_buffer.append(chunk)

    def on_finish(self):
        # http://docs.sqlalchemy.org/en/latest/orm/contextual.html#using-thread-local-scope-with-web-applications
        self.db.remove()

    def data_received(self, chunk):
        pass


class TestFixtureListResource(BaseResource):
    def get(self):
        body = []
        for bench in self.db.query(TestFixture).all():
            body.append(bench.as_dict())
        self.finish(body)


class TestExecutionListResource(BaseResource):
    json_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "priority": {"type": "integer"},
            "failfast": {"type": "boolean"},
            "rsrcname": {"type": ["string", "null"]},
            "testsuites": {"type": "array"}
        },
        "required": ["id", "testsuites"],
        "additionalProperties": False
    }

    def get(self):
        states = self.get_query_arguments("state")
        ids = self.get_query_arguments("id")
        query = self.db.query(TestExecution)
        conditions = []

        if states:
            conditions.append(TestExecution.state.in_(states))

        if ids:
            conditions.append(TestExecution.id.in_(ids))

        if conditions:
            query = self.db.query(TestExecution).filter(*conditions)

        chunk = []
        for execution in query.all():
            chunk.append(execution.as_dict())
        self.finish(chunk)

    def post(self):
        data = self.request.json
        logger.debug("Create a new TestExecution with data: %s", pprint.pformat(data))
        try:
            validate(data, self.json_schema)
        except ValidationError as err:
            self.set_status(400)
            self.finish({"message": err.message})
        else:
            rsrcname = data.get("rsrcname", None)
            if rsrcname:
                bench = self.db.query(TestFixture).filter_by(name=rsrcname).one_or_none()
                if bench is None:
                    self.set_status(400)
                    return self.finish({"message": "rsrcname not exists."})

            if self.db.query(TestExecution).filter_by(id=data["id"]).one_or_none():
                self.set_status(409)
                self.finish({"message": "id already exists."})
            else:
                execution = TestExecution(**data)
                self.db.add(execution)
                self.db.commit()
                self.set_status(201)


class TestExecutionDetailResource(BaseResource):
    json_schema = {
        "type": "object",
        "properties": {
            "priority": {"type": "integer"},
            "failfast": {"type": "boolean"},
            "rsrcname": {"type": ["string", "null"]},
            "testsuites": {"type": "array"}
        },
        "additionalProperties": False
    }

    actions = ("pause", "resume", "abort", "rerun")

    def get(self, ident):
        execution = self.db.query(TestExecution).get(ident)
        if execution:
            chunk = execution.as_dict()
            logger.debug("Response Body: %s", chunk)
            self.finish(chunk)
        else:
            self.set_status(404)

    def put(self, ident):
        execution = self.db.query(TestExecution).get(ident)
        if execution:
            action = self.get_query_argument("action", default=None)
            if action is not None and action.lower() not in self.actions:
                self.set_status(400)
                return self.finish({"message": "Action can only be {}.".format(self.actions)})

            attr_updated = False
            if execution.state in (TestExecution.State.SUBMITTED,
                                   TestExecution.State.ASSIGNED,
                                   TestExecution.State.INITIAL):
                for key, value in self.request.json.items():
                    setattr(execution, key, value)
                self.db.commit()
                attr_updated = True

            if action is not None:
                action = action.lower()
                if execution.state in (TestExecution.State.RUNNING, TestExecution.State.SUSPEND):
                    if action == "pause" and execution.state != TestExecution.State.RUNNING:
                        body = {"message": "Action 'pause' can only be invoked when state is RUNNING."}
                        self.set_status(409)
                        return self.finish(body)
                    if action == "resume" and execution.state != TestExecution.State.SUSPEND:
                        body = {"message": "Action 'resume' can only be invoked when state is SUSPEND."}
                        self.set_status(409)
                        return self.finish(body)

                    called = ExecuteWorker.instance().invoke(ident, action)
                    if called:
                        self.set_status(204)
                        self.finish()
                    else:
                        self.set_status(404)
                        self.finish({"message": "Can't find id(%d) in testrunner list." % ident})
                else:
                    if action == "rerun":
                        if execution.state in (TestExecution.State.ABORTED,
                                               TestExecution.State.UNEXPECT,
                                               TestExecution.State.FINISHED):
                            execution.state = TestExecution.State.SUBMITTED
                            self.db.commit()
                            self.set_status(204)
                            self.finish()
                        else:
                            body = {
                                "message": "Action 'rerun' can only be invoked when state is ABORTED, UNEXPECT or FINISHED."
                            }
                            self.set_status(409)
                            return self.finish(body)
                    body = {"message": "Action can't be invoked because state is not match with the requirement."}
                    self.set_status(409)
                    self.finish(body)
            else:
                if attr_updated:
                    self.set_status(204)
                    self.finish()
                else:
                    self.set_status(400)
                    self.finish()
        else:
            self.set_status(404)
            self.finish()

    def delete(self, ident):
        # TODO: abort the execution first, then delete it.
        count = self.db.query(TestExecution).filter_by(id=ident).delete()
        self.db.commit()
        if count:
            self.set_status(204)
        else:
            self.set_status(404)


class TestHierarchyResource(BaseResource):
    def get(self):
        try:
            url = self.get_query_argument("url")
            type = self.get_query_argument("type", default="svn")
            username = self.get_query_argument("username", default=None)
            password = self.get_query_argument("password", default=None)
        except web.MissingArgumentError:
            self.set_status(400)
        else:
            client = pysvn.Client()
            client.exception_style = 1
            # _ indicate: (realm, username, may_save)
            client.callback_get_login = lambda _: (True, username, password, True)

            if not client.is_url(url):
                self.set_status(404)
                return self.finish()

            location = None
            for child in os.listdir(common.CASE_DIR):
                path = os.path.join(common.CASE_DIR, child)
                try:
                    entry = client.info(path)
                    logger.debug("Path %s svn info: %s", path, entry)
                except pysvn.ClientError:
                    continue
                else:
                    if entry is not None and entry.url == url:
                        location = path
                        break

            try:
                if location:
                    server_revision = client.revpropget("revision", url=url)[0].number
                    native_revision = client.info(location).revision
                    if server_revision > native_revision:
                        logger.info("server revision %s is greater than native revision %s, do update.",
                                    server_revision, native_revision)
                        client.update(location)
                else:
                    repo = url.rpartition("/")[2]
                    location = os.path.join(common.CASE_DIR, repo)
                    client.checkout(url, location)
                relative_path = os.path.relpath(location, common.CASE_DIR)
                hierarchy = generate_hierarchy_from_module('cases.%s' % relative_path.replace(os.path.sep, "."))
                self.finish(hierarchy)
            except (pysvn.ClientError, ImportError) as err:
                logger.exception("")
                self.set_status(500)
                self.finish({"message": str(err)})


class CleanupWorker(threading.Thread):
    __instance = None
    __lock = threading.Lock()

    @classmethod
    def instance(cls, *args, **kwargs):
        if cls.__instance is None:
            with cls.__lock:
                if cls.__instance is None:
                    cls.__instance = cls(*args, **kwargs)
        return cls.__instance

    def __init__(self, scoped_session, days_ago, interval):
        super(CleanupWorker, self).__init__()
        self.days_ago = days_ago
        self.interval = interval
        self.scoped_session = scoped_session
        self.__should_stop = threading.Event()

    @contextmanager
    def session(self):
        try:
            yield self.scoped_session
        finally:
            self.scoped_session.remove()

    def run_once(self):
        logger.info("*** Cleanup TestExecution Task Begin ***")
        logger.info("days_ago: %d", self.days_ago)
        logger.info("interval: %d", self.interval)
        current = datetime.datetime.utcnow()
        thirty_days_ago = current - datetime.timedelta(days=self.days_ago)
        with self.session() as session:
            query = session.query(TestExecution).filter(TestExecution.local_creation_datetime < thirty_days_ago)
            count = query.delete()
            logger.info("remove %d rows.", count)
            session.commit()
        logger.info("*** Cleanup TestExecution Task Finish ***")

    def run(self):
        self.__should_stop.clear()
        while True:
            self.run_once()
            is_set = self.__should_stop.wait(self.interval)
            if is_set:
                break

    def stop(self, wait=True):
        self.__should_stop.set()
        if wait:
            logger.debug("Waiting for CleanupWorker join().")
            self.join()
        logger.info("CleanupWorker exit successfully.")


class ExecuteWorker(object):
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def instance(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(*args, **kwargs)
        return cls._instance

    def __init__(self,
                 scoped_session,
                 amqp_url, exchange_name, exchange_type, routing_key_pattern,
                 recover, interval,
                 listeners=None):
        super(ExecuteWorker, self).__init__()
        self.scoped_session = scoped_session
        self.listeners = listeners or []
        self.interval = interval
        self.recover = recover
        self._runners = {}
        self._benches = {}

        self._stop_sync = threading.Event()
        self._stop_exec = threading.Event()
        self._state_queue = multiprocessing.JoinableQueue()

        self._amqp_conn = kombu.Connection(amqp_url)
        exchange = kombu.Exchange(exchange_name, exchange_type, channel=self._amqp_conn, durable=True)
        exchange.declare()
        self._amqp_producer = self._amqp_conn.Producer(exchange=exchange, auto_declare=False)
        self._amqp_routing_key_pattern = routing_key_pattern
        self._sync_thread = threading.Thread(target=self.__sync_thread_run)
        self._exec_thread = threading.Thread(target=self.__exec_thread_run)

    @contextmanager
    def session(self):
        try:
            yield self.scoped_session
        finally:
            self.scoped_session.remove()

    def add_testfixture(self, fixture):
        self._benches[fixture.name] = fixture

    def __recover(self):
        """
        All testfixtures' state will set to idle when initialize, so don't check the IDLE state when recovering.
        Assign testexecution with rsrcname first.
        """
        state_in = TestExecution.state.in_([TestExecution.State.SUBMITTED,
                                            TestExecution.State.ASSIGNED,
                                            TestExecution.State.INITIAL,
                                            TestExecution.State.RUNNING,
                                            TestExecution.State.SUSPEND])
        conditions = (state_in,)
        self.__assign(conditions)

    def __assign(self, conditions):
        """
        # For each TestExecution with state is null,
        #   * if rsrcname is None, new ProcessTestRunner directly. This is for tests not require a TestFixture.
        #   * if rsrcname is not None, assign TestFixture to the TestExecution only when TestFixture is IDLE.
        """
        with self.session() as session:
            for execution in session.query(TestExecution).filter(*conditions).order_by(TestExecution.priority).all():
                logger.info("Assign %s", execution)
                rsrcname = execution.rsrcname
                if rsrcname is None:
                    logger.info("Assign %s -> TestFixture: None", execution)
                    self.__new_testrunner(execution)
                else:
                    bench = session.query(TestFixture) \
                        .filter(TestFixture.state == BaseTestFixture.State.IDLE, TestFixture.name == rsrcname) \
                        .one_or_none()
                    if bench is None:
                        logger.warn("Can't find IDLE testfixture with name %s ", rsrcname)
                    else:
                        logger.info("Assign %s -> TestFixture: %s", execution, bench)
                        self.__new_testrunner(execution, self._benches[rsrcname])
                        bench.state = BaseTestFixture.State.BUSY.value
                session.commit()
        logger.info("Current live runners: %s", list(self._runners.values()))

    def __new_testrunner(self, execution, fixture=None):
        context = TestContext()
        if fixture:
            context.fixture = fixture
        runner = ProcessTestRunner(execution.id, execution.failfast, context, state_queue=self._state_queue)
        with self._lock:
            self._runners[execution.id] = runner
        log_dir = os.path.join(common.LOG_DIR, "%s_r%d" % (time.strftime("%Y-%m-%d_%H-%M-%S"), execution.id))
        listeners = []
        listeners.extend(self.listeners)
        listeners.append(TestRunnerLogFileInterceptor(log_dir))
        listeners.append(TestCaseLogFileInterceptor(log_dir))
        listeners.append(TestResultShelveInterceptor(os.path.join(log_dir, "result.shelve")))
        logger.debug(listeners)
        for listener in listeners:
            logger.debug("%s add context listener: %s", runner, listener)
            context.add_listener(listener)

        for testsuite in execution.testsuites:
            runner.add_testsuite(testsuite)
        runner.start()
        execution.state = TestExecution.State.ASSIGNED
        execution.start_datetime = datetime.datetime.utcnow()

    def __sync_thread_run(self):
        while True:
            try:
                data = self._state_queue.get_nowait()
            except queues.Empty:
                pass
            else:
                logger.debug("RECV TestRunner state: {}".format(data))

                s = json.dumps(data, cls=ComplexJsonEncoder)

                self._amqp_producer.publish(
                    s,
                    routing_key=self._amqp_routing_key_pattern.format(node=uuid.getnode(), id=data["id"]),
                    retry=True,
                    delivery_mode=2,
                    content_type="application/json",
                    content_encoding="utf-8"
                )

                with self._lock, self.session() as session:
                    ident = data["id"]
                    state = data["state"]
                    runner = self._runners.get(ident)
                    if runner is not None:
                        stop_datetime = None
                        if state in (runner.State.ABORTED, runner.State.UNEXPECT, runner.State.FINISHED):
                            stop_datetime = datetime.datetime.utcnow()
                            bench = session.query(TestFixture) \
                                .join(TestExecution, TestFixture.name == TestExecution.rsrcname) \
                                .filter(TestExecution.id == ident).one()
                            bench.state = BaseTestFixture.State.IDLE.value
                            del self._runners[ident]
                            runner.join()
                            logger.debug("%s is stopped, remove and join it.", runner)

                        stmt = TestExecution.__table__ \
                            .update() \
                            .where(TestExecution.id == ident) \
                            .values(state=state, stop_datetime=stop_datetime)
                        session.execute(stmt)
                        session.commit()
                self._state_queue.task_done()
            finally:
                if self._stop_sync.wait(0.1):
                    break

    def __exec_thread_run(self):
        while True:
            self.__assign((TestExecution.state == TestExecution.State.ASSIGNED, ))
            if self._stop_exec.wait(self.interval):
                break

    def run(self):
        if self.recover:
            self.__recover()

        self._stop_sync.clear()
        self._stop_exec.clear()
        self._sync_thread.start()
        self._exec_thread.start()

    def start(self):
        self.run()

    def invoke(self, testexecution_id, action):
        with self._lock:
            runner = self._runners.get(testexecution_id)
            if runner:
                try:
                    getattr(runner, action)()
                    return True
                except runner.PipeCallError as err:
                    logger.error(str(err))
            return False

    def stop(self):
        self._stop_exec.set()
        self._exec_thread.join()

        with self._lock:
            for runner in self._runners.values():
                logger.debug("Abort %s.", runner)
                try:
                    runner.abort()
                except runner.PipeCallError as err:
                    logger.error(str(err))
                finally:
                    runner.join()
        self._state_queue.join()
        self._stop_sync.set()
        self._sync_thread.join()
        self._amqp_conn.close()
        logger.info("ExecuteWorker exit successfully.")


class ResSetting(object):
    def __init__(self, filename):
        self.__filename = filename
        tree = etree.parse(self.__filename)
        self.__root = tree.getroot()

    def get_all_testfixtures(self):
        benches = []
        for benchelement in list(self.__root.find("testfixtures")):
            bench = TestFixtureFactory.build_testfixture_by_element(benchelement)
            benches.append(bench)
        return benches

    def get_testfixture_by_name(self, name):
        xpath = "./testfixtures/testfixture[@name='%s']" % name
        fixture_element = self.__root.find(xpath)
        if fixture_element is None:
            raise ValueError("Can't get TestFixture element by path: %s" % xpath)
        return TestFixtureFactory.build_testfixture_by_element(fixture_element)


class SrvSetting(XmlSetting):
    def __init__(self, xml):
        super(SrvSetting, self).__init__(xml)
        for element in list(self._tree.xpath("/testagent/definitions")[0]):
            name, value = self._parse_buildin_type_element(element)
            self._container[name] = value

    def get_listeners(self):
        listeners = []
        for element in self._tree.xpath("//execute-worker/listeners/listener"):
            args = []
            kwargs = {}
            for arg_element in element.findall("constructor-arg"):
                name = arg_element.get("name")
                value = self._parse_value(arg_element)
                if name:
                    kwargs[name] = value
                else:
                    args.append(value)

            cls = pydoc.locate(element.get("class"))
            obj = cls(*args, **kwargs)
            listeners.append(obj)
        return listeners


class Application(web.Application):
    def __init__(self, scoped_session):
        self.scoped_session = scoped_session
        handlers = [
            (r"/api/rest/testfixtures", TestFixtureListResource),
            (r"/api/rest/testexecutions", TestExecutionListResource),
            (r"/api/rest/testexecutions/([0-9]+)", TestExecutionDetailResource),
            (r"/api/rest/testhierarchy/?", TestHierarchyResource),
        ]
        web.Application.__init__(self, handlers)


class TestAgent(object):
    def __init__(self):
        self.srv_setting = SrvSetting(os.path.join(common.CFG_DIR, "srvconf.xml"))
        self.res_setting = ResSetting(os.path.join(common.CFG_DIR, "resconf.xml"))
        self.engine = sqlalchemy.create_engine(self.srv_setting.get("//sqlalchemy/@url"))
        self.webapp = Application(self._create_scoped_session())

        self.execute_worker = ExecuteWorker.instance(
            self._create_scoped_session(),
            self.srv_setting.get("//execute-worker/@amqp_url"),
            self.srv_setting.get("//execute-worker/@exchange_name", "ngta.runner.topic"),
            self.srv_setting.get("//execute-worker/@exchange_type", "topic"),
            self.srv_setting.get("//execute-worker/@routing_key_pattern", "%(node)s.execution.%(id)s"),
            self.srv_setting.get_boolean("//execute-worker/@recover", True),
            self.srv_setting.get_float("//execute-worker/@interval", 5),
            self.srv_setting.get_listeners(),
        )

        self.cleanup_worker = CleanupWorker.instance(
            self._create_scoped_session(),
            self.srv_setting.get_integer("//cleanup-worker/@days_ago", 30),
            self.srv_setting.get_float("//cleanup-worker/@interval", 86400),
        )
        self.exiting = False

    def init_db(self):
        BaseModel.metadata.create_all(self.engine)

    def drop_db(self):
        BaseModel.metadata.drop_all(self.engine)

    def _create_scoped_session(self):
        """
        Session = scoped_session(some_factory)
        print(Session.query(MyClass).all())

        # equivalent to:
        #
        # session = Session()
        # print(session.query(MyClass).all())
        """
        return sqlalchemy.orm.scoped_session(sqlalchemy.orm.sessionmaker(bind=self.engine))

    def startup(self):
        self.init_db()

        session = self._create_scoped_session()
        try:
            logger.info("DELETE all TestFixtures in database.")
            session.query(TestFixture).delete()
            objects = []
            benches = self.res_setting.get_all_testfixtures()
            for bench in benches:
                self.execute_worker.add_testfixture(bench)
                objects.append(TestFixture(bench.name))
            logger.info("INSERT TestFixtures: %s", objects)
            session.bulk_save_objects(objects)
            session.commit()
        finally:
            session.remove()

        self.webapp.listen(port=self.srv_setting.get_integer("//webapp/listen/@port"),
                           address=self.srv_setting.get("//webapp/listen/@host"))

        self.cleanup_worker.start()
        self.execute_worker.start()

        import signal
        signal.signal(signal.SIGINT, self._sigint_handler)
        ioloop.PeriodicCallback(self._try_exit, 100).start()
        # ioloop.PeriodicCallback(self.cleanup_worker.run_once, self.cleanup_worker.interval*1000).start()
        # ioloop.PeriodicCallback(self.execute_worker.run_once, self.execute_worker.interval*1000).start()
        ioloop.IOLoop.current().start()

    def shutdown(self):
        ioloop.IOLoop.current().stop()
        self.cleanup_worker.stop()
        self.execute_worker.stop()
        logging.info('TestAgent exit success!')

    def _try_exit(self):
        if self.exiting:
            self.shutdown()

    def _sigint_handler(self, signum, frame):
        logging.info("Receive SIGINT(%d), exiting...", signum)
        self.exiting = True


def main():
    logconf = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': DEFAULT_LOG_LAYOUT
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': 'verbose'
            },
            'file_srv': {
                'class': 'logging.handlers.RotatingFileHandler',  # must set subprocess.Popen(close_fds=True)
                'level': 'DEBUG',
                'formatter': 'verbose',
                'filename': os.path.join(common.LOG_DIR, "srv.log"),
                'maxBytes': 50000000,
                'backupCount': 10,
            },
            'file_sqlalchemy': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': 'INFO',
                'formatter': 'verbose',
                'filename': os.path.join(common.LOG_DIR, "sqlalchemy.log"),
                'maxBytes': 50000000,
                'backupCount': 10,
            }
        },
        'loggers': {
            'sqlalchemy': {
                'level': 'DEBUG',
                'propagate': False,
                'handlers': ['file_sqlalchemy'],
            }
        },
        'root': {
            'level': 'DEBUG',
            'handlers': ['console', 'file_srv'],
        }
    }
    logging.config.dictConfig(logconf)
    agent = TestAgent()
    agent.startup()

if __name__ == '__main__':
    main()
