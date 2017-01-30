## 本地执行
* 为每次执行在./logs目录下生成时间戳目录，用以存放日志、报告、数据库文件。
* 每个测试用例生成一个日志文件，并针对测试结果进行归类。
* 生html报告，可配置是否邮件发送报告。
* 生成本地shelve文件

#### 配置XML
TestFixture模式：


控制反转(IoC)模式：


---------------------------------------

### 作为Http服务器执行
* 由于GIL的限制，使用多进程来执行测试请求。
* 对测试资源进行管理，当有多个测试请求同一个资源时，按优先级进行分配。
* 每个用例的执行结果AMQP来进行回传（可配置）。
* 每个测试执行和测试用例的日志通过redis来进行存储（可配置）。
* 数据格式为JSON。
* TODO: 目前每次收到一个TestExecution测试请求，就为其分配一个进程和测试资源来执行用例。
后续考虑添加模式：当收到测试请求时（包含开启进程数、AMQP用例源），主动从RabbitMQ中获取用例并执行。

**支持的URL请求**
<table>
    <thead align="left">
        <tr>
            <th>URL</th>
            <th>METHOD</th>
            <th>解释</th>
        </tr>
    </thead>
    <tbody valign="top">
        <tr>
            <td>/api/rest/testfixtures</td>
            <td>GET</td>
            <td>返回所有testfixtures的名称和状态</td>
        </tr>
        <tr>
            <td>/api/rest/testexecutions</td>
            <td>GET</td>
            <td>返回所有testexecution的信息，可通过id和state查询参数指定范围。</td>
        </tr>
        <tr>
            <td>/api/rest/testexecutions</td>
            <td>POST</td>
            <td>添加testexecution</td>
        </tr>
        <tr>
            <td>/api/rest/testexecutions/(id)</td>
            <td>GET</td>
            <td>获取testexecution</td>
        </tr>
        <tr>
            <td>/api/rest/testexecutions/(id)</td>
            <td>PUT</td>
            <td>在testexecution还未执行时，更新testexecution。<br/>在执行时，支持action查询参数(pause, resume, abort)进行操作。</td>
        </tr>
        <tr>
            <td>/api/rest/testexecutions/(id)</td>
            <td>DELETE</td>
            <td>删除testexecution</td>
        </tr>
    </tbody>
</table>

JSON Schema when POST testexecution：
```
{
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
```

JSON Schema when PUT testexecution：
```
{
    "type": "object",
    "properties": {
        "priority": {"type": "integer"},
        "failfast": {"type": "boolean"},
        "rsrcname": {"type": ["string", "null"]},
        "testsuites": {"type": "array"}
    },
    "additionalProperties": False
}
```