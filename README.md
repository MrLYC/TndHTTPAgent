# TndHTTPAgent

一个特殊基于 Tornado 开发的特殊 HTTP 代理。通过客户端 POST 的请求数据来构造 HTTP 请求并返回目标服务器的结果。

## 快速启动

### 安装依赖

```shell
pip install -r requirements.txt
```



### 启动服务

```shell
python http_agent.py
```

服务默认监听在8080端口，打开一个新的终端，测试请求 http://localhost:8080/request：

```shell
curl -X POST -d '{"url": "http://www.timeapi.org/utc/now", "headers": {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"}}' -i http://localhost:8080/request
```

可以得到类似输出：

> HTTP/1.1 200 OK
> X-Xss-Protection: 1; mode=block
> Transfer-Encoding: chunked
> Server: thin 1.5.0 codename Knife
> Via: 1.1 vegur
> Date: Mon, 05 Sep 2016 14:59:13 GMT
> X-Frame-Options: sameorigin
> Content-Type: text/html;charset=utf-8
>
> 2016-09-05T15:59:13+01:00



## 程序介绍

### 工作原理

客户端按照约定格式 POST 数据到服务器，服务器根据参数组装成请求去请求指定的 url，并将 url 返回的内容进行流式返回。



### 启动参数

| 参数                | 含义                    | 示例                                    |
| ----------------- | --------------------- | ------------------------------------- |
| --curl-httpclient | 使用 curl 库，需要安装 pycurl |                                       |
| --debug           | 开启 debug 模式           |                                       |
| --interface-roles | interface 规则配置        | ctcc: 202.96.128.86,cucc:210.21.4.130 |
| --logpath         | 日志目录                  | /var/log/http_agent.log               |
| --port            | 监听端口                  | 8080                                  |

更多参数查看：

```shell
python http_agent.py --help
```



### 请求参数

| 参数                  | 含义                                       | 类型                  | 示例（加粗为默认）                                |
| ------------------- | ---------------------------------------- | ------------------- | ---------------------------------------- |
| url                 | 请求的 url                                  | string              | http://www.timeapi.org/utc/now           |
| method              | 请求的方法                                    | string              | **GET**                                  |
| version             | 请求格式版本                                   | string              | **chp v1**                               |
| timeout             | 请求超时时间（120秒内）                            | number/string       | **10**                                   |
| post_type           | post 请求的数据类型（form，json，string）           | string/null         | **string**                               |
| max_http_redirects  | 最大重定向次数（0-3次）                            | integer/null        | **0**                                    |
| proxies             | 请求代理设置                                   | object/null         | {"http": "proxy.example.com:1080"}       |
| headers             | 请求头设置                                    | object/null         | {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"} |
| data                | POST 请求内容（根据 post_type 自动转码）             | object/string/null  | {"value": "xx"}                          |
| verify_cert         | 是否校验证书                                   | boolean/string/null | **true**                                 |
| insecure_connection | 是否对 https 启用不安全连接（curl-httpclient 功能）    | boolean/string/null | **false**                                |
| role                | 指定使用的 interface 规则（和启动参数名称匹配，curl-httpclient 功能） | string/null         | ctcc                                     |



### 请求头部

#### 原请求

自动复制以下头：

- User-Agent
- Accept
- Accept-Encoding
- Referer

#### 请求参数头部

服务器并不会接受所有写在 `headers` 中的头部，只允许对原请求头的字段（以便重写），以 `X-` 开头自定义头部和以下头部：

- From
- Forwarded
- Accept-Datetime
- Accept-Charset
- Range
- Accept-Language
- If-Unmodified-Since
- Accept-Encoding
- Origin
- Accept
- User-Agent
- If-Range
- Host
- Referer
- If-Match
- If-Modified-Since
- Date
- If-None-Match
- Content-Type
- Expect

#### 额外头部

请求加上`X-Proxy-Agent` 头部来避免递归请求。



### 响应头部

服务器会移除以下响应头部：

- Transfer-Encoding
- Proxy-Authenticate
- Content-Length
- Connection
- Content-Encoding

