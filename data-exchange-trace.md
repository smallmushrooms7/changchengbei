# 统一数据交换平台 —— 任务4：实际实施植入的来源溯源 Writeup

## 一、题目信息

| 项目 | 内容 |
| --- | --- |
| 容器地址 | `https://eci-2zeaozfkj6lfb1nlkdtv.cloudeci1.ichunqiu.com:80` |
| SSH 地址 | `101.200.36.33:36889`，账号 `admin` / 密码 `6IWU1Pen` |
| 任务要求 | 给出实际实施植入操作的来源 IP 与最早一次植入的时间 |
| 提交格式 | `flag{[来源IP]_[YYYYMMDD-HHMMSS]}` |

## 二、结论（Flag）

```
flag{198.51.100.23_20260812-040311}
```

- **来源 IP**：`198.51.100.23`
- **最早植入时间**：`2026-08-12 04:03:11 (+0800)`

## 三、环境侦察

1. Web 应用「统一数据交换平台」，技术栈：
   - Spring Boot `2.7.18` / Tomcat `9.0.83` / Java `1.8.0_402`
   - fastjson `1.2.83`（存在 autoType 绕过反序列化漏洞）
   - 主程序：`/opt/app/exchange-platform.jar`（8080 端口）
   - nginx 反向代理 `80` 端口 → 后端 `8080`

2. 关键端点：
   - `/api/parse` — 报文解析接口（GET `?msg=` / POST 报文体）
   - `/admin/login` — 管理后台登录
   - `/admin/notices` — 公告接口
   - `/debug.html` — 接口联调（冒烟测试入口）

3. SSH 登录后确认：
   - 当前用户 `admin`，sudo 特权仅限 4 个自定义工具（NOPASSWD）：
     - `/usr/local/bin/exdb`
     - `/usr/local/bin/rootcron`
     - `/usr/local/bin/rootrc`
     - `/usr/sbin/userdel`
   - 服务器时区 UTC，但攻击回溯日志（8 月）时区为 `+0800`

## 四、攻击链还原（核心：`/var/log/nginx/access.log`）

本题为 **Fastjson 反序列化 RCE 植入内存马** 的应急响应题。完整时序如下（均为 `2026-08-12`，`+0800` 时区）：

| 时间 | 来源 IP | 行为 |
| --- | --- | --- |
| 03:37–03:42 | `203.0.113.7` | sqlmap 目录扫描（全 404） |
| 03:42:17 | `203.0.113.7` | fastjson `@type` 探测：`http://3405803783:31337/probe`（`3405803783` = `203.0.113.7`） |
| 03:43:04–34 | `203.0.113.7` | sqlmap 对 `/api/parse` 的 SQLi 尝试（500） |
| 03:45:34 | `203.0.113.7` | `@type` `java.net.Inet4Address`（DNS 外带） |
| 03:48:46 | `203.0.113.7` | `@type` `JndiConverter` + `ldap://x`（JNDI） |
| 03:50:44 | `203.0.113.7` | `@type` `java.lang.Class` + `JdbcRowSetImpl`（探测） |
| 03:51:52 | `203.0.113.7` | `@type` `http://0x7f000001:31337/probe`（`0x7f000001` = `127.0.0.1`） |
| **04:03:11** | **`198.51.100.23`** | **★ 植入：`TemplatesImpl` + `_bytecodes`，`_name="metrics"` → 注册内存马** |
| 04:11:33 | `198.51.100.23` | 重复投递同一植入载荷（二次植入） |
| 04:16:33–44 | `198.51.100.23` | `/admin/login` + `/admin/notices`（植入后利用） |
| 04:17:57 | `198.51.100.23` | `POST /api/v2/health` |
| 04:20:33 | `198.51.100.23` | `POST /api/parse` |

## 五、植入物确认（内存马 `MetricFilter`）

1. 植入载荷（`GET /api/parse` 中的 `msg`，URL 解码后）：

```json
{
  "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  "_bytecodes": ["yv66vgAA...QAc="],
  "_name": "metrics",
  "_tfactory": {},
  "_outputProperties": {}
}
```

- `_bytecodes` 以 `yv66vgAA` 开头（`0xCAFEBABE`，Java class 文件魔数）
- 该字段在日志中被题目作者截断（`...QAc=`），无法还原完整字节码

2. 植入结果：内存马类 `com.ms.shell.MetricFilter`

   `/var/log/app.log` 异常堆栈中出现：

   ```
   at com.ms.shell.MetricFilter.doFilter(MetricFilter.java:46)
   ```

   经 `unzip -l` 检查 `exchange-platform.jar`，jar 内 **不存在** `com/ms/shell/MetricFilter` 类，说明它是通过 fastjson 反序列化动态注入的 **Filter 型内存马**（Tomcat Filter 内存 webshell）。

## 六、溯源判定依据

1. 唯一携带 `TemplatesImpl` 字节码（`_bytecodes`）的载荷只来自 `198.51.100.23`；全量 grep 关键词（`@type` / `ldap` / `rmi` / `TemplatesImpl` / `_bytecodes` / `JdbcRowSetImpl` / `JndiConverter` / `Inet4Address` 等）仅命中 `203.0.113.7` 与 `198.51.100.23` 两个 IP。

2. `203.0.113.7` 全程只做「探测 / 回连测试」，从未投递字节码，属于漏洞侦察阶段，不是"实际实施植入"。

3. 内网 IP（`10.0.2.15` / `10.0.2.31` / `10.0.3.21` / `10.0.4.7` / `172.16.8.44` / `172.16.8.9` / `172.16.9.12`）各约 3000 条请求，均为正常业务流量（`POST /api/parse`、`/api/order/query`、`/api/report/summary`、`/api/heartbeat` 等），无植入行为。

4. `wtmp` / `btmp` / `~/.ssh/authorized_keys` 均无攻击者 SSH 痕迹，说明植入纯走 Web 入口，无 SSH 层面的后门。

5. 最早植入时间 = 第一次投递 `TemplatesImpl` 载荷的时刻：`2026-08-12 04:03:11`（日志字面值，`+0800`）。

## 七、Flag

```
flag{198.51.100.23_20260812-040311}
```

## 八、附注

- 题目遗留的提权路径（供后续任务参考，非本题考点）：
  - `sudo /usr/local/bin/rootcron` → 查看/替换 root crontab（当前 crontab：`0 3 * * * /usr/local/bin/backup.sh`）
  - `sudo /usr/local/bin/rootrc` → 查看/替换 `/etc/rc.local`
  - `sudo /usr/local/bin/exdb` → 以 root 执行 mysql SQL（`exchange` 库）
  - `/etc/rc.local` 中已发现 `flag2` / `flag3`（对应其他任务）
