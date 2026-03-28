# 角色卡广场 — 用户系统 & 积分迁移 技术架构设计

> 目标：为现有 Express.js + better-sqlite3 + Vue 3 论坛添加用户注册/登录、服务端积分、评论点赞、热评系统。

---

## 1. 数据库变更

### 1.1 新建表

```sql
-- 用户表（与 admin_users 完全独立）
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    download_credits INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 评论点赞表（每用户每评论只能点赞一次）
CREATE TABLE IF NOT EXISTS comment_likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES character_comments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(comment_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_comment_likes_comment_id ON comment_likes(comment_id);
CREATE INDEX IF NOT EXISTS idx_comment_likes_user_id ON comment_likes(user_id);

-- 积分变动日志（可审计，非必须但建议）
CREATE TABLE IF NOT EXISTS credit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    reason TEXT NOT NULL,
    ref_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credit_logs_user_id ON credit_logs(user_id);
```

### 1.2 ALTER 现有表

```sql
-- character_comments 增加 user_id 列（可为 NULL，兼容匿名历史评论）
ALTER TABLE character_comments ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

-- character_cards 增加 uploader_user_id 列（可为 NULL，兼容匿名历史上传）
ALTER TABLE character_cards ADD COLUMN uploader_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
```

> **注意**：SQLite 的 `ALTER TABLE ADD COLUMN` 不支持添加带 NOT NULL 约束且无默认值的列，所以这里都用可为 NULL。`initDatabase()` 中用 `try-catch` 包裹 ALTER 语句，若列已存在则忽略错误。

### 1.3 initDatabase() 中的迁移逻辑

```js
// 在 initDatabase() 末尾追加：
// 安全地添加新列（如果已存在则捕获错误忽略）
const safeAlter = (sql) => {
    try { db.exec(sql); } catch (e) {
        if (!e.message.includes('duplicate column')) throw e;
    }
};
safeAlter('ALTER TABLE character_comments ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL');
safeAlter('ALTER TABLE character_cards ADD COLUMN uploader_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL');
```

---

## 2. JWT 双令牌方案

| 属性 | Admin Token | User Token |
|------|-------------|------------|
| localStorage key | `admin_token` | `user_token` |
| JWT payload | `{ id, username, role: 'admin' }` | `{ id, username, role: 'user' }` |
| JWT_SECRET | 共用同一个 `JWT_SECRET` | 同左 |
| 过期时间 | 24h | 7d（普通用户更长驻留） |
| 中间件 | `authenticateAdmin` (不变) | `authenticateUser` (新增) |

### 2.1 新增中间件

```js
// 生成用户 token
function generateUserToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: 'user' },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

// 认证用户（必须登录）
function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'user') {
            return res.status(403).json({ error: '权限不足' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: '令牌无效或已过期' });
    }
}

// 可选认证（不强制登录，但如果有 token 就解析）
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'user') {
                req.user = decoded;
            } else if (decoded.role === 'admin') {
                req.admin = decoded;
            }
        } catch (e) { /* token 无效则忽略 */ }
    }
    next();
}
```

### 2.2 authenticateAdmin 保持不变

现有的 `authenticateAdmin` 中间件完全不动。管理员登录端点 `POST /api/auth/login` 也不动（它只查 `admin_users` 表）。

---

## 3. 新增 API 端点

### 3.1 用户注册

```
POST /api/user/register
Auth: 无
Rate-limit: 独立限流 (5 req / 15min / IP)
```

**Request:**
```json
{ "username": "foo", "password": "bar123" }
```

**验证规则:**
- `username`: 2-20 字符，只允许字母数字下划线中文，`COLLATE NOCASE` 不区分大小写
- `password`: 6-50 字符
- 用户名不能与 `admin_users` 中的用户名重复（防止混淆）

**逻辑:**
1. 校验输入
2. 检查 `users` 表和 `admin_users` 表用户名是否已存在
3. `bcrypt.hashSync(password, 12)`
4. INSERT 到 `users` 表（`download_credits` 默认 1，即注册送 1 积分）
5. 写入 `credit_logs` (amount: +1, reason: 'register')
6. 生成 JWT token
7. 返回

**Response 200:**
```json
{
    "token": "eyJ...",
    "user": { "id": 1, "username": "foo", "download_credits": 1 }
}
```

**Response 409:**
```json
{ "error": "用户名已被注册" }
```

### 3.2 用户登录

```
POST /api/user/login
Auth: 无
Rate-limit: 复用 loginLimiter
```

**Request:**
```json
{ "username": "foo", "password": "bar123" }
```

**逻辑:**
1. 校验输入
2. `checkBruteForce(ip, username)` — 复用现有防暴力破解
3. 从 `users` 表查询
4. `bcrypt.compareSync`
5. `recordLoginAttempt` 记录
6. 更新 `last_login`
7. 生成 `generateUserToken(user)`
8. 返回

**Response 200:**
```json
{
    "token": "eyJ...",
    "user": { "id": 1, "username": "foo", "download_credits": 5 }
}
```

### 3.3 获取当前用户信息

```
GET /api/user/me
Auth: authenticateUser
```

**Response 200:**
```json
{
    "user": { "id": 1, "username": "foo", "download_credits": 5 }
}
```

> 前端用此端点在页面加载时验证 token 是否仍然有效，并同步最新积分。

### 3.4 评论点赞

```
POST /api/comments/:commentId/like
Auth: authenticateUser
```

**逻辑:**
1. 检查评论是否存在
2. 检查 `comment_likes` 中是否已存在 `(comment_id, user_id)` 组合
3. 如已赞，返回 409
4. 在事务中执行：
   - INSERT into `comment_likes`
   - 点赞者 `download_credits += 1`（`UPDATE users SET download_credits = download_credits + 1 WHERE id = ?`）
   - 写入 `credit_logs` (amount: +1, reason: 'like', ref_id: commentId)
5. 返回该评论最新点赞数和当前用户是否已赞

**Response 200:**
```json
{ "likes_count": 6, "user_liked": true, "download_credits": 8 }
```

**Response 409:**
```json
{ "error": "你已经点赞过了" }
```

### 3.5 取消点赞

```
DELETE /api/comments/:commentId/like
Auth: authenticateUser
```

**逻辑:**
1. 检查 `comment_likes` 是否存在
2. 如不存在，返回 404
3. 在事务中执行：
   - DELETE from `comment_likes`
   - 扣除积分 `download_credits = MAX(0, download_credits - 1)`
   - 写入 `credit_logs` (amount: -1, reason: 'unlike', ref_id: commentId)
4. 返回

**Response 200:**
```json
{ "likes_count": 5, "user_liked": false, "download_credits": 7 }
```

### 3.6 获取用户积分

```
GET /api/user/credits
Auth: authenticateUser
```

**Response 200:**
```json
{ "download_credits": 5 }
```

> 轻量端点，前端可定时或操作后轮询获取最新积分。

---

## 4. 修改现有 API 端点

### 4.1 `GET /api/cards/:cardId/comments` — 评论列表（增加点赞信息）

**变更：** 加入 `optionalAuth` 中间件

**新增返回字段:**
```json
[
    {
        "id": "uuid",
        "card_id": "uuid",
        "nickname": "张三",
        "user_id": 1,
        "content": "...",
        "created_at": "...",
        "likes_count": 6,
        "user_liked": false,
        "is_hot": true
    }
]
```

**SQL 变更:**

```sql
SELECT 
    c.*,
    COALESCE(lc.cnt, 0) AS likes_count,
    CASE WHEN ul.id IS NOT NULL THEN 1 ELSE 0 END AS user_liked
FROM character_comments c
LEFT JOIN (
    SELECT comment_id, COUNT(*) AS cnt FROM comment_likes GROUP BY comment_id
) lc ON lc.comment_id = c.id
LEFT JOIN comment_likes ul ON ul.comment_id = c.id AND ul.user_id = ?
WHERE c.card_id = ?
ORDER BY c.created_at ASC
```

- `?` user_id 参数：如果 `req.user` 存在就用 `req.user.id`，否则用 `NULL`（`user_liked` 将全为 0）

**热评标记逻辑（在应用层计算）:**
```js
// 查询到 comments 后：
const maxLikes = Math.max(...comments.map(c => c.likes_count), 0);
comments.forEach(c => {
    c.is_hot = (c.likes_count >= 5 && c.likes_count === maxLikes);
});
```

### 4.2 `POST /api/cards/:cardId/comments` — 发表评论（关联用户 + 积分）

**变更：** 加入 `optionalAuth` 中间件

**逻辑变化:**
1. 新增校验：如果用户已登录（`req.user` 存在），`content.trim().length` 必须 >= 5 才给积分
2. INSERT 时：
   - 如果已登录：`nickname` 用 `req.user.username`，`user_id` 用 `req.user.id`
   - 如果未登录：保持原来的匿名逻辑（`nickname` 来自 body，`user_id` 为 NULL）
3. 如果已登录且内容长度 >= 5 字符：
   - `UPDATE users SET download_credits = download_credits + 2 WHERE id = ?`
   - 写入 `credit_logs` (amount: +2, reason: 'comment', ref_id: commentId)
4. 返回时额外返回 `download_credits`（如果已登录）

**Request:**
```json
{ "content": "这个角色太棒了！" }
```

**Response 200:**
```json
[{
    "id": "uuid",
    "card_id": "uuid",
    "nickname": "foo",
    "user_id": 1,
    "content": "这个角色太棒了！",
    "created_at": "...",
    "likes_count": 0,
    "user_liked": false,
    "download_credits": 7
}]
```

### 4.3 `POST /api/cards/:id/download` — 下载（积分扣除）

**变更：** 加入 `optionalAuth` 中间件

**逻辑变化:**
1. 下载计数递增（保持不变）
2. 如果 `req.user` 存在（普通用户已登录）：
   - 查询 card 的 `uploader_user_id`
   - 如果 `uploader_user_id === req.user.id`（自己的卡），**不扣积分**
   - 否则检查 `download_credits > 0`，不足则返回 403
   - `UPDATE users SET download_credits = MAX(0, download_credits - 1) WHERE id = ?`
   - 写入 `credit_logs` (amount: -1, reason: 'download', ref_id: cardId)
3. 如果 `req.admin` 存在（管理员），**不扣积分**
4. 如果未登录，按原逻辑不处理积分（仍由前端 localStorage 降级控制，或后续可禁止未登录下载）
5. 返回 `download_credits`

**Response 200:**
```json
{ "success": true, "download_credits": 4 }
```

**Response 403:**
```json
{ "error": "积分不足，无法下载" }
```

### 4.4 `POST /api/cards` — 上传卡片（关联上传者）

**变更：** 加入 `optionalAuth` 中间件

**逻辑变化:**  
INSERT 时，如果 `req.user` 存在，将 `uploader_user_id` 设为 `req.user.id`。

### 4.5 `GET /api/admin/stats` — 管理后台统计

**新增返回字段:**
```json
{
    "totalUsers": 42,
    ...existing fields...
}
```

---

## 5. 完整端点清单

| 方法 | 路径 | 中间件 | 说明 |
|------|------|--------|------|
| `POST` | `/api/user/register` | rate-limit | 用户注册 |
| `POST` | `/api/user/login` | loginLimiter | 用户登录 |
| `GET` | `/api/user/me` | `authenticateUser` | 获取当前用户信息+积分 |
| `GET` | `/api/user/credits` | `authenticateUser` | 仅获取积分 |
| `POST` | `/api/comments/:commentId/like` | `authenticateUser` | 点赞 |
| `DELETE` | `/api/comments/:commentId/like` | `authenticateUser` | 取消点赞 |
| `GET` | `/api/cards` | 无 | 卡片列表（不变） |
| `POST` | `/api/cards` | `optionalAuth` | 上传卡片 (**改**) |
| `GET` | `/api/cards/:cardId/comments` | `optionalAuth` | 评论列表 (**改**) |
| `POST` | `/api/cards/:cardId/comments` | `optionalAuth` | 发评论 (**改**) |
| `POST` | `/api/cards/:id/download` | `optionalAuth` | 下载 (**改**) |
| `DELETE` | `/api/cards/:id` | `authenticateAdmin` | 删卡 (不变) |
| `PUT` | `/api/cards/:id` | `authenticateAdmin` | 改卡时间 (不变) |
| `POST` | `/api/auth/login` | loginLimiter | 管理员登录 (不变) |
| `GET` | `/api/auth/me` | `authenticateAdmin` | 管理员信息 (不变) |
| 所有 `/api/admin/*` | | `authenticateAdmin` | 管理后台 (不变) |

---

## 6. 积分规则汇总

| 操作 | 积分变动 | 条件 | reason 标识 |
|------|----------|------|-------------|
| 注册 | +1 | 自动（DEFAULT 1） | `register` |
| 发表评论 | +2 | 已登录且内容 >= 5 字符 | `comment` |
| 点赞评论 | +1 | 已登录 | `like` |
| 取消点赞 | -1 | 已登录，积分最低为 0 | `unlike` |
| 下载卡片 | -1 | 已登录，非自己的卡，非管理员 | `download` |

**硬约束：** `download_credits` 永远 >= 0。扣除时使用：
```sql
UPDATE users SET download_credits = MAX(0, download_credits - 1) WHERE id = ? AND download_credits > 0
```
检查 `changes === 0` 来判断是否扣除成功（如果原先就是 0，则 `changes` 为 0 → 积分不足）。

---

## 7. 前端状态变更 (Vue 3 Composition API)

### 7.1 新增响应式变量

```js
// ---- 用户认证 ----
const userToken = ref(localStorage.getItem('user_token') || '');
const currentUser = ref(null);      // { id, username, download_credits }
const isLoggedIn = computed(() => !!currentUser.value);

// ---- 用户登录/注册弹窗 ----
const showUserAuth = ref(false);     // 控制弹窗显隐
const authMode = ref('login');        // 'login' | 'register'
const userAuthForm = reactive({ username: '', password: '' });
const userAuthError = ref('');

// ---- 评论点赞 ----
// comments 数组中每个对象新增字段：likes_count, user_liked, is_hot
// 无需单独变量，跟随 comments ref
```

### 7.2 修改现有变量

```js
// downloadCredits 不再从 localStorage 读取
// 改为从 currentUser.download_credits 读取
const downloadCredits = computed(() => currentUser.value?.download_credits ?? 0);
// 删除: localStorage.getItem('download_credits')
```

### 7.3 新增方法

```js
// 用户认证 headers
const userAuthHeaders = () => ({
    'Authorization': 'Bearer ' + userToken.value,
    'Content-Type': 'application/json'
});

// 页面加载时检查用户 token
const checkUserToken = async () => {
    if (!userToken.value) return;
    try {
        const resp = await fetch(API_BASE + '/api/user/me', {
            headers: { 'Authorization': 'Bearer ' + userToken.value }
        });
        if (resp.ok) {
            const data = await resp.json();
            currentUser.value = data.user;
        } else {
            userToken.value = '';
            localStorage.removeItem('user_token');
        }
    } catch (e) {
        userToken.value = '';
        localStorage.removeItem('user_token');
    }
};

// 用户注册
const handleUserRegister = async () => { ... };

// 用户登录
const handleUserLogin = async () => { ... };

// 用户登出
const handleUserLogout = () => {
    userToken.value = '';
    currentUser.value = null;
    localStorage.removeItem('user_token');
};

// 同步积分（在操作后调用）
const syncCredits = (newCredits) => {
    if (currentUser.value) {
        currentUser.value.download_credits = newCredits;
    }
};

// 点赞评论
const handleLikeComment = async (commentId) => {
    const resp = await fetch(API_BASE + `/api/comments/${commentId}/like`, {
        method: 'POST',
        headers: userAuthHeaders()
    });
    const data = await resp.json();
    if (resp.ok) {
        // 更新 comments 数组中该评论的 likes_count 和 user_liked
        const c = comments.value.find(c => c.id === commentId);
        if (c) { c.likes_count = data.likes_count; c.user_liked = data.user_liked; }
        syncCredits(data.download_credits);
        recalcHotComments();
    }
};

// 取消点赞
const handleUnlikeComment = async (commentId) => { /* 类似 */ };

// 重新计算热评标记
const recalcHotComments = () => {
    const maxLikes = Math.max(...comments.value.map(c => c.likes_count), 0);
    comments.value.forEach(c => {
        c.is_hot = (c.likes_count >= 5 && c.likes_count === maxLikes);
    });
};
```

### 7.4 修改现有方法

| 方法 | 变更 |
|------|------|
| `updateCredits()` | 删除。不再手动修改 localStorage，积分从 `currentUser.download_credits` 读取 |
| `handleUploadCard()` | 如已登录，携带 `Authorization` header；上传成功后无需 `saveMyCardId`（服务端通过 `uploader_user_id` 自动关联） |
| `handlePostComment()` | 如已登录，携带 `Authorization` header，不再手动传 `nickname`；从响应中取 `download_credits` 并 `syncCredits`；如未登录，保持原匿名逻辑 |
| `handleDownload()` | 如已登录，携带 `Authorization` header；积分检查由服务端返回 403 处理；从响应取 `download_credits` 并 `syncCredits`；如未登录 + 管理员，走原有本地逻辑（降级） |
| `loadComments()` | fetch 时如已登录携带 header；响应中含 `likes_count`, `user_liked`, `is_hot` |
| `onMounted` | 增加 `await checkUserToken()` |

### 7.5 新增 UI 组件要素

| 位置 | 组件 | 说明 |
|------|------|------|
| 顶栏右侧 | 用户按钮 | 未登录显示"登录/注册"按钮，已登录显示用户名+积分+登出 |
| 弹窗 | 登录/注册弹窗 | 切换 login/register 模式，表单含用户名+密码 |
| 评论区每条评论 | 点赞按钮+计数 | 心形/大拇指图标，已赞高亮，点击切换 |
| 评论区 | 热评标签 | `is_hot === true` 的评论显示 🔥 或"热评"标签 |
| "我的"Tab | 积分显示 | 从 `currentUser.download_credits` 读取，不再从 localStorage |

---

## 8. 完整 server.js 变更位置索引

```
server.js 修改清单:
├── 新增 generateUserToken()              # ~L58 附近
├── 新增 authenticateUser()               # ~L60 附近  
├── 新增 optionalAuth()                   # ~L75 附近
├── 新增 POST /api/user/register          # 新 section: User Auth Routes
├── 新增 POST /api/user/login             # 同上
├── 新增 GET  /api/user/me                # 同上
├── 新增 GET  /api/user/credits           # 同上
├── 新增 POST /api/comments/:id/like      # 新 section: Like Routes
├── 新增 DELETE /api/comments/:id/like    # 同上
├── 修改 GET  /api/cards/:cardId/comments # 加 optionalAuth + JOIN 点赞
├── 修改 POST /api/cards/:cardId/comments # 加 optionalAuth + 积分逻辑
├── 修改 POST /api/cards/:id/download     # 加 optionalAuth + 积分扣减
├── 修改 POST /api/cards                  # 加 optionalAuth + uploader_user_id
└── 修改 GET  /api/admin/stats            # 加 totalUsers
```

```
database.js 修改清单:
├── initDatabase() 中新增 3 个 CREATE TABLE
├── initDatabase() 中新增 ALTER TABLE (带 safeAlter)
└── 新增索引
```

---

## 9. 事务安全

所有涉及积分变动的操作**必须使用事务**：

```js
const likeTransaction = db.transaction((commentId, userId) => {
    // 1. INSERT comment_likes
    db.prepare('INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)').run(commentId, userId);
    // 2. 增加积分
    db.prepare('UPDATE users SET download_credits = download_credits + 1 WHERE id = ?').run(userId);
    // 3. 记录日志
    db.prepare('INSERT INTO credit_logs (user_id, amount, reason, ref_id) VALUES (?, 1, ?, ?)').run(userId, 'like', commentId);
    // 4. 查询最新数据
    const count = db.prepare('SELECT COUNT(*) as cnt FROM comment_likes WHERE comment_id = ?').get(commentId).cnt;
    const credits = db.prepare('SELECT download_credits FROM users WHERE id = ?').get(userId).download_credits;
    return { likes_count: count, download_credits: credits };
});
```

同理：`register`、`comment`（加积分部分）、`download`（扣积分部分）、`unlike` 都需要事务。

---

## 10. 安全检查清单

- [x] 密码使用 `bcrypt` 哈希 (cost=12)
- [x] 注册端点独立限流 (5 req/15min/IP)
- [x] 用户名检查 `COLLATE NOCASE` 防止大小写绕过
- [x] 用户名校验正则：`/^[\w\u4e00-\u9fff]{2,20}$/`
- [x] 用户表与管理员表独立，注册时检查不与 admin 用户名冲突
- [x] JWT role 字段严格校验：`authenticateUser` 只接受 `role: 'user'`
- [x] 点赞唯一约束 `UNIQUE(comment_id, user_id)` 数据库层面防重
- [x] 积分操作均在事务中执行
- [x] 积分下限校验：SQL 层面 `MAX(0, credits - 1)` + `changes` 校验
- [x] 评论 content 长度上限保持 5000 字
- [x] 所有用户输入服务端校验，不信任前端

---

## 11. 实施顺序建议

1. **Phase 1 — 数据库** → 修改 `database.js`，添加新表和 ALTER
2. **Phase 2 — 中间件** → 在 `server.js` 添加 `generateUserToken`, `authenticateUser`, `optionalAuth`
3. **Phase 3 — 用户 API** → 注册、登录、/me、/credits
4. **Phase 4 — 修改评论 API** → GET comments (带点赞)、POST comment (关联用户+积分)
5. **Phase 5 — 点赞 API** → POST/DELETE like
6. **Phase 6 — 修改下载 API** → 积分扣减逻辑
7. **Phase 7 — 修改上传 API** → 关联 uploader_user_id
8. **Phase 8 — 前端用户系统** → 登录/注册弹窗、token 管理、积分显示迁移
9. **Phase 9 — 前端评论点赞** → 点赞按钮、热评标签
10. **Phase 10 — 清理** → 移除 localStorage 中 `download_credits` 的旧逻辑
