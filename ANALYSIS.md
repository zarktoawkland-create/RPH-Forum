# RPH-Forum (角色卡广场) 架构分析文档

> 分析日期：2026-04-06
> 项目版本：1.0.0

---

## 1. 项目概述

**RPH-Forum** 是一个自部署的角色卡分享论坛，支持 Docker 一键部署到 Zeabur。

### 核心功能
- 角色卡上传与分享（PNG/JSON 格式）
- 匿名评论系统
- 下载积分系统（上传赚积分，下载消耗积分）
- 管理员后台（Web 界面）
- 暴力破解防护（IP/账户级别登录限制）
- 内置 SQLite 数据库（无需外部数据库）

---

## 2. 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| **后端框架** | Express.js 4.18 | Node.js Web 框架 |
| **数据库** | better-sqlite3 11.7 | 同步 SQLite ORM，性能好 |
| **认证** | JWT (jsonwebtoken) | Token 过期时间：Admin 24h / User 7d |
| **密码加密** | bcryptjs | Cost 12 |
| **安全头** | Helmet 7.1 | 安全 HTTP 头 |
| **图片处理** | Sharp 0.34 | 可选，图片压缩 |
| **前端框架** | Vue 3 (CDN) | Composition API |
| **CSS 框架** | Tailwind CSS (CDN) |  |
| **Markdown** | Marked.js + DOMPurify | 评论渲染 |
| **压缩** | Compression | Gzip 压缩 |
| **Cookie** | cookie-parser |  |
| **容器化** | Docker + Zeabur | 一键部署 |

---

## 3. 项目结构

```
RPH-Forum/
├── server.js              # Express 服务器 (~700行)
├── database.js            # SQLite 数据库初始化 (~250行)
├── package.json           # 依赖配置
├── Dockerfile             # Docker 构建文件
├── zeabur.json            # Zeabur 部署模板
├── ARCHITECTURE.md        # 技术架构设计文档（未来功能规划）
├── public/
│   ├── index.html         # 论坛主页 (Vue 3)
│   ├── admin.html         # 管理后台 (Vue 3)
│   ├── vue.global.js      # Vue 3 CDN
│   ├── tailwind.js        # Tailwind CDN
│   ├── marked.min.js      # Markdown 渲染
│   └── purify.min.js      # HTML 净化
└── data/                  # SQLite 数据库文件 (运行时生成)
```

---

## 4. 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户浏览器                               │
│  ┌─────────────────┐    ┌─────────────────┐                   │
│  │   index.html    │    │   admin.html    │                   │
│  │  (Vue 3 SPA)    │    │  (Vue 3 SPA)    │                   │
│  └────────┬────────┘    └────────┬────────┘                   │
└───────────┼───────────────────────┼─────────────────────────────┘
            │                       │
            │   HTTP/REST API       │   HTTP/REST API
            │   (无缓存 HTML)        │   (JWT Bearer Token)
            │                       │
┌───────────┴───────────────────────┴─────────────────────────────┐
│                      Express.js Server                           │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Auth Routes  │  │  Card Routes │  │ Admin Routes│          │
│  │ /api/auth/*  │  │  /api/cards/*│  │ /api/admin/*│          │
│  │ /api/user/*  │  │              │  │              │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│  ┌──────┴─────────────────┴─────────────────┴───────┐         │
│  │              Middleware Layer                       │         │
│  │  • authenticateAdmin    (JWT 验证)                 │         │
│  │  • authenticateUser     (JWT 验证)                 │         │
│  │  • optionalUserAuth     (可选认证)                 │         │
│  │  • checkBruteForce      (防暴力破解)               │         │
│  │  • logOperation          (审计日志)                 │         │
│  └─────────────────────────┬───────────────────────────┘         │
│                            │                                       │
└────────────────────────────┼───────────────────────────────────────┘
                             │
┌────────────────────────────┼───────────────────────────────────────┐
│                    better-sqlite3                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │  admin_users   │  │     users      │  │character_cards │        │
│  │  (管理员账户)   │  │  (普通用户)    │  │  (角色卡)      │        │
│  └────────────────┘  └────────────────┘  └────────────────┘        │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │character_comm. │  │ comment_likes │  │  card_likes    │        │
│  │   (评论)       │  │   (点赞)       │  │   (卡片点赞)    │        │
│  └────────────────┘  └────────────────┘  └────────────────┘        │
│  ┌────────────────┐  ┌────────────────┐                            │
│  │login_attempts  │  │operation_logs  │                            │
│  │  (登录尝试)    │  │  (操作日志)    │                            │
│  └────────────────┘  └────────────────┘                            │
│                            │                                       │
│                     /app/data/forum.db                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. 数据库设计

### 5.1 ER 关系图

```
┌─────────────┐       ┌─────────────────┐       ┌─────────────┐
│ admin_users │       │ character_cards │       │    users    │
├─────────────┤       ├─────────────────┤       ├─────────────┤
│ id (PK)     │       │ id (PK)         │       │ id (PK)     │
│ username    │       │ name            │       │ username    │
│ password_hash│      │ description     │       │ password_hash│
│ created_at  │       │ avatar_url      │◄──────│download_credits│
│ last_login  │       │ data            ││      │ created_at  │
└─────────────┘       │ creator_notes   ││      │ last_login  │
                      │ downloads_count ││      └─────────────┘
                      │ uploader_user_id│        │      ▲
                      │ created_at      │        │      │
                      │ likes_count      │        │      │
                      └────────┬─────────┘        │      │
                               │                  │      │
                      ┌────────┴────────┐         │      │
                      │character_comm. │         │      │
                      ├────────────────┤         │      │
                      │ id (PK)        │         │      │
                      │ card_id (FK)───┼─────────┘      │
                      │ user_id (FK)───► references    │
                      │ nickname       │         │      │
                      │ content        │         │      │
                      │ likes_count    │         │      │
                      │ created_at     │         │      │
                      └───────┬────────┘         │      │
                              │                  │      │
               ┌──────────────┴───────┐         │      │
               │    comment_likes     │         │      │
               ├──────────────────────┤         │      │
               │ id (PK)              │         │      │
               │ comment_id (FK)──────┼─────────┘      │
               │ user_id (FK)─────────┼────────────────┘
               │ created_at           │
               └──────────────────────┘

               ┌──────────────────────┐
               │      card_likes      │
               ├──────────────────────┤
               │ id (PK)              │
               │ card_id (FK)─────────┼──────────────────┐
               │ user_id (FK)─────────┼──────────────────┤
               │ created_at           │
               └──────────────────────┘
```

### 5.2 表说明

| 表名 | 说明 | 记录类型 |
|------|------|----------|
| `admin_users` | 管理员账户 | 1-3条 |
| `users` | 普通用户 | 上传/评论用户 |
| `character_cards` | 角色卡 | 核心内容 |
| `character_comments` | 评论 | 用户评论 |
| `comment_likes` | 评论点赞 | 用户点赞记录 |
| `card_likes` | 卡片点赞 | 用户点赞记录 |
| `login_attempts` | 登录尝试 | 安全审计 |
| `operation_logs` | 操作日志 | 管理员操作记录 |
| `settings` | 系统设置 | 站点配置 |

---

## 6. API 架构

### 6.1 认证体系

```
┌─────────────────────────────────────────────────────────┐
│                    认证 Token 双系统                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   Admin Token (24h)          User Token (7d)            │
│   ───────────────           ──────────────             │
│   Key: admin_token           Key: user_token            │
│   Payload:                   Payload:                    │
│   { id, username,           { id, username,             │
│     role: 'admin' }           role: 'user' }            │
│                                                         │
│   存储位置: localStorage      存储位置: localStorage     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 6.2 中间件层级

| 中间件 | 说明 | 使用场景 |
|--------|------|----------|
| `authenticateAdmin` | 必须管理员 | `/api/admin/*` |
| `authenticateUser` | 必须登录用户 | `/api/user/me`, `/api/user/credits` |
| `optionalUserAuth` | 可选认证 | `/api/cards`, 评论/下载 |
| `requireUserOrAdmin` | 用户或管理员 | 需要明确身份的写操作 |

### 6.3 API 端点清单

#### 公开端点 (无需认证)
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/api/cards` | 获取卡片列表 |
| GET | `/api/cards/:id` | 获取卡片详情 |
| GET | `/api/cards/:cardId/comments` | 获取评论列表 |
| POST | `/api/user/register` | 用户注册 |
| POST | `/api/user/login` | 用户登录 |

#### 需要认证的端点
| 方法 | 路径 | 中间件 | 说明 |
|------|------|--------|------|
| GET | `/api/user/me` | authenticateUser | 获取当前用户信息 |
| GET | `/api/user/credits` | authenticateUser | 获取积分 |
| POST | `/api/cards` | optionalUserAuth | 上传卡片 |
| POST | `/api/cards/:cardId/comments` | optionalUserAuth | 发评论 |
| POST | `/api/cards/:id/download` | optionalUserAuth | 下载 |
| POST | `/api/cards/:id/like` | authenticateUser | 点赞卡片 |
| DELETE | `/api/cards/:id/like` | authenticateUser | 取消点赞 |
| POST | `/api/comments/:id/like` | authenticateUser | 点赞评论 |
| DELETE | `/api/comments/:id/like` | authenticateUser | 取消点赞 |

#### 管理端点 (需要 admin 角色)
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/auth/me` | 管理员信息 |
| POST | `/api/auth/login` | 管理员登录 |
| GET | `/api/admin/stats` | 统计信息 |
| GET | `/api/admin/cards` | 卡片管理列表 |
| DELETE | `/api/admin/cards/:id` | 删除卡片 |
| GET | `/api/admin/comments` | 评论管理列表 |
| DELETE | `/api/admin/comments/:id` | 删除评论 |
| GET | `/api/admin/users` | 用户管理列表 |
| PUT | `/api/admin/users/:id/credits` | 调整用户积分 |
| GET | `/api/admin/tags` | 标签管理 |
| PUT | `/api/admin/tags` | 更新标签 |
| GET | `/api/admin/logs` | 操作日志 |
| GET | `/api/admin/settings` | 系统设置 |
| PUT | `/api/admin/settings` | 更新系统设置 |
| PUT | `/api/admin/password` | 修改管理员密码 |

---

## 7. 积分系统

### 7.1 积分规则

| 操作 | 积分变动 | 条件 | 备注 |
|------|----------|------|------|
| 注册 | +1 | 自动 | 新用户注册送1积分 |
| 发表评论 | +2 | 已登录且内容>=5字符 | 评论赚积分 |
| 点赞评论 | +1 | 已登录 | 点赞他人评论 |
| 取消点赞 | -1 | 已登录，积分>=0 | 热评标记触发 |
| 点赞卡片 | +1 | 已登录 | 点赞角色卡 |
| 取消点赞 | -1 | 已登录 | |
| 下载卡片 | -1 | 已登录，非自己上传，非管理员 | 扣积分 |
| 上传卡片 | +0 | - | 不直接加分 |

### 7.2 硬约束
- `download_credits >= 0` 永远成立
- 扣除使用 `MAX(0, credits - 1)`
- 检查 `changes === 0` 判断是否成功

---

## 8. 安全机制

### 8.1 暴力破解防护
- **IP 级别**：同一 IP 15分钟内最多 5 次失败尝试
- **用户名级别**：同一用户名 15分钟内最多 5 次失败尝试
- **锁定时间**：15 分钟 (LOCKOUT_MINUTES)
- **记录表**：`login_attempts`

### 8.2 JWT 安全
- **Admin Token**：24小时过期
- **User Token**：7天过期
- **密钥派生**：如果没有显式设置 JWT_SECRET，从 ADMIN_PASSWORD 派生

### 8.3 密码安全
- **bcrypt cost**：12
- **不存储明文密码**

### 8.4 安全头
```javascript
helmet({
    contentSecurityPolicy: false,  // 允许 CDN 脚本
    crossOriginEmbedderPolicy: false,
    frameguard: false  // 允许 iframe 嵌入
})
```

---

## 9. 前端架构 (Vue 3 SPA)

### 9.1 index.html (论坛主页)
```
├── 顶栏
│   ├── Logo/站点名称
│   ├── 搜索框
│   ├── 用户按钮 (登录/注册 或 用户名+积分)
│   └── 管理后台入口 (admin)
│
├── 主内容区
│   ├── Tab 切换 (最新/最热)
│   ├── 筛选器 (标签)
│   ├── 卡片网格
│   │   ├── 卡片封面
│   │   ├── 卡片名称
│   │   ├── 下载/点赞/评论 统计
│   │   └── 上传者信息
│   └── 加载更多
│
├── 侧边栏
│   ├── 上传卡片按钮
│   ├── 我的卡片
│   ├── 我的积分
│   └── 热门标签
│
├── 卡片详情弹窗
│   ├── 角色卡预览
│   ├── 角色信息
│   ├── 下载按钮
│   └── 评论区域
│
├── 用户认证弹窗
│   ├── 登录表单
│   └── 注册表单
│
└── 页脚
```

### 9.2 admin.html (管理后台)
```
├── 侧边导航
│   ├── 仪表盘
│   ├── 卡片管理
│   ├── 评论管理
│   ├── 用户管理
│   ├── 标签管理
│   ├── 操作日志
│   └── 系统设置
│
└── 主内容区
    └── 各模块内容
```

### 9.3 状态管理 (Vue 3 Composition API)
```javascript
// 用户认证
const userToken = ref(localStorage.getItem('user_token') || '');
const currentUser = ref(null);
const isLoggedIn = computed(() => !!currentUser.value);

// 卡片数据
const cards = ref([]);
const currentCard = ref(null);

// UI 状态
const showAuth = ref(false);
const showCardDetail = ref(false);
const loading = ref(false);

// 筛选/排序
const sortBy = ref('latest'); // 'latest' | 'hot'
const activeTag = ref('');
```

---

## 10. 部署架构

### 10.1 Docker 部署
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 9191
CMD ["npm", "start"]
```

### 10.2 环境变量
| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | (平台生成) | 管理员初始密码 |
| `JWT_SECRET` | (平台生成/派生) | JWT 签名密钥 |
| `PORT` | `9191` | 服务端口 |
| `DATA_DIR` | `/app/data` | 数据存储目录 |

### 10.3 Zeabur 部署
- Volume 挂载：`data` → `/app/data`
- 自动生成强密码
- 支持一键部署

---

## 11. 运行逻辑流程

### 11.1 用户上传角色卡流程
```
用户点击上传
    ↓
选择 PNG/JSON 文件
    ↓
前端验证文件格式
    ↓
POST /api/cards (optionalUserAuth)
    ↓
服务端：
  1. 生成 UUID
  2. 处理图片 (Sharp 可选)
  3. 存储到数据库
  4. 关联 uploader_user_id (如果已登录)
    ↓
返回卡片信息
    ↓
前端更新列表
```

### 11.2 用户下载角色卡流程
```
用户点击下载
    ↓
前端检查 localStorage
    ↓
POST /api/cards/:id/download (optionalUserAuth)
    ↓
服务端检查：
  1. 是否管理员 → 不扣积分
  2. 是否自己上传 → 不扣积分
  3. 积分是否充足 → 扣除积分，记录日志
    ↓
返回文件数据 / 403 积分不足
    ↓
前端处理响应
```

### 11.3 评论点赞流程
```
用户点击点赞
    ↓
POST /api/comments/:id/like (authenticateUser)
    ↓
服务端：
  1. 检查 UNIQUE(comment_id, user_id)
  2. 事务中：
     - INSERT comment_likes
     - UPDATE users SET credits + 1
     - INSERT credit_logs
     - SELECT 最新点赞数
    ↓
返回 { likes_count, download_credits }
    ↓
前端更新 UI
```

---

## 12. 代码质量评估

### 12.1 优点
- ✅ 模块化清晰（server.js / database.js 分离）
- ✅ 数据库使用事务保证数据一致性
- ✅ 完善的暴力破解防护
- ✅ JWT 双 Token 系统（Admin/User 分离）
- ✅ 操作审计日志完整
- ✅ SQLite WAL 模式提升并发性能
- ✅ 外键约束开启
- ✅ 完善的错误处理和日志记录

### 12.2 可优化点
- ⚠️ server.js 单文件约 700 行，可拆分路由模块
- ⚠️ 缺少请求参数验证中间件（如 Joi）
- ⚠️ 没有分页 API（列表查询全量返回）
- ⚠️ 图片存储在数据库（大文件会影响性能）
- ⚠️ 没有缓存层（Redis）
- ⚠️ rate-limit 使用简单内存存储，容器重启会丢失

---

## 13. 扩展性分析

### 13.1 未来可扩展功能 (参见 ARCHITECTURE.md)
- [ ] 用户头像
- [ ] 积分商城/兑换
- [ ] 用户等级系统
- [ ] 私信系统
- [ ] 收藏功能
- [ ] 分享链接追踪
- [ ] 多语言支持

### 13.2 性能优化建议
1. **大列表分页**：添加 `LIMIT/OFFSET` 支持
2. **图片存储**：改为文件系统 + CDN
3. **缓存**：引入 Redis 缓存热门数据
4. **搜索**：考虑 Elasticsearch 全文搜索
5. **CDN**：静态资源走 CDN 加速

---

## 14. 总结

RPH-Forum 是一个**架构清晰、功能完整**的角色卡分享平台：

**核心优势：**
- 轻量级（SQLite + Express）
- 部署简单（Docker 一键部署）
- 安全完善（JWT + bcrypt + 防暴力破解）
- 代码质量高（事务 + 审计日志）

**技术亮点：**
- 双 Token 认证系统
- 积分经济系统
- Vue 3 CDN 版本（无构建工具）
- 完善的评论/点赞系统

**适合场景：**
- 小型社区/论坛
- 私有角色卡分享平台
- 学习 Node.js + SQLite 开发
