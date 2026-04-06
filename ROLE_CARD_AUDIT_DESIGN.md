# RPH-Forum 角色卡审核功能设计文档

> 编写日期：2026-04-06
> 参考项目：D:\github\RP-Hub (角色卡解析逻辑)

---

## 1. 需求概述

在 RPH-Forum 上传角色卡时，自动解析 PNG/JSON 文件中的角色数据，检查是否包含违禁词，如果有则拒绝上传。

---

## 2. 角色卡格式说明

### 2.1 支持的格式

| 格式 | 说明 | 解析方式 |
|------|------|----------|
| `.png` | SillyTavern 格式 | 读取 PNG tEXt/iTXt chunk 中的 `chara` 字段，Base64 解码后解析 JSON |
| `.json` | 标准 JSON | 直接 JSON.parse() |

### 2.2 SillyTavern 角色卡数据结构 (chara_card_v2 / v3)

```javascript
// V2 包装格式
{
  "spec": "chara_card_v2" | "chara_card_v3",
  "data": {
    // === 核心字段 ===
    "name": "角色名称",
    "description": "角色描述（主要文本，需重点审核）",
    "personality": "性格设定",
    "scenario": "场景/世界观设定",
    "first_mes": "开场白",
    "mes_example": "对话示例",

    // === 扩展字段 ===
    "creator_notes": "创作者备注",
    "creator": "创作者名称",
    "character_version": "版本号",

    // === 系统指令 ===
    "system_prompt": "系统提示词",
    "post_history_instructions": "对话历史指令",

    // === 其他 ===
    "tags": ["标签1", "标签2"],
    "alternate_greetings": ["备用开场1", "备用开场2"],

    // === 世界书 (Character Book) ===
    "character_book": {
      "name": "世界书名称",
      "entries": [
        {
          "keys": ["触发词1", "触发词2"],
          "secondary_keys": ["次要触发词"],
          "content": "世界书条目内容（需审核）",
          "name": "条目名称",
          "description": "条目描述",
          " extensions": { ... }
        }
      ]
    }
  }
}

// V1 格式（无 data 包装，直接是 charData）
{
  "char_name": "角色名称",
  "char_persona": "角色描述",
  "description": "角色描述（备用字段）",
  ...
}
```

---

## 3. 解析逻辑（移植自 RP-Hub）

### 3.1 PNG 文件解析流程

```
PNG 文件
  ↓
读取 FileReader.readAsArrayBuffer(file)
  ↓
readPngChunks(buffer) - 遍历 PNG chunks
  ├─ tEXt chunk: key\0value (直接读取)
  └─ iTXt chunk: 支持压缩的 Unicode 文本
  ↓
查找 'chara' key（或任何 >100 字符的大文本块）
  ↓
Base64 UTF-8 解码 decodeBase64Utf8(rawDataStr)
  ↓
JSON.parse(decoded) → 角色数据对象
  ↓
判断 V2 (rawData.spec === 'chara_card_v2/v3' || rawData.data)
  ↓
提取字段 (优先级: V2 > V1 > Fallback)
```

### 3.2 关键解析代码位置

**文件：** `D:\github\RP-Hub\assets\js\app.js`

| 行号 | 函数 | 说明 |
|------|------|------|
| 3408-3480 | `readPngChunks(buffer)` | 读取 PNG tEXt/iTXt chunk |
| 3483-3496 | `decodeBase64Utf8(str)` | Base64 UTF-8 解码 |
| 3500-3600+ | `normalizeWorldInfoEntry(entry)` | 标准化世界书条目 |
| 3653-3800+ | `processCharacterData()` 内 | SillyTavern 数据结构解析 |

### 3.3 核心字段提取逻辑

```javascript
// === 优先级: V2字段 > V1字段 > Fallback ===

const name = charData.name || charData.char_name || 'Unknown';
const description = charData.description || charData.char_persona || '';
const personality = charData.personality || '';
const scenario = charData.scenario || '';
const first_mes = charData.first_mes || '';
const mes_example = charData.mes_example || '';
const creator_notes = charData.creator_notes || charData.creatorcomment || charData.creator_comment || '';
const creator = charData.creator || '';
const character_version = charData.character_version || '';
const tags = charData.tags || [];
const system_prompt = charData.system_prompt || '';
const post_history_instructions = charData.post_history_instructions || '';
const alternate_greetings = charData.alternate_greetings || [];
```

---

## 4. 审核字段清单

### 4.1 需审核的文本字段

| 字段路径 | 类型 | 审核优先级 | 说明 |
|----------|------|----------|------|
| `name` | string | 高 | 角色名称 |
| `description` | string | 最高 | 角色描述，最重要 |
| `personality` | string | 高 | 性格设定 |
| `scenario` | string | 高 | 场景/世界观 |
| `first_mes` | string | 中 | 开场白 |
| `mes_example` | string | 中 | 对话示例 |
| `creator_notes` | string | 中 | 创作者备注 |
| `creator` | string | 低 | 创作者名称 |
| `system_prompt` | string | 高 | 系统提示词 |
| `post_history_instructions` | string | 高 | 对话历史指令 |
| `alternate_greetings` | array | 中 | 备用开场列表 |
| `tags` | array | 低 | 标签列表 |
| `character_book.entries[].content` | string | 高 | 世界书条目内容 |
| `character_book.entries[].keys` | array | 中 | 触发关键词 |
| `character_book.entries[].name` | string | 低 | 条目名称 |

### 4.2 审核字段汇总（递归扫描）

```javascript
function extractAllTextFields(obj, fields = []) {
    if (typeof obj === 'string') {
        fields.push(obj);
    } else if (Array.isArray(obj)) {
        obj.forEach(item => extractAllTextFields(item, fields));
    } else if (typeof obj === 'object' && obj !== null) {
        // 跳过的字段（不含用户内容）
        const skipFields = ['extensions', 'avatar', 'avatar_url', 'data'];
        for (const key of skipFields) {
            if (obj[key] !== undefined) delete obj[key];
        }
        for (const key in obj) {
            extractAllTextFields(obj[key], fields);
        }
    }
    return fields;
}
```

---

## 5. 违禁词检测方案

### 5.1 违禁词类型

| 类型 | 示例 | 检测方式 |
|------|------|----------|
| 政治敏感词 | 领导人姓名、敏感事件 | 词库匹配 |
| 色情低俗词 | 性行为描写、器官名称 | 词库匹配 |
| 暴力恐怖词 | 杀人、虐待、恐怖组织 | 词库匹配 |
| 违法内容 | 毒品、赌博、诈骗 | 词库匹配 |
| 恶意代码 | `<script>`、`javascript:` | 正则匹配 |

### 5.2 检测实现

```javascript
// 违禁词正则（示例）
const PROHIBITED_PATTERNS = [
    // 恶意代码
    /<script[\s\S]*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,  // onclick=, onerror=, etc.

    // 色情相关（简化示例）
    /裸体|全裸|露点|色情/gi,

    // 暴力相关（简化示例）
    /杀人|虐待|折磨|血腥/gi,
];

function checkProhibitedWords(text) {
    const violations = [];
    for (const pattern of PROHIBITED_PATTERNS) {
        const matches = text.match(pattern);
        if (matches) {
            violations.push({
                pattern: pattern.toString(),
                matches: matches.slice(0, 3), // 最多3个示例
                count: matches.length
            });
        }
    }
    return violations;
}
```

---

## 6. 集成到 RPH-Forum

### 6.1 修改位置

**文件：** `D:\github\RPH-Forum\server.js`

```javascript
// 在 POST /api/cards 路由中添加审核逻辑

app.post('/api/cards', requireUserOrAdmin, async (req, res) => {
    try {
        const { name, description, avatar_url, data, creator_notes } = req.body;

        // === 新增：角色卡内容审核 ===
        if (data) {
            const violations = await auditCharacterCard(data);
            if (violations.length > 0) {
                logOperation({
                    userType: req.user ? 'user' : 'admin',
                    userId: req.user?.id || req.admin?.id,
                    username: req.user?.username || req.admin?.username,
                    action: 'upload_rejected',
                    targetType: 'card',
                    ip: req.ip,
                    details: { reason: 'prohibited_content', violations }
                });

                return res.status(400).json({
                    error: '角色卡包含违规内容，无法上传',
                    violations: violations.map(v => ({
                        field: v.field,
                        sample: v.matches[0]
                    }))
                });
            }
        }
        // === 审核结束 ===

        // ... 后续正常逻辑 ...
    } catch (err) {
        // ...
    }
});
```

### 6.2 新增函数

```javascript
// === 角色卡审核模块 ===

/**
 * 解析 PNG 文件中的角色数据
 * @param {Buffer} buffer - PNG 文件 buffer
 * @returns {Object|null} 解析后的角色数据
 */
function parsePngCharacterCard(buffer) {
    // 简化版：实际实现需要读取 PNG chunks
    // 参考 RP-Hub: readPngChunks(), decodeBase64Utf8()
    return null;
}

/**
 * 提取角色卡所有文本字段
 * @param {Object} cardData - 角色卡数据对象
 * @returns {Array<{field: string, value: string}>} 字段列表
 */
function extractCharacterCardText(cardData) {
    const fields = [];

    // 处理 V2 格式
    const charData = cardData.data || cardData;

    // 核心文本字段
    const textFields = [
        { path: 'name', value: charData.name || charData.char_name },
        { path: 'description', value: charData.description || charData.char_persona },
        { path: 'personality', value: charData.personality },
        { path: 'scenario', value: charData.scenario },
        { path: 'first_mes', value: charData.first_mes },
        { path: 'mes_example', value: charData.mes_example },
        { path: 'creator_notes', value: charData.creator_notes },
        { path: 'creator', value: charData.creator },
        { path: 'system_prompt', value: charData.system_prompt },
        { path: 'post_history_instructions', value: charData.post_history_instructions },
    ];

    textFields.forEach(f => {
        if (f.value) fields.push({ field: f.path, value: String(f.value) });
    });

    // 数组字段
    if (Array.isArray(charData.alternate_greetings)) {
        charData.alternate_greetings.forEach((v, i) => {
            if (v) fields.push({ field: `alternate_greetings[${i}]`, value: String(v) });
        });
    }

    if (Array.isArray(charData.tags)) {
        charData.tags.forEach((v, i) => {
            if (v) fields.push({ field: `tags[${i}]`, value: String(v) });
        });
    }

    // 世界书条目
    const characterBook = charData.character_book;
    if (characterBook && characterBook.entries) {
        let entries = characterBook.entries;
        if (!Array.isArray(entries) && typeof entries === 'object') {
            entries = Object.values(entries);
        }
        entries.forEach((entry, i) => {
            if (entry.content) {
                fields.push({ field: `character_book.entries[${i}].content`, value: String(entry.content) });
            }
            if (entry.name) {
                fields.push({ field: `character_book.entries[${i}].name`, value: String(entry.name) });
            }
            if (Array.isArray(entry.keys)) {
                entry.keys.forEach((k, j) => {
                    if (k) fields.push({ field: `character_book.entries[${i}].keys[${j}]`, value: String(k) });
                });
            }
        });
    }

    return fields;
}

/**
 * 审核角色卡内容
 * @param {Object} cardData - 角色卡数据对象
 * @returns {Array<{field: string, pattern: string, matches: string[]}>} 违规列表
 */
function auditCharacterCard(cardData) {
    const violations = [];
    const fields = extractCharacterCardText(cardData);

    // 违禁词正则（可扩展为从文件读取）
    const prohibitedPatterns = [
        // 恶意代码/注入
        { pattern: /<script[\s\S]*?<\/script>/gi, name: 'XSS脚本注入' },
        { pattern: /javascript:/gi, name: 'JavaScript协议' },
        { pattern: /on\w+\s*=/gi, name: '事件处理器注入' },

        // 政治敏感词（需配置具体词库）
        // { pattern: /敏感词1|敏感词2/gi, name: '政治敏感' },

        // 色情低俗（简化示例）
        { pattern: /色情| porn /gi, name: '色情内容' },

        // 暴力恐怖（简化示例）
        { pattern: /杀人|虐待|分尸/gi, name: '暴力内容' },
    ];

    fields.forEach(field => {
        prohibitedPatterns.forEach(({ pattern, name }) => {
            const matches = field.value.match(pattern);
            if (matches) {
                violations.push({
                    field: field.field,
                    type: name,
                    pattern: pattern.toString(),
                    matches: matches.slice(0, 3),
                    count: matches.length
                });
            }
        });
    });

    return violations;
}
```

---

## 7. 实施计划

### Phase 1: 文档整理（已完成）
- [x] 分析 RP-Hub 角色卡解析逻辑
- [x] 确定审核字段范围
- [x] 设计检测方案

### Phase 2: 实现审核模块（已完成）
- [x] 在 `server.js` 中添加 `auditCharacterCard()` 函数
- [x] 在 `server.js` 中添加 `extractCharacterCardText()` 函数
- [x] 在 `POST /api/cards` 路由中集成审核逻辑
- [x] 内置 XSS/注入攻击检测规则 (`PROHIBITED_PATTERNS`)
- [x] 自定义违禁词数据库表 (`prohibited_patterns`)
- [x] 自定义违禁词 CRUD API (`/api/admin/audit-patterns`)

### Phase 3: 管理面板前端（已完成）
- [x] 在 `admin.html` 导航栏添加「违禁词检测」菜单项
- [x] 审核开关（audit_enabled）UI 和保存逻辑
- [x] 违禁词列表展示（启用/禁用切换、编辑、删除）
- [x] 添加/编辑违禁词弹窗（正则输入、类型选择、严重程度、描述）
- [x] 正则语法实时验证
- [x] 修复后端 `ALLOWED_SETTINGS_KEYS` 包含 `audit_enabled`

### Phase 4: 测试
- [ ] 测试 PNG 格式角色卡审核
- [ ] 测试 JSON 格式角色卡审核
- [ ] 测试各种违禁词检测
- [ ] 测试管理面板违禁词 CRUD 操作

---

## 8. 管理面板操作说明

### 8.1 进入违禁词检测页面

1. 登录管理后台 `/admin`
2. 点击左侧导航栏的「违禁词检测」

### 8.2 开启/关闭审核

- 页面顶部的开关按钮控制 `audit_enabled` 设置
- 关闭时：上传角色卡不做违禁词检测
- 开启时：上传角色卡会自动检测内置规则 + 自定义违禁词

### 8.3 添加违禁词

1. 点击「添加违禁词」按钮
2. 填写正则表达式（多个词用 `|` 分隔，自动忽略大小写）
3. 选择类型（自定义/内容过滤/XSS防护/注入防护/URL防护）
4. 选择严重程度（低/中/高/严重）
5. 可选填写描述
6. 点击「保存」

### 8.4 管理违禁词

- **启用/禁用**：点击每条规则左侧的开关
- **编辑**：点击编辑图标，修改后保存
- **删除**：点击删除图标，确认后删除

---

## 9. 参考资料

- **SillyTavern 角色卡格式规范**
- **RP-Hub 项目：** `D:\github\RP-Hub\assets\js\app.js`
  - 行 3408-3496: PNG 解析
  - 行 3653-3800: SillyTavern 数据结构解析
