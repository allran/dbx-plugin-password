# 密码管理（Password Manager）

DBX 工作台插件：按多层分组管理本地密码条目。

## 功能

- 左侧多层分组树（可折叠）+ 搜索
- 新建密码 / 新建分组（可嵌套）
- 分组右键：新建分组、新建密码、重命名、删除（默认分组不可改名/删除）
- 密码右键：编辑、删除
- 右侧详情：标题、用户名、密码、链接、说明、创建/修改日期、随机密码
- **本地加密密码库**（默认无解锁；可选主密码）

## 数据与安全

数据在 Sidecar 本地目录（`DBX_PLUGIN_DATA_DIR/`），**不会上传**。

| 文件 | 说明 |
| --- | --- |
| `vault.json` | 始终为加密信封（AES-256-GCM），不含明文密码字段 |
| `vault.key` | 仅「开放模式」存在：随机密钥，用于自动解锁 |

| 模式 | 行为 |
| --- | --- |
| 开放模式（默认，无主密码） | 用 `vault.key` 自动解密，打开不弹解锁页 |
| 主密码模式 | Argon2id(主密码) 派生密钥；无 `vault.key`；每次打开需解锁 |

**旧版兼容**：若检测到旧版明文 `vault.json`（含 `groups`/`entries`），首次加载会自动迁移为开放模式加密，并写出 `vault.key`。

说明：开放模式下能读数据目录的人仍可同时拿到密钥与密文；主密码模式可防止仅拿到文件却不知口令的访问。

## 开发

需要 Node.js 22（见 `.nvmrc`）与 Rust toolchain。

```bash
nvm use
npm install
npm run build
dbx-plugin dev --path . --port 5191
```

## 打包

```bash
npm run build
dbx-plugin package .
```
