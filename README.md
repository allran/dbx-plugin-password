# 密码管理（Password Manager）

DBX 工作台插件：按分组管理本地密码条目。

## 功能

- 左侧分组树（可折叠）+ 搜索
- 新建密码 / 新建分组
- 分组右键：新建密码、重命名、删除（默认分组不可改名/删除）
- 右侧详情：标题、用户名、密码、链接、说明、创建/修改日期

数据保存在 Sidecar 本地目录（`DBX_PLUGIN_DATA_DIR/vault.json`），不会上传。

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
