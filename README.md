# 密码管理（Password Manager）

DBX 工作台插件：按多层分组管理本地密码条目。

## 功能

- 左侧多层分组树（可折叠）+ 搜索
- 新建密码 / 新建分组（可嵌套）
- 分组右键：新建分组、新建密码、重命名、删除（默认分组不可改名/删除）
- 密码右键：编辑、删除
- 右侧详情：标题、用户名、密码、链接、说明、创建/修改日期、随机密码

## 数据与安全

数据保存在 Sidecar 本地目录（`DBX_PLUGIN_DATA_DIR/vault.json`），**不会上传到网络**。

当前为**本地明文存储**（无主密码、无加密）。请仅在受信任的本机环境使用；卸载插件或清理数据目录会删除库文件。

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
