# TrickyStore Restored (1.1.0 → 1.4.1)

基于开源基线 `qwq233/TrickyStore@3a515c5`，对照闭源仓库 [5ec1cff/TrickyStore](https://github.com/5ec1cff/TrickyStore) 的 README / SECURITY / changelog，并借鉴开源同类实现 [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator) 复原闭源后的功能。

> 说明：闭源版本无官方源码，本树为**功能级复原**，不是二进制反编译结果。行为对齐更新日志与文档中的公开接口。

## 版本能力对照

| 版本 | 能力 | 实现位置 |
|------|------|----------|
| 1.1.1 | 自动/生成模式 bug 修复；root 管理器内更新 | `Config.kt` AUTO/`!`/`?`；`customize.sh` + `update.json` |
| 1.1.2 | arm 支持；Magisk 升级自动禁用修复 | NDK abiFilters；`customize.sh` 保留 `disable` 清理 |
| 1.2.0-RC1 | Android 10–11；自动检测硬件加密；签名算法选择 | `util.kt` osVersion；`Config.teeBroken`；`CertHack` normalize sig |
| 1.2.0-RC2 | 叶证书改安全等级/信任根为非软件；补 osVersion | `CertHack.hackCertificateChain` |
| 1.2.1 | `security_patch.txt` | `Config` + `util.getPatchLevels` |
| 1.3.0 | moduleHash；Android 16；Play 商店默认列表；证书链修复 | `ModuleHash.kt`；`target.txt`；Attestation 构建 |
| 1.4.0 | 密钥持久化 `key_db`；AVB key 解析；更多 keystore 拦截 | `KeyDb.kt`；`util` vbmeta；`SecurityLevelInterceptor` + `SoftwareOperation` |
| 1.4.1 | 若干修复 | RoT 检测、uid 参数、Domain.APP、applicationId 分区等 |

## 配置（与闭源文档一致）

- `/data/adb/tricky_store/keybox.xml`
- `/data/adb/tricky_store/target.txt` — 无后缀 AUTO，`!` 强制 generate，`?` 强制 leaf-hack
- `/data/adb/tricky_store/security_patch.txt` — 1.2.1+
- `/data/adb/tricky_store/key_db/` — 1.4.0+ 生成密钥持久化（仅 root 可访问）
- `/data/adb/tricky_store/tee_status` — 自动模式缓存 TEE 是否可用

## 2026-07-26 复审修复

### 编译 / stub
- 从 TEESimulator 补齐 stub：`Domain`、`CreateOperationResponse`、`OperationChallenge`、`IKeystoreOperation`、`KeyParameters`、`BlockMode`、`Digest`、`PaddingMode`

### 逻辑 bug
1. **Domain.APP 写错**：`getKeyResponse` 曾写 `domain = 2`（SELINUX），已改为 `Domain.APP = 0`
2. **applicationId 分区错误**：`hackCertificateChain` 曾把 tag 709 写入 teeEnforced；已改写 softwareEnforced (index 6)
3. **SoftwareOperation**
   - 签名算法名 `"SHA256ECDSA"` → `"SHA256withECDSA"`
   - 删除不存在的 `KeyPurpose.MAC`
   - 补 `updateAad` 以匹配 `IKeystoreOperation`
   - 参数读取改用 `getAlgorithm()` / `getKeyPurpose()` 等 getter（避免与静态 tag 常量名冲突）
4. **deleteKey**：同时清 SLI 内存缓存 + KeyDb（`removeKey`）
5. **listEntries**：按线程缓存 `startPastAlias`；合并时优先软件密钥；支持 KeyDb 磁盘 alias
6. **USER_ID**：改为 `uid / 100000`，不再误用 nspace
7. **createOperation**：进程重启后可从 KeyDb 回填；opId 用原子计数

## 构建

```bash
./gradlew :module:zipRelease
```

产物为 Magisk / KernelSU / APatch 模块 zip。

## 许可与致谢

- 开源基线：TrickyStore (5ec1cff / qwq233 fork)
- 参考实现：TEESimulator (JingMatrix)
- FrameworkPatch / BootloaderSpoofer / KeystoreInjection / LSPosed / LSPlt
