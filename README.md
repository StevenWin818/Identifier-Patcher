# Identifier-Patcher

基于底层 Binder 拦截的 TEE 硬件密钥认证参数重写模块。基于 [TEESimulator](https://www.google.com/search?q=https://github.com/jingmatrix/TEESimulator) 修改而来，原作者: [JingMatrix](https://github.com/JingMatrix)。

## 项目简介

Identifier-Patcher 是一个专为 Android 设备设计的 Magisk / KernelSU / APatch 模块。其主要用于解决跨区域刷机（例如基于国行底层硬件运行 EEA 或国际版固件），并[伪装 BitLocker 已锁定状态](https://github.com/StevenWin818/GBL_Root_HyperCanoe)时，由于操作系统属性与底层硬件安全区（RPMB/Fuses）硬编码信息不匹配，导致的硬件支持密钥证明失败（Keystore Error -66: `CANNOT_ATTEST_IDS`）问题。

与传统的依赖软件模拟或泄漏 Keybox 的方案不同，本模块作为运行在内核 `/dev/binder` 层级的守护进程，在 Android 框架层与底层物理 TEE（可信执行环境）的通信链路中充当拦截器。它通过动态修改传往 KeyMint / Keymaster HAL 的设备标识参数，强制底层硬件 TEE 签发包含正确物理设备指纹的合法证明证书，从而完美通过 Google 密钥认证（`Key Attestation`）校验。

## 核心特性

* **零 Keybox 依赖**：完全不使用任何第三方泄漏的密钥盒，100% 依赖设备自带的物理硬件私钥进行密码学签名，确保底层信任链的绝对合法性。
* **纯底层数据包篡改**：深度解析并重写 `IKeystoreSecurityLevel.generateKey` 事务中的 `KeyParameter` 数组，放行重写后的数据包交由真实硬件处理。
* **隔离进程穿透**：支持全局无条件重写（通过通配符 `*` 配置），有效解决 GMS `unstable` 隔离进程（DroidGuard）因 UID 丢失导致的漏报问题，修复 Google Wallet 等依赖底层令牌化（Tokenization）的安全应用报错。
* **轻量级与低功耗**：精简了全部软件证书生成与 PKI 逻辑，利用 Native C++ 驱动与 Kotlin 拦截器协同工作，仅对特定的 Keystore 事务进行微秒级的内存覆盖，对系统续航无感知。

## 配置与使用

模块刷入并重启设备后，配置文件位于 `/data/adb/modules/identifier_patcher/` 目录下（具体路径视您的 Root 管理器而定）。

### 1. 目标应用配置 (`target.txt`)
该文件用于控制模块对哪些发起 Keystore 请求的应用程序生效。
* 写入 `*`：开启全局拦截。由于 GMS 等系统级安全组件会通过特殊的隔离进程发起请求，指定具体的包名可能导致拦截失效。使用 `*` 可确保所有硬件证明请求均被正确对齐。
* 写入具体包名（例如 `io.github.vvb2060.keyattestation`）：仅对指定应用生效。

### 2. 设备标识符配置 (`attestation_ids.txt`)
该文件用于指定传递给底层物理 TEE 的正确硬件标识符。格式为标准键值对，请务必将其修改为您设备物理主板对应的出厂参数：
以 小米 17 国行为例，正确的配置如下：
```properties
ATTESTATION_ID_DEVICE=pudding
ATTESTATION_ID_PRODUCT=pudding
ATTESTATION_ID_MODEL=25113PN0EC
ATTESTATION_ID_BRAND=Xiaomi
ATTESTATION_ID_MANUFACTURER=Xiaomi
```
## 开源许可与致谢 (License & Acknowledgements)

本项目基于 [GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.en.html) 协议开源。

本项目底层的 Binder 通信拦截框架、C++ 注入逻辑以及核心的基础类结构，派生并修改自开源项目 [TEESimulator](https://www.google.com/search?q=https://github.com/jingmatrix/TEESimulator) (原作者: [JingMatrix](https://github.com/JingMatrix)。在此对原作者及开源社区的卓越贡献表示诚挚的感谢。
