# RNA-ROM

[中文](#中文) · [English](#english) · [开源组件](#已开源的组件) · [Open Source](#open-source-components)

![Latest release](https://img.shields.io/github/v/release/littlepe/RNA-ROM-Public-Release?label=latest)

RNA-ROM 致力于打造 Android 平台的全能固件处理工具。

本仓库负责分发 APK 与运行时资源。主程序（RNA-ROM）目前暂未开源，CLI 部分已拆分为独立组件逐步开源，见[已开源的组件](#已开源的组件)。

---

## 中文

### 已开源的组件

主程序闭源，CLI 部分按功能拆分为独立组件开源。两者都是跨平台的纯 Python 工具，克隆对应分支后 `pip install -e .` 即可使用：

| 组件 | 说明 | 源码分支 |
| --- | --- | --- |
| [getrom](https://github.com/littlepe/RNA-ROM-Public-Release/tree/RNA/getrom) | 官方 OTA 固件查询：vivo / iQOO、小米 / Redmi / POCO、Obric、联想、OPPO / 一加 / 真我（ColorOS）、StepAOS | `RNA/getrom` |
| [oem-unpack](https://github.com/littlepe/RNA-ROM-Public-Release/tree/RNA/OemUnpackTool) | 厂商固件解包：华为 APP / update.bin、LG KDZ / DZ、展锐 PAC、索尼 SIN、OPPO ozip / ofp / ops、AMLogic、瑞芯微 RKFW / RKAF、诺基亚 NB0 | `RNA/OemUnpackTool` |

两个组件都只依赖 Python；`oem-unpack` 的 OPPO 与索尼解包另需 `lz4` 与 `zstandard`，二者均为懒加载。

### 下载

**123 云盘**

https://1813596286.share.123pan.cn/123pan/Tx0SVv-aUhqv?pwd=btaD

> 提取码：`btaD`

**GitHub Releases**

https://github.com/littlepe/RNA-ROM-Public-Release/releases

### 版本号说明

APK 命名规则如下：

```
RNA-ROM_<提交短哈希>-Stable.<versionCode>.apk
```

其中 `versionCode` 为版本号乘以 10000，示例：

| 版本号 | versionCode | 文件名示例 |
| --- | --- | --- |
| 5.0.0 | 50000 | `RNA-ROM_56cd864-Stable.50000.apk` |

### 反馈

如发现 bug，可通过 [Issues](https://github.com/littlepe/RNA-ROM-Public-Release/issues) 提交，或在官方 QQ 群中反馈。

提交前请附上以下信息：

- **软件版本号**：APK 版本号与后台主程序版本号，两项均需提供，缺少任一项将无法定位问题。
- **应用崩溃**：`dropbox` 或 `tombstones` 中的日志。
- **功能异常**：截图，以及开启调试输出后的完整日志。请提供可复现部分的全部日志，勿仅截取片段。

信息不全将无法分析，版本信息不符的反馈不予受理。

官方 QQ 群：`1031148744`

### 关于

- 项目完全免费，作者为在校学生，更新频率视个人时间而定，恕不接受催更，亦不存在收费版本。
- 主程序暂时闭源，CLI 部分已拆分为独立组件逐步开源，见[已开源的组件](#已开源的组件)。本仓库中的清单与资源遵循 [LICENSE](LICENSE)（MIT）；随包分发的第三方组件（JRE、jadx、smali 等）各自遵循其原始许可。
- 刷机有风险。首次使用建议先以确认可回刷的固件包进行测试，并自行做好重要数据的备份。

### 支持项目

RNA-ROM 始终免费，不售卖功能或授权。若本项目对你有帮助，可自愿请作者喝杯奶茶，金额不限；不捐赠亦可正常下载、更新与反馈。

<img src="donate.jpg" alt="微信赞赏码 / 支付宝收款码" width="240">

- 捐赠仅为自愿支持，不构成购买行为，不提供额外功能、优先支持或发票。
- 本软件不通过任何渠道出售。若有人要求你付费才能下载或使用 RNA-ROM，均属诈骗，请停止付款并向平台举报。

---

## English

RNA-ROM aims to be an all-in-one firmware processing tool for Android. This repository distributes APKs and runtime resources. The main program (RNA-ROM) is currently not open source; the CLI part has been split into standalone components that are open source one by one, see [Open Source Components](#open-source-components).

### Open Source Components

The main program is closed source, the CLI part is split into standalone components that are open source one by one. They are cross platform pure Python tools: clone the branch and run `pip install -e .`.

| Component | Description | Source branch |
| --- | --- | --- |
| [getrom](https://github.com/littlepe/RNA-ROM-Public-Release/tree/RNA/getrom) | Official OTA firmware query: vivo / iQOO, Xiaomi / Redmi / POCO, Obric, Lenovo, OPPO / OnePlus / Realme (ColorOS), StepAOS | `RNA/getrom` |
| [oem-unpack](https://github.com/littlepe/RNA-ROM-Public-Release/tree/RNA/OemUnpackTool) | Vendor firmware unpack: Huawei APP / update.bin, LG KDZ / DZ, Unisoc PAC, Sony SIN, OPPO ozip / ofp / ops, AMLogic, Rockchip RKFW / RKAF, Nokia NB0 | `RNA/OemUnpackTool` |

Both components need nothing but Python. The OPPO and the Sony unpackers of `oem-unpack` use `lz4` and `zstandard`, they are imported lazily.

### Download

**123 Cloud Drive**

https://1813596286.share.123pan.cn/123pan/Tx0SVv-aUhqv?pwd=btaD

> Access code: `btaD`

**GitHub Releases**

https://github.com/littlepe/RNA-ROM-Public-Release/releases

### Version Numbering

APK naming convention:

```
RNA-ROM_<short-commit-hash>-Stable.<versionCode>.apk
```

`versionCode` is the version number multiplied by 10000. Example:

| Version | versionCode | Example Filename |
| --- | --- | --- |
| 5.0.0 | 50000 | `RNA-ROM_56cd864-Stable.50000.apk` |

### Feedback

If you find a bug, submit it via [Issues](https://github.com/littlepe/RNA-ROM-Public-Release/issues) or report it in the official QQ group.

Before submitting, please include the following information:

- **Software version numbers**: the APK version and the backend main program version. Both are required; if either is missing, the problem cannot be located.
- **App crash**: logs from `dropbox` or `tombstones`.
- **Malfunction**: a screenshot and the complete logs after enabling debug output. Please provide all logs for the reproducible part; do not provide only excerpts.
- Feedback with incomplete information cannot be analyzed, and reports with mismatched version information will not be accepted.

Official QQ group: `1031148744`

### About

- The project is completely free. The author is a student, and the update frequency depends on personal time. Please do not rush updates. There is no paid version.
- The main program is currently closed source. The CLI part has been split into standalone components and is open source one by one, see [Open Source Components](#open-source-components). The manifests and resources in this repository are licensed under [LICENSE](LICENSE) (MIT); third-party components distributed with the package (JRE, jadx, smali, etc.) are subject to their original licenses.
- Flashing firmware carries risks. For first-time use, it is recommended to test with a firmware package that is confirmed to be re-flashable, and to back up important data yourself.

### Support the Project

RNA-ROM is always free and does not sell features or licenses. If this project helps you, you may voluntarily buy the author a cup of milk tea, in any amount. You can still download, update, and provide feedback normally without donating.

<img src="donate.jpg" alt="WeChat reward code / Alipay payment code" width="240">

- Donations are voluntary support only. They do not constitute a purchase and do not provide extra features, priority support, or invoices.
- This software is not sold through any channel. If anyone asks you to pay to download or use RNA-ROM, it is a scam. Please stop payment and report it to the platform.