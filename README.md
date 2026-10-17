# PrismDetector

基于 EaseCation 棱镜反作弊的逆向证据重建的检测 APK。

**当前版本：1.2.0** · 包名 `na1xue.prism.detector` · Android 7.0/API24+ · ARM64 与 x86_64。

检测引擎、哈希、阈值、组件匹配与报告序列化使用 C++；Kotlin/Java 负责 Ruru Compose 界面、系统 API 桥接与报告导出。UI 源码来自所提供的 Ruru 工程，保留其卡片、图标、主题与动画。

## 界面与使用

打开应用自动检测，点卡片展开详情。“关于”提供仓库链接、重新检测、设置和报告导出。

默认显示七项：我的世界安装包体积、我的世界 APK 证书、北京时间校对、无障碍、输入法、KeyMapper 安装状态、设备 ID。底部“显示次要检测项”展开其他十四项；折叠只影响显示，完整报告仍含 21 项。

详情图标位于首行前方，长文本换行保持对齐。普通无障碍/输入法组件按指定规则显示眼睛“可疑”；KeyMapper 精确组件及已安装状态显示病毒“危险”。输入法登记不等于已启用或正在使用。

## 检测范围

- **Minecraft APK**：查询当前用户的 `com.netease.x19`，base APK ≤ 1,073,741,824 字节时显示“我的世界安装包体积异常”。分包、OBB、下载资源及缓存不计入门槛。
- **Minecraft 证书**：系统 PackageManager 读取当前签名，C++ SHA-256 精确匹配提供的 `3.9.15.297907` 样本。基准为 `09efd061af7b7b28a4c1ea362151e760b550f58507691204823630daa878a807`。匹配不代表全 APK 字节一致。
- **北京时间**：双源 SNTP 校对，以 UTC+8 展示；绝对时差 >120 秒提示异常。无网络、单源失败、双源不一致时显示未完成。公共 NTP 不等于国家授时认证。
- **无障碍、输入法、设备 ID**：复用已恢复的采集及哈希路径，显示组件快照、变化事件或设备 ID 来源。
- **次要检查**：TracerPid、Seccomp/SIGSYS、四库现场完整性、类可见性、环境事件、部分映射/入口模型与宿主特征。未闭合的门控和缺失名单保留为未完成。

进程检查观察的是 PrismDetector 自身。普通独立 APK 不会检测另一应用的进程内存、ClassLoader 或调试状态。未加入 MCP 文件检测。主动 SIGSYS 默认关闭，ARM64 专用分支在 x86_64 上显示未执行。

## 构建

已验证 Windows 构建环境：Python 3.11+、JDK17+、SDK platform36/build-tools36.1.0、NDK27.0.12077973、CMake3.22.1、Gradle8.13、AGP8.13.2、Kotlin1.9.24。

```powershell
git clone https://github.com/BestPVPNa1Xue/PrismDetector.git
cd PrismDetector
python build.py --sdk "C:/path/to/Android/Sdk" --jdk "C:/path/to/jdk"
```

脚本创建本地开发签名、生成 SDK 配置，运行 `assembleRelease`、完整 `lintRelease`、apksigner 与 zipalign。首次构建需下载 Gradle/Maven 依赖，缓存齐全后可加 `--offline`。`--abis arm64-v8a` 可只构建 ARM64。输出位于 `dist/PrismDetector-1.2.0.apk`。

私钥不在仓库内，自行构建将使用新生成的本地开发密钥；覆盖安装既有 APK 需要相同密钥。构建脚本初始化后也可使用附带的 Gradle wrapper。

## 版本与验证

每个交付版本以源码提交和注释 tag `vX.Y.Z` 记录，详见 [CHANGELOG.md](CHANGELOG.md)。构建与源码摘要、已运行验证及尚未覆盖的平台记录在 `releases/`。

API34 x86_64 专用模拟器用于界面和 Android API 集成测试。ARM64 产物已编译；ARM64 真机和 Android 15/API35 现场验证尚未完成，尤其四库现场比对和主动 SIGSYS 不以模拟器界面测试替代验收。

## 来源与许可

Ruru UI 的 Apache-2.0 许可保留在 [LICENSE-Ruru.md](LICENSE-Ruru.md)，修改说明见 [NOTICE.md](NOTICE.md)。原 UI 参考工程保存在 `vendor-ui/Ruru-1.1.1`。本仓库不包含原始游戏安装包、签名私钥或原始设备报告。
