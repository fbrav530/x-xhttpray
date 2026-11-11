# X-Tunnel Android — GitHub Actions 出未签名 APK

## 一、本次改动（gomobile 绑定壳）

你更新的 `xtunnel.go` 是**桌面版**（`package main`，带 `func main()` 和 `flag` 参数解析），
Java 侧需要的三个入口全部不存在。本方案把它改造为 gomobile 可绑定的库。

### 1. `xtunnel.go` 的改动

| 改动 | 原因 |
|---|---|
| `package main` → `package tunnel` | gomobile 不能绑定 main 包 |
| 删除 `func main()`（122–273 行） | 命令行分支逻辑由 `gomobile_bind.go` 重写 |
| 删除 `init()` 里的 `flag.*Var` | 安卓上无命令行解析；保留默认值 |
| 移除 `_ "embed"` 与 `//go:embed index.html` | 工程里没有 index.html，否则编译失败；客户端不用伪装页 |
| 移除 `github.com/google/uuid` 导入 | 删 `main()` 后本文件不再使用（bind 层自己导入） |
| `ECHPool` 增加 `ctx/cancel` 字段 | 原版无停止能力，无限重连循环无法退出 |
| 新增 `(*ECHPool).Close()` / `Ready()` | 供停止与就绪检测 |
| `dialAndServe` 加取消检查 | 停止后不再重连 |

> 原始文件已备份为 `xtunnel.go.bak`（已加进 `.gitignore`）。

### 2. 新增 `gomobile_bind.go`

提供 Java 需要的三个接口，签名与 `TProxyService.java` 调用**完全一致**：

```go
func StartSocksProxy(host, wsServer string, n int, udpBlockPortsStr, dns, ech,
                     ip, tkn string, fb bool, ipsPref string, insecureFlag bool) error
func WaitSocksProxyReady(timeoutMs int) bool
func StopSocksProxy()
```

参数映射（Java `Tunnel.startSocksProxy` 11 个参数，顺序一致）：

| Java | Go | 说明 |
|---|---|---|
| `getSocksAddress():getSocksPort()` | `host` | 本地监听，如 `127.0.0.1:1080` |
| `wsAddr` | `wsServer` | 必须 `wss://` |
| `getWsConn()` (int) | `n` | 通道数 |
| `getUdpBlockPorts()` | `udpBlockPortsStr` | 如 `443` |
| `getEchDns()` | `dns` | ECH 公钥查询 DNS |
| `getEchDomain()` | `ech` | ECH 域名 |
| `getPrefIp()` | `ip` | 固定服务端 IP，可为空 |
| `getToken()` | `tkn` | `X-Token` 头 |
| `getDisableEch()` (bool) | `fb` | true=禁用 ECH |
| `getIpsPref()` | `ipsPref` | `4`/`6`/`4,6`/`6,4` |
| `getInsecure()` (bool) | `insecureFlag` | 跳过证书校验 |

**关键差异点**：原 Android 版 `runSOCKS5Listener` 里用 `log.Fatalf`，在安卓上会直接杀进程。
绑定层改为自建 `net.Listen` + Accept 循环，失败返回 `error` 给 Java。

## 二、工程原本缺什么

原目录只有源码，没有任何构建脚本。已补齐：

| 文件 | 作用 |
|---|---|
| `settings.gradle` | 声明 `:app` 模块 |
| `build.gradle` | 根脚本，AGP 8.5.2 |
| `gradle.properties` | JVM 参数 |
| `app/build.gradle` | 路径映射、ndk-build 集成、ABI 过滤 |
| `.github/workflows/build-apk.yml` | Go → AAR → NDK → APK |
| `.gitignore` | 排除产物与备份 |

> 根目录的 `build-app.gradle` 是早期试错残留，已标注废弃，删掉不影响。

## 三、三个必须理解的约束

### 1. Java 依赖 gomobile 生成的类

```java
import com.x.tunnel.tunnel.Tunnel;
```

由 `gomobile bind -javapkg com.x.tunnel` 生成（`-javapkg` + Go 包名 `tunnel` = `com.x.tunnel.tunnel`）。
**这个参数不能省**。

### 2. 两个 `.so` 来自两条链路

| 库 | 来源 | 职责 |
|---|---|---|
| `libgojni.so` | gomobile AAR | Go 核心：xhttp、ECH、SOCKS5 |
| `libhev-socks5-tunnel.so` | ndk-build（`src/main/jni/`） | VPN 数据面 |

### 3. minSdk 锁 29

`Application.mk` 里 `APP_PLATFORM := android-29`，Gradle `minSdk` 和 gomobile `-androidapi` 都已对齐到 29。

## 四、怎么跑

```bash
cd x-tunnel-android-src
git init && git add . && git commit -m "xhttp + gomobile bind"
git branch -M main
git remote add origin <你的仓库>
git push -u origin main
```

push 后自动触发，或 Actions 页手动 Run workflow。

产物：**Artifacts → x-tunnel-unsigned-apk** → `app-release-unsigned.apk`

## 五、本地签名

```bash
keytool -genkeypair -v -keystore my.jks -keyalg RSA -keysize 2048 -validity 10000 -alias mykey
zipalign -v -p 4 app-release-unsigned.apk app-aligned.apk
apksigner sign --ks my.jks --ks-key-alias mykey --out app-signed.apk app-aligned.apk
```

## 六、可能遇到的问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `cannot find symbol: Tunnel` | 缺 `-javapkg` | 检查 workflow |
| `no Go files in ...` | `.go` 不在根目录 | 两个 `.go` 必须在仓库根 |
| `bind: package main` | 包名没改 | 确认是 `package tunnel` |
| APK 里没有 `libhev-*.so` | ndk-build 没跑 | 看 `externalNativeBuild` 日志 |
| 装上后连接失败 | ECH DNS 被挡 | 界面上勾「禁用 ECH」 |
| `undefined: ECHPool.ctx` | 用了旧版 xtunnel.go | 用当前这版 |
| `gomobile bind requires golang.org/x/mobile in the current module` | 新版 gomobile 要求该依赖进入模块依赖图，仅 `go install` 不够 | workflow 里用 `go get -tool` 记录到 go.mod（已修） |
| `go get -tool` 报 unknown flag | Go 版本 < 1.24 | workflow 已固定 `go-version: '1.24'` |
| `package github.com/xtaci/smux is not in std` | 漏了源码依赖 | 已补 `go get github.com/xtaci/smux@latest` |

## 七、说明

- 只产出**未签名** APK，签名在本地完成。
- 未修改任何 Java / JNI 源码。
- 本地无 Go / NDK / Android SDK，**未实跑构建**；配置按工程实际结构与工具版本要求编写，首次构建若报错请贴日志。
