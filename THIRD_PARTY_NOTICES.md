# 第三方声明

AIGuard（AI 出差管家）本身以 GPL-3.0 发布，见 [LICENSE](LICENSE)。构建出的 macOS App / DMG、Android APK 与 Windows zip 打包了下列第三方组件和数据，它们各自遵循原许可证。

## mihomo

- 项目：https://github.com/MetaCubeX/mihomo
- 用途：代理内核，以独立进程运行。macOS 打包为 `Contents/Resources/mihomo`；Android 打包 `mihomo-android-arm64-v8` 为 APK 的 `assets/core/mihomo`，由守护进程释放到 `/data/adb/aiguard/bin/`；Windows 打包 `mihomo-windows-amd64-v1` / `mihomo-windows-arm64` 为 `core\mihomo.exe`（其中内嵌了 WireGuard LLC 发布的 wintun 驱动，按 wintun 的预编译二进制许可原样分发）
- 许可证：MIT，原文如下

```
Copyright 2023 KT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.```

## meta-rules-dat

- 项目：https://github.com/MetaCubeX/meta-rules-dat
- 用途：打包的规则数据 `geosite-cn.mrs`、`geoip-cn.mrs`、`geosite-anthropic.mrs`、`geosite-category-ntp.mrs`，以及由 `geoip/cn.list` 合并网段生成的 `cn4.txt`
- 许可证：GPL-3.0，全文与本项目的 [LICENSE](LICENSE) 相同

## domain-list-community

- 项目：https://github.com/v2fly/domain-list-community
- 用途：`Sources/AIGuardCore/AIRuleCatalog.swift` 与 `android/core/.../AIRuleCatalog.kt` 中 AI 域名名单的主要来源（`category-ai-!cn` 及其子列表）
- 许可证：MIT，原文如下

```
MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ios_rule_script

- 项目：https://github.com/blackmatrix7/ios_rule_script
- 用途：参考了 OpenAI、Claude、Gemini、Copilot 规则中的部分域名条目，与上面的名单合并去重
- 许可证：GPL-2.0

## Android 版依赖库

APK 内以字节码形式包含以下库，均为 Apache License 2.0（与 GPL-3.0 兼容），全文见 https://www.apache.org/licenses/LICENSE-2.0 ：

| 组件 | 项目 |
|---|---|
| Kotlin 标准库、kotlinx.coroutines、kotlinx.serialization | https://github.com/JetBrains/kotlin 、https://github.com/Kotlin/kotlinx.coroutines 、https://github.com/Kotlin/kotlinx.serialization |
| OkHttp、Okio | https://github.com/square/okhttp 、https://github.com/square/okio |
| AndroidX（Core、Activity、Lifecycle）与 Jetpack Compose（含 Material 3、Material Icons） | https://android.googlesource.com/platform/frameworks/support |

OkHttp 内置的公共后缀列表（`PublicSuffixDatabase.list`）来自 https://publicsuffix.org ，遵循 MPL-2.0。

## Windows 版依赖

`aiguard-service.exe` 与 `AIGuard.exe` 静态链接了下列 Go 模块（以 `go version -m` 读出的为准），均与 GPL-3.0 兼容：

| 组件 | 项目 | 许可证 | 版权 |
|---|---|---|---|
| Wails v3 | https://github.com/wailsapp/wails | MIT | Copyright (c) 2018-Present Lea Anthony |
| go-ole | https://github.com/go-ole/go-ole | MIT | Copyright © 2013-2017 Yasuhiro Matsumoto |
| go-winio | https://github.com/microsoft/go-winio | MIT | Copyright (c) 2015 Microsoft |
| wireguard-windows（`tunnel/winipcfg`） | https://git.zx2c4.com/wireguard-windows | MIT | Copyright (C) 2018-2026 WireGuard LLC |
| wf（tailscale/wf，修改版位于 `windows/third_party/wf`） | https://github.com/tailscale/wf | BSD-3-Clause | Copyright (c) 2021 The Inet.af AUTHORS |
| netipx | https://github.com/go4org/netipx | BSD-3-Clause | Copyright (c) 2020 The Inet.af AUTHORS |
| golang.org/x/sys | https://go.googlesource.com/sys | BSD-3-Clause | Copyright 2009 The Go Authors |

界面内嵌的 Apache ECharts 6.1.0（`windows/cmd/aiguard/frontend/vendor/echarts.min.js`）遵循 Apache License 2.0，原文与 NOTICE 随文件放在同一目录。

上表中 MIT 许可的组件适用以下条款（各自的版权声明见上表）：

```
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

上表中 BSD-3-Clause 许可的组件适用以下条款（各自的版权声明见上表，「the copyright holder」指对应的版权方）：

```
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   * Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
