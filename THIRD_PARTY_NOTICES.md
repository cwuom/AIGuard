# 第三方声明

AIGuard（AI 出差管家）本身以 GPL-3.0 发布，见 [LICENSE](LICENSE)。构建出的 App 和 DMG 打包了下列第三方组件和数据，它们各自遵循原许可证。

## mihomo

- 项目：https://github.com/MetaCubeX/mihomo
- 用途：代理内核，以独立进程运行，打包为 `Contents/Resources/mihomo`
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
- 用途：`Sources/AIGuardCore/AIRuleCatalog.swift` 中 AI 域名名单的主要来源（`category-ai-!cn` 及其子列表）
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
