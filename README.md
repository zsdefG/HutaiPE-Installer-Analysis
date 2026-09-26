# 东莞虎泰 PE 装机工具系列 · 恶意行为同源逆向分析

> **取证性质的安全研究报告** —— 针对 **东莞虎泰网络科技有限公司**（统一社会信用代码 `91441900MA4WJXLR19`）旗下三款 PE 装机工具
> **大白菜（DaBaiCai）/ 老毛桃（LaoMaoTao）/ 电脑店（DianNaoDian）** 的**纯静态逆向分析**，
> 以哈希级证据证明三者属于**同一恶意代码体系**，并还原其关闭系统防护、篡改安全软件白名单、伪装驱动、捆绑推广、远程下载执行等恶意行为。
>
> ⚠️ **本仓库不含任何可执行样本**（exe / dll / 加壳模块 / 加密压缩载荷）。分析对象为受恶意代码感染的软件，
> 请勿下载、传播或运行原始样本。详见 [安全与法律声明](#十二安全与法律声明)。

---

## 目录

1. [项目背景](#一项目背景)
2. [致谢](#二致谢)
3. [核心结论（摘要）](#三核心结论摘要)
4. [样本信息（三品牌）](#四样本信息三品牌)
5. [同源证据矩阵](#五同源证据矩阵)
6. [统一逆向方法论（可复现）](#六统一逆向方法论可复现)
7. [密码清单](#七密码清单)
8. [恶意行为罪证清单](#八恶意行为罪证清单)
9. [分析局限性](#九分析局限性)
10. [仓库结构](#十仓库结构)
11. [复现指南](#十一复现指南)
12. [安全与法律声明](#十二安全与法律声明)

---

## 一、项目背景

三款产品均为面向普通用户的 PE 启动盘 / 系统安装工具，分别以"大白菜"、"老毛桃"、"电脑店"为品牌在多个渠道发行。
安装 / 使用完成后，它们会：

- **静默关闭 Windows 安全防护**（UAC、防火墙、安全软件服务）；
- **篡改 360 安全软件白名单数据库**，使自身免于查杀；
- **将恶意载荷伪装成系统驱动 / 系统文件**（`.SYS` / `.bin` 实为 7-Zip 压缩包）安装；
- **执行后立即销毁源文件**，压缩静态取证窗口；
- **捆绑安装推广软件**，且官方免责声明未对此作出披露；
- **携带已确认的木马组件**（`Dlg86.dll` → `Wacatac.H!ml`、`Hi.exe` → `Ymacco!rfn`）；
- **内置远程下载执行组件**（`DNDUpdate.exe`，`/downexec` 直接"下载即执行"）。

本仓库通过三个独立品牌样本的**纯静态逆向**与**三方哈希比对**，将这些行为落实到**代码级 / 配置级 / 哈希级**证据。

**分析声明**：全部分析在隔离环境下完成，**从未在宿主系统运行样本**；
使用 Ghidra 12.1.4、Capstone、7-Zip、自研 PECMD CMPa 解密脚本等工具完成。

---

## 二、致谢

本研究的许多关键素材直接来自 **B 站用户 [SYSTEM-RAMOS-ZDY]**，包括但不限于：

- **逆向文件**：原始样本的获取与初步解包文件；
- **解压密码**：多层加密压缩包的解压口令；
- **样本溯源线索**：PE 工具发行渠道与版本的追踪信息。

在此对 SYSTEM-RAMOS-ZDY 的前期工作与无私分享表示诚挚感谢。
没有这些基础素材，本报告的代码级与配置级还原将无法完成。

> 说明：上述素材仅用于安全研究与取证目的，请勿用于任何非法用途。

---

## 三、核心结论（摘要）

| # | 核心结论 | 证据强度 | 证据位置 |
|---|---|---|---|
| 1 | **三品牌同一公司出品、同一恶意代码体系**（东莞虎泰网络科技有限公司，统一社会信用代码 `91441900MA4WJXLR19`） | 签名级 + 哈希级 | 数字签名 / 资源 SHA-256 比对 |
| 2 | **核心载荷 RCDATA 资源高度同源**：电脑店 `Sysset.exe` 与大白菜 `SetSys.exe` 22/27、与老毛桃 `TaoSet.exe` 23/27 逐字节相同；三方**完全一致**的共有资源达 22 个（含 `DEPLOY` / `SECURCONF` / `AFTER` / `TOPDRVIER` 等关键恶意载荷） | 哈希级（逐字节） | 资源比对脚本 |
| 3 | **木马组件三品牌逐字节一致**：`Dlg86.dll`（`f801eb9f…`，检出 `Wacatac.H!ml`）、`Hi.exe`（`384d42ef…`，检出 `Ymacco!rfn`） | 哈希级（逐字节） | 样本哈希 |
| 4 | **关闭 UAC / 防火墙**：`EnableLUA` / `ConsentPromptBehaviorAdmin` / `PromptOnSecureDesktop` 写 0，防火墙双配置 `EnableFirewall` 写 0（PE 内还有明文 `wpeutil DisableFirewall`） | 代码级（明文反汇编 / 明文脚本） | `DEPLOY` 函数 `0x10007E80` / 10PE64 PECMD L158 |
| 5 | **删除 / 处置安全软件**：内置 `CDelSecuritySoft` 类 + 服务管理器 API（最终调用被 VMProtect 虚拟化） | 机制级（RTTI + 导入表） | `DEPLOY` |
| 6 | **篡改 360 白名单**：携带 360 数据库文件（`360ss2.dat` / `ignorelist.ini` / `sl2.db` 等）写入忽略列表 | 配置级 | `RCDATA\360SAFE` |
| 7 | **驱动伪装 + 签名白名单 + 分目录密码表**：12 个随机名驱动服务、11 个厂商签名放行、14 组目标目录解压密码（`RES1` 明文） | 配置级 | `RCDATA\RES1` |
| 8 | **捆绑推广且未披露**：推广 URL + 压缩包伪装驱动静默安装；官方免责声明未提及 | 配置级 + 文档级 | `RES1` / 官方网页存档 PDF |
| 9 | **远程下载执行**：`DNDUpdate.exe`（`/type:10/11 /downexec`、`-startup`）；更新清单暴露 CDN `https://downdnd.softdownb.com:9002/v2/` | 机制级 + 配置级 | `Data\Hash` / NEI 脚本 |
| 10 | **多层对抗检测**：自写壳 / VMProtect / UPX / CMPa 加密 / 7z 魔数篡改（`37 7A`→`54 78`）/ 零字符串 | 技术级 | 全部核心模块 |

---

## 四、样本信息（三品牌）

### 4.1 大白菜（DaBaiCai）

| 项目 | 内容 |
|---|---|
| 主安装器 | `DaBaiCai_d30_v6.0_2606_Online.exe`（5.4 MB，自写壳 `.text` 全加密） |
| 数字签名 | 东莞虎泰网络科技有限公司 |
| 内嵌核心组件 | `SetSys.exe`（9.7 MB，自写壳 `.itext/.didata`） |
| 关键资源 | `RCDATA\DEPLOY`（2.7 MB，VMProtect）、`AFTER`（NSIS v3.01）、`360SAFE`、`RES1`、`SECURCONF`、`TOPDRVIER(_X64)`、`7Z/7ZA` |
| 杀软检出 | `Trojan:Win32/Wacatac.B!ml`、`Wacatac.H!ml`、`Ymacco!rfn` |

### 4.2 老毛桃（LaoMaoTao）

| 项目 | 内容 |
|---|---|
| 样本包 | `LaoMaoTao.7z`（外层 7z 未加密，内层统一密码 `8A86Jxp@EZj!@SY3`） |
| 启动程序 | `work\LaoMaoTao.exe` |
| 数字签名 | 东莞虎泰网络科技有限公司（与大白菜同一主体） |
| PE 镜像 | `03PE.wim` / `10PE64.wim` / `UD.7z` / `Boot.7z` / `Driver.7z` 等 |
| 核心载荷 | `TaoSet.exe`（8,886,272 B）、`Hi.exe`（540,160 B）、`Dlg86.dll`（344,576 B）、`Dlg64.dll`（378,880 B）、`Apple.exe`（1,012,736 B）、`LOADSYS.EXE` |
| 伪装驱动 | `IntelRaid.sys` / `APPLEDRV.SYS` / `AppleDrv.sys` / `ACP.SYS` / `IO.SYS`（实为 7-Zip 压缩包） |
| 杀软检出 | `Hi.exe` → `Ymacco!rfn`；`Dlg86.dll` → `Wacatac.H!ml` |

### 4.3 电脑店（DianNaoDian）

| 项目 | 内容 |
|---|---|
| 样本包 | `DianNaoDian_v7.5_2609.zip`（ZIP 无密码，1.55 GB） |
| 版本 | `7.5.2606.12`（`Data\Config`） |
| 启动程序 | `DianNaoDian.exe`（Delphi + `.itext/.didata` 自写壳；**官方有效签名 = 东莞虎泰网络科技有限公司**，统一社会信用代码 `91441900MA4WJXLR19`） |
| PE 镜像 | `10PE64.wim`（334 MB）/ `03PE.wim`（67 MB） |
| 核心载荷 | `Sysset.exe`（8,752,128 B，UPX 壳，无签名）、`Hi.exe`（542,720 B）、`Dlg86.dll`（344,576 B）、`Dlg64.dll`、`Apple.exe`、`ACP.exe`、`LOADSYS.EXE`、`DNDUpdate.exe`（812,544 B，UPX 壳，无签名） |
| 伪装驱动 | `IntelRaid.sys` / `PW.bin` / `ACP.SYS` / `AppleDrv.sys`（实为 7-Zip 压缩包） |
| 杀软检出 | `Dlg86.dll` → `Wacatac.H!ml` |

---

## 五、同源证据矩阵

| 证据项 | 大白菜 | 老毛桃 | 电脑店 |
|---|---|---|---|
| **签名主体** | 东莞虎泰 | 东莞虎泰（同一主体） | 东莞虎泰（`DianNaoDian.exe` **官方有效签名**） |
| **核心载荷** | `SetSys.exe` | `TaoSet.exe` | `Sysset.exe` |
| **载荷资源两两比对** | — | 白菜↔老毛桃 **23/27** 逐字节相同 | 电脑店↔白菜 **22/27**；电脑店↔老毛桃 **23/27** |
| **三方逐字节一致的 22 个资源** | `7Z` `7ZA` `AFTER` `DEPLOY` `DOSBOX` `DVCLAL` `FBINST` `NET` `None` `RES2` `RES3` `RESH11` `RESH12` `RESH21` `RESH22` `RESP` `SECURCONF` `SWAPADD` `SWAPADD64` `TNOTICEFORM` `TOPDRVIER` `TOPDRVIER_X64` | 同 | 同 |
| **`Dlg86.dll`**（`Wacatac.H!ml`） | `f801eb9f…` | 逐字节一致 | 逐字节一致 |
| **`Hi.exe`**（`Ymacco!rfn`） | `384d42ef…` | 逐字节一致 | 同源（被搬运到 `SysWOW64` 生效；未断言逐字节） |
| **`RES1` 明文操作配置** | 200,787 B | 208,633 B | 208,633 B（**=老毛桃逐字节相同**） |
| **`PECMD` / `NEI` 内嵌脚本** | — | 前缀 `LMT` / `ILMT` | 前缀 `DND` / `IDND`（**逐行对应改名**） |
| **伪驱动手法** | `IntelRaid.sys`（7z 魔数 `37 7A`→`54 78`） | 同款（6 个 `.SYS`/`.bin`） | 同款（4 个） |
| **内层主包密码** | — | `8A86Jxp@EZj!@SY3` | `Data\Xkdonz` 三包复用同一密码（**一次性全部破解**） |
| **10PE64 解压密码** | — | `F2554E…` / `893FD5…` | 与老毛桃**逐字符相同** |
| **远程更新组件** | （未公开样本） | `LMTUpdate.exe` + `update.json` | `DNDUpdate.exe` + `Data\Hash` 清单（CDN `downdnd.softdownb.com:9002/v2/`） |

> 差异项均为版本更新（`360SAFE`、`RES1`、`SCJ1`、`TEST`、`PACKAGEINFO` 等），
> 说明三品牌共用一套代码基座，仅做品牌化改名与少量配置更新后分渠道发行。

---

## 六、统一逆向方法论（可复现）

三份品牌报告的逆向路径完全一致，可归纳为六个阶段：

### 阶段一：解包与外层密码提取
- 用 7-Zip 解包外层（exe 自解压 / zip / 7z）。
- 从启动程序（`LaoMaoTao.exe` / `DianNaoDian.exe`）字符串与配置中提取**硬编码主密码**（老毛桃内层主包 / 电脑店 `Xkdonz` 三包共用 `8A86Jxp@EZj!@SY3`）。

### 阶段二：PECMD CMPa 解密
PE 镜像内的 `PECMD.INI` 以 **CMPa 格式加密**（mode=0x14），使用 `cmpa_official.py`（官方 daiaji/pecmd-decompile 算法）还原明文（约 30 KB）。还原后逐行定位：

- **解压密码行**（`7-Zip\ZipFile_7z.exe x ... -p<密码>`）；
- **执行链**（`EXEC ...\SysSet.EXE` / `Taoset.EXE` 等核心载荷）；
- **销毁链**（`FILE <源文件>` 解压后立即删除）；
- **远程组件链**（`DNDUpdate.exe -startup` / `/type:10 /downexec`）。

关键明文示例（电脑店 10PE64）：
```
L158 EXEC !wpeutil.exe DisableFirewall
L196 EXEC *=...7z.exe x "...\Drivers\IntelRaid.sys" -pF2554EF7FE28DDC5896ACCBB36FCF97A
L197 EXEC *=...7z.exe x "...\安装维护\PW.bin" -p893FD5B3CD2D027CD7F205CBDE11AA75
L198 FILE %ProgramFiles%\安装维护\PW.bin
L201 FILE ...\DNDPE.EXE|FILE ...\Drivers\IntelRaid.sys
L209 EXEC X:\Windows\System32\SysSet.EXE
```

### 阶段三：伪驱动魔数恢复
`.SYS` / `.bin` 文件头 2 字节被篡改为 `54 78`（"Tx"），**恢复为 7z 魔数 `37 7A`** 后即可解压得到真实载荷（`Sysset.exe` / `Hi.exe` / `Dlg86.dll` / `devconx64.exe` / `NEI` / `PESET` / `Task2` 等）。

### 阶段四：资源 dump 与三方哈希比对
- 用 `pefile` / 7-Zip 提取核心载荷的全部 RCDATA 资源（大白菜 `DBC_*`、老毛桃 `LMT_*`、电脑店 `DND_*`）。
- 逐资源 SHA-256 两两比对（`dnd_cmp2.py`），得到 22/27、23/27、23/27 的同源矩阵。

### 阶段五：代码级反汇编（Ghidra + Capstone）
- **Ghidra 12.1.4 headless** 自动分析 `DEPLOY`（VMProtect 虚拟化模块）。
- **Capstone 脚本族**还原明文函数：`DEPLOY 0x10007E80` 逐指令还原"关闭 UAC + 防火墙"5 个注册表键写入（经 `qcutil::CWinRegKey`，写 `HKLM` DWORD 0）。
- **RTTI 定位**：`.?AVIDelSecuritySoft@@` → `CDelSecuritySoft`（"删除安全软件"类）+ 服务管理 API 导入（`OpenSCManagerW → EnumServicesStatusExW → OpenServiceW → QueryServiceConfigW`）。
- **排除性排查**：扫描 `AFTER`（NSIS）与主安装器，确认关闭安全软件行为集中于 `DEPLOY`。

### 阶段六：操作配置与远程组件
- **`RES1` 明文解读**：`[drivers]` 12 个随机名驱动服务、`[signature]` 11 个厂商签名放行、`[attributes]` 驱动识别规则、`[7z]` 14 组目标目录解压密码表 + 内嵌 URL `https://windows.sydxwl.cn/`。
- **远程组件**：`DNDUpdate.exe`（UPX 壳，导入 `URLMON/wininet`），`Data\Hash` 更新清单暴露下发服务器 `https://downdnd.softdownb.com:9002/v2/`（含 `DianNaoDian.7z` / `Bin.7z` 及逐文件 SHA-256）。

---

## 七、密码清单

所有密码均从**启动程序内提取**或从 **PECMD / NEI 明文脚本**中读取，非暴力破解（`SUPPORT.IMG*` 除外）。

| # | 用途 | 品牌 | 密码 |
|---|---|---|---|
| 1 | 内层主包 / `Data\Xkdonz` 三包 | 老毛桃 / 电脑店 | `8A86Jxp@EZj!@SY3` |
| 2 | 03PE `IntelRaid.sys` | 老毛桃 | `0601518C128831244F3239CF2D7CE2E3` |
| 3 | 10PE64 `IntelRaid.sys` | 老毛桃 / 电脑店 | `F2554EF7FE28DDC5896ACCBB36FCF97A` |
| 4 | `PW.bin` | 老毛桃 / 电脑店 | `893FD5B3CD2D027CD7F205CBDE11AA75` |
| 5 | `ACP.SYS` / `AppleDrv.sys` / `IO.SYS`（老毛桃 10PE64）；03PE `IntelRaid.sys` / `ACP.SYS` / `AppleDrv.sys`（电脑店） | 老毛桃 / 电脑店 | `4469616e4e616f4469616e32303137474f`（ASCII：`DianNaoDian2017GO`） |
| 6 | 03PE `APPLEDRV.SYS` | 老毛桃 | `亿维凌DND15553676811`（NEI 脚本明文） |
| 7 | `RES1 [7z]` 目标目录部署密码（14 组，`DecodeXor1` = XOR 解码标志） | 大白菜 / 老毛桃 / 电脑店 | `qazwsx`、`qq123456`、`CUc_sndf23dne`、`DHsf_dysfe273391`、`10CcaCrLeC`、`11#6b9Dzxk`、`1022H2Dzxk`、`11ibWSnULxPg`、`11Ng6CycqxS&CWS*Ce`、`11RSLGwzbgeDQ32m3y`、`11jqlJgPgAs2nXs8tG` |
| 未破 | `SUPPORT.IMG*`（约 88 MB 加密镜像） | 老毛桃 | —（**当前唯一未决项**） |

> 备注：`Data\Xkdonz\Boot.7z` / `Other.7z` / `Ver.7z` 为**头部加密**（连文件名均隐藏），复用老毛桃主密码一次性全部破解；`Ver.7z` 内容 `Ver.ini` 显示构建日期 `20260918`。

---

## 八、恶意行为罪证清单

1. **官方签名主体 = 东莞虎泰网络科技有限公司**（电脑店 `DianNaoDian.exe` 官方有效签名，统一社会信用代码 `91441900MA4WJXLR19`），三品牌同一公司、同一恶意代码体系。
2. **静默关闭系统防护**：UAC 三策略项（`EnableLUA` / `ConsentPromptBehaviorAdmin` / `PromptOnSecureDesktop`）+ 防火墙双配置文件 `EnableFirewall` 全部置 0（大白菜 `DEPLOY 0x10007E80` 代码级证据；电脑店 PE 内另有明文 `wpeutil DisableFirewall`）。
3. **删除 / 处置安全软件**：内置 `CDelSecuritySoft` 类，经服务管理器 API 枚举并处置安全软件服务；最终调用被 VMProtect 虚拟化隐藏。
4. **篡改 360 白名单**：`RCDATA\360SAFE` 携带 360 数据库文件（`360ss2.dat` / `ignorelist.ini` / `sl2.db` / `speedmem2.hg` 等）写入忽略列表，使自身免于查杀。
5. **压缩包伪装成驱动**：`IntelRaid.sys` / `PW.bin` / `ACP.SYS` / `AppleDrv.sys` / `APPLEDRV.SYS` / `IO.SYS` 等 `.SYS`/`.bin` 文件实为 7-Zip 压缩包（魔数 `37 7A` 篡改为 `54 78`），在 PE 启动阶段解压并安装。
6. **执行后销毁证据**：解压→执行→立即 `FILE` 删除源文件（`LOADSYS.EXE`、`IntelRaid.sys`、`PW.bin`、`ReadDMI.EXE`、`LMTPE.EXE` / `DNDPE.EXE`），静态取证窗口被刻意压缩。
7. **驱动服务注册 + 签名白名单 + 分目录密码表**：`RES1` 明文配置注册 12 个随机名服务（`adkirs`/`xjwsks`/`wupxbxets` 等）、放行 11 个厂商签名、按目标目录（`Windows\Web\`、`Windows\Speech\` 等）硬编码 14 组解压密码；`Windows\Speech\...` 含大量故意拼错路径变体（`Comnon/Conmon/Cammon…`）规避路径匹配。
8. **捆绑推广且未披露**：推广 URL（`uqb.yxyxxfw.cn` / `uqb.ndlkj.cn` / `windows.sydxwl.cn`）+ 压缩包伪装驱动静默安装推广软件；官方免责声明**未提及"为用户下载推荐应用"**，与实际行为不符。
9. **携带已确认木马组件**：`Dlg86.dll`（`f801eb9f…`，`Wacatac.H!ml`）、`Hi.exe`（`384d42ef…`，`Ymacco!rfn`）三品牌逐字节一致，且在 PE 启动阶段被主动搬运到 `SysWOW64` 生效（`Dlg86.DLL AppleHFS.SYS` 以"注册驱动"方式安装）。
10. **远程下载执行组件**：`DNDUpdate.exe`（UPX 壳）经 `URLMON/wininet` 下载，`/type:10/11 /downexec` 参数直接"下载并执行"网页浏览器 / ToDesk 组件，`-startup` 开机自启；`Data\Hash` 更新清单暴露下发服务器 `https://downdnd.softdownb.com:9002/v2/`。
11. **多层对抗检测**：自写壳（`.text` 全加密 / `.itext/.didata`）、VMProtect 虚拟化（`.vmp0/.vmp1`）、UPX 压缩壳、PECMD CMPa 加密、7z 魔数篡改、载荷全部无签名、`Hi.exe`/`Dlg86.dll` 零字符串。

---

## 九、分析局限性

- **VMProtect 虚拟化边界**：`CDelSecuritySoft` 方法体及"关闭 Windows Defender"的最终 API 调用（停止/删除服务）被虚拟化，**纯静态无法还原逐条指令**。已通过类名、导入表、调用链三种证据锁定其功能。
- **UPX 压缩壳**：`DNDUpdate.exe` 的远程 URL 因 UPX 压缩未从二进制中静态提取；但 `Data\Hash` 更新清单已暴露下发服务器与分发路径。
- **唯一未决项**：老毛桃 `SUPPORT.IMG*`（约 88 MB 加密镜像）密码未破解，内容未知；`10.7z` / `Net.7z` 等部分内层压缩包密码未破。
- **RES1 [7z] 载荷未实采**：密码表对应的目标目录载荷位于目标系统内，需在目标环境动态取证。
- **获取逐 API 铁证**需在 Hyper-V 隔离虚拟机中动态运行（API Monitor / Procmon），本仓库基于"不运行样本"原则未包含该部分。
- 大白菜官方网页存档 PDF（免责声明 / 用户协议）为二进制文件，未随仓库发布，原件留档于分析者本地。

---

## 十、仓库结构

```
.
├── README.md                      ← 本文件（三品牌综合报告）
├── 样本说明.txt                    ← 为何不含原始样本
├── baicai/                        ← 大白菜（DaBaiCai）
│   ├── README_逆向分析报告.md
│   ├── 提取证据/                   ← RES1/SECURCONF/360SAFE/DEPLOY 文本化证据
│   └── 逆向脚本/                   ← 25 个可复现脚本
├── laomaotao/                     ← 老毛桃（LaoMaoTao）
│   ├── README_逆向分析报告.md
│   └── 逆向脚本/                   ← 22 个可复现脚本
└── diannaodian/                   ← 电脑店（DianNaoDian）
    ├── README_逆向分析报告.md
    └── 逆向脚本/                   ← 5 个可复现脚本
```

---

## 十一、复现指南

依赖：`7-Zip`、`Python 3.12+`（`pefile`、`capstone`）、`JDK 21+`、`Ghidra 12.1.4`

```bash
# 1. 解包外层（以电脑店为例）
7z x DianNaoDian_v7.5_2609.zip
7z x 10PE64.wim -oextract10

# 2. 解密 PECMD（CMPa 格式）
python laomaotao/逆向脚本/cmpa_official.py PECMD.INI > PECMD.INI.dec.txt

# 3. 伪驱动魔数恢复后解压
#    将 IntelRaid.sys 文件头 2 字节 54 78 改回 37 7A，另存为 .7z
7z x IntelRaid_fixed.7z -pF2554EF7FE28DDC5896ACCBB36FCF97A -oraid_unpacked

# 4. 核心载荷资源 dump + 三方比对
python diannaodian/逆向脚本/dnd_rsrc_dump.py Sysset.exe
python diannaodian/逆向脚本/dnd_cmp2.py

# 5. Ghidra 自动分析 DEPLOY
analyzeHeadless.bat proj DEPLOY -import <DEPLOY路径> -analysisTimeoutPerFile 600

# 6. 还原注册表写入逻辑（大白菜）
python baicai/逆向脚本/scan_reg_strings.py
python baicai/逆向脚本/dump_reg_core.py
python baicai/逆向脚本/find_all_reg_writes.py
```

> 脚本输入路径为分析时的绝对路径，复现时请按需修改为本地路径。

---

## 十二、安全与法律声明

1. **本仓库不含恶意样本**，仅包含分析报告、逆向脚本与配置级/文本化证据。
2. 原始样本保留在分析者的隔离环境（已配置杀软豁免），**请勿索取、传播或运行**。
3. 本报告基于静态分析结论，证据强度已在各章节标注；如需法律用途，
   建议在司法鉴定机构监督下补充动态取证与哈希链完整性校验。
4. 相关品牌官方页面 / 免责声明存档仅用于对照其未尽披露义务。
5. 发现可疑安装残留，处置建议：彻底卸载该工具、核查已装推广软件、检查
   `HKLM\SYSTEM\ControlSet001\Services` 下随机名驱动服务、检查 `Windows\Web\` 与
   `Windows\Speech\` 目录残留；鉴于 UAC / 防火墙 / 安全软件已被代码级确认会被关闭，
   建议在干净主机上重装系统。

---

*分析日期：2026-09-25 至 2026-09-26　|　方法：纯静态逆向　|　状态：取证留档*
