# 老毛桃 PE 装机工具 — 逆向分析报告（罪证留存）

> 本报告为**纯静态逆向分析**产物，样本从未在宿主机运行。
> 分析对象：`LaoMaoTao.7z`（含启动程序 `LaoMaoTao.exe` 及 PE 镜像包）
> 签名主体：东莞虎泰网络科技有限公司（与大白菜 PE 装机工具**同一签名主体**）
> 分析日期：2026-09-26（2026-09-27 更新：行为 7 大白菜实机证据）
> 分析工具链：7-Zip / Python（pefile、capstone）/ 自研 PECMD 解密脚本 / FAT 镜像解析器
> 对照基准：大白菜逆向分析报告（`..\baicai\某白菜PE装机工具+取证工具留档\README_逆向分析报告.md`）

---

## 〇、素材来源与同源说明

- 样本 `LaoMaoTao.7z` 为本地留档，内层压缩包统一使用硬编码密码 `8A86Jxp@EZj!@SY3`（从启动程序内提取，与大白菜同款密码管理方式）。
- 本次分析发现老毛桃与大白菜**高度同源**：同一签名主体、相同的"压缩包伪装成驱动"手法、核心载荷 `TaoSet.exe` 与大白菜 `SetSys.exe` 的 RCDATA 资源 23/27 个 SHA-256 逐字节相同、`Hi.exe` / `Dlg86.dll` 与白菜样本逐字节一致。
- 因此大白菜报告中已证实的行为（关闭 UAC / 防火墙、`CDelSecuritySoft` 删除安全软件、篡改 360 白名单、捆绑推广）在本报告中作为**同源继承行为**引用，并标注其原始证据出处。

---

## 一、样本信息

| 项目 | 内容 |
|---|---|
| 样本包 | `LaoMaoTao.7z`（外层 7z 未加密，内层统一密码 `8A86Jxp@EZj!@SY3`） |
| 启动程序 | `work\LaoMaoTao.exe` |
| 签名主体 | 东莞虎泰网络科技有限公司（与大白菜同一主体） |
| PE 镜像 | `03PE.wim` / `10PE64.wim` / `UD.7z` / `Boot.7z` / `Driver.7z` 等 |
| 核心载荷 | `TaoSet.exe`（8,886,272 B）、`Hi.exe`（540,160 B）、`Dlg86.dll`（344,576 B）、`Dlg64.dll`（378,880 B）、`Apple.exe`（1,012,736 B）、`LOADSYS.EXE`（~158 KB） |
| 伪装驱动 | `IntelRaid.sys` / `APPLEDRV.SYS` / `AppleDrv.sys` / `ACP.SYS` / `IO.SYS`（实为 7-Zip 压缩包） |
| 杀软检出 | `Hi.exe` → **Ymacco!rfn**；`Dlg86.dll` → **Wacatac.H!ml**（与大白菜样本逐字节一致） |

**样本与解包产物全部保留**于 `my\laomaotao\`：
- `LaoMaoTao.7z` / `work\`（解包及 PE 镜像）
- `work\pkg\pe_scripts\PECMD.INI.plain.txt`（03PE PECMD 明文）
- `work\pkg\pe_scripts\10pe64_pcmd\PECMD.INI.dec.txt`（10PE64 PECMD 明文）
- `work\pkg\pe_scripts\pe10_raid\unpacked\`（10PE64 伪驱动载荷 16 文件）
- `work\pkg\pe_scripts\pe10_pw\unpacked\NTPWEDIT.EXE`（PW.bin 载荷）
- `work\pkg\pe_scripts\raid_payload\NEI.dec.txt` / `Task2.dec.txt`（PECMD 内嵌脚本明文）
- `work\pkg\pe_scripts\appledrv\`（03PE APPLEDRV.SYS 解包载荷）
- `work\pkg\pe_scripts\taoset_rsrc\LMT_*`（TaoSet.exe 资源提取，27 个）
- `work\unpack\UD\ILMT\ILMT\IMGS\`（GRUB 引用的 5 个常规 IMG + SUPPORT.IMG* 加密镜像）

---

## 二、逆向步骤（可复现）

### 1. 解包与主密码提取
```
D:\7-Zip\7z.exe x LaoMaoTao.7z            ← 外层未加密
D:\7-Zip\7z.exe x <内层7z> -p8A86Jxp@EZj!@SY3
```
内层压缩包全部使用硬编码密码 `8A86Jxp@EZj!@SY3`（与启动程序内提取结果一致）。

### 2. PECMD 脚本解密（CMPa 加密）
PECMD 脚本以 CMPa 格式加密，使用 `cmpa_official.py`（官方 daiaji/pecmd-decompile 算法，mode=0x14）还原明文：
- 03PE `PECMD.INI` → `PECMD.INI.plain.txt`
- 10PE64 `PECMD.INI` → `10pe64_pcmd\PECMD.INI.dec.txt`
- 内嵌脚本 `NEI` / `PESET` / `Task2` / `ApplePT` → 各自 `.dec.txt`

> 备用解密路线（本次验证成功）：CMPa 头格式为 `00 00 00 00 43 4D 50 61 <4字节key> 00 00 00 00 <加密数据>`（16 字节头）。官方 `Pecmd.exe CMPS` 仅加密不可逆（遇已加密输入返回 `E_INVALIDARG 0x80070057`）；可改用外部解密器 `sylcmpa.exe`（GUI 工具 "CMPS 加解密工具 v3.0"，为修改版 PECMD v201201.88.05.85）直接还原 `lmt_PECMD.INI.wcs`（UTF-16LE，247 行）。本次 10PE64 `PECMD.INI` 两路线结果一致。

### 3. 03PE PECMD 明文关键行
```
L57  EXEC *="...\7-Zip\ZipFile_7z.exe" x "%WinDir%\SYSTEM32\Drivers\IntelRaid.sys" -p0601518C128831244F3239CF2D7CE2E3 ...
L70  EXEC *=%WinDir%\SYSTEM32\LOADSYS.EXE
L71  TEAM FILE ...\LOADSYS.EXE|FILE ...\Drivers\IntelRaid.sys     ← 解压后立即删除源文件
L131 EXEC %WinDir%\System32\Taoset.EXE                            ← 执行核心载荷
```

### 4. 10PE64 PECMD 明文关键行
```
L199 EXEC *=...\7-Zip\ZipFile_7z.exe x "%WinDir%\sysnative\Drivers\IntelRaid.sys" -o... -pF2554EF7FE28DDC5896ACCBB36FCF97A
L200 EXEC *=...\7-Zip\ZipFile_7z.exe x "%ProgramFiles%\安装维护\PW.bin" -o... -p893FD5B3CD2D027CD7F205CBDE11AA75
L201 FILE %ProgramFiles%\安装维护\PW.bin                          ← 证据销毁
L202 ReadDMI.EXE 移动→执行→立即删除
L204 删除 LMTPE.EXE + %WinDir%\System32\Drivers\IntelRaid.sys      ← 销毁载荷源文件
L210 EXEC X:\Windows\System32\TaoSet.EXE
```

### 5. 伪驱动复原（魔数篡改）
`IntelRaid.sys` / `PW.bin` 文件头 2 字节被篡改为 `54 78`（"Tx"），**恢复为 7z 魔数 `37 7A`** 后解压成功：
- `IntelRaid.sys` → `IntelRaid_fixed.7z` → 16 个文件（TaoSet.exe / Hi.exe / Dlg86.dll / Dlg64.dll / AppleDrv.sys / devconx64.exe / devconx86.exe / ReadDMI.exe / NEI / PESET / Task2 / ApplePT 等）
- `PW.bin` → `PW_fixed.7z` → `NTPWEDIT.EXE`（Windows 登录密码编辑器）

### 6. 其余伪驱动（密码5 与 APPLEDRV.SYS）
- 10PE64 `NEI` 脚本明文（L134-138 / L288 / L712-719）：`ACP.SYS` / `AppleDrv.sys` / `IO.SYS` 均以密码 `4469616e4e616f4469616e32303137474f`（ASCII：`DianNaoDian2017GO`）解压，内含 SRS / 苹果分区 / IO 总线驱动。
- 03PE `NEI` 脚本明文（L18）：`APPLEDRV.SYS` 以密码 `亿维凌DND15553676811` 解压 → `APPLEHFS.INF/SYS`、`EXT2FSD.SYS`（苹果分区驱动）。

> 注：上述"伪驱动"载荷本身为良性驱动包，**其恶性点在于伪装手法与销毁行为**，与大白菜 `IntelRaid.sys` 完全一致。

### 7. 同源比对（核心证据）
- `TaoSet.exe` 提取 27 个 RCDATA 资源（`LMT_*`），与大白菜 `SetSys.exe`（`DBC_*`）比对：**23 个 SHA-256 逐字节相同**（360SAFE / DEPLOY / AFTER / SECURCONF / TOPDRVIER / TOPDRVIER_X64 / FBINST / 7Z / 7ZA / SWAPADD / SWAPADD64 / RESH* / RESP / DVCLAL / TNOTICEFORM 等），4 个差异为版本更新（RES1、SCJ1、TEST、PACKAGEINFO）。
- `Hi.exe` SHA-256 `384d42ef9f28ceea`：与大白菜逐字节相同（检出 Ymacco!rfn）。
- `Dlg86.dll` SHA-256 `f801eb9f15f73202`：与大白菜逐字节相同（检出 Wacatac.H!ml）。
- `TaoSet.exe` 在 03PE 与 10PE64 中哈希一致（`d9d05ab85eb62a59`）。

### 8. IMG 镜像分析
自写 FAT12/16 解析器（`fat_list.py`）提取 GRUB 菜单引用的 5 个 IMG：
- `MAXDOS.IMG` → MaxDOS 工具箱（常规）
- `MEMTEST.IMG` → MemTest86+ 内存测试（常规）
- `KON.IMG` / `KONNEW.IMG` → Kon-Boot 密码绕过（常规，乱码布局未深挖）
- `PASSWORD.IMG` → PWDCN.EXE 密码破解器（常规）

**结论：GRUB 引用 IMG 均为标准 PE 工具，未发现恶意载荷。**

`SUPPORT.IMG*` 家族（9 个文件：SUPPORT.IMG / IMG2 / IMG4 / IMG6 / IMG7 / IMG9 / IMG10 / IMG11 / IMG12，共约 88 MB）均为**真 7z 且头加密**（魔数 `37 7A BC AF 27 1C`，无密码无法列出/解压）。其用途由 `Config.ini`（解自 UD 内 `Res.7z`，即 TaoSet 推广软件 UI 配置）给出映射：

| SUPPORT.IMG* | 对应推广软件 |
|---|---|
| SUPPORT.IMG / IMG2 / IMG10 | 360tao |
| SUPPORT.IMG4 | 2345Explorer |
| SUPPORT.IMG6 | WinSystemTool |
| SUPPORT.IMG7 | chaojituzi（超级兔子） |
| SUPPORT.IMG9 | Doubao（豆包） |
| SUPPORT.IMG11 | Edge |
| SUPPORT.IMG12 | Taobao |
| SUPPORT.IMG8（IMGS 目录中缺失） | Chrome |

> 即 SUPPORT.IMG* 为**推广软件安装包（7z 加密）**，由 PE 阶段 TaoSet.exe 按用户勾选解压安装——与"捆绑推广"行为链吻合（见行为 3）。密码未破，见 §9。

### 9. TaoSet.exe 深度分析（UPX 脱壳 + 资源 + 反汇编定位）

**脱壳**：`TaoSet.exe`（8,886,272 B）为 UPX 壳（UPX0/UPX1），`upx.exe -d` 成功脱壳 → `TaoSet_unpacked.exe`（9,851,904 B）。`.rsrc` 未压缩，可直接提取 27 个 `LMT_*` 资源。

**开发者路径泄露**（脱壳后 UTF-16 字符串，xref `0x4d59d6`）：
```
E:\OneDrive - tp.edu.tw\Program\Hutai\LaoMaoTao\taoset-delphi\NativeXml.pas
```
确证 TaoSet 为虎泰（Hutai）自研 Delphi 工程（`Hutai\LaoMaoTao\taoset-delphi`）。

**关键资源分析**（`work\pkg\pe_scripts\raid_payload\taoset_rsrc\`，27 个 `LMT_*`）：
- `LMT_RES1`（208,633 B，**明文 INI**）：驱动部署 + 推广配置，段结构：
  - `[7z]`：密码格式 `路径|密码=Sysprep`——明文（`qazwsx`、`qq123456`、`1022H2Dzxk`、`11ibWSnULxPg`、`11Ng6CycqxS&CWS*Ce` 等，对应 `Windows\Web\` 浏览器劫持配置，WIN10/11 各一套）或 **XOR 混淆**（`token|DecodeXor1`，XorKey=`377ABCAF271C` = 7z 魔数，token 如 `10CcaCrLeC` / `11#6b9Dzxk`，本次未解出算法）
  - `[Deploy7z]`：明文密码 `123456` / `3229696`（EasyDrv7 `SoftExt` 软件扩展包）
  - `[Merge.*]`：**30 个 7 位数字密码**（EasyDrv7 驱动合并包：`5253304` / `5550856` / `6092176` / `5370128` 等）
  - `[Encrypt]`：`beep.sys` 驱动级文件隐藏（ISO 映像 / DSE 规避）
- `LMT_360SAFE`（202 KB，7z）：**未加密**，可直接解出（与 [7z] 密码机制无关）
- `LMT_DEPLOY`（2.7 MB）：**VMProtect 壳**（`.vmp0`，熵 7.62，TimeDateStamp 2020-09-05），静态无法还原
- `LMT_SECURCONF`（938 B）：加密（熵 7.08，非简单 XOR，疑似 AES 类），推测为签名白名单/服务配置

**反汇编定位（capstone，`taoset_analyze.py`）**：
- `Extract7zFile_Section: %s 7ZipFile: %s, Pass: %s...` → 函数 xref `0x4fc248`（内部日志 `0x4fc642`）——**7z 解压函数，密码 Pass 以参数传入，来源在调用方**
- `PE-_PE_InstallSysset_InputSupportFile: %s` → xref `0x506e06`，位于大函数 `_PE_InstallSysset`（`0x506a14`–`0x506e7b`）—— **SUPPORT.IMG* 的处理入口**
- `PE-_PE_InstallSysset_RegFile: %s` → xref `0x506c3d`
- **结论**：SUPPORT.IMG* 密码由 `_PE_InstallSysset` 内部构造后传入 `Extract7zFile_Section`；二进制内无明文字面量（12173 个候选串全部命中失败），**密码为运行时混淆构造**——静态提取需继续追踪 `0x506a14` 调用链（本次未完成）。

---

## 三、软件行为（代码级证据）

### 行为 1：压缩包伪装成驱动（确凿，明文 PECMD）
`IntelRaid.sys` / `APPLEDRV.SYS` / `AppleDrv.sys` / `ACP.SYS` / `IO.SYS` / `PW.bin` 均为 7-Zip 压缩包，以 `.SYS`/`.bin` 扩展名存放在 `System32\Drivers\`，由 PECMD 在启动阶段解压——与大白菜 `IntelRaid.sys` 手法**同名同法**。

### 行为 2：执行后销毁证据（确凿，明文 PECMD）
解压→执行→立即 `FILE` 删除源文件：`LOADSYS.EXE`、`IntelRaid.sys`、`PW.bin`、`ReadDMI.EXE`、`LMTPE.EXE`（03PE L70-71、10PE64 L201-204）。静态取证窗口被刻意压缩。

### 行为 3：同源继承恶意行为（资源层确凿，套用大白菜已证实结论）
`TaoSet.exe` 与大白菜 `SetSys.exe` 的 `DEPLOY` / `360SAFE` / `SECURCONF` / `AFTER` 等关键资源逐字节相同，因此继承大白菜报告中已证实的恶意行为：
- **关闭 UAC**（`EnableLUA`/`ConsentPromptBehaviorAdmin`/`PromptOnSecureDesktop` 置 0）
- **关闭防火墙**（双配置文件 `EnableFirewall=0`）
- **删除/处置安全软件**（`CDelSecuritySoft` 类，经服务管理 API 枚举处置，最终调用被 VMProtect 虚拟化）
- **篡改 360 白名单**（`360SAFE` 数据库包写入忽略列表）

### 行为 4：携带已确认木马组件（AV 检出）
`Hi.exe`（Ymacco!rfn）、`Dlg86.dll`（Wacatac.H!ml）与大白菜样本逐字节相同，且由 10PE64 PECMD L202 在启动阶段主动搬运到 `SysWOW64` 生效。

### 行为 5：高权限环境下的自升级通道（机制级）
PECMD 明文存在 `LMTUpdate.exe` 更新工具与远程 `update.json` 下发路径（早期分析结论），配合 PE 的 SYSTEM 高权限环境，存在远程下发执行能力。

### 行为 6：对抗检测（技术证据）
- PECMD 脚本 CMPa 加密
- 7z 魔数前 2 字节篡改（`37 7A` → `54 78`）
- `LOADSYS.EXE` VB6 混淆壳，`GetProcAddress`/`LoadLibraryA`/`VirtualAlloc` 字符串逐字符改写，API 动态解析
- 载荷统一使用 `.SYS` 扩展名规避驱动签名与审查

### 行为 7：安装后静默推广（大白菜 unattend.xml 实测证据，2026-09-27）
用户在 Hyper-V 中实机安装大白菜 PE 系统，安装器**卡 99% 异常**；检查 `C:\panther\unattend.xml` 发现完整恶意自动化链（截图存 `laomaotao/evidence/QQ2026*.png`）：
- **specialize 阶段**：启用内置 `Administrator` + 可疑自定义 `Administrator_ploc` 账户、`ConsentPromptBehaviorAdmin=0`（**关闭 UAC**）、`FilterAdministratorToken=1`
- **oobeSystem 阶段**：跳过全部 OOBE（EULA/无线/用户创建）、`ProtectYourPC=2`（关更新）
- **FirstLogonCommands**（首次登录静默执行）：
  ```xml
  <CommandLine>%WinDir%\Shbqoiziy\Naidbc.exe</CommandLine>
  <Order>1</Order>
  <RequiresUserInput>false</RequiresUserInput>
  ```
- `Shbqoiziy` = 10 字符**随机目录名**（RES1"随机名"手法延续）；Naidbc.exe（8.60 MB / 9,021,952 B，**无数字签名、无版本资源**，修改时间 2026/9/11）与**解压后的 SUPPORT.IMG\* 及推广标记文件（DriveTheLife.ext / QuarkPC.ext / WPS.ext）同目录** `C:\Windows\Shbqoiziy\`，为解开 SUPPORT.IMG\* 的执行者，**密码必然硬编码/构造于其中**；卡 99% = Naidbc.exe 推广安装环节
- **同套体系确认**：大白菜与老毛桃的 SUPPORT.IMG\* 家族**大部分文件大小一致**（同套推广包体系，编号对应不同推广软件：大白菜无 IMG9 有 IMG8，老毛桃反之），密码大概率通用
- **Naidbc.exe 样本缺失**：老毛桃/电脑店样本均无此文件（DBC=大白菜缩写，大白菜新版专属外层程序）；Hyper-V 传文件受限，待 vhdx 挂载法导出后静态分析提取 SUPPORT.IMG* 密码

---

## 四、罪证清单（揭发要点）

1. **与大白菜同一签名主体、同一恶意代码体系**（东莞虎泰网络科技有限公司）。
2. **压缩包伪装成驱动**：6 个 `.SYS`/`.bin` 文件实为 7z 压缩包，在 PE 启动阶段解压并安装（代码级证据，行为 1）。
3. **执行后销毁证据**：解压即删源文件，压缩静态取证窗口（代码级证据，行为 2）。
4. **携带已确认木马**：`Hi.exe`（Ymacco!rfn）、`Dlg86.dll`（Wacatac.H!ml）逐字节等于大白菜恶意样本（行为 4）。
5. **继承大白菜已证实恶意行为**：关闭 UAC/防火墙、删除安全软件、篡改 360 白名单（行为 3，资源逐字节同源）。
6. **高权限 + 远程下发通道**：PE SYSTEM 环境 + `update.json` 更新机制（行为 5）。
7. **多层对抗**：CMPa 加密、魔数篡改、VB6 混淆壳、伪驱动扩展名（行为 6）。
8. **安装后静默推广**：unattend.xml 预置关闭 UAC/启用隐藏管理员账户，首次登录静默执行 `%WinDir%\Shbqoiziy\Naidbc.exe` 解压安装 SUPPORT.IMG* 推广包（行为 7，大白菜实机实测）。

---

## 五、安全边界与处置建议

- 本报告全部为**静态分析，样本未在宿主执行**。`DEPLOY`/`SetSys` 的 VMProtect 虚拟化段（同大白菜）无法静态还原，若需逐 API 铁证应在 Hyper-V 隔离虚拟机中结合 API Monitor/Procmon 动态取证。
- **未决项（更新）**：`SUPPORT.IMG*` 加密 7z（10 个文件，编号 2/4/6/7/9/10/11/12 + 无编号，全部 header 加密，独立密码体系）密码未破——已知全部品牌密码 + RES1 各段密码 + 二进制候选串均未命中，密码由推广执行器**运行时构造**（老毛桃 TaoSet.exe `_PE_InstallSysset`→`Extract7zFile_Section` 调用链，见 §9；大白菜新版为独立 `Naidbc.exe`，与 SUPPORT.IMG 同目录，待 vhdx 导出分析，行为 7）。另 `RES1 [DecodeXor1]` XOR 密码算法未解出。
- 建议：彻底卸载该工具；核查 PE 使用过程中被安装的推广软件；检查 `Services` 注册表项中的随机名驱动服务；鉴于 UAC/防火墙/安全软件已被代码级确认会被关闭，建议在干净主机上重装系统。
- 样本目录 `my\laomaotao\` 已含带毒可执行文件，请保持隔离（如 Defender 临时豁免仅限分析目录，完成后立即移除）；**不得向公开仓库上传可执行样本**。

---

## 六、附：密码清单

| # | 用途 | 密码 |
|---|---|---|
| 1 | 内层主包 | `8A86Jxp@EZj!@SY3` |
| 2 | 03PE `IntelRaid.sys` | `0601518C128831244F3239CF2D7CE2E3` |
| 3 | 10PE64 `IntelRaid.sys` | `F2554EF7FE28DDC5896ACCBB36FCF97A` |
| 4 | `PW.bin` | `893FD5B3CD2D027CD7F205CBDE11AA75` |
| 5 | `ACP.SYS`/`AppleDrv.sys`/`IO.SYS` | `4469616e4e616f4469616e32303137474f`（ASCII `DianNaoDian2017GO`） |
| 附加 | 03PE `APPLEDRV.SYS` | `亿维凌DND15553676811`（明文出处：NEI 脚本 L18） |
| 6 | `SUPPORT.IMG*`（**未破解**） | —（见 §9：运行时混淆构造；大白菜侧 Naidbc.exe 待取） |
| 附加 | RES1 `[Deploy7z]`（EasyDrv7 软件扩展） | `123456` / `3229696` |
| 附加 | RES1 `[7z]` 浏览器劫持配置（WIN10/11） | `qazwsx` / `qq123456` / `1022H2Dzxk` / `11ibWSnULxPg` / `11Ng6CycqxS&CWS*Ce` 等 |
| 附加 | RES1 `[Merge.*]`（EasyDrv7 驱动合并包） | 30 个 7 位数字（`5253304` / `5550856` / `6092176` / `5370128` 等） |
| 未决 | RES1 `[DecodeXor1]` XOR 混淆密码 | 算法未解（XorKey = `377ABCAF271C` = 7z 魔数） |

---

## 七、附：逆向脚本索引（`my\laomaotao\`）

| 脚本 | 用途 |
|---|---|
| `cmpa_official.py` / `cmpa_decrypt.py` / `pecmd_keyscan.py` / `pecmd_analyze.py` | PECMD CMPa 解密与键扫描 |
| `fat_list.py` / `scan_fat.py` | FAT12/16 镜像解析与提取 |
| `peinfo.py` / `disasm.py` / `trace_args.py` / `trace2.py` | PE 信息、反汇编、调用链追踪 |
| `find_pwd.py` / `try_pwd.py` / `pwd_cands.py` | 压缩包密码探测 |
| `find_7znames.py` / `dump_cfg.py` / `dump_delphi_strs.py` / `utf16_scan.py` / `full_scan.py` | 内嵌 7z 名、配置、字符串扫描 |
| `support7z_try_pwd.py` | SUPPORT.IMG* 密码批量探测（内置品牌密码表，`-l` 可扩展外部列表） |
| `taoset_analyze.py` | TaoSet 脱壳分析：候选密码收割 / 关键字符串 VA+xref 定位 / capstone 反汇编 |
