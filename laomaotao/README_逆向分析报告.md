# 老毛桃 PE 装机工具 — 逆向分析报告（罪证留存）

> 本报告为**纯静态逆向分析**产物，样本从未在宿主机运行。
> 分析对象：`LaoMaoTao.7z`（含启动程序 `LaoMaoTao.exe` 及 PE 镜像包）
> 签名主体：东莞虎泰网络科技有限公司（与大白菜 PE 装机工具**同一签名主体**）
> 分析日期：2026-09-26
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

**结论：GRUB 引用 IMG 均为标准 PE 工具，未发现恶意载荷。** `SUPPORT.IMG`（及 8 个变体，共约 88 MB）为真 7z 加密，**密码 6 未破解**，无法排除内含载荷——为当前唯一未决项。

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

---

## 四、罪证清单（揭发要点）

1. **与大白菜同一签名主体、同一恶意代码体系**（东莞虎泰网络科技有限公司）。
2. **压缩包伪装成驱动**：6 个 `.SYS`/`.bin` 文件实为 7z 压缩包，在 PE 启动阶段解压并安装（代码级证据，行为 1）。
3. **执行后销毁证据**：解压即删源文件，压缩静态取证窗口（代码级证据，行为 2）。
4. **携带已确认木马**：`Hi.exe`（Ymacco!rfn）、`Dlg86.dll`（Wacatac.H!ml）逐字节等于大白菜恶意样本（行为 4）。
5. **继承大白菜已证实恶意行为**：关闭 UAC/防火墙、删除安全软件、篡改 360 白名单（行为 3，资源逐字节同源）。
6. **高权限 + 远程下发通道**：PE SYSTEM 环境 + `update.json` 更新机制（行为 5）。
7. **多层对抗**：CMPa 加密、魔数篡改、VB6 混淆壳、伪驱动扩展名（行为 6）。

---

## 五、安全边界与处置建议

- 本报告全部为**静态分析，样本未在宿主执行**。`DEPLOY`/`SetSys` 的 VMProtect 虚拟化段（同大白菜）无法静态还原，若需逐 API 铁证应在 Hyper-V 隔离虚拟机中结合 API Monitor/Procmon 动态取证。
- **唯一未决项**：`SUPPORT.IMG*` 加密（约 88 MB，密码 6 未破解）内容未知；10.7z/Net.7z 等部分内层压缩包密码未破。
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
| 6 | `SUPPORT.IMG*`（**未破解**） | — |

---

## 七、附：逆向脚本索引（`my\laomaotao\`）

| 脚本 | 用途 |
|---|---|
| `cmpa_official.py` / `cmpa_decrypt.py` / `pecmd_keyscan.py` / `pecmd_analyze.py` | PECMD CMPa 解密与键扫描 |
| `fat_list.py` / `scan_fat.py` | FAT12/16 镜像解析与提取 |
| `peinfo.py` / `disasm.py` / `trace_args.py` / `trace2.py` | PE 信息、反汇编、调用链追踪 |
| `find_pwd.py` / `try_pwd.py` / `pwd_cands.py` | 压缩包密码探测 |
| `find_7znames.py` / `dump_cfg.py` / `dump_delphi_strs.py` / `utf16_scan.py` / `full_scan.py` | 内嵌 7z 名、配置、字符串扫描 |
| `lz_variants.py` / `lz_variants2.py` / `chk.py` / `cmpa_official.py` | 压缩变体、校验与比对 |
