# -*- coding: utf-8 -*-
"""
SUPPORT.IMG* 加密 7z 密码批量探测脚本（老毛桃 PE 未决项）

用法（在样本根目录运行，或设置 PE_BASE 环境变量指向样本根目录）：
    python support7z_try_pwd.py                    # 用内置密码表测试 my\\laomaotao\\work\\unpack\\UD\\ILMT\\ILMT\\IMGS\\SUPPORT.IMG10
    python support7z_try_pwd.py -t <7z文件>        # 指定目标 7z
    python support7z_try_pwd.py -l <密码列表.txt>   # 追加外部密码列表（每行一个）

依赖：D:\7-Zip\7z.exe（可用环境变量 SEVENZ 覆盖）
输出：成功密码打印到 stdout，全部结果写入 support7z_try.log
"""
import os
import subprocess
import sys
import argparse

_BASE = os.environ.get("PE_BASE") or os.getcwd()
SEVENZ = os.environ.get("SEVENZ") or r"D:\7-Zip\7z.exe"

# 相对样本根目录的默认目标：老毛桃 UD 内 SUPPORT.IMG* 家族（最小的先试）
DEFAULT_TARGET = os.path.join(
    _BASE,
    "my", "laomaotao", "work", "unpack", "UD", "ILMT", "ILMT", "IMGS", "SUPPORT.IMG10",
)

# 内置密码候选：已知品牌密码 + RES1 [7z]/[Deploy7z]/[Merge.*] 提取值
BUILTIN_PWDS = [
    # 老毛桃/大白菜/电脑店已知密码
    "8A86Jxp@EZj!@SY3",                       # 内层主包
    "0601518C128831244F3239CF2D7CE2E3",       # 03PE IntelRaid.sys
    "F2554EF7FE28DDC5896ACCBB36FCF97A",       # 10PE64 IntelRaid.sys
    "893FD5B3CD2D027CD7F205CBDE11AA75",       # PW.bin
    "4469616e4e616f4469616e32303137474f",     # ACP/AppleDrv/IO（ASCII: DianNaoDian2017GO）
    "DianNaoDian2017GO",
    "亿维凌DND15553676811",                   # 03PE APPLEDRV.SYS（NEI L18 明文）
    "B28EE087884D379ABF0088132464CAB9A3A21638",  # 大白菜 IntelRaid.sys
    "86BD127D8054",
    # RES1 [7z] 段明文密码（浏览器劫持配置，WIN10/WIN11）
    "qazwsx", "qq123456", "1022H2Dzxk", "11ibWSnULxPg",
    "11Ng6CycqxS&CWS*Ce", "11RSLGwzbgeDQ32m3y",
    "11jqlJgPgAs2nXs8tG", "11C7ESKCJeS7cxZLMR",
    # RES1 [Deploy7z] 段明文密码（EasyDrv7 SoftExt）
    "123456", "3229696",
    # RES1 [Merge.*] 段（EasyDrv7 驱动合并包）
    "5253304", "5550856", "4888696", "5261576", "4675328", "2972672",
    "5546640", "4972912", "3042592", "2701312", "6092176", "5373176",
    "60921761", "5373200", "3230720", "2973184", "5633384", "5054000",
    "3067376", "2724584", "2872320", "2616320", "6089584", "5370128",
    "5625136", "5050360", "6400000", "3200000",
    # RES1 [DecodeXor1] 混淆 token（未解码，原样尝试）
    "10CcaCrLeC", "11#6b9Dzxk",
    # 常见弱口令
    "6", "123", "123456", "12345678", "888888", "abc123", "111111",
]


def try_password(sevenz, target, pwd):
    """用 7z t 测试单个密码，返回 True 表示成功。"""
    try:
        r = subprocess.run(
            [sevenz, "t", target, "-p" + pwd, "-y"],
            capture_output=True, timeout=20,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        out = (r.stdout + r.stderr).decode("gbk", "ignore")
    except Exception as e:
        print("ERR", pwd, e)
        return False
    return "Everything is Ok" in out or "CRC OK" in out


def main():
    ap = argparse.ArgumentParser(description="SUPPORT.IMG* 密码批量探测")
    ap.add_argument("-t", "--target", default=DEFAULT_TARGET, help="目标 7z 文件")
    ap.add_argument("-l", "--list", default=None, help="外部密码列表文件（每行一个）")
    args = ap.parse_args()

    if not os.path.isfile(args.target):
        print("目标不存在:", args.target)
        sys.exit(1)
    if not os.path.isfile(SEVENZ):
        print("7z 未找到:", SEVENZ, "（可用环境变量 SEVENZ 指定）")
        sys.exit(1)

    pwds = list(BUILTIN_PWDS)
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if line:
                    pwds.append(line)

    print("测试目标:", args.target)
    print("候选密码数:", len(pwds))
    seen = set()
    found = []
    log_path = os.path.join(os.path.dirname(os.path.abspath(args.target)), "support7z_try.log")
    with open(log_path, "w", encoding="utf-8") as log:
        for i, p in enumerate(pwds):
            if p in seen:
                continue
            seen.add(p)
            if try_password(SEVENZ, args.target, p):
                found.append(p)
                msg = "SUCCESS: %s" % p
                log.write(msg + "\n")
                print(msg, flush=True)
            elif i % 50 == 0:
                print("[%d/%d] 已测，命中 %d" % (len(seen), len(pwds), len(found)), flush=True)
    print("完成。命中密码:", found)
    print("日志:", log_path)


if __name__ == "__main__":
    main()
