#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
from collections import defaultdict, Counter
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <文件夹名>")
        print("示例: python script.py TASK0024")
        sys.exit(1)

    folder_name = sys.argv[1]

    # 当前脚本所在目录
    script_dir = Path(__file__).resolve().parent

    # attack_results.json 路径
    json_path = script_dir / "output_realapp" / folder_name / "attack_execution" / "attack_results.json"

    if not json_path.is_file():
        print(f"[错误] 找不到文件: {json_path}")
        sys.exit(1)

    # 读取 JSON
    try:
        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[错误] 读取或解析 JSON 失败: {e}")
        sys.exit(1)

    if not isinstance(data, list):
        print("[错误] attack_results.json 格式不是列表(list)，请检查文件结构。")
        sys.exit(1)

    # vuln_type 计数器、任务列表、条目映射
    counter = Counter()
    vuln_tasks = defaultdict(list)
    vuln_entries = defaultdict(list)

    for item in data:
        result = item.get("result", {})
        if result.get("vulnerable", False):
            vuln_type = item.get("vuln_type", "UNKNOWN")
            task_id = item.get("task_id", "NO_TASK_ID")

            counter[vuln_type] += 1
            vuln_tasks[vuln_type].append(task_id)
            vuln_entries[vuln_type].append(item)

    # --- 输出统计结果 ---
    print(f"文件: {json_path}")
    print("按 vuln_type 统计的 vulnerable=true 数量：\n")

    if not counter:
        print("没有发现 result.vulnerable == true 的条目。")
    else:
        for vuln_type, count in counter.items():
            print(f"### {vuln_type}: {count}")
            print("任务号列表:")
            for tid in vuln_tasks[vuln_type]:
                print(f"  - {tid}")
            print()

    # --- 输出 JSON 文件 ---
    out_path = script_dir / f"{folder_name}.json"

    sorted_output = {
        vuln_type: vuln_entries[vuln_type]
        for vuln_type in sorted(vuln_entries.keys())
    }

    try:
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(sorted_output, f, indent=2, ensure_ascii=False)

        print(f"\n已生成分组后的 JSON 文件: {out_path}")
    except Exception as e:
        print(f"[错误] 写入 JSON 失败: {e}")


if __name__ == "__main__":
    main()
