#!/usr/bin/env python3
import argparse
import sys
import os
from openai import OpenAI

# 添加项目根目录到path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from high_level_agent.decision_agent import HighLevelDecisionAgent


def main():
    parser = argparse.ArgumentParser(
        description='自主化Web应用安全测试框架',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:

  # 需要登录的应用（默认使用LLM智能规划）
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --output "output/test1"

  # 无需登录的应用
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000" \\
      --output "output/test2"

  # 登录后指定爬取起始URL
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --crawl_start_url "http://127.0.0.1:3000/admin" \\
      --output "output/test3"

  # 🆕 消融实验：使用穷举模式（为每个请求生成所有漏洞类型的任务）
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --output "output/experiment_exhaustive" \\
      --attack_planning_mode exhaustive

  python autonomous_test.py --target_url "http://127.0.0.1:4281/#/login" --login_task "Log in with username: 1474715931@qq.com, password: 123456" --output "output/juiceshop" &> logs/juiceshop.log

工作流程:
  1. 执行登录（可选） → 如果提供login_task则执行登录
  2. 深度爬取 → 从指定URL/登录后页面/目标URL开始爬取（50页）
  3. 任务规划 → 识别并执行应用任务
  4. 攻击规划 → 分析潜在攻击面（支持LLM智能规划或穷举全测）
  5. 攻击执行 → 测试各类漏洞
  6. 生成报告 → 输出详细测试结果
        """
    )

    parser.add_argument(
        "--target_url",
        required=True,
        help="登录页面的URL（例如: http://127.0.0.1:3000/login）"
    )

    parser.add_argument(
        "--login_task",
        required=False,
        default=None,
        help="可选的登录任务描述（例如: 'Log in with username: admin, password: admin123'）。如果不提供，将直接从目标URL开始爬取"
    )

    parser.add_argument(
        "--crawl_start_url",
        required=False,
        default=None,
        help="可选的爬取起始URL。登录后会导航到此URL开始爬取（例如: 'http://127.0.0.1:3000/admin'）。如果不提供，将从登录后页面或目标URL开始爬取"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="结果输出目录（例如: output/test1）"
    )

    parser.add_argument(
        "--attack_planning_mode",
        choices=["llm", "exhaustive"],
        default="llm",
        help="攻击规划模式: llm（LLM智能规划，默认）或 exhaustive（穷举全测，用于消融实验）"
    )

    args = parser.parse_args()

    # 初始化OpenAI client
    client = OpenAI(
        api_key="sk-8b1270b35adc418e8b878c7df3d7f54c",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )

    # client = OpenAI(
    #     api_key="sk-cfb6401c67664818bf8e961d59736575",
    #     base_url="https://api.deepseek.com"
    # )

    # 打印启动信息
    print("\n" + "="*70)
    print("🚀 自主化安全测试框架")
    print("="*70)
    print(f"目标URL: {args.target_url}")
    if args.login_task:
        print(f"登录任务: {args.login_task}")
    else:
        print(f"登录任务: 无（直接爬取）")
    if args.crawl_start_url:
        print(f"爬取起始URL: {args.crawl_start_url}")
    print(f"输出目录: {args.output}")

    # 🆕 显示攻击规划模式
    mode_display = {
        "llm": "LLM智能规划",
        "exhaustive": "穷举全测（消融实验）"
    }
    print(f"攻击规划模式: {mode_display.get(args.attack_planning_mode, args.attack_planning_mode)}")

    print("="*70)
    print("")

    # 创建顶层Agent
    agent = HighLevelDecisionAgent(
        client=client,
        initial_url=args.target_url,
        login_task=args.login_task,
        crawl_start_url=args.crawl_start_url,
        output_dir=args.output,
        config={
            "attack_planning_mode": args.attack_planning_mode  # 🆕 传入攻击规划模式
        }
    )

    # 执行测试
    try:
        results = agent.run()

        # 打印最终摘要
        print("\n" + "="*70)
        print("✅ 测试完成 - 快速摘要")
        print("="*70)
        print(f"发现页面数: {results['crawling']['total_pages']}")
        print(f"执行任务数: {results['testing']['tasks_executed']}")
        print(f"攻击测试数: {results['testing']['attacks_planned']}")
        print(f"发现漏洞数: {results['testing']['vulnerabilities_found']}")
        print(f"总用时: {results['timing']['total_seconds']:.1f}秒")
        print("")
        print(f"📁 详细报告: {args.output}/final_report.json")
        print(f"📁 日志文件: {args.output}/high_level_agent.log")
        print("="*70)

        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  测试被用户中断")
        return 1

    except Exception as e:
        print(f"\n\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
