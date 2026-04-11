#!/usr/bin/env python3
import argparse
import sys
import os
from openai import OpenAI

# Add the project root directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from high_level_agent.decision_agent import HighLevelDecisionAgent
from utils.token_tracker import make_tracked_client, tracker


def main():
    parser = argparse.ArgumentParser(
        description='Autonomous Web Application Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:

  # Application requiring login (uses LLM-based intelligent planning by default)
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --output "output/test1"

  # Application without login
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000" \\
      --output "output/test2"

  # Specify crawl start URL after login
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --crawl_start_url "http://127.0.0.1:3000/admin" \\
      --output "output/test3"

  # 🆕 Ablation experiment: use exhaustive mode (generate tasks for all vulnerability types per request)
  python autonomous_test.py \\
      --target_url "http://127.0.0.1:3000/login" \\
      --login_task "Log in with username: admin, password: admin123" \\
      --output "output/experiment_exhaustive" \\
      --attack_planning_mode exhaustive

  python autonomous_test.py --target_url "http://127.0.0.1:3000/login" --login_task "Log in with username: admin, password: admin123" --output "output/test4" &> logs/test4.log

Workflow:
  1. Login (optional) -> Execute login if login_task is provided
  2. Deep crawl -> Crawl from specified URL / post-login page / target URL (50 pages)
  3. Task planning -> Identify and execute application tasks
  4. Attack planning -> Analyze potential attack surface (supports LLM intelligent planning or exhaustive testing)
  5. Attack execution -> Test various vulnerabilities
  6. Report generation -> Output detailed test results
        """
    )

    parser.add_argument(
        "--target_url",
        required=True,
        help="URL of the login page (e.g., http://127.0.0.1:3000/login)"
    )

    parser.add_argument(
        "--login_task",
        required=False,
        default=None,
        help="Optional login task description (e.g., 'Log in with username: admin, password: admin123'). If not provided, crawling will start directly from the target URL"
    )

    parser.add_argument(
        "--crawl_start_url",
        required=False,
        default=None,
        help="Optional crawl start URL. After login, navigates to this URL to begin crawling (e.g., 'http://127.0.0.1:3000/admin'). If not provided, crawling starts from the post-login page or the target URL"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for results (e.g., output/test1)"
    )

    parser.add_argument(
        "--attack_planning_mode",
        choices=["llm", "exhaustive"],
        default="llm",
        help="Attack planning mode: llm (LLM intelligent planning, default) or exhaustive (test all types, for ablation experiments)"
    )

    args = parser.parse_args()

    # Initialize OpenAI client
    # Supports any OpenAI-compatible API
    client = OpenAI(
        api_key=os.environ.get("LLM_API_KEY", "YOUR_API_KEY_HERE"),
        base_url=os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1"),
    )

    # Wrap the original client with a tracking wrapper; all LLM calls will automatically record token usage
    client = make_tracked_client(client)
    tracker.set_default_model("default")  # Keep consistent with DEFAULT_MODEL in llm_config.py

    # Print startup information
    print("\n" + "="*70)
    print("🚀 Autonomous Security Testing Framework")
    print("="*70)
    print(f"Target URL: {args.target_url}")
    if args.login_task:
        print(f"Login task: {args.login_task}")
    else:
        print(f"Login task: None (direct crawling)")
    if args.crawl_start_url:
        print(f"Crawl start URL: {args.crawl_start_url}")
    print(f"Output directory: {args.output}")

    # 🆕 Display attack planning mode
    mode_display = {
        "llm": "LLM Intelligent Planning",
        "exhaustive": "Exhaustive Testing (Ablation Experiment)"
    }
    print(f"Attack planning mode: {mode_display.get(args.attack_planning_mode, args.attack_planning_mode)}")

    print("="*70)
    print("")

    # Create top-level Agent
    agent = HighLevelDecisionAgent(
        client=client,
        initial_url=args.target_url,
        login_task=args.login_task,
        crawl_start_url=args.crawl_start_url,
        output_dir=args.output,
        config={
            "attack_planning_mode": args.attack_planning_mode  # 🆕 Pass attack planning mode
        }
    )

    # Execute tests
    try:
        results = agent.run()

        # Print final summary
        print("\n" + "="*70)
        print("✅ Testing Complete - Quick Summary")
        print("="*70)
        print(f"Pages discovered: {results['crawling']['total_pages']}")
        print(f"Tasks executed: {results['testing']['tasks_executed']}")
        print(f"Attack tests: {results['testing']['attacks_planned']}")
        print(f"Vulnerabilities found: {results['testing']['vulnerabilities_found']}")
        print(f"Total time: {results['timing']['total_seconds']:.1f}s")
        print("")
        print(f"📁 Detailed report: {args.output}/final_report.json")
        print(f"📁 Log file: {args.output}/high_level_agent.log")
        print("="*70)

        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
        return 1

    except Exception as e:
        print(f"\n\n❌ Testing failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
