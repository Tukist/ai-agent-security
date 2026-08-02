"""
本地快速测评工具
===============
用法:
  # Stub 快速验证 (< 5秒)
  python local_test.py

  # 真实 LLM 验证 (DeepSeek API)
  python local_test.py --llm

  # 指定预算/候选数
  python local_test.py --budget 120 --replay 50

说明:
  - Stub 模式: 关键词匹配, 极快但 cell 多样性固定(1种), 分数最多 0.1
  - LLM 模式: 调用 DeepSeek API, 能验证 prompt 在真实模型上的行为
  - 两种模式都确认: 代码不崩溃、EXFIL predicate 触发
"""
import sys
import os
from pathlib import Path

HERE = Path(__file__).parent
SDK_DIR = HERE / "reference" / "jed-redteam-attack"
sys.path.insert(0, str(SDK_DIR))

from local_harness import load_attack_class, make_env, evaluate_redteam_local
from aicomp_sdk import AttackRunConfig


def test(attack_path="attack_quick.py", budget=30, max_replay=30, use_llm=False, verbose=False):
    if use_llm:
        os.environ.setdefault("VLLM_BASE_URL", "https://api.deepseek.com/v1")
        os.environ.setdefault("VLLM_API_KEY", "sk-302d533f3e7a42a69025e0e351a7debb")
        os.environ.setdefault("VLLM_MODEL", "deepseek-chat")

    AttackAlgorithm = load_attack_class(attack_path)
    config = AttackRunConfig(time_budget_s=budget, max_tool_hops=8, seed=123)
    env = make_env(use_llm=use_llm, seed=123, verbose=verbose)

    t0 = __import__("time").time()
    result = evaluate_redteam_local(AttackAlgorithm, env, config, verbose=verbose, max_replay=max_replay)
    elapsed = __import__("time").time() - t0

    print(f"\n{'='*50}")
    print(f"  结果: {result.score:.4f}分 | {result.findings_count}命中 | {result.unique_cells}cell | {elapsed:.1f}s")
    print(f"{'='*50}")

    # Predicate breakdown
    preds = {}
    for f in result.findings:
        for p in f.get("triggered", []):
            preds[p] = preds.get(p, 0) + 1
    for p, c in sorted(preds.items()):
        print(f"  {p}: {c}")

    return result


if __name__ == "__main__":
    use_llm = "--llm" in sys.argv
    budget = 30
    replay = 30
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    for i, a in enumerate(sys.argv):
        if a == "--budget" and i+1 < len(sys.argv):
            budget = int(sys.argv[i+1])
        if a == "--replay" and i+1 < len(sys.argv):
            replay = int(sys.argv[i+1])

    mode = "LLM (DeepSeek)" if use_llm else "Stub"
    print(f"本地测评: {mode} | budget={budget}s | replay={replay}")

    # Auto-detect: use attack_quick.py for fast testing, attack_local.py for multi-family
    attack = "attack_local.py"
    if len(sys.argv) > 1 and sys.argv[-1].endswith(".py"):
        attack = sys.argv[-1]
    elif not Path(attack).exists():
        attack = "attack_quick.py"

    print(f"Attack: {attack}\n")
    test(attack, budget, replay, use_llm, verbose)
