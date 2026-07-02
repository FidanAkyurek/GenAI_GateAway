import os
import sys
import json
import time
import asyncio
from pathlib import Path
from typing import List, Dict, Any

import pandas as pd

os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"
os.environ["DISABLE_MLFLOW_INTEGRATION"] = "TRUE"

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config_manager import ConfigManager
from app.services.layer1_regex import Layer1Regex
from app.services.layer2_deberta import Layer2DeBERTa
from app.services.layer3_llm_judge import Layer3LLMJudge

DATA_FILES = [
    ROOT / "data" / "custom_dataset_part1.csv",
    ROOT / "data" / "custom_dataset_part2.csv",
    ROOT / "data" / "custom_dataset_part3.csv",
    ROOT / "data" / "custom_dataset_part4.csv",
]


def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        elif t == 1 and p == 0:
            fn += 1

    accuracy = (tp + tn) / len(y_true) if y_true else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "samples": len(y_true),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def load_eval_pool() -> pd.DataFrame:
    frames = []
    for path in DATA_FILES:
        if not path.exists():
            continue
        df = pd.read_csv(path)
        if {"text", "label_id"}.issubset(df.columns):
            subset = df[df["label_id"].isin([0, 1])].copy()
            subset = subset[["text", "label_id"]].copy()
            subset["label"] = (subset["label_id"] == 1).astype(int)
            frames.append(subset)
    if not frames:
        raise FileNotFoundError("No evaluation data found in data/ folder")
    return pd.concat(frames, ignore_index=True)


def build_eval_set(pool: pd.DataFrame, num_prompts: int = 100, safe_ratio: float = 0.5, seed: int = 42) -> pd.DataFrame:
    safe_pool = pool[pool["label"] == 0]
    unsafe_pool = pool[pool["label"] == 1]

    safe_count = int(round(num_prompts * safe_ratio))
    unsafe_count = num_prompts - safe_count

    safe_count = min(safe_count, len(safe_pool))
    unsafe_count = min(unsafe_count, len(unsafe_pool))

    if safe_count + unsafe_count < num_prompts:
        remaining = num_prompts - (safe_count + unsafe_count)
        if safe_count < len(safe_pool) and remaining > 0:
            safe_count += min(remaining, len(safe_pool) - safe_count)
        remaining = num_prompts - (safe_count + unsafe_count)
        if remaining > 0 and unsafe_count < len(unsafe_pool):
            unsafe_count += min(remaining, len(unsafe_pool) - unsafe_count)

    safe_sample = safe_pool.sample(n=safe_count, random_state=seed) if safe_count > 0 else safe_pool.iloc[0:0]
    unsafe_sample = unsafe_pool.sample(n=unsafe_count, random_state=seed + 1) if unsafe_count > 0 else unsafe_pool.iloc[0:0]
    eval_set = pd.concat([safe_sample, unsafe_sample], ignore_index=True)
    eval_set = eval_set.sample(frac=1, random_state=seed + 2).reset_index(drop=True)
    return eval_set


async def evaluate_layer3(texts: List[str]) -> List[int]:
    preds = []
    for idx, text in enumerate(texts):
        verdict = await Layer3LLMJudge.evaluate(text)
        preds.append(1 if verdict.upper() == "UNSAFE" else 0)
        if idx < len(texts) - 1:
            time.sleep(3)
    return preds


def evaluate_layer1(texts: List[str]) -> List[int]:
    preds = []
    for text in texts:
        result = Layer1Regex.scan(text)
        preds.append(1 if (result.blacklist_hits or result.has_pii) else 0)
    return preds


def evaluate_layer2(texts: List[str], threshold: float) -> List[int]:
    Layer2DeBERTa.load_model()
    preds = []
    for text in texts:
        score = Layer2DeBERTa.predict_score(text)
        preds.append(1 if score >= threshold else 0)
    return preds


def print_report(name: str, metrics: Dict[str, Any]) -> None:
    print(f"\n=== {name} ===")
    print(f"samples={metrics['samples']}")
    print(f"accuracy={metrics['accuracy']:.4f}")
    print(f"precision={metrics['precision']:.4f}")
    print(f"recall={metrics['recall']:.4f}")
    print(f"f1={metrics['f1']:.4f}")
    print("confusion_matrix=", metrics["confusion_matrix"])


async def main() -> None:
    pool = load_eval_pool()
    eval_set = build_eval_set(pool, num_prompts=120, safe_ratio=0.5, seed=42)
    texts = eval_set["text"].tolist()
    labels = eval_set["label"].tolist()

    print(f"Başlangıç: {len(eval_set)} örneklik test seti hazırlandı.")
    print(f"Safe/Unsafe dağılımı: safe={sum(1 for x in labels if x == 0)}, unsafe={sum(1 for x in labels if x == 1)}")
    print(f"Layer3 için API anahtarı durumu: {'var' if os.getenv('GEMINI_API_KEY') else 'yok'}")

    layer1_preds = evaluate_layer1(texts)
    layer1_metrics = compute_metrics(labels, layer1_preds)
    print_report("Layer 1 (Regex + Blacklist + PII)", layer1_metrics)

    thresholds = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]
    layer2_results = []
    for threshold in thresholds:
        preds = evaluate_layer2(texts, threshold)
        metrics = compute_metrics(labels, preds)
        layer2_results.append({"threshold": threshold, **metrics})
        print(f"threshold={threshold:.2f} | accuracy={metrics['accuracy']:.4f} | precision={metrics['precision']:.4f} | recall={metrics['recall']:.4f} | f1={metrics['f1']:.4f}")

    best = max(layer2_results, key=lambda x: x["f1"])
    print("\nEn iyi Layer 2 threshold (F1):")
    print(json.dumps(best, ensure_ascii=False, indent=2))

    layer3_metrics = None
    if os.getenv("GEMINI_API_KEY"):
        layer3_preds = await evaluate_layer3(texts)
        layer3_metrics = compute_metrics(labels, layer3_preds)
        print_report("Layer 3 (LLM Judge)", layer3_metrics)
    else:
        print("Layer 3 atlanıyor: GEMINI_API_KEY yok")

    report = {
        "dataset_size": len(eval_set),
        "safe_count": sum(1 for x in labels if x == 0),
        "unsafe_count": sum(1 for x in labels if x == 1),
        "layer1": layer1_metrics,
        "layer2_threshold_sweep": layer2_results,
        "best_layer2_threshold": best,
        "layer3": layer3_metrics,
    }

    report_path = ROOT / "tests" / "layer_evaluation_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nRapor kaydedildi: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
