"""
ONNX Export and Dynamic INT8 Quantization Script for TRACE-MAIL AI.
Exports fine-tuned PyTorch DistilBERT model to ONNX format and applies
dynamic INT8 quantization for sub-10ms CPU inference latency.
"""

import os
import sys
import time
import json
from pathlib import Path

import numpy as np

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

MODELS_DIR = BASE_DIR / "engine" / "models"
TRANSFORMER_DIR = MODELS_DIR / "distilbert_threat_model"
ONNX_FP32_PATH = MODELS_DIR / "threat_transformer.onnx"
ONNX_INT8_PATH = MODELS_DIR / "threat_transformer_int8.onnx"
BENCHMARK_PATH = MODELS_DIR / "onnx_benchmark.json"


def export_and_quantize():
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import onnx
    import onnxruntime as ort
    from onnxruntime.quantization import quantize_dynamic, QuantType

    print(f"--- 1. Loading Fine-Tuned PyTorch Model from {TRANSFORMER_DIR} ---")
    if not TRANSFORMER_DIR.exists():
        raise FileNotFoundError(f"Model directory not found: {TRANSFORMER_DIR}. Run train_transformer.py first.")

    tokenizer = AutoTokenizer.from_pretrained(TRANSFORMER_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(TRANSFORMER_DIR)
    model.eval()
    model.to("cpu")

    # Sample input for tracing
    dummy_text = "Urgent action required: Update your banking and wire transfer credentials immediately."
    inputs = tokenizer(
        dummy_text,
        return_tensors="pt",
        max_length=128,
        padding="max_length",
        truncation=True
    )

    print(f"\n--- 2. Exporting PyTorch Model to ONNX (FP32) ---")
    torch.onnx.export(
        model,
        (inputs["input_ids"], inputs["attention_mask"]),
        str(ONNX_FP32_PATH),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "sequence_length"},
            "attention_mask": {0: "batch_size", 1: "sequence_length"},
            "logits": {0: "batch_size"}
        },
        opset_version=17,
        dynamo=False,
        do_constant_folding=True
    )

    fp32_size_mb = ONNX_FP32_PATH.stat().st_size / (1024 * 1024)
    print(f"ONNX FP32 exported successfully: {ONNX_FP32_PATH} ({fp32_size_mb:.2f} MB)")

    print(f"\n--- 3. Applying Dynamic INT8 Quantization ---")
    quantize_dynamic(
        model_input=str(ONNX_FP32_PATH),
        model_output=str(ONNX_INT8_PATH),
        weight_type=QuantType.QInt8
    )
    int8_size_mb = ONNX_INT8_PATH.stat().st_size / (1024 * 1024)
    reduction = ((fp32_size_mb - int8_size_mb) / fp32_size_mb) * 100
    print(f"ONNX INT8 quantized model saved: {ONNX_INT8_PATH} ({int8_size_mb:.2f} MB)")
    print(f"Model compression: {reduction:.1f}% size reduction")

    print(f"\n--- 4. Benchmarking ONNX INT8 Inference Latency (CPU) ---")
    session_options = ort.SessionOptions()
    session_options.intra_op_num_threads = 4
    session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

    session = ort.InferenceSession(str(ONNX_INT8_PATH), session_options, providers=["CPUExecutionProvider"])

    test_queries = [
        "Urgent: Please wire $50,000 to our updated vendor bank account immediately.",
        "Security Alert: Your Microsoft Office 365 password expired. Verify credentials here.",
        "Department meeting scheduled for Monday morning. Please review the attached slide deck.",
        "Smart India Hackathon campus screening timetable has been published.",
        "Wire transfer confidential request do not call me scratch apple gift cards."
    ]

    # Warmup
    for _ in range(5):
        encoded = tokenizer("Warmup text", return_tensors="np", max_length=128, truncation=True, padding="max_length")
        session.run(None, {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"]
        })

    latencies = []
    iterations = 50
    for i in range(iterations):
        query = test_queries[i % len(test_queries)]
        t0 = time.perf_counter()
        encoded = tokenizer(query, return_tensors="np", max_length=128, truncation=True, padding="max_length")
        outputs = session.run(None, {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"]
        })
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    mean_lat = float(np.mean(latencies))
    p50_lat = float(np.percentile(latencies, 50))
    p95_lat = float(np.percentile(latencies, 95))
    min_lat = float(np.min(latencies))
    max_lat = float(np.max(latencies))

    print(f"Latency over {iterations} runs:")
    print(f"  Mean:  {mean_lat:.2f} ms")
    print(f"  P50:   {p50_lat:.2f} ms")
    print(f"  P95:   {p95_lat:.2f} ms")
    print(f"  Min:   {min_lat:.2f} ms | Max: {max_lat:.2f} ms")

    # Verify Predictions
    print(f"\n--- 5. Verifying Test Query Predictions ---")
    class_names = ["LEGITIMATE", "PHISHING", "BEC_FRAUD"]
    sample_evals = []
    for query in test_queries:
        encoded = tokenizer(query, return_tensors="np", max_length=128, truncation=True, padding="max_length")
        logits = session.run(None, {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"]
        })[0][0]
        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)
        pred_idx = int(np.argmax(probs))
        pred_label = class_names[pred_idx]
        sample_evals.append({
            "query": query[:60] + "...",
            "prediction": pred_label,
            "confidence": round(float(probs[pred_idx]), 4),
            "probs": {
                "legitimate": round(float(probs[0]), 4),
                "phishing": round(float(probs[1]), 4),
                "bec_fraud": round(float(probs[2]), 4)
            }
        })
        print(f"[{pred_label:<10}] ({probs[pred_idx]*100:.1f}%) -> {query[:65]}")

    benchmark_data = {
        "onnx_model": "threat_transformer_int8.onnx",
        "fp32_size_mb": round(fp32_size_mb, 2),
        "int8_size_mb": round(int8_size_mb, 2),
        "compression_ratio_percent": round(reduction, 2),
        "latency_metrics_ms": {
            "mean": round(mean_lat, 2),
            "p50": round(p50_lat, 2),
            "p95": round(p95_lat, 2),
            "min": round(min_lat, 2),
            "max": round(max_lat, 2)
        },
        "sample_evaluations": sample_evals
    }

    with open(BENCHMARK_PATH, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2)

    print(f"\nBenchmark metrics serialized to {BENCHMARK_PATH}")
    print("ONNX Export & INT8 Quantization Complete!")


if __name__ == "__main__":
    export_and_quantize()
