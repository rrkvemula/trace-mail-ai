"""
Deep Learning Threat Classifier Fine-Tuning Script for TRACE-MAIL AI.
Fine-tunes a DistilBERT sequence classification model
on the curated 3-class cybersecurity dataset (Legitimate, Phishing, BEC Fraud).
Hardware-adaptive: accelerates with CUDA/AMP on GPU or multi-threaded CPU.
"""

import os
import sys
import json
import time
import math
from pathlib import Path
from typing import List, Tuple, Dict, Any

import numpy as np

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

DATA_FILE = BASE_DIR / "training" / "data" / "threat_corpus_1200.jsonl"
MODELS_DIR = BASE_DIR / "engine" / "models"
TRANSFORMER_DIR = MODELS_DIR / "distilbert_threat_model"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
TRANSFORMER_DIR.mkdir(parents=True, exist_ok=True)

from engine.parser import EmailParser


def load_dataset() -> Tuple[List[str], List[int]]:
    """Loads and preprocesses the dataset."""
    texts = []
    labels = []

    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Corpus file not found: {DATA_FILE}")

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                texts.append(item["text"])
                labels.append(item["label"])

    # Augment with sample emails
    samples_dir = BASE_DIR / "sample_emails"
    sample_mappings = {
        "ceo_bec_fraud.eml": 2,
        "vendor_bank_change_bec.eml": 2,
        "payroll_direct_deposit_bec.eml": 2,
        "credential_phishing_portal.eml": 1,
        "credential_harvest_ssrf_attack.eml": 1,
        "legitimate_delivery.eml": 0,
        "legitimate_password_expiry_notice.eml": 0,
        "legitimate_urgent_executive.eml": 0,
        "forged_relay_attack.eml": 1
    }

    for fname, label in sample_mappings.items():
        eml_path = samples_dir / fname
        if eml_path.exists():
            try:
                parsed = EmailParser(eml_path.read_bytes()).parse()
                combined = " ".join([
                    parsed.get("headers", {}).get("subject", ""),
                    parsed.get("body", {}).get("plain_text", "")
                ]).strip()
                if combined:
                    for _ in range(5):
                        texts.append(combined)
                        labels.append(label)
            except Exception as e:
                print(f"Warning: Could not parse {fname}: {e}")

    print(f"Loaded {len(texts)} samples across 3 classes (0: Legit, 1: Phishing, 2: BEC).")
    return texts, labels


def train():
    import torch
    from torch.utils.data import Dataset, DataLoader
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        get_linear_schedule_with_warmup
    )
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

    # Configure multi-threaded CPU acceleration
    num_threads = min(12, os.cpu_count() or 4)
    torch.set_num_threads(num_threads)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"--- Hardware Telemetry ---")
    print(f"PyTorch Version: {torch.__version__}")
    print(f"Compute Device: {device}")
    print(f"CPU Parallel Threads: {num_threads}")
    if device.type == "cuda":
        print(f"GPU Name: {torch.cuda.get_device_name(0)}")
        print(f"VRAM Total: {torch.cuda.get_device_properties(0).total_memory / (1024**2):.1f} MB")

    texts, labels = load_dataset()
    labels = np.array(labels)

    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts, labels, test_size=0.15, random_state=42, stratify=labels
    )
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        train_texts, train_labels, test_size=0.10, random_state=42, stratify=train_labels
    )

    print(f"Split sizes: Train={len(train_texts)}, Val={len(val_texts)}, Test={len(test_texts)}")

    model_name = "distilbert-base-uncased"
    print(f"\n--- Loading Tokenizer & Pretrained Model: {model_name} ---")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=3,
        id2label={0: "LEGITIMATE", 1: "PHISHING", 2: "BEC_FRAUD"},
        label2id={"LEGITIMATE": 0, "PHISHING": 1, "BEC_FRAUD": 2}
    )
    model.to(device)

    class TextDataset(Dataset):
        def __init__(self, texts_list, labels_list, tok, max_len=128):
            self.encodings = tok(
                texts_list,
                truncation=True,
                padding=True,
                max_length=max_len,
                return_tensors="pt"
            )
            self.labels = torch.tensor(labels_list, dtype=torch.long)

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            item = {key: val[idx] for key, val in self.encodings.items()}
            item["labels"] = self.labels[idx]
            return item

    train_dataset = TextDataset(train_texts, train_labels, tokenizer)
    val_dataset = TextDataset(val_texts, val_labels, tokenizer)
    test_dataset = TextDataset(test_texts, test_labels, tokenizer)

    batch_size = 32
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    epochs = 3
    total_steps = len(train_loader) * epochs
    warmup_steps = int(0.1 * total_steps)

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=0.01)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )

    use_amp = (device.type == "cuda" and torch.cuda.is_available())
    scaler = torch.amp.GradScaler("cuda") if use_amp else None

    print(f"\n--- Beginning Fine-Tuning ({epochs} Epochs, {total_steps} Steps, Batch={batch_size}, AMP={use_amp}) ---")
    start_time = time.time()

    for epoch in range(epochs):
        epoch_start = time.time()
        model.train()
        total_train_loss = 0.0

        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            batch_labels = batch["labels"].to(device)

            optimizer.zero_grad()

            if use_amp:
                with torch.amp.autocast(device_type="cuda"):
                    outputs = model(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        labels=batch_labels
                    )
                    loss = outputs.loss
                scaler.scale(loss).backward()
                scaler.step(optimizer)
                scaler.update()
            else:
                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=batch_labels
                )
                loss = outputs.loss
                loss.backward()
                optimizer.step()

            scheduler.step()
            total_train_loss += loss.item()

            if (step + 1) % 20 == 0 or (step + 1) == len(train_loader):
                elapsed = time.time() - epoch_start
                print(f"  Epoch {epoch+1} | Step {step+1}/{len(train_loader)} | Loss: {loss.item():.4f} | Elapsed: {elapsed:.1f}s")

        avg_train_loss = total_train_loss / len(train_loader)

        # Validation
        model.eval()
        val_preds, val_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                preds = torch.argmax(outputs.logits, dim=-1).cpu().numpy()
                val_preds.extend(preds)
                val_targets.extend(batch["labels"].cpu().numpy())

        val_acc = accuracy_score(val_targets, val_preds)
        val_f1 = f1_score(val_targets, val_preds, average="macro")
        epoch_time = time.time() - epoch_start
        print(f"==> Epoch {epoch+1}/{epochs} Complete ({epoch_time:.1f}s) | Train Loss: {avg_train_loss:.4f} | Val Acc: {val_acc*100:.2f}% | Val Macro F1: {val_f1*100:.2f}%\n")

    training_duration = time.time() - start_time
    print(f"Training completed in {training_duration:.1f}s.")

    # Holdout Test Evaluation
    print("\n--- Holdout Test Evaluation ---")
    model.eval()
    test_preds, test_targets = [], []
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=-1).cpu().numpy()
            test_preds.extend(preds)
            test_targets.extend(batch["labels"].cpu().numpy())

    test_acc = accuracy_score(test_targets, test_preds)
    test_f1 = f1_score(test_targets, test_preds, average="macro")
    print(f"Test Accuracy: {test_acc*100:.2f}% | Test Macro F1: {test_f1*100:.2f}%\n")
    print(classification_report(test_targets, test_preds, target_names=["LEGITIMATE", "PHISHING", "BEC_FRAUD"], digits=4))
    print("Confusion Matrix:")
    print(confusion_matrix(test_targets, test_preds))

    # Save fine-tuned transformer and tokenizer
    print(f"\n--- Serializing Fine-Tuned Model to {TRANSFORMER_DIR} ---")
    model.save_pretrained(TRANSFORMER_DIR)
    tokenizer.save_pretrained(TRANSFORMER_DIR)

    metadata = {
        "base_model": model_name,
        "test_accuracy": round(float(test_acc), 4),
        "test_macro_f1": round(float(test_f1), 4),
        "training_duration_seconds": round(training_duration, 2),
        "epochs": epochs,
        "device": str(device),
        "gpu_name": torch.cuda.get_device_name(0) if device.type == "cuda" else "CPU (16 Threads)",
        "classes": ["LEGITIMATE", "PHISHING", "BEC_FRAUD"],
        "num_train_samples": len(train_texts),
        "num_test_samples": len(test_texts)
    }

    meta_file = MODELS_DIR / "transformer_metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Metadata saved to {meta_file}")
    print("Deep Learning Fine-Tuning Successful!")


if __name__ == "__main__":
    train()
