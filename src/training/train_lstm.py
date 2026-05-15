#!/usr/bin/env python3
"""
Train a lightweight LSTM classifier on audit event sequences.

The model consumes categorical token IDs plus numeric event features generated
by src/features/build_lstm_sequences.py. CUDA is used automatically when available.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from torch import nn
from torch.utils.data import DataLoader, Dataset


class SequenceDataset(Dataset):
    def __init__(
        self,
        x_cat: np.ndarray,
        x_num: np.ndarray,
        y: np.ndarray,
        indices: np.ndarray,
        num_mean: np.ndarray,
        num_std: np.ndarray,
    ) -> None:
        self.x_cat = x_cat[indices].astype(np.int64)
        self.x_num = ((x_num[indices] - num_mean) / num_std).astype(np.float32)
        self.y = y[indices].astype(np.float32)

    def __len__(self) -> int:
        return len(self.y)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        return (
            torch.from_numpy(self.x_cat[idx]),
            torch.from_numpy(self.x_num[idx]),
            torch.tensor(self.y[idx], dtype=torch.float32),
        )


class AuditLSTM(nn.Module):
    def __init__(
        self,
        vocab_sizes: List[int],
        numeric_dim: int,
        embedding_dim: int,
        hidden_dim: int,
        num_layers: int,
        dropout: float,
    ) -> None:
        super().__init__()
        self.embeddings = nn.ModuleList(
            [nn.Embedding(size, embedding_dim, padding_idx=0) for size in vocab_sizes]
        )
        event_dim = (len(vocab_sizes) * embedding_dim) + numeric_dim
        lstm_dropout = dropout if num_layers > 1 else 0.0
        self.lstm = nn.LSTM(
            input_size=event_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=lstm_dropout,
        )
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, x_cat: torch.Tensor, x_num: torch.Tensor) -> torch.Tensor:
        embedded = [
            embedding(x_cat[:, :, idx]) for idx, embedding in enumerate(self.embeddings)
        ]
        event_features = torch.cat(embedded + [x_num], dim=-1)
        _, (hidden, _) = self.lstm(event_features)
        logits = self.classifier(hidden[-1]).squeeze(-1)
        return logits


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_schema(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_dataset(path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    with np.load(path, allow_pickle=False) as data:
        x_cat = data["X_cat"]
        x_num = data["X_num"]
        y = data["y"]
    if len(x_cat) != len(x_num) or len(x_cat) != len(y):
        raise ValueError("Dataset arrays have inconsistent lengths")
    return x_cat, x_num, y


def choose_device(requested: str) -> torch.device:
    if requested == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if requested == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA was requested but torch.cuda.is_available() is false")
    return torch.device(requested)


def group_train_val_split(
    manifest: pd.DataFrame,
    y: np.ndarray,
    val_size: float,
    random_state: int,
) -> Tuple[np.ndarray, np.ndarray]:
    if "segment_id" not in manifest.columns:
        raise ValueError("Manifest is missing segment_id")

    indices = np.arange(len(y))
    groups = manifest["segment_id"].astype(str).to_numpy()

    splitter = GroupShuffleSplit(n_splits=1, test_size=val_size, random_state=random_state)
    train_idx, val_idx = next(splitter.split(indices, y, groups))

    if len(np.unique(y[train_idx])) < 2 or len(np.unique(y[val_idx])) < 2:
        raise ValueError("Group split produced a single-class train or validation set")
    return train_idx, val_idx


def normalization_stats(x_num: np.ndarray, train_idx: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    train_num = x_num[train_idx]
    mean = train_num.mean(axis=(0, 1), keepdims=True).astype(np.float32)
    std = train_num.std(axis=(0, 1), keepdims=True).astype(np.float32)
    std[std < 1e-6] = 1.0
    return mean, std


def metrics_from_probs(y_true: np.ndarray, probs: np.ndarray, threshold: float) -> Dict[str, float]:
    preds = (probs >= threshold).astype(int)
    metrics = {
        "accuracy": float(accuracy_score(y_true, preds)),
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall": float(recall_score(y_true, preds, zero_division=0)),
        "f1": float(f1_score(y_true, preds, zero_division=0)),
    }
    if len(np.unique(y_true)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, probs))
    else:
        metrics["roc_auc"] = float("nan")
    return metrics


def evaluate(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
    threshold: float,
) -> Tuple[float, Dict[str, float], np.ndarray]:
    model.eval()
    losses: List[float] = []
    probs: List[np.ndarray] = []
    labels: List[np.ndarray] = []

    with torch.no_grad():
        for x_cat, x_num, y in loader:
            x_cat = x_cat.to(device)
            x_num = x_num.to(device)
            y = y.to(device)
            logits = model(x_cat, x_num)
            loss = criterion(logits, y)
            losses.append(float(loss.item()))
            probs.append(torch.sigmoid(logits).cpu().numpy())
            labels.append(y.cpu().numpy())

    all_probs = np.concatenate(probs)
    all_labels = np.concatenate(labels).astype(int)
    return float(np.mean(losses)), metrics_from_probs(all_labels, all_probs, threshold), all_probs


def train(
    model: nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    y_train: np.ndarray,
    device: torch.device,
    epochs: int,
    learning_rate: float,
    threshold: float,
    patience: int,
) -> Tuple[Dict[str, object], Dict[str, torch.Tensor]]:
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    pos_weight = torch.tensor([neg / max(pos, 1)], dtype=torch.float32, device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)

    best_f1 = -1.0
    best_state: Dict[str, torch.Tensor] = {}
    best_epoch = 0
    epochs_without_improvement = 0
    history: List[Dict[str, object]] = []

    for epoch in range(1, epochs + 1):
        model.train()
        train_losses: List[float] = []
        for x_cat, x_num, y in train_loader:
            x_cat = x_cat.to(device)
            x_num = x_num.to(device)
            y = y.to(device)

            optimizer.zero_grad(set_to_none=True)
            logits = model(x_cat, x_num)
            loss = criterion(logits, y)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            train_losses.append(float(loss.item()))

        val_loss, val_metrics, _ = evaluate(model, val_loader, criterion, device, threshold)
        row = {
            "epoch": epoch,
            "train_loss": float(np.mean(train_losses)),
            "val_loss": val_loss,
            **{f"val_{key}": value for key, value in val_metrics.items()},
        }
        history.append(row)

        print(
            f"[+] Epoch {epoch:03d} "
            f"train_loss={row['train_loss']:.4f} "
            f"val_loss={val_loss:.4f} "
            f"val_f1={val_metrics['f1']:.4f} "
            f"val_precision={val_metrics['precision']:.4f} "
            f"val_recall={val_metrics['recall']:.4f}"
        )

        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            best_epoch = epoch
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1

        if epochs_without_improvement >= patience:
            print(f"[+] Early stopping after {patience} epochs without validation F1 improvement")
            break

    return {"best_epoch": best_epoch, "best_val_f1": best_f1, "history": history}, best_state


def save_predictions(
    path: Path,
    manifest: pd.DataFrame,
    val_idx: np.ndarray,
    probs: np.ndarray,
    threshold: float,
) -> None:
    output = manifest.iloc[val_idx].copy().reset_index(drop=True)
    output["lstm_malicious_probability"] = probs
    output["lstm_prediction"] = np.where(probs >= threshold, 1, 0)
    output["lstm_prediction_label"] = np.where(output["lstm_prediction"] == 1, "malicious", "benign")
    path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(path, index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an LSTM classifier on audit sequence data.")
    parser.add_argument("--dataset", default="data/model/lstm_sequences.npz")
    parser.add_argument("--vocab", default="data/model/lstm_vocab.json")
    parser.add_argument("--manifest", default="data/model/lstm_sequence_manifest.csv")
    parser.add_argument("--model-out", default="models/lstm_classifier.pt")
    parser.add_argument("--metrics-out", default="data/model/lstm_metrics.json")
    parser.add_argument("--predictions-out", default="data/model/lstm_validation_predictions.csv")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--embedding-dim", type=int, default=16)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=1)
    parser.add_argument("--dropout", type=float, default=0.25)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--val-size", type=float, default=0.25)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    if args.epochs <= 0:
        raise ValueError("--epochs must be positive")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be positive")
    if not 0.0 < args.val_size < 1.0:
        raise ValueError("--val-size must be between 0 and 1")
    if args.hidden_dim < 2:
        raise ValueError("--hidden-dim must be at least 2")

    set_seed(args.random_state)
    device = choose_device(args.device)

    x_cat, x_num, y = load_dataset(Path(args.dataset))
    schema = load_schema(Path(args.vocab))
    manifest = pd.read_csv(args.manifest)

    if len(manifest) != len(y):
        raise ValueError("Manifest row count does not match dataset label count")

    train_idx, val_idx = group_train_val_split(manifest, y, args.val_size, args.random_state)
    num_mean, num_std = normalization_stats(x_num, train_idx)

    train_dataset = SequenceDataset(x_cat, x_num, y, train_idx, num_mean, num_std)
    val_dataset = SequenceDataset(x_cat, x_num, y, val_idx, num_mean, num_std)
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size, shuffle=False)

    vocab_sizes = [len(schema["vocabs"][column]) for column in schema["categorical_columns"]]
    model = AuditLSTM(
        vocab_sizes=vocab_sizes,
        numeric_dim=x_num.shape[-1],
        embedding_dim=args.embedding_dim,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
    ).to(device)

    print(f"[+] Device: {device}")
    if device.type == "cuda":
        print(f"[+] CUDA device: {torch.cuda.get_device_name(0)}")
    print(f"[+] Train sequences: {len(train_idx)}")
    print(f"[+] Validation sequences: {len(val_idx)}")
    print(f"[+] Train labels: benign={int((y[train_idx] == 0).sum())} malicious={int((y[train_idx] == 1).sum())}")
    print(f"[+] Validation labels: benign={int((y[val_idx] == 0).sum())} malicious={int((y[val_idx] == 1).sum())}")

    train_result, best_state = train(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        y_train=y[train_idx],
        device=device,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        threshold=args.threshold,
        patience=args.patience,
    )

    model.load_state_dict(best_state)
    criterion = nn.BCEWithLogitsLoss()
    val_loss, val_metrics, val_probs = evaluate(model, val_loader, criterion, device, args.threshold)

    model_path = Path(args.model_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "model_config": {
                "vocab_sizes": vocab_sizes,
                "numeric_dim": int(x_num.shape[-1]),
                "embedding_dim": args.embedding_dim,
                "hidden_dim": args.hidden_dim,
                "num_layers": args.num_layers,
                "dropout": args.dropout,
            },
            "categorical_columns": schema["categorical_columns"],
            "numeric_columns": schema["numeric_columns"],
            "num_mean": num_mean.astype(np.float32),
            "num_std": num_std.astype(np.float32),
            "threshold": args.threshold,
            "label_mapping": schema.get("label_mapping", {"benign": 0, "malicious": 1}),
        },
        model_path,
    )

    predictions_path = Path(args.predictions_out)
    save_predictions(predictions_path, manifest, val_idx, val_probs, args.threshold)

    metrics = {
        "dataset": args.dataset,
        "manifest": args.manifest,
        "device": str(device),
        "cuda_available": torch.cuda.is_available(),
        "train_sequences": int(len(train_idx)),
        "validation_sequences": int(len(val_idx)),
        "train_label_counts": {
            "benign": int((y[train_idx] == 0).sum()),
            "malicious": int((y[train_idx] == 1).sum()),
        },
        "validation_label_counts": {
            "benign": int((y[val_idx] == 0).sum()),
            "malicious": int((y[val_idx] == 1).sum()),
        },
        "validation_loss": val_loss,
        "validation_metrics": val_metrics,
        **train_result,
    }
    metrics_path = Path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        f.write("\n")

    print(f"[+] Best epoch: {train_result['best_epoch']}")
    print(f"[+] Validation metrics: {val_metrics}")
    print(f"[+] Wrote model: {model_path}")
    print(f"[+] Wrote metrics: {metrics_path}")
    print(f"[+] Wrote validation predictions: {predictions_path}")


if __name__ == "__main__":
    main()
