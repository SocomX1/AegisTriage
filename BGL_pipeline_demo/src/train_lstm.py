#!/usr/bin/env python3
"""
Train and evaluate an LSTM event-sequence classifier on BGL windows.

Input:
    data/processed/bgl_windows.csv

Outputs:
    models/lstm_event_classifier.pt
    models/event_vocab.json
    data/processed/lstm_predictions.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from torch import nn
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm


def str_to_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def parse_event_sequence(raw_sequence: str) -> list[str]:
    sequence = json.loads(raw_sequence)

    if not isinstance(sequence, list):
        raise ValueError("event_sequence must be a JSON list")

    return [str(event_id) for event_id in sequence]


class EventWindowDataset(Dataset):
    def __init__(self, sequences: np.ndarray, labels: np.ndarray):
        self.sequences = torch.tensor(sequences, dtype=torch.long)
        self.labels = torch.tensor(labels, dtype=torch.float32)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, index: int):
        return self.sequences[index], self.labels[index]


class EventLSTMClassifier(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = 64,
        hidden_size: int = 128,
        num_layers: int = 1,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embedding_dim,
            padding_idx=0,
        )

        self.lstm = nn.LSTM(
            input_size=embedding_dim,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(x)
        _, (hidden, _) = self.lstm(embedded)
        last_hidden = hidden[-1]
        logits = self.classifier(last_hidden).squeeze(1)
        return logits


def build_vocab(sequences: list[list[str]]) -> dict[str, int]:
    event_ids = sorted(
        {event_id for sequence in sequences for event_id in sequence},
        key=lambda event_id: int(event_id[1:]) if event_id.startswith("E") else event_id,
    )

    vocab = {"<PAD>": 0}

    for event_id in event_ids:
        vocab[event_id] = len(vocab)

    return vocab


def encode_sequences(sequences: list[list[str]], vocab: dict[str, int]) -> np.ndarray:
    encoded = []

    for sequence in sequences:
        encoded.append([vocab[event_id] for event_id in sequence])

    return np.array(encoded, dtype=np.int64)


def choose_best_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(y_true, probabilities)

    best_threshold = 0.5
    best_f1 = -1.0

    for i, threshold in enumerate(thresholds):
        p = precision[i]
        r = recall[i]

        if p + r == 0:
            current_f1 = 0.0
        else:
            current_f1 = 2 * p * r / (p + r)

        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = threshold

    return float(best_threshold)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, probabilities: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0

    try:
        roc_auc = roc_auc_score(y_true, probabilities)
    except ValueError:
        roc_auc = float("nan")

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc,
        "false_positive_rate": fpr,
        "true_negative_rate": tnr,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def print_metrics(title: str, metrics: dict) -> None:
    print(f"\n{title}")
    print("=" * len(title))
    print(f"Accuracy:             {metrics['accuracy']:.4f}")
    print(f"Precision:            {metrics['precision']:.4f}")
    print(f"Recall:               {metrics['recall']:.4f}")
    print(f"F1 Score:             {metrics['f1']:.4f}")
    print(f"ROC-AUC:              {metrics['roc_auc']:.4f}")
    print(f"False Positive Rate:  {metrics['false_positive_rate']:.4f}")
    print(f"True Negative Rate:   {metrics['true_negative_rate']:.4f}")
    print()
    print("Confusion Matrix")
    print("----------------")
    print(f"TN: {metrics['true_negatives']}")
    print(f"FP: {metrics['false_positives']}")
    print(f"FN: {metrics['false_negatives']}")
    print(f"TP: {metrics['true_positives']}")


def evaluate_model(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
) -> tuple[np.ndarray, np.ndarray]:
    model.eval()

    all_probs = []
    all_labels = []

    with torch.no_grad():
        for sequences, labels in loader:
            sequences = sequences.to(device)
            logits = model(sequences)
            probabilities = torch.sigmoid(logits)

            all_probs.extend(probabilities.cpu().numpy())
            all_labels.extend(labels.numpy())

    return np.array(all_labels, dtype=np.int64), np.array(all_probs, dtype=np.float32)


def train_lstm(
    input_csv: Path,
    model_output: Path,
    vocab_output: Path,
    predictions_output: Path,
    test_size: float,
    val_size: float,
    random_state: int,
    batch_size: int,
    epochs: int,
    learning_rate: float,
    embedding_dim: int,
    hidden_size: int,
    num_layers: int,
    dropout: float,
) -> None:
    torch.manual_seed(random_state)
    np.random.seed(random_state)

    df = pd.read_csv(input_csv)

    required = {"event_sequence", "is_alert_window"}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    sequences = [parse_event_sequence(raw) for raw in df["event_sequence"]]
    labels = df["is_alert_window"].map(str_to_bool).astype(int).to_numpy()

    vocab = build_vocab(sequences)
    encoded_sequences = encode_sequences(sequences, vocab)

    temp_size = test_size + val_size

    X_train, X_temp, y_train, y_temp, df_train, df_temp = train_test_split(
        encoded_sequences,
        labels,
        df,
        test_size=temp_size,
        random_state=random_state,
        stratify=labels,
    )

    relative_test_size = test_size / temp_size

    X_val, X_test, y_val, y_test, df_val, df_test = train_test_split(
        X_temp,
        y_temp,
        df_temp,
        test_size=relative_test_size,
        random_state=random_state,
        stratify=y_temp,
    )

    train_dataset = EventWindowDataset(X_train, y_train)
    val_dataset = EventWindowDataset(X_val, y_val)
    test_dataset = EventWindowDataset(X_test, y_test)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = EventLSTMClassifier(
        vocab_size=len(vocab),
        embedding_dim=embedding_dim,
        hidden_size=hidden_size,
        num_layers=num_layers,
        dropout=dropout,
    ).to(device)

    num_positive = y_train.sum()
    num_negative = len(y_train) - num_positive
    pos_weight_value = num_negative / num_positive if num_positive else 1.0

    loss_fn = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([pos_weight_value], dtype=torch.float32, device=device)
    )

    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

    print("\nLSTM training started")
    print("=====================")
    print(f"Input CSV:           {input_csv}")
    print(f"Rows loaded:         {len(df)}")
    print(f"Vocabulary size:     {len(vocab)}")
    print(f"Sequence length:     {encoded_sequences.shape[1]}")
    print(f"Training rows:       {len(X_train)}")
    print(f"Validation rows:     {len(X_val)}")
    print(f"Test rows:           {len(X_test)}")
    print(f"Alert rate overall:  {labels.mean():.4%}")
    print(f"Positive weight:     {pos_weight_value:.4f}")
    print(f"Device:              {device}")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0

        progress = tqdm(train_loader, desc=f"Epoch {epoch}/{epochs}", leave=False)

        for batch_sequences, batch_labels in progress:
            batch_sequences = batch_sequences.to(device)
            batch_labels = batch_labels.to(device)

            optimizer.zero_grad()
            logits = model(batch_sequences)
            loss = loss_fn(logits, batch_labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * batch_sequences.size(0)
            progress.set_postfix(loss=loss.item())

        avg_train_loss = total_loss / len(train_dataset)

        val_labels, val_probs = evaluate_model(model, val_loader, device)
        val_threshold = choose_best_threshold(val_labels, val_probs)
        val_preds = (val_probs >= val_threshold).astype(int)
        val_metrics = compute_metrics(val_labels, val_preds, val_probs)

        print(
            f"Epoch {epoch:02d} | "
            f"train_loss={avg_train_loss:.4f} | "
            f"val_f1={val_metrics['f1']:.4f} | "
            f"val_precision={val_metrics['precision']:.4f} | "
            f"val_recall={val_metrics['recall']:.4f} | "
            f"val_fpr={val_metrics['false_positive_rate']:.4f}"
        )

    val_labels, val_probs = evaluate_model(model, val_loader, device)
    threshold = choose_best_threshold(val_labels, val_probs)
    val_preds = (val_probs >= threshold).astype(int)
    val_metrics = compute_metrics(val_labels, val_preds, val_probs)

    test_labels, test_probs = evaluate_model(model, test_loader, device)
    test_preds = (test_probs >= threshold).astype(int)
    test_metrics = compute_metrics(test_labels, test_preds, test_probs)

    model_output.parent.mkdir(parents=True, exist_ok=True)
    vocab_output.parent.mkdir(parents=True, exist_ok=True)
    predictions_output.parent.mkdir(parents=True, exist_ok=True)

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "vocab_size": len(vocab),
            "embedding_dim": embedding_dim,
            "hidden_size": hidden_size,
            "num_layers": num_layers,
            "dropout": dropout,
            "threshold": threshold,
        },
        model_output,
    )

    with vocab_output.open("w", encoding="utf-8") as f:
        json.dump(vocab, f, indent=2)

    output_df = df_test.copy()
    output_df["alert_probability"] = test_probs
    output_df["predicted_alert"] = test_preds.astype(bool)
    output_df["threshold"] = threshold
    output_df.to_csv(predictions_output, index=False)

    print("\nLSTM training complete")
    print("======================")
    print(f"Chosen threshold:      {threshold:.6f}")
    print(f"Model saved to:        {model_output}")
    print(f"Vocabulary saved to:   {vocab_output}")
    print(f"Predictions saved to:  {predictions_output}")

    print_metrics("Validation Metrics", val_metrics)
    print_metrics("Test Metrics", test_metrics)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train LSTM classifier on BGL event windows."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_windows.csv"),
    )

    parser.add_argument(
        "--model-output",
        type=Path,
        default=Path("models/lstm_event_classifier.pt"),
    )

    parser.add_argument(
        "--vocab-output",
        type=Path,
        default=Path("models/event_vocab.json"),
    )

    parser.add_argument(
        "--predictions-output",
        type=Path,
        default=Path("data/processed/lstm_predictions.csv"),
    )

    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--embedding-dim", type=int, default=64)
    parser.add_argument("--hidden-size", type=int, default=128)
    parser.add_argument("--num-layers", type=int, default=1)
    parser.add_argument("--dropout", type=float, default=0.3)

    args = parser.parse_args()

    train_lstm(
        input_csv=args.input,
        model_output=args.model_output,
        vocab_output=args.vocab_output,
        predictions_output=args.predictions_output,
        test_size=args.test_size,
        val_size=args.val_size,
        random_state=args.random_state,
        batch_size=args.batch_size,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        embedding_dim=args.embedding_dim,
        hidden_size=args.hidden_size,
        num_layers=args.num_layers,
        dropout=args.dropout,
    )


if __name__ == "__main__":
    main()
