#!/usr/bin/env python3

import argparse
import csv
import re
import subprocess
from pathlib import Path


def run_command(cmd):
    print("\n[RUN]", " ".join(cmd))
    result = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {result.returncode}")

    return result.stdout


def extract_metric(output, metric_name):
    patterns = [
        rf"{metric_name}\s*[:=]\s*([0-9.]+)",
        rf"Validation\s+{metric_name}\s*[:=]\s*([0-9.]+)",
        rf"val_{metric_name.lower()}\s*[:=]\s*([0-9.]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return float(match.group(1))

    return None


def main():
    parser = argparse.ArgumentParser(description="Run LSTM ablation sweeps.")

    parser.add_argument("--train-script", default="src/train_lstm.py")
    parser.add_argument("--output", default="reports/lstm_ablation_results.csv")

    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--num-layers", type=int, default=1)

    parser.add_argument(
        "--input-10",
        default="data/processed/bgl_windows_deleaked_10.csv",
    )
    parser.add_argument(
        "--input-20",
        default="data/processed/bgl_windows_deleaked.csv",
    )
    parser.add_argument(
        "--input-50",
        default="data/processed/bgl_windows_deleaked_50.csv",
    )

    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_config = {
        "window_size": 20,
        "hidden_size": 128,
        "dropout": 0.3,
        "embedding_dim": 64,
    }

    window_inputs = {
        10: args.input_10,
        20: args.input_20,
        50: args.input_50,
    }

    sweeps = {
        "window_size": [10, 20, 50],
        "hidden_size": [64, 128, 256],
        "dropout": [0.1, 0.3, 0.5],
        "embedding_dim": [32, 64, 128],
    }

    rows = []

    for sweep_name, values in sweeps.items():
        for value in values:
            config = base_config.copy()
            config[sweep_name] = value

            input_file = window_inputs[config["window_size"]]
            run_name = f"{sweep_name}_{value}"

            model_out = f"models/ablations/lstm_{run_name}.pt"
            vocab_out = f"models/ablations/vocab_{run_name}.json"

            Path(model_out).parent.mkdir(parents=True, exist_ok=True)

            cmd = [
                "python",
                args.train_script,
                "--input",
                input_file,
                "--model-output",
                model_out,
                "--vocab-output",
                vocab_out,
                "--test-size",
                str(args.test_size),
                "--val-size",
                str(args.val_size),
                "--random-state",
                str(args.random_state),
                "--batch-size",
                str(args.batch_size),
                "--epochs",
                str(args.epochs),
                "--learning-rate",
                str(args.learning_rate),
                "--embedding-dim",
                str(config["embedding_dim"]),
                "--hidden-size",
                str(config["hidden_size"]),
                "--num-layers",
                str(args.num_layers),
                "--dropout",
                str(config["dropout"]),
            ]

            try:
                output = run_command(cmd)

                row = {
                    "sweep": sweep_name,
                    "setting": value,
                    "input_file": input_file,
                    "window_size": config["window_size"],
                    "hidden_size": config["hidden_size"],
                    "dropout": config["dropout"],
                    "embedding_dim": config["embedding_dim"],
                    "accuracy": extract_metric(output, "accuracy"),
                    "precision": extract_metric(output, "precision"),
                    "recall": extract_metric(output, "recall"),
                    "f1": extract_metric(output, "f1"),
                    "roc_auc": extract_metric(output, "roc_auc"),
                    "model_output": model_out,
                    "vocab_output": vocab_out,
                    "status": "ok",
                }

            except Exception as e:
                row = {
                    "sweep": sweep_name,
                    "setting": value,
                    "input_file": input_file,
                    "window_size": config["window_size"],
                    "hidden_size": config["hidden_size"],
                    "dropout": config["dropout"],
                    "embedding_dim": config["embedding_dim"],
                    "accuracy": None,
                    "precision": None,
                    "recall": None,
                    "f1": None,
                    "roc_auc": None,
                    "model_output": model_out,
                    "vocab_output": vocab_out,
                    "status": f"failed: {e}",
                }

            rows.append(row)

    fieldnames = list(rows[0].keys())

    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[DONE] Results saved to {output_path}")


if __name__ == "__main__":
    main()
