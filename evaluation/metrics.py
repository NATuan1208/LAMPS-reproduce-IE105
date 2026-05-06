from __future__ import annotations

from dataclasses import dataclass
from math import erf, sqrt
from typing import Iterable, Tuple


@dataclass
class ClassificationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    balanced_accuracy: float
    tp: int
    tn: int
    fp: int
    fn: int


def confusion_counts(y_true: Iterable[int], y_pred: Iterable[int]) -> Tuple[int, int, int, int]:
    tp = tn = fp = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 1 and pred == 0:
            fn += 1
    return tp, tn, fp, fn


def compute_metrics(y_true: Iterable[int], y_pred: Iterable[int]) -> ClassificationMetrics:
    y_true = list(y_true)
    y_pred = list(y_pred)
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have equal length.")
    if not y_true:
        raise ValueError("Cannot compute metrics for empty input.")

    tp, tn, fp, fn = confusion_counts(y_true, y_pred)
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    balanced_accuracy = (recall + tnr) / 2.0

    return ClassificationMetrics(
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        balanced_accuracy=balanced_accuracy,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
    )


def mcnemar_test(y_true: Iterable[int], model_a_pred: Iterable[int], model_b_pred: Iterable[int]) -> dict:
    y_true = list(y_true)
    a = list(model_a_pred)
    b = list(model_b_pred)
    if not (len(y_true) == len(a) == len(b)):
        raise ValueError("y_true and predictions must have equal length.")

    n01 = 0
    n10 = 0
    for truth, pred_a, pred_b in zip(y_true, a, b):
        a_correct = int(pred_a == truth)
        b_correct = int(pred_b == truth)
        if a_correct == 0 and b_correct == 1:
            n01 += 1
        elif a_correct == 1 and b_correct == 0:
            n10 += 1

    if n01 + n10 == 0:
        return {
            "n01": 0,
            "n10": 0,
            "chi2": 0.0,
            "p_value_approx": 1.0,
        }

    chi2 = ((abs(n01 - n10) - 1) ** 2) / (n01 + n10)
    p_value = _chi_square_sf_1df(chi2)

    return {
        "n01": n01,
        "n10": n10,
        "chi2": chi2,
        "p_value_approx": p_value,
    }


def _chi_square_sf_1df(x: float) -> float:
    if x <= 0:
        return 1.0
    z = sqrt(x / 2.0)
    cdf = erf(z)
    return max(0.0, min(1.0, 1.0 - cdf))



# ---------------------------------------------------------------------------
# G3 -- Real-world imbalance metrics (no sklearn dependency)
# ---------------------------------------------------------------------------

def _prepare_binary_rank_inputs(
    y_true: Iterable[int],
    y_scores: Iterable[float],
) -> tuple[list[int], list[float]]:
    true_list = [int(value) for value in y_true]
    score_list = [float(value) for value in y_scores]

    if len(true_list) != len(score_list):
        raise ValueError("y_true and y_scores must have equal length.")

    return true_list, score_list


def compute_pr_curve(
    y_true: Iterable[int],
    y_scores: Iterable[float],
) -> dict:
    """Compute a manual precision-recall curve without sklearn."""
    true_list, score_list = _prepare_binary_rank_inputs(y_true, y_scores)
    if not true_list:
        return {
            "precisions": [],
            "recalls": [],
            "thresholds": [],
        }

    ranked_pairs = sorted(zip(score_list, true_list), key=lambda item: item[0], reverse=True)
    total_positives = sum(true_list)

    precisions: list[float] = []
    recalls: list[float] = []
    thresholds: list[float] = []

    for threshold in sorted({score for score, _ in ranked_pairs}, reverse=True):
        tp = fp = 0
        for score, label in ranked_pairs:
            if score >= threshold:
                if label == 1:
                    tp += 1
                else:
                    fp += 1

        predicted_positive = tp + fp
        precision = tp / predicted_positive if predicted_positive else 0.0
        recall = tp / total_positives if total_positives else 0.0

        thresholds.append(threshold)
        precisions.append(precision)
        recalls.append(recall)

    return {
        "precisions": precisions,
        "recalls": recalls,
        "thresholds": thresholds,
    }


def compute_average_precision(
    y_true: Iterable[int],
    y_scores: Iterable[float],
) -> float:
    """Compute Average Precision from the manual PR curve."""
    true_list, score_list = _prepare_binary_rank_inputs(y_true, y_scores)
    if not true_list or sum(true_list) == 0:
        return 0.0

    curve = compute_pr_curve(true_list, score_list)
    precisions = curve["precisions"]
    recalls = curve["recalls"]

    ap = 0.0
    previous_recall = 0.0
    for precision, recall in zip(precisions, recalls):
        delta_recall = recall - previous_recall
        if delta_recall > 0:
            ap += precision * delta_recall
        previous_recall = recall

    return max(0.0, min(1.0, ap))


def compute_bayesian_precision(tpr: float, fpr: float, prior: float) -> float:
    """Compute expected precision after deployment under a given class prior."""
    numerator = tpr * prior
    denominator = numerator + fpr * (1.0 - prior)
    return numerator / denominator if denominator > 0.0 else 0.0


def compute_expected_fdr(tpr: float, fpr: float, prior: float) -> float:
    """Expected false discovery rate under a given deployment prior."""
    return 1.0 - compute_bayesian_precision(tpr, fpr, prior)
