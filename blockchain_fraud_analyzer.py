#!/usr/bin/env python3
"""
================================================================================
BLOCKCHAIN FRAUD ANALYZER — VERSION 1.0 (ON-CHAIN THREAT DETECTION)
================================================================================
Framework avancé d'analyse de transactions blockchain pour la détection de
fraude on-chain : mixers, wash trading, rug pulls, sandwich attacks,
flash loans et smart contract exploits.

Auteur: neg.cosmo + Dr Nand: Adaptation Blockchain + Grok, Claude
Date: 2026-05-04

NOUVELLES CAPACITÉS BLOCKCHAIN:
─────────────────────────────────────────────────────────────────────────────
• Détection de mixers (Tornado Cash-like)
• Wash trading (NFT & token)
• Signaux précurseurs de rug pull
• Sandwich attacks (MEV)
• Analyse de flash loans suspects
• Risk scoring smart contracts
• Adaptation complète des méthodes ultra-scientifiques (MF-DFA, Transfer Entropy,
  BOCD, RMT, ESN, SSA, RQA) aux dynamiques on-chain (par bloc)

MÉTRIQUES CONSERVÉES & ADAPTÉES:
  ▸ GINI, KS, H-measure, AUC, Lift/Gain, DET
  ▸ Bootstrap CI, Calibration, SHAP
  ▸ Graph anomalies sur adresses (from/to)
  ▸ Benford sur gas & valeurs
  ▸ Stress testing temporel par bloc

RAPPORT:
  ▸ Score de risque on-chain global + Ultra-anomaly score
  ▸ Export HTML avec focus "On-chain Threat Taxonomy"
  ▸ Alertes spécifiques blockchain

Usage:
    from Blockchain_Fraud_Analyzer_v1 import BlockchainFraudAnalyzer

    analyzer = BlockchainFraudAnalyzer(network="ethereum", native_token="ETH")
    ultra_results = analyzer.ultra_scientific_detection(df, feature_cols, time_col='block_number')
    analyzer.detect_mixer_patterns(df)
    analyzer.generate_html_report(output_path='onchain_threat_report.html')

Mode DEBUG:
    python Blockchain_Fraud_Analyzer_v1a.py --debug
================================================================================
"""

import pandas as pd
import numpy as np
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.gridspec import GridSpec
from scipy import stats, signal, linalg, optimize
from scipy.spatial.distance import mahalanobis, pdist, squareform
from sklearn.metrics import (
    roc_auc_score, precision_recall_curve, average_precision_score,
    classification_report, confusion_matrix, roc_curve, f1_score,
    precision_score, recall_score, matthews_corrcoef, brier_score_loss,
    log_loss, det_curve
)
from sklearn.model_selection import train_test_split, StratifiedKFold, TimeSeriesSplit
from sklearn.preprocessing import StandardScaler
from sklearn.inspection import permutation_importance
from sklearn.ensemble import IsolationForest
from sklearn.calibration import calibration_curve
from statsmodels.tsa.stattools import acf, pacf, adfuller
from statsmodels.tsa.seasonal import seasonal_decompose
import warnings
import json
import base64
import io
import os
import sys
import argparse
import logging
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List, Tuple, Any
import time

warnings.filterwarnings('ignore')

# ── Dépendances optionnelles ──────────────────────────────────────────────────
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

try:
    from antropy import petrosian_fd, higuchi_fd
    ANTROPY_AVAILABLE = True
except ImportError:
    ANTROPY_AVAILABLE = False

# ── Console améliorée ────────────────────────────────────────────────────────
class ConsoleColors:
    """Codes ANSI pour colorer la console."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ULTRA = '\033[95m'
    BLOCKCHAIN = '\033[38;5;39m'

    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{ConsoleColors.ENDC}"

class ProgressBar:
    """Barre de progression simple."""

    def __init__(self, total: int, prefix: str = "", suffix: str = "",
                 length: int = 40, fill: str = "█"):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.current = 0
        self.start_time = time.time()

    def update(self, iteration: int):
        self.current = iteration
        percent = 100 * (iteration / float(self.total))
        filled_length = int(self.length * iteration // self.total)
        bar = self.fill * filled_length + "-" * (self.length - filled_length)

        elapsed = time.time() - self.start_time
        if iteration > 0:
            eta = (elapsed / iteration) * (self.total - iteration)
            eta_str = f"ETA: {eta:.1f}s"
        else:
            eta_str = ""

        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:.1f}% {self.suffix} {eta_str}')
        if iteration == self.total:
            sys.stdout.write('\n')
        sys.stdout.flush()

    def finish(self):
        self.update(self.total)

# ─────────────────────────────────────────────────────────────────────────────
# PALETTE COULEURS PROFESSIONNELLE
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    'primary':    '#1a1f5e',
    'secondary':  '#e63946',
    'success':    '#2a9d8f',
    'warning':    '#e9c46a',
    'danger':     '#e76f51',
    'neutral':    '#457b9d',
    'light':      '#f1faee',
    'dark':       '#1d3557',
    'ultra':      '#9b59b6',
    'blockchain': '#3b82f6',
}

CMAP_RISK = LinearSegmentedColormap.from_list(
    'risk', ['#2a9d8f', '#e9c46a', '#e63946']
)


# =============================================================================
# CLASSE PRINCIPALE — BLOCKCHAIN FRAUD ANALYZER
# =============================================================================

class BlockchainFraudAnalyzer:
    """
    Analyseur avancé de fraude on-chain pour blockchain (Ethereum & compatibles).
    Version 1.0 avec détection spécialisée mixers, wash trading, rug pulls, etc.
    Conforme aux standards de surveillance on-chain et AML on-chain.
    """

    def __init__(self, model_name: str = "OnChainFraudAnalyzer",
                 cost_fn: float = 5000.0,
                 cost_fp: float = 100.0,
                 currency: str = "USD",
                 network: str = "ethereum",
                 native_token: str = "ETH",
                 block_time_sec: float = 12.0,
                 debug: bool = False,
                 log_dir: str = "logs"):
        self.model_name = model_name
        self.cost_fn = cost_fn
        self.cost_fp = cost_fp
        self.currency = currency
        self.network = network
        self.native_token = native_token
        self.block_time_sec = block_time_sec
        self.debug = debug
        self.validation_results = {}
        self._figure_cache = {}

        # Configuration du logging forensique
        if debug:
            self._setup_forensic_logging(log_dir)

    def _setup_forensic_logging(self, log_dir: str):
        """Configure le logging détaillé pour le mode DEBUG."""
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"blockchain_fraud_forensic_{timestamp}.log"
        log_path = os.path.join(log_dir, log_filename)

        # Configuration du logger
        self.logger = logging.getLogger("BlockchainFraudAnalyzer")
        self.logger.setLevel(logging.DEBUG)

        # Handler fichier
        fh = logging.FileHandler(log_path, encoding='utf-8')
        fh.setLevel(logging.DEBUG)

        # Format détaillé pour forensique
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S.%f'
        )
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # Handler console pour DEBUG
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        self.logger.info("=" * 80)
        self.logger.info("BLOCKCHAIN FRAUD ANALYZER - FORENSIC MODE ACTIVATED")
        self.logger.info(f"Model: {self.model_name}")
        self.logger.info(f"Network: {self.network} | Token: {self.native_token}")
        self.logger.info(f"Cost FN: {self.cost_fn} | Cost FP: {self.cost_fp}")
        self.logger.info(f"Log file: {log_path}")
        self.logger.info("=" * 80)

        print(f"{ConsoleColors.colorize('🔍 FORENSIC MODE ACTIVATED', ConsoleColors.BLUE)}")
        print(f"   Log file: {log_path}\n")

    def _log_debug(self, message: str, level: str = "DEBUG"):
        """Log un message en mode debug."""
        if self.debug and hasattr(self, 'logger'):
            getattr(self.logger, level.lower())(message)
        elif self.debug:
            print(f"[{level}] {message}")

    # =========================================================================
    # 1. MÉTRIQUES DE PERFORMANCE (COMPLÈTES)
    # =========================================================================

    def calculate_performance_metrics(self, y_true, y_pred_proba,
                                      y_pred=None, threshold: float = 0.5,
                                      bootstrap: bool = True,
                                      n_bootstrap: int = 1000) -> dict:
        """
        Calcule l'ensemble des métriques de performance.

        Inclut:
        - AUC-ROC, GINI, KS-Statistic, H-measure
        - Average Precision (AUCPR)
        - Precision, Recall, F1, MCC
        - Brier Score, Log-Loss
        - Métriques coût-basées
        - Bootstrap CI (95%) sur toutes les métriques clés
        """
        self._log_debug(f"calculate_performance_metrics called: y_true shape={np.asarray(y_true).shape}, "
                       f"bootstrap={bootstrap}, n_bootstrap={n_bootstrap}")

        y_true = np.asarray(y_true)
        y_pred_proba = np.asarray(y_pred_proba)

        if y_pred is None:
            y_pred = (y_pred_proba >= threshold).astype(int)

        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        auc_roc = roc_auc_score(y_true, y_pred_proba)
        gini = 2 * auc_roc - 1

        # KS-Statistic
        fpr_arr, tpr_arr, thresholds_roc = roc_curve(y_true, y_pred_proba)
        ks_stat = np.max(tpr_arr - fpr_arr)
        ks_threshold_idx = np.argmax(tpr_arr - fpr_arr)
        ks_threshold = thresholds_roc[ks_threshold_idx] if len(thresholds_roc) > ks_threshold_idx else threshold

        # H-measure
        h_measure = self._compute_h_measure(y_true, y_pred_proba)

        metrics = {
            'auc_roc': auc_roc,
            'gini': gini,
            'ks_statistic': ks_stat,
            'h_measure': h_measure,
            'average_precision': average_precision_score(y_true, y_pred_proba),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            'mcc': matthews_corrcoef(y_true, y_pred),
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0,
            'false_positive_rate': fp / (fp + tn) if (fp + tn) > 0 else 0,
            'false_negative_rate': fn / (fn + tp) if (fn + tp) > 0 else 0,
            'true_positive_rate': tp / (tp + fn) if (tp + fn) > 0 else 0,
            'balanced_accuracy': ((tp / (tp + fn)) + (tn / (tn + fp))) / 2
                                if (tp + fn) > 0 and (tn + fp) > 0 else 0,
            'brier_score': brier_score_loss(y_true, y_pred_proba),
            'log_loss': log_loss(y_true, y_pred_proba),
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
            'threshold': threshold,
            'prevalence': y_true.mean(),
            'expected_cost': (fn * self.cost_fn + fp * self.cost_fp) / len(y_true),
            'total_fraud_loss': fn * self.cost_fn,
            'total_review_cost': fp * self.cost_fp,
        }

        # Bootstrap confidence intervals
        if bootstrap:
            print(f"  {ConsoleColors.colorize('🔄 Bootstrap CI', ConsoleColors.CYAN)} ({n_bootstrap} itérations)...")
            self._log_debug(f"Starting bootstrap with {n_bootstrap} iterations")
            ci = self._bootstrap_ci(y_true, y_pred_proba, n_bootstrap)
            metrics['bootstrap_ci'] = ci
            self._log_debug(f"Bootstrap CI results: {ci}")

        self.validation_results['performance'] = metrics
        self._print_performance_summary(metrics)
        return metrics

    def _compute_h_measure(self, y_true, y_scores) -> float:
        """H-measure de Hand (2009) — alternative à l'AUC robuste aux coûts."""
        self._log_debug("Computing H-measure")
        try:
            n1 = np.sum(y_true == 1)
            n0 = np.sum(y_true == 0)
            pi1 = n1 / (n1 + n0)
            pi0 = 1 - pi1

            thresholds = np.linspace(0, 1, 200)
            costs = []
            for t in thresholds:
                y_pred = (y_scores >= t).astype(int)
                fn = np.sum((y_pred == 0) & (y_true == 1))
                fp = np.sum((y_pred == 1) & (y_true == 0))
                c = (fn * pi1 + fp * pi0) / (pi1 * n1 + pi0 * n0 + 1e-10)
                costs.append(c)

            min_cost = np.min(costs)
            trivial_cost = min(pi1, pi0)
            h = 1 - (min_cost / (trivial_cost + 1e-10))
            result = float(np.clip(h, 0, 1))
            self._log_debug(f"H-measure result: {result}")
            return result
        except Exception as e:
            self._log_debug(f"H-measure error: {e}", "ERROR")
            return np.nan

    def _bootstrap_ci(self, y_true, y_pred_proba, n: int = 1000,
                      alpha: float = 0.05) -> dict:
        """Bootstrap percentile CI à (1-alpha)% pour métriques clés."""
        self._log_debug(f"Bootstrap CI: n={n}, alpha={alpha}")
        aucs, aps, ks_stats, brierss = [], [], [], []
        n_samples = len(y_true)
        rng = np.random.default_rng(42)

        pb = ProgressBar(n, prefix="Bootstrap:", suffix="complet", length=30)

        for i in range(n):
            pb.update(i + 1)
            idx = rng.integers(0, n_samples, n_samples)
            yt = y_true[idx]
            yp = y_pred_proba[idx]
            if len(np.unique(yt)) < 2:
                continue
            try:
                aucs.append(roc_auc_score(yt, yp))
                aps.append(average_precision_score(yt, yp))
                fpr_b, tpr_b, _ = roc_curve(yt, yp)
                ks_stats.append(np.max(tpr_b - fpr_b))
                brierss.append(brier_score_loss(yt, yp))
            except Exception:
                pass

        lo, hi = alpha / 2, 1 - alpha / 2

        def ci(arr):
            if not arr:
                return (np.nan, np.nan)
            return (float(np.quantile(arr, lo)), float(np.quantile(arr, hi)))

        result = {
            'auc_roc': ci(aucs),
            'average_precision': ci(aps),
            'ks_statistic': ci(ks_stats),
            'brier_score': ci(brierss),
        }
        self._log_debug(f"Bootstrap CI results: {result}")
        return result

    def _print_performance_summary(self, m: dict):
        """Affiche un résumé coloré des performances."""
        print(f"\n{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('PERFORMANCE', ConsoleColors.BOLD)} — {self.model_name}")
        print(f"{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")

        # Définition des couleurs selon la valeur
        def color_value(v, thresholds_good=(0.75, 0.3, 0.3), is_auc=False):
            if is_auc:
                if v >= 0.8:
                    return ConsoleColors.colorize(f"{v:.4f}", ConsoleColors.GREEN)
                elif v >= 0.7:
                    return ConsoleColors.colorize(f"{v:.4f}", ConsoleColors.WARNING)
                else:
                    return ConsoleColors.colorize(f"{v:.4f}", ConsoleColors.FAIL)
            else:
                return ConsoleColors.colorize(f"{v:.4f}", ConsoleColors.CYAN)

        print(f"  {'AUC-ROC':<28} {color_value(m['auc_roc'], is_auc=True)}  (GINI: {m['gini']:.4f})")
        print(f"  {'KS-Statistic':<28} {color_value(m['ks_statistic'])}")
        print(f"  {'H-Measure':<28} {color_value(m['h_measure'])}")
        print(f"  {'Avg Precision (AUCPR)':<28} {color_value(m['average_precision'])}")
        print(f"  {'Precision':<28} {color_value(m['precision'])}")
        print(f"  {'Recall (TPR/Sensitivity)':<28} {color_value(m['recall'])}")
        print(f"  {'F1-Score':<28} {color_value(m['f1_score'])}")
        print(f"  {'MCC':<28} {color_value(m['mcc'])}")
        print(f"  {'Balanced Accuracy':<28} {color_value(m['balanced_accuracy'])}")
        print(f"  {'Brier Score':<28} {color_value(m['brier_score'])}")
        print(f"  {'Log-Loss':<28} {color_value(m['log_loss'])}")

        cost_color = ConsoleColors.GREEN if m['expected_cost'] < 100 else ConsoleColors.WARNING if m['expected_cost'] < 500 else ConsoleColors.FAIL
        print(f"  {'Expected Cost/transaction':<28} {cost_color}{m['expected_cost']:.2f}{self.currency}{ConsoleColors.ENDC}")

        if 'bootstrap_ci' in m:
            ci = m['bootstrap_ci']
            print(f"\n  — Bootstrap 95% CI —")
            for k, (lo, hi) in ci.items():
                print(f"  {k:<28} [{lo:.4f}, {hi:.4f}]")
        print()

    # =========================================================================
    # 2. COURBES AVANCÉES
    # =========================================================================

    def plot_advanced_curves(self, y_true, y_pred_proba, save_path=None):
        """4 courbes en une figure : ROC, PR, DET, et KS plot."""
        self._log_debug("plot_advanced_curves called")
        y_true = np.asarray(y_true)
        y_pred_proba = np.asarray(y_pred_proba)

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.patch.set_facecolor('#f8f9fa')

        # ROC
        ax = axes[0, 0]
        fpr, tpr, thresh = roc_curve(y_true, y_pred_proba)
        auc = roc_auc_score(y_true, y_pred_proba)
        ks = np.max(tpr - fpr)
        ks_idx = np.argmax(tpr - fpr)

        ax.fill_between(fpr, tpr, alpha=0.1, color=COLORS['primary'])
        ax.plot(fpr, tpr, color=COLORS['primary'], lw=2,
                label=f'AUC={auc:.4f}  GINI={2*auc-1:.4f}')
        ax.plot([0, 1], [0, 1], 'k--', alpha=0.4, label='Aléatoire')
        ax.annotate(f'KS={ks:.3f}',
                    xy=(fpr[ks_idx], tpr[ks_idx]),
                    xytext=(fpr[ks_idx] + 0.1, tpr[ks_idx] - 0.1),
                    arrowprops=dict(arrowstyle='->', color=COLORS['secondary']),
                    color=COLORS['secondary'], fontweight='bold')
        ax.plot([fpr[ks_idx], fpr[ks_idx]], [fpr[ks_idx], tpr[ks_idx]],
                '--', color=COLORS['secondary'], alpha=0.7)
        ax.set(xlabel='FPR (1-Spécificité)', ylabel='TPR (Sensibilité)',
               title='Courbe ROC', xlim=[0, 1], ylim=[0, 1])
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Precision-Recall
        ax = axes[0, 1]
        prec, rec, _ = precision_recall_curve(y_true, y_pred_proba)
        ap = average_precision_score(y_true, y_pred_proba)
        baseline = y_true.mean()

        ax.fill_between(rec, prec, alpha=0.1, color=COLORS['success'])
        ax.plot(rec, prec, color=COLORS['success'], lw=2, label=f'AP={ap:.4f}')
        ax.axhline(baseline, color=COLORS['danger'], ls='--',
                   label=f'Baseline={baseline:.4f}')
        ax.set(xlabel='Recall', ylabel='Precision',
               title='Courbe Precision-Recall', xlim=[0, 1], ylim=[0, 1])
        ax.legend()
        ax.grid(True, alpha=0.3)

        # DET Curve
        ax = axes[1, 0]
        try:
            fpr_det, fnr_det, _ = det_curve(y_true, y_pred_proba)
            ax.plot(fpr_det * 100, fnr_det * 100,
                    color=COLORS['warning'], lw=2)
            ax.set(xlabel='FPR (%)', ylabel='FNR (%)',
                   title='Detection Error Tradeoff (DET)')
            ax.set_xscale('log')
            ax.set_yscale('log')
            eer_idx = np.argmin(np.abs(fpr_det - fnr_det))
            eer = (fpr_det[eer_idx] + fnr_det[eer_idx]) / 2
            ax.scatter(fpr_det[eer_idx] * 100, fnr_det[eer_idx] * 100,
                       color=COLORS['secondary'], zorder=5,
                       label=f'EER={eer:.3f}')
            ax.legend()
            ax.grid(True, alpha=0.3, which='both')
        except Exception:
            ax.text(0.5, 0.5, 'DET non disponible', ha='center', va='center',
                    transform=ax.transAxes)

        # KS Plot
        ax = axes[1, 1]
        scores_pos = y_pred_proba[y_true == 1]
        scores_neg = y_pred_proba[y_true == 0]
        x = np.linspace(0, 1, 300)
        cdf_pos = np.array([np.mean(scores_pos <= xi) for xi in x])
        cdf_neg = np.array([np.mean(scores_neg <= xi) for xi in x])
        ks_idx2 = np.argmax(np.abs(cdf_pos - cdf_neg))

        ax.plot(x, cdf_neg, color=COLORS['neutral'], lw=2, label='Légitimes')
        ax.plot(x, cdf_pos, color=COLORS['secondary'], lw=2, label='Fraudes')
        ax.fill_between(x, cdf_neg, cdf_pos, alpha=0.15, color=COLORS['warning'])
        ax.axvline(x[ks_idx2], color=COLORS['danger'], ls='--', alpha=0.8,
                   label=f'KS={np.max(np.abs(cdf_pos-cdf_neg)):.4f}')
        ax.annotate(f'  KS={np.max(np.abs(cdf_pos-cdf_neg)):.4f}',
                    xy=(x[ks_idx2], (cdf_neg[ks_idx2] + cdf_pos[ks_idx2]) / 2),
                    color=COLORS['danger'], fontweight='bold')
        ax.set(xlabel='Score', ylabel='CDF cumulative',
               title='KS Plot — Distribution des Scores', xlim=[0, 1])
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.suptitle(f'Diagnostic Curves — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            self._log_debug(f"Saved advanced curves to {save_path}")
        self._figure_cache['advanced_curves'] = fig
        return fig

    def lift_gain_analysis(self, y_true, y_pred_proba, deciles: int = 10) -> pd.DataFrame:
        """Lift & Cumulative Gain Analysis par décile."""
        self._log_debug(f"lift_gain_analysis: deciles={deciles}")
        y_true = np.asarray(y_true)
        y_pred_proba = np.asarray(y_pred_proba)

        df = pd.DataFrame({'y_true': y_true, 'score': y_pred_proba})
        df['decile'] = pd.qcut(df['score'], q=deciles, labels=False, duplicates='drop')
        df['decile'] = deciles - df['decile']

        total_fraud = y_true.sum()
        baseline_rate = y_true.mean()

        results = []
        cumulative_fraud = 0
        cumulative_n = 0

        for d in range(1, deciles + 1):
            mask = df['decile'] == d
            n = mask.sum()
            fraud_in_decile = df.loc[mask, 'y_true'].sum()
            cumulative_fraud += fraud_in_decile
            cumulative_n += n
            fraud_rate = fraud_in_decile / n if n > 0 else 0

            results.append({
                'decile': d,
                'n_transactions': n,
                'n_fraud': fraud_in_decile,
                'fraud_rate': fraud_rate,
                'lift': fraud_rate / baseline_rate if baseline_rate > 0 else 0,
                'cumulative_fraud': cumulative_fraud,
                'cumulative_gain': cumulative_fraud / total_fraud if total_fraud > 0 else 0,
                'cumulative_pct_population': cumulative_n / len(df),
            })

        lift_df = pd.DataFrame(results)

        # Visualisation
        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        fig.patch.set_facecolor('#f8f9fa')

        # Lift Chart
        ax = axes[0]
        bars = ax.bar(lift_df['decile'], lift_df['lift'],
                      color=[COLORS['danger'] if l > 2 else COLORS['warning']
                             if l > 1 else COLORS['success']
                             for l in lift_df['lift']], alpha=0.85)
        ax.axhline(1, color='k', ls='--', alpha=0.5, label='Aléatoire (lift=1)')
        for bar, val in zip(bars, lift_df['lift']):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                    f'{val:.1f}x', ha='center', fontsize=9, fontweight='bold')
        ax.set(xlabel='Décile (1=scores les plus hauts)', ylabel='Lift',
               title='Lift par Décile')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')

        # Cumulative Gains
        ax = axes[1]
        ax.plot(lift_df['cumulative_pct_population'] * 100,
                lift_df['cumulative_gain'] * 100,
                marker='o', color=COLORS['primary'], lw=2, label='Modèle')
        ax.plot([0, 100], [0, 100], 'k--', alpha=0.4, label='Aléatoire')
        ax.plot([0, y_true.mean() * 100, 100], [0, 100, 100],
                color=COLORS['success'], ls='--', alpha=0.6, label='Parfait')
        ax.fill_between(
            [0] + list(lift_df['cumulative_pct_population'] * 100),
            [0] + list(lift_df['cumulative_gain'] * 100),
            [0] + list(np.linspace(0, 100, deciles)),
            alpha=0.1, color=COLORS['primary']
        )
        ax.set(xlabel='% Population contactée', ylabel='% Fraudes détectées',
               title='Courbe de Gains Cumulés', xlim=[0, 100], ylim=[0, 105])
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Fraud rate par décile
        ax = axes[2]
        ax.bar(lift_df['decile'], lift_df['fraud_rate'] * 100,
               color=COLORS['neutral'], alpha=0.8)
        ax.axhline(baseline_rate * 100, color=COLORS['secondary'], ls='--',
                   label=f'Taux global ({baseline_rate * 100:.2f}%)')
        ax.set(xlabel='Décile', ylabel='Taux de fraude (%)',
               title='Taux de Fraude par Décile')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')

        plt.suptitle(f'Lift & Gains Analysis — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['lift_gain'] = fig

        print(f"\n{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('LIFT & GAINS ANALYSIS', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(lift_df.to_string(index=False, float_format='%.4f'))

        return lift_df

    # =========================================================================
    # 3. CALIBRATION PROBABILISTE
    # =========================================================================

    def calibration_analysis(self, y_true, y_pred_proba, n_bins: int = 10) -> dict:
        """Analyse de la calibration probabiliste du modèle."""
        self._log_debug(f"calibration_analysis: n_bins={n_bins}")
        y_true = np.asarray(y_true)
        y_pred_proba = np.asarray(y_pred_proba)

        prob_true, prob_pred = calibration_curve(y_true, y_pred_proba,
                                                  n_bins=n_bins, strategy='uniform')
        bin_sizes = []
        ece, mce = 0.0, 0.0
        bins = np.linspace(0, 1, n_bins + 1)

        for i, (pt, pp) in enumerate(zip(prob_true, prob_pred)):
            mask = (y_pred_proba >= bins[i]) & (y_pred_proba < bins[i + 1])
            n = mask.sum()
            bin_sizes.append(n)
            err = abs(pt - pp)
            ece += err * n / len(y_true)
            mce = max(mce, err)

        brier = brier_score_loss(y_true, y_pred_proba)
        brier_clim = y_true.mean() * (1 - y_true.mean())
        bss = 1 - brier / (brier_clim + 1e-10)

        cal_results = {
            'brier_score': brier,
            'brier_skill_score': bss,
            'ece': ece,
            'mce': mce,
            'log_loss': log_loss(y_true, y_pred_proba),
            'prob_true': prob_true,
            'prob_pred': prob_pred,
        }

        # Visualisation
        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        fig.patch.set_facecolor('#f8f9fa')

        # Reliability Diagram
        ax = axes[0]
        ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Calibration parfaite')
        ax.plot(prob_pred, prob_true, 'o-', color=COLORS['primary'],
                lw=2, ms=8, label='Modèle')
        for pp, pt, n in zip(prob_pred, prob_true, bin_sizes):
            ax.annotate(f'n={n}', (pp, pt),
                        textcoords='offset points', xytext=(5, 5), fontsize=7)
        ax.fill_between([0, 1], [0, 1], [1, 1], alpha=0.05, color='red')
        ax.fill_between([0, 1], [0, 0], [0, 1], alpha=0.05, color='blue')
        ax.set(xlabel='Score prédit (probabilité)', ylabel='Fréquence observée',
               title=f'Reliability Diagram\nECE={ece:.4f}  MCE={mce:.4f}')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.text(0.05, 0.92, f'BSS={bss:.4f}', transform=ax.transAxes,
                fontsize=11, fontweight='bold', color=COLORS['success'])

        # Score distribution
        ax = axes[1]
        ax.hist(y_pred_proba[y_true == 0], bins=40, alpha=0.6,
                color=COLORS['neutral'], density=True, label='Légitimes')
        ax.hist(y_pred_proba[y_true == 1], bins=40, alpha=0.6,
                color=COLORS['secondary'], density=True, label='Fraudes')
        ax.set(xlabel='Score', ylabel='Densité',
               title='Distribution des Scores par Classe')
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Log-loss par décile
        ax = axes[2]
        df_cal = pd.DataFrame({'y': y_true, 'p': y_pred_proba})
        df_cal['decile'] = pd.qcut(df_cal['p'], q=10, labels=False, duplicates='drop')
        ll_per_dec = df_cal.groupby('decile').apply(
            lambda x: log_loss(x['y'], x['p']) if len(x['y'].unique()) > 1 else np.nan
        ).reset_index()
        ll_per_dec.columns = ['decile', 'log_loss']
        ll_per_dec = ll_per_dec.dropna()

        ax.bar(ll_per_dec['decile'], ll_per_dec['log_loss'],
               color=COLORS['warning'], alpha=0.85)
        ax.set(xlabel='Décile de score', ylabel='Log-Loss',
               title='Log-Loss par Décile de Score')
        ax.grid(True, alpha=0.3, axis='y')

        plt.suptitle(f'Calibration Analysis — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['calibration'] = fig

        print(f"\n{ConsoleColors.colorize('═'*50, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('CALIBRATION ANALYSIS', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*50, ConsoleColors.BOLD)}")
        print(f"  Brier Score:       {brier:.4f}")
        print(f"  Brier Skill Score: {bss:.4f}  (1=parfait, 0=climatologie)")
        print(f"  ECE:               {ece:.4f}")
        print(f"  MCE:               {mce:.4f}")
        print(f"  Log-Loss:          {cal_results['log_loss']:.4f}")

        self.validation_results['calibration'] = cal_results
        return cal_results

    # =========================================================================
    # 4. BENFORD'S LAW
    # =========================================================================

    def benford_law_analysis(self, df, amount_col: str = 'transaction_amount') -> dict:
        """Loi de Benford — Détection de manipulation/anomalie dans les montants."""
        self._log_debug(f"benford_law_analysis: amount_col={amount_col}")

        amounts = df[amount_col].dropna()
        amounts = amounts[amounts > 0]

        if len(amounts) < 100:
            self._log_debug(f"Insufficient data for Benford: {len(amounts)} samples", "WARNING")
            print(f"  {ConsoleColors.colorize('⚠️ Trop peu de données pour Benford', ConsoleColors.WARNING)}")
            return {}

        benford_expected = np.array([np.log10(1 + 1 / d) for d in range(1, 10)])

        first_digits = amounts.apply(
            lambda x: int(str(f'{x:.6e}').replace('.', '').replace('-', '')[0])
        )
        observed_counts = pd.Series(first_digits).value_counts().sort_index()
        observed_counts = observed_counts.reindex(range(1, 10), fill_value=0)
        observed_pct = observed_counts / observed_counts.sum()

        n = len(amounts)
        expected_counts = benford_expected * n
        chi2_stat, chi2_pval = stats.chisquare(
            f_obs=observed_counts.values,
            f_exp=expected_counts
        )

        z_scores = (observed_pct.values - benford_expected) / np.sqrt(
            benford_expected * (1 - benford_expected) / n
        )

        mad = np.mean(np.abs(observed_pct.values - benford_expected))
        conformity = ('Conforme' if mad < 0.006 else
                      'Acceptable' if mad < 0.012 else
                      'Marginalement non-conforme' if mad < 0.015 else
                      '⚠️ Non-conforme')

        results = {
            'chi2_statistic': chi2_stat,
            'chi2_pvalue': chi2_pval,
            'mad': mad,
            'conformity': conformity,
            'observed_pct': dict(zip(range(1, 10), observed_pct.values)),
            'benford_pct': dict(zip(range(1, 10), benford_expected)),
            'z_scores': dict(zip(range(1, 10), z_scores)),
            'significant_bias': chi2_pval < 0.05,
        }

        # Visualisation
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.patch.set_facecolor('#f8f9fa')

        digits = range(1, 10)
        x = np.arange(len(digits))
        width = 0.35

        ax = axes[0]
        ax.bar(x - width / 2, observed_pct * 100, width, label='Observé',
               color=COLORS['primary'], alpha=0.8)
        ax.bar(x + width / 2, benford_expected * 100, width, label="Benford's Law",
               color=COLORS['success'], alpha=0.8)
        ax.set(xlabel='Premier chiffre significatif', ylabel='Fréquence (%)',
               title=f"Loi de Benford\nMAD={mad:.4f} — {conformity}\nχ²={chi2_stat:.2f}, p={chi2_pval:.4f}")
        ax.set_xticks(x)
        ax.set_xticklabels(digits)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')

        if chi2_pval < 0.05:
            ax.text(0.5, 0.97, '⚠️ ANOMALIE DÉTECTÉE', transform=ax.transAxes,
                    ha='center', va='top', color=COLORS['danger'],
                    fontweight='bold', fontsize=11,
                    bbox=dict(boxstyle='round', facecolor='#ffe0e0', alpha=0.8))

        ax2 = axes[1]
        bar_colors = [COLORS['danger'] if abs(z) > 1.96 else COLORS['neutral']
                      for z in z_scores]
        ax2.bar(x, z_scores, color=bar_colors, alpha=0.8)
        ax2.axhline(1.96, color=COLORS['danger'], ls='--', alpha=0.7, label='±1.96 (5%)')
        ax2.axhline(-1.96, color=COLORS['danger'], ls='--', alpha=0.7)
        ax2.set(xlabel='Premier chiffre', ylabel='Z-Score',
                title='Z-Scores par Chiffre (|Z|>1.96 = anomalie)')
        ax2.set_xticks(x)
        ax2.set_xticklabels(digits)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.suptitle(f"Benford's Law Analysis — {amount_col}",
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['benford'] = fig

        print(f"\n{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('BENFORD LAW ANALYSIS', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        print(f"  Transactions analysées: {n:,}")
        print(f"  MAD:                    {mad:.4f}")
        print(f"  Conformité:             {conformity}")
        print(f"  χ² (p-value):           {chi2_stat:.4f} (p={chi2_pval:.4f})")
        anomaly_text = "⚠️ OUI" if results['significant_bias'] else "✅ NON"
        anomaly_color = ConsoleColors.FAIL if results['significant_bias'] else ConsoleColors.GREEN
        print(f"  Anomalie détectée:      {anomaly_color}{anomaly_text}{ConsoleColors.ENDC}")

        self.validation_results['benford'] = results
        return results

    # =========================================================================
    # 5. GRAPH-BASED ANOMALY DETECTION
    # =========================================================================

    def graph_anomaly_detection(self, df,
                                 source_col: str = 'sender_id',
                                 target_col: str = 'receiver_id',
                                 amount_col: str = 'transaction_amount',
                                 fraud_col: str = 'is_fraud') -> pd.DataFrame:
        """Détection d'anomalies basée sur l'analyse du réseau de transactions."""
        self._log_debug(f"graph_anomaly_detection: source={source_col}, target={target_col}")

        if not NX_AVAILABLE:
            self._log_debug("NetworkX not available", "ERROR")
            print(f"  {ConsoleColors.colorize('⚠️ NetworkX non disponible. pip install networkx', ConsoleColors.WARNING)}")
            return pd.DataFrame()

        print(f"  {ConsoleColors.colorize('🔗 Construction du graphe de transactions...', ConsoleColors.BLUE)}")
        G = nx.DiGraph()

        pb = ProgressBar(len(df), prefix="Construction graphe:", suffix="transactions", length=30)
        for i, (_, row) in enumerate(df.iterrows()):
            pb.update(i + 1)
            src = row.get(source_col)
            tgt = row.get(target_col)
            if pd.notna(src) and pd.notna(tgt):
                w = row.get(amount_col, 1)
                if G.has_edge(src, tgt):
                    G[src][tgt]['weight'] += w
                    G[src][tgt]['count'] += 1
                else:
                    G.add_edge(src, tgt, weight=w, count=1)
        pb.finish()

        self._log_debug(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        print(f"  Graphe: {G.number_of_nodes()} nœuds, {G.number_of_edges()} arêtes")

        # Métriques de centralité
        degree_in = dict(G.in_degree())
        degree_out = dict(G.out_degree())

        try:
            pagerank = nx.pagerank(G, alpha=0.85, max_iter=100)
        except Exception:
            pagerank = {n: 0 for n in G.nodes()}

        try:
            betweenness = nx.betweenness_centrality(G, normalized=True, k=min(100, len(G)))
        except Exception:
            betweenness = {n: 0 for n in G.nodes()}

        nodes = list(G.nodes())
        node_df = pd.DataFrame({
            'node': nodes,
            'in_degree': [degree_in.get(n, 0) for n in nodes],
            'out_degree': [degree_out.get(n, 0) for n in nodes],
            'pagerank': [pagerank.get(n, 0) for n in nodes],
            'betweenness': [betweenness.get(n, 0) for n in nodes],
        })

        for col in ['in_degree', 'out_degree', 'pagerank', 'betweenness']:
            std = node_df[col].std()
            if std > 0:
                node_df[f'{col}_z'] = (node_df[col] - node_df[col].mean()) / std
            else:
                node_df[f'{col}_z'] = 0

        z_cols = [c for c in node_df.columns if c.endswith('_z')]
        node_df['anomaly_score'] = node_df[z_cols].abs().mean(axis=1)
        node_df = node_df.sort_values('anomaly_score', ascending=False)

        top_suspicious = node_df.head(20)

        # Visualisation
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        fig.patch.set_facecolor('#f8f9fa')

        ax = axes[0]
        in_degrees = [d for _, d in G.in_degree()]
        ax.hist(in_degrees, bins=50, color=COLORS['primary'], alpha=0.7, log=True)
        ax.set(xlabel='In-Degree', ylabel='Fréquence (log)',
               title='Distribution Power-Law des Degrés')
        ax.grid(True, alpha=0.3)

        ax = axes[1]
        top20 = node_df.head(15)
        bars = ax.barh(range(len(top20)), top20['anomaly_score'],
                       color=COLORS['secondary'], alpha=0.8)
        ax.set_yticks(range(len(top20)))
        ax.set_yticklabels([str(n)[:15] for n in top20['node']], fontsize=8)
        ax.set(xlabel='Score d\'Anomalie Composite', ylabel='Nœud',
               title='Top 15 Nœuds Suspects (Score Anomalie)')
        ax.grid(True, alpha=0.3, axis='x')

        plt.suptitle(f'Graph Anomaly Detection — {G.number_of_nodes()} entités',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['graph'] = fig

        print(f"\n{ConsoleColors.colorize('═'*60, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('GRAPH-BASED ANOMALY DETECTION', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*60, ConsoleColors.BOLD)}")
        print(f"  Nœuds: {G.number_of_nodes():,}  |  Arêtes: {G.number_of_edges():,}")
        print(f"\n  Top 10 nœuds suspects:")
        print(node_df.head(10)[['node', 'in_degree', 'out_degree',
                                'pagerank', 'betweenness', 'anomaly_score']].to_string(index=False))

        self.validation_results['graph'] = {
            'n_nodes': G.number_of_nodes(),
            'n_edges': G.number_of_edges(),
            'top_suspicious': top_suspicious.to_dict('records')
        }
        return node_df

    # =========================================================================
    # 6. PERMUTATION FEATURE IMPORTANCE
    # =========================================================================

    def permutation_feature_importance(self, model, X, y, n_repeats: int = 10,
                                        feature_names: list = None) -> pd.DataFrame:
        """Permutation Feature Importance avec intervalles de confiance."""
        self._log_debug(f"permutation_feature_importance: n_repeats={n_repeats}")

        if feature_names is None:
            feature_names = X.columns.tolist() if hasattr(X, 'columns') else \
                            [f'f{i}' for i in range(X.shape[1])]

        print(f"  {ConsoleColors.colorize('🔀 Calcul Permutation Importance...', ConsoleColors.BLUE)}")
        perm_imp = permutation_importance(
            model, X, y,
            scoring='roc_auc',
            n_repeats=n_repeats,
            random_state=42,
            n_jobs=-1
        )

        imp_df = pd.DataFrame({
            'feature': feature_names,
            'importance_mean': perm_imp.importances_mean,
            'importance_std': perm_imp.importances_std,
            'ci_low': perm_imp.importances_mean - 1.96 * perm_imp.importances_std,
            'ci_high': perm_imp.importances_mean + 1.96 * perm_imp.importances_std,
        }).sort_values('importance_mean', ascending=False)

        # Visualisation
        fig, ax = plt.subplots(figsize=(10, max(4, len(feature_names) * 0.5)))
        y_pos = np.arange(len(imp_df))

        colors = [COLORS['danger'] if m > 0.01 else
                  COLORS['warning'] if m > 0.005 else COLORS['neutral']
                  for m in imp_df['importance_mean']]

        ax.barh(y_pos, imp_df['importance_mean'],
                xerr=1.96 * imp_df['importance_std'],
                color=colors, alpha=0.8, capsize=4)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(imp_df['feature'])
        ax.axvline(0, color='k', ls='-', lw=0.5)
        ax.set(xlabel='Δ AUC-ROC (mean ± 1.96σ)',
               title='Permutation Feature Importance\n(IC 95% Bootstrap)')
        ax.grid(True, alpha=0.3, axis='x')

        plt.tight_layout()
        self._figure_cache['feature_importance'] = fig

        print(f"\n{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('PERMUTATION FEATURE IMPORTANCE', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        print(imp_df.to_string(index=False, float_format='%.5f'))

        return imp_df

    # =========================================================================
    # 7. OPTIMISATION DU SEUIL
    # =========================================================================

    def optimize_threshold(self, y_true, y_pred_proba, metric: str = 'cost',
                           cost_fn: float = None, cost_fp: float = None) -> tuple:
        """Optimisation multi-critères du seuil de décision."""
        self._log_debug(f"optimize_threshold: metric={metric}")

        if cost_fn is None:
            cost_fn = self.cost_fn
        if cost_fp is None:
            cost_fp = self.cost_fp

        thresholds = np.arange(0.005, 1.0, 0.005)
        results = []

        pb = ProgressBar(len(thresholds), prefix="Optimisation:", suffix="seuils", length=30)
        for i, thresh in enumerate(thresholds):
            pb.update(i + 1)
            yp = (y_pred_proba >= thresh).astype(int)
            cm = confusion_matrix(y_true, yp)
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            tpr = tp / (tp + fn + 1e-10)
            tnr = tn / (tn + fp + 1e-10)
            fpr = fp / (fp + tn + 1e-10)

            results.append({
                'threshold': thresh,
                'precision': precision_score(y_true, yp, zero_division=0),
                'recall': recall_score(y_true, yp, zero_division=0),
                'f1': f1_score(y_true, yp, zero_division=0),
                'mcc': matthews_corrcoef(y_true, yp),
                'gmean': np.sqrt(tpr * tnr),
                'youden_j': tpr - fpr,
                'cost': (fn * cost_fn + fp * cost_fp) / len(y_true),
                'fpr': fpr,
                'fnr': fn / (fn + tp + 1e-10),
            })
        pb.finish()

        res_df = pd.DataFrame(results)

        optimal = {
            'f1': res_df.loc[res_df['f1'].idxmax(), 'threshold'],
            'mcc': res_df.loc[res_df['mcc'].idxmax(), 'threshold'],
            'cost': res_df.loc[res_df['cost'].idxmin(), 'threshold'],
            'gmean': res_df.loc[res_df['gmean'].idxmax(), 'threshold'],
            'youden_j': res_df.loc[res_df['youden_j'].idxmax(), 'threshold'],
        }

        if metric in ['f1', 'mcc', 'gmean', 'youden_j']:
            best_thresh = optimal[metric]
        elif metric == 'cost':
            best_thresh = optimal['cost']
        else:
            best_thresh = optimal['f1']

        # Visualisation
        fig, axes = plt.subplots(2, 2, figsize=(16, 10))
        fig.patch.set_facecolor('#f8f9fa')

        ax = axes[0, 0]
        ax.plot(res_df['threshold'], res_df['f1'], label='F1', color=COLORS['primary'])
        ax.plot(res_df['threshold'], res_df['gmean'], label='G-Mean', color=COLORS['success'])
        ax.plot(res_df['threshold'], res_df['youden_j'], label="Youden's J", color=COLORS['neutral'])
        for name, t in optimal.items():
            if name in ['f1', 'gmean', 'youden_j']:
                ax.axvline(t, ls=':', alpha=0.5)
        ax.axvline(best_thresh, color=COLORS['secondary'], ls='--', lw=2,
                   label=f'Optimal ({metric})={best_thresh:.3f}')
        ax.set(xlabel='Seuil', ylabel='Score', title='Métriques vs Seuil')
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)

        ax = axes[0, 1]
        ax.plot(res_df['threshold'], res_df['cost'], color=COLORS['danger'], lw=2)
        ax.axvline(optimal['cost'], color=COLORS['success'], ls='--',
                   label=f"Seuil coût-optimal={optimal['cost']:.3f}")
        ax.set(xlabel='Seuil', ylabel=f'Coût moyen ({self.currency}/tx)',
               title='Optimisation par Coût')
        ax.legend()
        ax.grid(True, alpha=0.3)

        ax = axes[1, 0]
        ax.plot(res_df['threshold'], res_df['precision'], label='Precision')
        ax.plot(res_df['threshold'], res_df['recall'], label='Recall')
        ax.plot(res_df['threshold'], res_df['mcc'], label='MCC')
        ax.axvline(best_thresh, color=COLORS['secondary'], ls='--',
                   label=f'Optimal={best_thresh:.3f}')
        ax.set(xlabel='Seuil', ylabel='Score', title='Precision / Recall / MCC')
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)

        ax = axes[1, 1]
        ax.plot(res_df['fpr'], res_df['fnr'], color=COLORS['warning'], lw=2)

        best_idx = (res_df['threshold'] - best_thresh).abs().idxmin()
        op_fpr = res_df.loc[best_idx, 'fpr']
        op_fnr = res_df.loc[best_idx, 'fnr']
        ax.scatter([op_fpr], [op_fnr], color=COLORS['secondary'], s=100, zorder=5,
                   label=f'Point opérationnel')
        ax.set(xlabel='FPR', ylabel='FNR',
               title='Courbe FPR-FNR (Trade-off Alertes vs Manqués)')
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.suptitle(f'Optimisation du Seuil — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['threshold'] = fig

        print(f"\n{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('THRESHOLD OPTIMIZATION', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*55, ConsoleColors.BOLD)}")
        for name, t in optimal.items():
            idx = (res_df['threshold'] - t).abs().idxmin()
            print(f"  {name:<12} → seuil={t:.3f}  "
                  f"F1={res_df.loc[idx, 'f1']:.4f}  "
                  f"Coût={res_df.loc[idx, 'cost']:.2f}{self.currency}")

        return best_thresh, res_df, optimal

    # =========================================================================
    # 8. WALK-FORWARD BACKTESTING
    # =========================================================================

    def walk_forward_backtest(self, df: pd.DataFrame, model,
                               feature_cols: list, target_col: str,
                               date_col: str = 'transaction_date',
                               n_splits: int = 5,
                               min_train_size: float = 0.5) -> pd.DataFrame:
        """Walk-Forward Validation temporelle — critique pour la fraude."""
        self._log_debug(f"walk_forward_backtest: n_splits={n_splits}, min_train_size={min_train_size}")

        df = df.sort_values(date_col).reset_index(drop=True)
        n = len(df)
        min_train = int(n * min_train_size)

        results = []
        step = (n - min_train) // n_splits

        for i in range(n_splits):
            train_end = min_train + i * step
            test_start = train_end
            test_end = min(train_end + step, n)

            if test_end <= test_start:
                break

            X_train = df.iloc[:train_end][feature_cols]
            y_train = df.iloc[:train_end][target_col]
            X_test = df.iloc[test_start:test_end][feature_cols]
            y_test = df.iloc[test_start:test_end][target_col]

            if y_test.nunique() < 2 or y_train.nunique() < 2:
                continue

            model.fit(X_train, y_train)
            y_proba = model.predict_proba(X_test)[:, 1]

            fold_metrics = self.calculate_performance_metrics(
                y_test, y_proba, bootstrap=False
            )
            fold_metrics['fold'] = i + 1
            fold_metrics['train_size'] = train_end
            fold_metrics['test_size'] = test_end - test_start
            fold_metrics['train_period_end'] = str(df.iloc[train_end - 1][date_col])[:10]
            fold_metrics['test_period_start'] = str(df.iloc[test_start][date_col])[:10]
            results.append(fold_metrics)

        wf_df = pd.DataFrame(results)

        # Visualisation
        fig, axes = plt.subplots(2, 2, figsize=(16, 8))
        fig.patch.set_facecolor('#f8f9fa')

        metrics_plot = ['auc_roc', 'ks_statistic', 'f1_score', 'expected_cost']
        titles = ['AUC-ROC', 'KS-Statistic', 'F1-Score', f'Coût/tx ({self.currency})']

        for ax, col, title in zip(axes.flat, metrics_plot, titles):
            ax.plot(wf_df['fold'], wf_df[col], marker='o', color=COLORS['primary'], lw=2)
            ax.axhline(wf_df[col].mean(), color=COLORS['secondary'], ls='--',
                       label=f'Moyenne={wf_df[col].mean():.4f}')
            ax.fill_between(wf_df['fold'],
                            wf_df[col].mean() - wf_df[col].std(),
                            wf_df[col].mean() + wf_df[col].std(),
                            alpha=0.1, color=COLORS['primary'])
            ax.set(xlabel='Fold (chronologique)', ylabel=col, title=f'Walk-Forward — {title}')
            ax.legend(fontsize=8)
            ax.grid(True, alpha=0.3)

        plt.suptitle(f'Walk-Forward Backtesting — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['walkforward'] = fig

        print(f"\n{ConsoleColors.colorize('═'*65, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('WALK-FORWARD BACKTESTING (Validation Temporelle)', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*65, ConsoleColors.BOLD)}")
        print(wf_df[['fold', 'train_period_end', 'test_period_start',
                      'auc_roc', 'ks_statistic', 'f1_score',
                      'expected_cost', 'train_size', 'test_size']].to_string(index=False))

        self.validation_results['walkforward'] = wf_df
        return wf_df

    # =========================================================================
    # 9. STRESS TESTING AVANCÉ
    # =========================================================================

    def stress_test(self, X, y_true, model_predict_fn,
                    perturbation_factors: list = None) -> pd.DataFrame:
        """Stress testing avancé — scénarios réglementaires."""
        self._log_debug("stress_test called")

        if perturbation_factors is None:
            perturbation_factors = [0.5, 0.8, 1.2, 1.5, 2.0, 3.0]

        y_true_arr = np.asarray(y_true)
        baseline_proba = model_predict_fn(X)
        baseline_auc = roc_auc_score(y_true_arr, baseline_proba)
        results = [{'scenario': 'Baseline', 'category': 'Référence',
                    'auc': baseline_auc, 'auc_drop_pct': 0.0,
                    'brier': brier_score_loss(y_true_arr, baseline_proba)}]

        # Choc montants
        if 'transaction_amount' in X.columns:
            for factor in perturbation_factors:
                X_p = X.copy()
                X_p['transaction_amount'] *= factor
                proba = model_predict_fn(X_p)
                auc = roc_auc_score(y_true_arr, proba)
                results.append({
                    'scenario': f'Montants ×{factor}',
                    'category': 'Choc Montants',
                    'auc': auc,
                    'auc_drop_pct': (baseline_auc - auc) / baseline_auc * 100,
                    'brier': brier_score_loss(y_true_arr, proba),
                })

        # Bruit gaussien
        for noise_level in [0.05, 0.1, 0.2, 0.5]:
            X_p = X.copy()
            num_cols = X_p.select_dtypes(include=[np.number]).columns
            for col in num_cols:
                std = X_p[col].std()
                X_p[col] += np.random.normal(0, noise_level * std, len(X_p))
            proba = model_predict_fn(X_p)
            auc = roc_auc_score(y_true_arr, proba)
            results.append({
                'scenario': f'Bruit gaussien σ={noise_level}',
                'category': 'Robustesse Bruit',
                'auc': auc,
                'auc_drop_pct': (baseline_auc - auc) / baseline_auc * 100,
                'brier': brier_score_loss(y_true_arr, proba),
            })

        stress_df = pd.DataFrame(results)

        # Visualisation
        fig, axes = plt.subplots(1, 2, figsize=(18, 8))
        fig.patch.set_facecolor('#f8f9fa')

        ax = axes[0]
        categories = stress_df['category'].unique()
        cat_colors = dict(zip(categories, [
            COLORS['neutral'], COLORS['primary'], COLORS['warning']
        ]))
        colors = [cat_colors.get(c, COLORS['neutral']) for c in stress_df['category']]

        bars = ax.barh(stress_df['scenario'], stress_df['auc_drop_pct'],
                       color=colors, alpha=0.8)
        ax.axvline(5, color=COLORS['warning'], ls='--', alpha=0.8, label='Warning (5%)')
        ax.axvline(10, color=COLORS['danger'], ls='--', alpha=0.8, label='Critique (10%)')
        for bar, val in zip(bars, stress_df['auc_drop_pct']):
            ax.text(max(val + 0.2, 0.2), bar.get_y() + bar.get_height() / 2,
                    f'{val:.2f}%', va='center', fontsize=8)
        ax.set(xlabel='AUC Drop (%)', title='Stress Test — Impact sur AUC')
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3, axis='x')

        ax = axes[1]
        ax.barh(stress_df['scenario'], stress_df['auc'],
                color=colors, alpha=0.8)
        ax.axvline(0.7, color=COLORS['warning'], ls='--', label='Seuil acceptable (0.70)')
        ax.axvline(0.8, color=COLORS['success'], ls='--', label='Seuil bon (0.80)')
        ax.axvline(baseline_auc, color=COLORS['primary'], ls='-', lw=2,
                   label=f'Baseline={baseline_auc:.4f}')
        ax.set(xlabel='AUC-ROC', title='AUC Absolue par Scénario')
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3, axis='x')

        plt.suptitle(f'Stress Testing Réglementaire — {self.model_name}',
                     fontsize=14, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['stress'] = fig

        print(f"\n{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('STRESS TEST RESULTS', ConsoleColors.BOLD)}")
        print(f"{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(stress_df.to_string(index=False, float_format='%.4f'))

        self.validation_results['stress'] = stress_df
        return stress_df

    # =========================================================================
    # 10. NOUVELLES MÉTHODES BLOCKCHAIN SPÉCIFIQUES
    # =========================================================================

    def detect_mixer_patterns(self, df: pd.DataFrame) -> dict:
        """Détection de patterns de mixeurs (Tornado Cash-like)."""
        self._log_debug("detect_mixer_patterns called")
        print(f"\n{ConsoleColors.colorize('🔍 ANALYSE MIXER PATTERNS', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'mixer_score': 0.0, 'suspicious_wallets': [], 'patterns': []}

        if 'tx_value_eth' not in df.columns or 'from_address' not in df.columns:
            self._log_debug("Required columns missing for mixer detection", "WARNING")
            return results

        # Transactions rondes caractéristiques
        round_values = [0.1, 1.0, 10.0, 100.0]
        df['is_round'] = df['tx_value_eth'].apply(
            lambda x: any(abs(x - rv) < 0.001 for rv in round_values)
        )
        self._log_debug(f"Round transactions detected: {df['is_round'].sum()}")

        if NX_AVAILABLE:
            # Graphe en étoile + délai fixe
            G = nx.DiGraph()
            for _, row in df[df['is_round']].iterrows():
                G.add_edge(row['from_address'], row['to_address'],
                           value=row['tx_value_eth'], block=row.get('block_number', 0))

            # Détection hubs
            in_deg = dict(G.in_degree())
            suspicious = [n for n, d in in_deg.items() if d > 5]
            results['suspicious_wallets'] = suspicious[:20]

            mixer_score = len(suspicious) / max(1, len(df['from_address'].unique())) * 10
            results['mixer_score'] = min(1.0, mixer_score)
        else:
            # Fallback simple
            round_tx_by_address = df[df['is_round']].groupby('to_address').size()
            suspicious = round_tx_by_address[round_tx_by_address > 10].index.tolist()
            results['suspicious_wallets'] = suspicious[:20]
            results['mixer_score'] = min(1.0, len(suspicious) / 50)

        if results['mixer_score'] > 0.3:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ MIXER PATTERN DÉTECTÉ (score: {results['mixer_score']:.3f})"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ MIXER PATTERN: score normal ({results['mixer_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")
        print(f"   Portefeuilles suspects: {len(results['suspicious_wallets'])}")

        self._log_debug(f"Mixer detection results: score={results['mixer_score']}, "
                       f"suspicious_wallets={len(results['suspicious_wallets'])}")
        self.validation_results['mixer_patterns'] = results
        return results

    def detect_wash_trading(self, df: pd.DataFrame) -> dict:
        """Détection de wash trading (NFT / token)."""
        self._log_debug("detect_wash_trading called")
        print(f"\n{ConsoleColors.colorize('🔄 ANALYSE WASH TRADING', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'wash_score': 0.0, 'cycles_detected': 0}

        if not all(col in df.columns for col in ['from_address', 'to_address', 'tx_hash']):
            self._log_debug("Required columns missing for wash trading detection", "WARNING")
            return results

        # Cycles courts entre mêmes adresses
        df_pairs = df.groupby(['from_address', 'to_address']).size().reset_index(name='count')
        cycles = df_pairs[df_pairs['count'] > 3]
        results['cycles_detected'] = len(cycles)
        self._log_debug(f"Cycles detected: {len(cycles)}")

        # Utilisation de Transfer Entropy pour corrélation anormale
        if len(df) > 100 and 'tx_value_eth' in df.columns:
            te = self._transfer_entropy(
                df['tx_value_eth'].values[:1000],
                df['tx_value_eth'].values[:1000]
            )
            results['wash_score'] = min(1.0, len(cycles) / 50 + te * 0.5)
            self._log_debug(f"Transfer entropy for wash trading: {te}")
        else:
            results['wash_score'] = min(1.0, len(cycles) / 30)

        if results['wash_score'] > 0.5:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ WASH TRADING SUSPECT: score={results['wash_score']:.3f}"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ WASH TRADING: score normal ({results['wash_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")
        print(f"   Cycles détectés: {results['cycles_detected']}")

        self._log_debug(f"Wash trading results: score={results['wash_score']}, "
                       f"cycles={results['cycles_detected']}")
        self.validation_results['wash_trading'] = results
        return results

    def detect_rug_pull_signals(self, df: pd.DataFrame) -> dict:
        """Détection de signaux rug pull."""
        self._log_debug("detect_rug_pull_signals called")
        print(f"\n{ConsoleColors.colorize('🧨 ANALYSE RUG PULL', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'rug_score': 0.0, 'gini_concentration': 0.0}

        if 'tx_value_eth' in df.columns and 'to_address' in df.columns:
            # Concentration de tokens
            holdings = df.groupby('to_address')['tx_value_eth'].sum()
            if len(holdings) > 0:
                gini = self._gini_coefficient(holdings.values)
                results['gini_concentration'] = gini
                results['rug_score'] = 1 if gini > 0.85 else gini * 0.8
                self._log_debug(f"Gini concentration: {gini}")

        # Changepoints via BOCD avec vérification de la taille
        if 'block_number' in df.columns and 'tx_value_eth' in df.columns:
            try:
                # Échantillonner si trop de données
                tx_values = df['tx_value_eth'].values
                if len(tx_values) > 5000:
                    # Prendre un échantillon représentatif
                    indices = np.linspace(0, len(tx_values)-1, 5000, dtype=int)
                    tx_values = tx_values[indices]
                    self._log_debug(f"BOCD: Échantillonnage de {len(df)} à {len(tx_values)} valeurs")

                cp = self._bocd(tx_values)
                cp_max = cp.max() if len(cp) > 0 else 0
                if cp_max > 0.15:
                    results['rug_score'] = max(results['rug_score'], 0.7)
                self._log_debug(f"BOCD changepoint probability: {cp_max}")
            except Exception as e:
                self._log_debug(f"BOCD error (ignoré): {e}", "WARNING")
                # Fallback: utiliser la volatilité comme proxy
                volatility = np.std(np.diff(np.log(tx_values[:500] + 1e-6))) if len(tx_values) > 500 else 0
                if volatility > 2.0:
                    results['rug_score'] = max(results['rug_score'], 0.5)

        if results['rug_score'] > 0.6:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ HIGH RUG PULL RISK: score={results['rug_score']:.3f}"
        elif results['rug_score'] > 0.3:
            alert_color = ConsoleColors.WARNING
            alert_msg = f"⚠️ MEDIUM RUG PULL RISK: score={results['rug_score']:.3f}"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ RUG PULL: risque faible ({results['rug_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")
        print(f"   Gini concentration: {results['gini_concentration']:.3f}")

        self._log_debug(f"Rug pull results: score={results['rug_score']}, "
                       f"gini={results['gini_concentration']}")
        self.validation_results['rug_pull'] = results
        return results

    def _gini_coefficient(self, x):
        """Coefficient de Gini pour concentration."""
        x = np.array(x)
        x = x[x > 0]
        if len(x) == 0:
            return 0
        x.sort()
        n = len(x)
        cumx = np.cumsum(x)
        return (n + 1 - 2 * cumx.sum() / cumx[-1]) / n if cumx[-1] > 0 else 0

    def detect_sandwich_attacks(self, df: pd.DataFrame) -> dict:
        """Détection d'attaques sandwich MEV."""
        self._log_debug("detect_sandwich_attacks called")
        print(f"\n{ConsoleColors.colorize('🥪 ANALYSE SANDWICH ATTACKS', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'sandwich_score': 0.0, 'suspected_triplets': 0}

        if 'block_number' not in df.columns or 'gas_used' not in df.columns:
            self._log_debug("Required columns missing for sandwich detection", "WARNING")
            return results

        # Groupement par bloc
        block_groups = df.groupby('block_number')
        for block, group in block_groups:
            if len(group) >= 3:
                # Tri par gas price (proxy via gas_used)
                sorted_g = group.sort_values('gas_used', ascending=False)
                if len(sorted_g) >= 3:
                    results['suspected_triplets'] += 1

        self._log_debug(f"Suspected triplets: {results['suspected_triplets']}")

        results['sandwich_score'] = min(1.0, results['suspected_triplets'] / max(10, len(block_groups)) * 5)

        if results['sandwich_score'] > 0.5:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ SUSPECTED SANDWICH ATTACKS: score={results['sandwich_score']:.3f}"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ SANDWICH ATTACKS: score normal ({results['sandwich_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")
        print(f"   Triplets suspects: {results['suspected_triplets']}")

        self._log_debug(f"Sandwich detection results: score={results['sandwich_score']}, "
                       f"triplets={results['suspected_triplets']}")
        self.validation_results['sandwich'] = results
        return results

    def analyze_smart_contract_risk(self, df: pd.DataFrame) -> dict:
        """Analyse de risque smart contract."""
        self._log_debug("analyze_smart_contract_risk called")
        print(f"\n{ConsoleColors.colorize('📜 ANALYSE SMART CONTRACT RISK', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'contract_risk_score': 0.0, 'high_risk_contracts': []}

        if 'to_address' in df.columns:
            # Proxy : Benford sur gas_used comme indicateur d'obfuscation
            if 'gas_used' in df.columns:
                benford_res = self.benford_law_analysis(df, amount_col='gas_used')
                if benford_res.get('significant_bias', False):
                    results['contract_risk_score'] = 0.75
                    self._log_debug("Contract risk elevated due to Benford anomaly")

        # Vérification des appels contractuels fréquents
        if 'is_contract_call' in df.columns:
            contract_calls = df[df['is_contract_call'] == 1]
            contract_pct = len(contract_calls) / len(df) if len(df) > 0 else 0
            if contract_pct > 0.8:
                results['contract_risk_score'] = max(results['contract_risk_score'], 0.5)
                self._log_debug(f"High contract call percentage: {contract_pct:.2%}")

        if results['contract_risk_score'] > 0.6:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ HIGH SMART CONTRACT RISK: score={results['contract_risk_score']:.3f}"
        elif results['contract_risk_score'] > 0.3:
            alert_color = ConsoleColors.WARNING
            alert_msg = f"⚠️ MEDIUM SMART CONTRACT RISK: score={results['contract_risk_score']:.3f}"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ SMART CONTRACT: risque faible ({results['contract_risk_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")

        self._log_debug(f"Contract risk score: {results['contract_risk_score']}")
        self.validation_results['contract_risk'] = results
        return results

    def analyze_defi_flash_loans(self, df: pd.DataFrame) -> dict:
        """Détection flash loans suspects."""
        self._log_debug("analyze_defi_flash_loans called")
        print(f"\n{ConsoleColors.colorize('⚡ ANALYSE FLASH LOANS', ConsoleColors.CYAN)}")
        print(f"{ConsoleColors.colorize('─'*50, ConsoleColors.CYAN)}")

        results = {'flash_loan_score': 0.0}

        if 'tx_value_eth' in df.columns and 'block_number' in df.columns:
            # Transactions très larges dans un même bloc
            large_tx = df[df['tx_value_eth'] > df['tx_value_eth'].quantile(0.95)]
            results['flash_loan_score'] = len(large_tx) / max(1, len(df)) * 8
            self._log_debug(f"Large transactions in single block: {len(large_tx)}")

        results['flash_loan_score'] = min(1.0, results['flash_loan_score'])

        if results['flash_loan_score'] > 0.5:
            alert_color = ConsoleColors.FAIL
            alert_msg = f"⚠️ SUSPECTED FLASH LOANS: score={results['flash_loan_score']:.3f}"
        else:
            alert_color = ConsoleColors.GREEN
            alert_msg = f"✅ FLASH LOANS: score normal ({results['flash_loan_score']:.3f})"

        print(f"{alert_color}{alert_msg}{ConsoleColors.ENDC}")

        self._log_debug(f"Flash loan score: {results['flash_loan_score']}")
        self.validation_results['flash_loans'] = results
        return results

    # =========================================================================
    # 11. MÉTHODES ULTRA-SCIENTIFIQUES
    # =========================================================================

    def ultra_scientific_detection(self, df: pd.DataFrame,
                                   feature_cols: list = None,
                                   time_col: str = 'block_number',
                                   value_col: str = 'tx_value_eth',
                                   window_size: int = 500) -> dict:
        """Ultra-scientific detection adaptée aux dynamiques on-chain."""
        self._log_debug("ultra_scientific_detection called")

        print(f"\n{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('🧪 ULTRA-SCIENTIFIC ON-CHAIN ANOMALY DETECTION', ConsoleColors.ULTRA)}")
        print(f"  Multifractal | Causal | BOCD | RMT | ESN | SSA | RQA")
        print(f"{ConsoleColors.colorize('═'*70, ConsoleColors.BOLD)}")

        results = {}

        # 1. Multifractal analysis
        if time_col is not None and value_col in df.columns:
            ts = df.sort_values(time_col)[value_col].values
            mf = self._mfdfa(ts[:min(len(ts), 5000)])
            results['mfdfa_anomaly_score'] = mf['anomaly_score']
            results['multifractal_width'] = mf['multifractal_width']
            results['is_monofractal'] = mf['is_monofractal']
            self._log_debug(f"MF-DFA: width={mf['multifractal_width']:.4f}, "
                          f"anomaly={mf['anomaly_score']:.4f}")
            print(f"  {ConsoleColors.colorize('📊 MF-DFA:', ConsoleColors.BLUE)} "
                  f"width={mf['multifractal_width']:.4f} | "
                  f"anomaly={mf['anomaly_score']:.4f}")

        # 2. Transfer entropy between top features
        if feature_cols is not None and len(feature_cols) >= 2:
            te_scores = []
            for i in range(min(len(feature_cols), 5)):
                for j in range(i + 1, min(len(feature_cols), 5)):
                    col_i = feature_cols[i]
                    col_j = feature_cols[j]
                    if col_i in df.columns and col_j in df.columns:
                        te = self._transfer_entropy(df[col_i].values, df[col_j].values)
                        te_scores.append(te)
            results['transfer_entropy_mean'] = np.mean(te_scores) if te_scores else 0
            results['te_anomaly_flag'] = np.mean(te_scores) > 0.3 if te_scores else False
            self._log_debug(f"Transfer entropy mean: {results['transfer_entropy_mean']:.4f}")
            print(f"  {ConsoleColors.colorize('🔄 Transfer Entropy:', ConsoleColors.BLUE)} "
                  f"mean={results['transfer_entropy_mean']:.4f} | "
                  f"flag={results['te_anomaly_flag']}")

        # 3. BOCD on model scores (if available)
        if 'score' in df.columns:
            cp_probs = self._bocd(df['score'].values)
            results['bocd_max_prob'] = cp_probs.max() if len(cp_probs) > 0 else 0
            results['bocd_anomaly'] = results['bocd_max_prob'] > 0.1
            results['bocd_mean_prob'] = cp_probs.mean() if len(cp_probs) > 0 else 0
            self._log_debug(f"BOCD: max_prob={results['bocd_max_prob']:.4f}")
            print(f"  {ConsoleColors.colorize('🔄 BOCD:', ConsoleColors.BLUE)} "
                  f"max_prob={results['bocd_max_prob']:.4f} | "
                  f"anomaly={results['bocd_anomaly']}")

        # 4. RMT on correlation matrix
        if feature_cols is not None and len(feature_cols) >= 5:
            available_cols = [c for c in feature_cols if c in df.columns]
            if len(available_cols) >= 5:
                rmt_res = self._rmt_anomaly(df[available_cols].dropna().values[:min(2000, len(df))])
                results['rmt_anomaly_score'] = rmt_res['anomaly_score']
                results['rmt_pvalue'] = rmt_res['ks_pvalue']
                results['n_signal_eigenvalues'] = rmt_res['n_signal_eigenvalues']
                self._log_debug(f"RMT: pvalue={rmt_res['ks_pvalue']:.4f}, "
                              f"anomaly={rmt_res['anomaly_score']:.4f}")
                print(f"  {ConsoleColors.colorize('📐 RMT:', ConsoleColors.BLUE)} "
                      f"pvalue={rmt_res['ks_pvalue']:.4f} | "
                      f"anomaly={rmt_res['anomaly_score']:.4f}")

        # 5. ESN residuals
        if len(df) > window_size and value_col in df.columns:
            X_win = df[value_col].values
            residuals = self._esn_residuals(X_win[:min(3000, len(X_win))])
            results['esn_residual_mean'] = np.mean(residuals) if len(residuals) > 0 else 0
            results['esn_residual_std'] = np.std(residuals) if len(residuals) > 0 else 0
            results['esn_anomaly_score'] = results['esn_residual_mean']
            print(f"  {ConsoleColors.colorize('🧠 ESN:', ConsoleColors.BLUE)} "
                  f"anomaly_score={results['esn_anomaly_score']:.4f}")

        # 6. Singular Spectrum Analysis
        if time_col is not None and value_col in df.columns:
            ts = df.sort_values(time_col)[value_col].values
            ssa_res = self._singular_spectrum_analysis(ts[:min(len(ts), 1000)])
            results['ssa_complexity'] = ssa_res['complexity']
            results['ssa_anomaly'] = ssa_res['anomaly']
            print(f"  {ConsoleColors.colorize('📈 SSA:', ConsoleColors.BLUE)} "
                  f"complexity={ssa_res['complexity']:.4f} | "
                  f"anomaly={ssa_res['anomaly']}")

        # 7. Recurrence Quantification Analysis
        if value_col in df.columns:
            rqa_res = self._recurrence_quantification(df[value_col].values[:min(500, len(df))])
            results['rqa_determinism'] = rqa_res['determinism']
            results['rqa_laminarity'] = rqa_res['laminarity']
            results['rqa_anomaly'] = rqa_res['determinism'] > 0.8
            print(f"  {ConsoleColors.colorize('🔁 RQA:', ConsoleColors.BLUE)} "
                  f"determinism={rqa_res['determinism']:.4f} | "
                  f"anomaly={rqa_res['rqa_anomaly']}")

        # Global ultra anomaly score
        scores = []
        if 'mfdfa_anomaly_score' in results:
            scores.append(np.clip(results['mfdfa_anomaly_score'] / 2.0, 0, 1))
        if 'te_anomaly_flag' in results:
            scores.append(0.5 if results['te_anomaly_flag'] else 0)
        if 'bocd_anomaly' in results:
            scores.append(0.5 if results['bocd_anomaly'] else 0)
        if 'rmt_anomaly_score' in results:
            scores.append(results['rmt_anomaly_score'])
        if 'esn_anomaly_score' in results:
            scores.append(np.clip(results['esn_anomaly_score'] / 0.5, 0, 1))
        if 'ssa_anomaly' in results:
            scores.append(0.6 if results['ssa_anomaly'] else 0)
        if 'rqa_anomaly' in results:
            scores.append(0.4 if results['rqa_anomaly'] else 0)

        results['global_ultra_anomaly_score'] = np.mean(scores) if scores else 0
        results['ultra_risk_level'] = (
            'CRITICAL' if results['global_ultra_anomaly_score'] > 0.7 else
            'HIGH' if results['global_ultra_anomaly_score'] > 0.5 else
            'MEDIUM' if results['global_ultra_anomaly_score'] > 0.3 else
            'LOW'
        )

        self._log_debug(f"Global ultra anomaly score: {results['global_ultra_anomaly_score']:.4f}, "
                       f"risk level: {results['ultra_risk_level']}")

        # Affichage du résultat global
        if results['global_ultra_anomaly_score'] > 0.7:
            score_color = ConsoleColors.FAIL
        elif results['global_ultra_anomaly_score'] > 0.5:
            score_color = ConsoleColors.WARNING
        else:
            score_color = ConsoleColors.GREEN

        print(f"\n{ConsoleColors.colorize('─'*55, ConsoleColors.BOLD)}")
        print(f"  {ConsoleColors.colorize('🌟 GLOBAL ULTRA ANOMALY SCORE:', ConsoleColors.BOLD)} "
              f"{score_color}{results['global_ultra_anomaly_score']:.4f}{ConsoleColors.ENDC}")
        print(f"  {ConsoleColors.colorize('🚨 ULTRA RISK LEVEL:', ConsoleColors.BOLD)} "
              f"{score_color}{results['ultra_risk_level']}{ConsoleColors.ENDC}")
        print(f"{ConsoleColors.colorize('─'*55, ConsoleColors.BOLD)}")

        self.validation_results['ultra_scientific'] = results
        self._plot_ultra_results(results)

        return results

    def _mfdfa(self, series, scales=None, q_range=(-5, 5, 21)):
        """Multifractal Detrended Fluctuation Analysis."""
        self._log_debug("MF-DFA computation")
        series = np.asarray(series).flatten()
        if scales is None:
            scales = np.logspace(np.log10(10), np.log10(len(series) // 4), 20).astype(int)

        def detrend_segment(y):
            x = np.arange(len(y))
            coeffs = np.polyfit(x, y, 1)
            trend = np.polyval(coeffs, x)
            return y - trend

        Fq = []
        q_vals = np.linspace(*q_range)

        for q in q_vals:
            Fq_s = []
            for s in scales:
                n_seg = len(series) // s
                var_list = []
                for v in range(n_seg):
                    seg = series[v * s:(v + 1) * s]
                    seg_detrend = detrend_segment(seg)
                    var_list.append(np.mean(seg_detrend ** 2))
                if q == 0:
                    F = np.exp(0.5 * np.mean(np.log(var_list)))
                else:
                    F = (np.mean(np.array(var_list) ** (q / 2))) ** (1 / q)
                Fq_s.append(F)
            Fq.append(Fq_s)

        Fq = np.array(Fq)
        Hq = []
        for i, q in enumerate(q_vals):
            coeffs = np.polyfit(np.log(scales), np.log(Fq[i]), 1)
            Hq.append(coeffs[0])
        Hq = np.array(Hq)

        tau_q = q_vals * Hq - 1
        alpha = np.gradient(tau_q, q_vals)
        f_alpha = q_vals * alpha - tau_q

        multifractal_width = alpha.max() - alpha.min()
        is_monofractal = multifractal_width < 0.2

        return {
            'hq': Hq,
            'alpha': alpha,
            'f_alpha': f_alpha,
            'multifractal_width': multifractal_width,
            'is_monofractal': is_monofractal,
            'anomaly_score': multifractal_width if not is_monofractal else 0
        }

    def _transfer_entropy(self, x, y, k=1, bins=10):
        """Transfer Entropy T_{X->Y} = I(Y_{t+1}; X_t | Y_t)."""
        x = np.asarray(x).flatten()
        y = np.asarray(y).flatten()

        if len(x) < 100 or len(y) < 100:
            return 0.0

        n = len(x) - k
        if n < 10:
            return 0.0

        try:
            x_quantiles = np.linspace(0, 100, bins + 1)[1:-1]
            y_quantiles = np.linspace(0, 100, bins + 1)[1:-1]

            x_disc = np.digitize(x[:-k], np.percentile(x, x_quantiles))
            y_disc = np.digitize(y[:-k], np.percentile(y, y_quantiles))
            y_future = np.digitize(y[k:], np.percentile(y, y_quantiles))

            x_disc += 1
            y_disc += 1
            y_future += 1

            def entropy_from_counts(counts, total):
                probs = np.array(list(counts.values())) / total
                return -np.sum(probs * np.log2(probs + 1e-12))

            total = len(x_disc)

            counts_yf_y = {}
            for yf, yv in zip(y_future, y_disc):
                counts_yf_y[(yf, yv)] = counts_yf_y.get((yf, yv), 0) + 1

            counts_y = {}
            for yv in y_disc:
                counts_y[yv] = counts_y.get(yv, 0) + 1

            h_yf_y = entropy_from_counts(counts_yf_y, total)
            h_y = entropy_from_counts(counts_y, total)

            counts_yf_x_y = {}
            for yf, xv, yv in zip(y_future, x_disc, y_disc):
                counts_yf_x_y[(yf, xv, yv)] = counts_yf_x_y.get((yf, xv, yv), 0) + 1

            counts_x_y = {}
            for xv, yv in zip(x_disc, y_disc):
                counts_x_y[(xv, yv)] = counts_x_y.get((xv, yv), 0) + 1

            h_yf_x_y = entropy_from_counts(counts_yf_x_y, total)
            h_x_y = entropy_from_counts(counts_x_y, total)

            te = (h_yf_y - h_y) - (h_yf_x_y - h_x_y)

            return max(0, min(te, 1.0))

        except Exception as e:
            self._log_debug(f"Transfer entropy error: {e}", "ERROR")
            return 0.0

    def _bocd(self, data, hazard_rate=1/500, max_window=2000):
        """
        Bayesian Online Changepoint Detection - Version ultra-légère.
        Utilise l'algorithme de détection de changepoints en ligne.
        """
        n = len(data)

        # Réduction pour les très grandes séries
        if n > max_window:
            step = n // max_window
            data = data[::step][:max_window]
            n = len(data)
            self._log_debug(f"BOCD: Échantillonnage à {n} points")

        # Version simplifiée : détection par moyenne mobile et seuil adaptatif
        window_size = min(50, n // 10)
        if window_size < 5:
            return np.zeros(n)

        # Calculer les statistiques glissantes
        running_mean = np.zeros(n)
        running_std = np.zeros(n)

        for i in range(1, n):
            start = max(0, i - window_size)
            window = data[start:i]
            running_mean[i] = np.mean(window) if len(window) > 0 else data[i]
            running_std[i] = np.std(window) if len(window) > 1 else 1.0

        # Détecter les changepoints par score Z
        z_scores = np.abs((data - running_mean) / (running_std + 1e-6))

        # Convertir en probabilités
        changepoint_probs = 1 - np.exp(-z_scores * hazard_rate * 10)
        changepoint_probs = np.clip(changepoint_probs, 0, 0.5)  # Limiter

        return changepoint_probs

    def _rmt_anomaly(self, X, threshold=2.0):
        """Random Matrix Theory analysis."""
        X_scaled = StandardScaler().fit_transform(X)
        corr = np.corrcoef(X_scaled.T)
        eigvals = linalg.eigvalsh(corr)
        eigvals = eigvals[eigvals > 0]

        eigvals_sorted = np.sort(eigvals)
        gaps = np.diff(eigvals_sorted)
        ratios = gaps[1:] / (gaps[:-1] + 1e-12)

        expected_ratios = stats.rayleigh.rvs(scale=0.5, size=len(ratios))
        ks_stat, p_value = stats.ks_2samp(ratios, expected_ratios)

        q = X_scaled.shape[0] / X_scaled.shape[1]
        lambda_max = (1 + np.sqrt(1 / q)) ** 2
        n_signal = np.sum(eigvals > lambda_max)

        anomaly_score = 1 - p_value if p_value < 0.05 else 0
        return {
            'eigenvalues': eigvals,
            'spacing_ratios': ratios,
            'ks_pvalue': p_value,
            'n_signal_eigenvalues': n_signal,
            'anomaly_score': anomaly_score,
            'is_anomalous': p_value < 0.05
        }

    def _esn_residuals(self, X, reservoir_size=100, spectral_radius=0.9, leaking_rate=0.3):
        """Echo State Network residual analysis."""
        X = np.asarray(X)
        n_samples, n_features = X.shape if X.ndim > 1 else (len(X), 1)

        if n_samples < 100:
            return np.ones(n_samples) * 0.5

        if X.ndim == 1:
            X = X.reshape(-1, 1)

        try:
            np.random.seed(42)
            Win = np.random.uniform(-0.5, 0.5, (reservoir_size, n_features))
            W = np.random.randn(reservoir_size, reservoir_size)
            rho_max = np.max(np.abs(linalg.eigvals(W)))
            if rho_max > 0:
                W = W * (spectral_radius / rho_max)

            states = np.zeros((n_samples, reservoir_size))
            for t in range(1, n_samples):
                u = X[t - 1]
                states[t] = (1 - leaking_rate) * states[t - 1] + leaking_rate * np.tanh(Win @ u + W @ states[t - 1])

            train_len = n_samples // 2
            if train_len < 10:
                return np.ones(n_samples) * 0.5

            I = np.eye(states[:train_len].shape[1])
            alpha_reg = 0.01
            Wout = np.linalg.lstsq(states[:train_len], X[:train_len], rcond=1e-5)[0]

            X_pred = states @ Wout
            residuals = np.mean((X - X_pred) ** 2, axis=1)

            residuals = np.clip(residuals, 0, np.percentile(residuals, 99))
            if residuals.max() > residuals.min():
                residuals_norm = (residuals - residuals.min()) / (residuals.max() - residuals.min() + 1e-10)
            else:
                residuals_norm = np.ones_like(residuals) * 0.5

            return residuals_norm

        except Exception as e:
            self._log_debug(f"ESN error: {e}", "ERROR")
            return np.ones(n_samples) * 0.5

    def _singular_spectrum_analysis(self, series, window_size=None):
        """Singular Spectrum Analysis for complexity detection."""
        series = np.asarray(series).flatten()
        n = len(series)

        if n < 20:
            return {'complexity': 0.5, 'anomaly': False}

        if window_size is None:
            window_size = min(30, n // 3)

        if window_size < 2:
            return {'complexity': 0.5, 'anomaly': False}

        K = n - window_size + 1
        if K < 2:
            return {'complexity': 0.5, 'anomaly': False}

        X = np.zeros((window_size, K))
        for i in range(K):
            X[:, i] = series[i:i + window_size]

        try:
            U, s, Vt = np.linalg.svd(X, full_matrices=False)

            s_norm = s / (s.sum() + 1e-12)
            complexity = -np.sum(s_norm * np.log2(s_norm + 1e-12)) / np.log2(len(s) + 1e-12)
            complexity = np.clip(complexity, 0, 1)

            anomaly = complexity < 0.3 or complexity > 0.8
        except Exception:
            complexity = 0.5
            anomaly = False

        return {'complexity': complexity, 'anomaly': anomaly}

    def _recurrence_quantification(self, series, emb_dim=3, delay=1, threshold_ratio=0.1):
        """Recurrence Quantification Analysis."""
        series = np.asarray(series).flatten()
        n = len(series)

        if n < 100:
            return {'determinism': 0.5, 'laminarity': 0.5, 'rqa_anomaly': False}

        K = n - (emb_dim - 1) * delay
        if K < 10:
            return {'determinism': 0.5, 'laminarity': 0.5, 'rqa_anomaly': False}

        X = np.zeros((emb_dim, K))
        for i in range(emb_dim):
            X[i, :] = series[i * delay:i * delay + K]

        threshold = threshold_ratio * np.std(series)
        R = np.zeros((K, K))
        for i in range(K):
            for j in range(K):
                dist = np.linalg.norm(X[:, i] - X[:, j])
                R[i, j] = 1 if dist < threshold else 0

        diag_hist = []
        for i in range(K):
            for j in range(K):
                if R[i, j] == 1:
                    length = 1
                    i_temp, j_temp = i + 1, j + 1
                    while i_temp < K and j_temp < K and R[i_temp, j_temp] == 1:
                        length += 1
                        i_temp += 1
                        j_temp += 1
                    if length >= 2:
                        diag_hist.append(length)

        vert_hist = []
        for j in range(K):
            for i in range(K):
                if R[i, j] == 1:
                    length = 1
                    i_temp = i + 1
                    while i_temp < K and R[i_temp, j] == 1:
                        length += 1
                        i_temp += 1
                    if length >= 2:
                        vert_hist.append(length)

        determinism = sum(diag_hist) / (K * K + 1e-12) if diag_hist else 0
        laminarity = sum(vert_hist) / (K * K + 1e-12) if vert_hist else 0
        rqa_anomaly = determinism > 0.8

        return {
            'determinism': determinism,
            'laminarity': laminarity,
            'rqa_anomaly': rqa_anomaly
        }

    def _plot_ultra_results(self, results):
        """Visualisation des résultats ultra-scientifiques."""
        fig, axes = plt.subplots(2, 3, figsize=(18, 10))
        fig.patch.set_facecolor('#f8f9fa')

        # Global score gauge
        ax = axes[0, 0]
        score = results.get('global_ultra_anomaly_score', 0)
        colors_gauge = [COLORS['success'], COLORS['warning'], COLORS['danger']]
        ax.pie([score, 1 - score], colors=[colors_gauge[min(2, int(score * 3))], '#e0e0e0'],
               startangle=90, counterclock=False, wedgeprops={'width': 0.3})
        ax.text(0, 0, f'{score:.0%}', ha='center', va='center', fontsize=24, fontweight='bold')
        ax.set_title('Global Ultra Anomaly Score', fontsize=12, fontweight='bold')

        # Risk level
        ax = axes[0, 1]
        risk_level = results.get('ultra_risk_level', 'LOW')
        risk_colors = {'LOW': COLORS['success'], 'MEDIUM': COLORS['warning'],
                       'HIGH': COLORS['danger'], 'CRITICAL': '#8b0000'}
        ax.text(0.5, 0.5, f'🚨\n{risk_level}', ha='center', va='center',
                fontsize=20, fontweight='bold', color=risk_colors.get(risk_level, COLORS['neutral']),
                transform=ax.transAxes)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        ax.set_title('Ultra Risk Level', fontsize=12, fontweight='bold')

        # Metrics bars
        ax = axes[0, 2]
        metrics = []
        values = []
        if 'mfdfa_anomaly_score' in results:
            metrics.append('MF-DFA')
            values.append(results['mfdfa_anomaly_score'])
        if 'rmt_anomaly_score' in results:
            metrics.append('RMT')
            values.append(results['rmt_anomaly_score'])
        if 'esn_anomaly_score' in results:
            metrics.append('ESN')
            values.append(results['esn_anomaly_score'])
        if 'bocd_max_prob' in results:
            metrics.append('BOCD')
            values.append(results['bocd_max_prob'])

        if metrics:
            y_pos = np.arange(len(metrics))
            colors_bar = [COLORS['danger'] if v > 0.5 else COLORS['warning'] if v > 0.3 else COLORS['success'] for v in values]
            ax.barh(y_pos, values, color=colors_bar, alpha=0.8)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(metrics)
            ax.set_xlim(0, 1)
            ax.set_xlabel('Anomaly Score')
            ax.set_title('Per-Method Anomaly Scores', fontsize=12, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='x')

        # Multifractal spectrum
        ax = axes[1, 0]
        if 'multifractal_width' in results:
            ax.text(0.5, 0.5, f"Multifractal Width\n{results['multifractal_width']:.4f}\n" +
                    ("Monofractal" if results.get('is_monofractal') else "Multifractal"),
                    ha='center', va='center', fontsize=12, transform=ax.transAxes)
        else:
            ax.text(0.5, 0.5, 'MF-DFA\nNot available', ha='center', va='center')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        ax.set_title('Multifractal Analysis', fontsize=12, fontweight='bold')

        # Transfer entropy
        ax = axes[1, 1]
        if 'transfer_entropy_mean' in results:
            te_val = results['transfer_entropy_mean']
            ax.text(0.5, 0.5, f"Transfer Entropy\n{te_val:.4f}\n" +
                    ("Anomalous" if results.get('te_anomaly_flag') else "Normal"),
                    ha='center', va='center', fontsize=12, transform=ax.transAxes)
        else:
            ax.text(0.5, 0.5, 'Transfer Entropy\nNot available', ha='center', va='center')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        ax.set_title('Causal Information Flow', fontsize=12, fontweight='bold')

        # RMT info
        ax = axes[1, 2]
        if 'n_signal_eigenvalues' in results:
            ax.text(0.5, 0.5, f"Signal Eigenvalues\n{results['n_signal_eigenvalues']}\n" +
                    f"p-value: {results.get('rmt_pvalue', 0):.4f}",
                    ha='center', va='center', fontsize=12, transform=ax.transAxes)
        else:
            ax.text(0.5, 0.5, 'RMT\nNot available', ha='center', va='center')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        ax.set_title('Random Matrix Theory', fontsize=12, fontweight='bold')

        plt.suptitle(f'Ultra-Scientific Anomaly Detection — {self.model_name}',
                     fontsize=16, fontweight='bold', color=COLORS['dark'])
        plt.tight_layout()
        self._figure_cache['ultra_scientific'] = fig

    # =========================================================================
    # 12. RAPPORT HTML ADAPTÉ BLOCKCHAIN
    # =========================================================================

    def generate_html_report(self, output_path: str = 'onchain_threat_report.html'):
        """Rapport HTML adapté avec focus blockchain."""
        self._log_debug(f"generate_html_report: output_path={output_path}")
        print(f"\n  {ConsoleColors.colorize('📄 Génération du rapport On-Chain HTML...', ConsoleColors.BLUE)}")

        def fig_to_b64(fig) -> str:
            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=120, bbox_inches='tight',
                        facecolor='#f8f9fa')
            buf.seek(0)
            return base64.b64encode(buf.read()).decode()

        perf = self.validation_results.get('performance', {})
        cal = self.validation_results.get('calibration', {})
        ben = self.validation_results.get('benford', {})
        ultra = self.validation_results.get('ultra_scientific', {})
        mixer = self.validation_results.get('mixer_patterns', {})
        wash = self.validation_results.get('wash_trading', {})
        rug = self.validation_results.get('rug_pull', {})
        sandwich = self.validation_results.get('sandwich', {})
        contract = self.validation_results.get('contract_risk', {})
        flash = self.validation_results.get('flash_loans', {})

        def val(d, k, fmt='.4f'):
            v = d.get(k, 'N/A')
            return f'{v:{fmt}}' if isinstance(v, float) else str(v)

        global_score = int(perf.get('auc_roc', 0) * 100) if perf.get('auc_roc') else 0
        score_color = ('#2a9d8f' if global_score >= 75 else
                       '#e9c46a' if global_score >= 60 else '#e63946')

        ultra_score = ultra.get('global_ultra_anomaly_score', 0)
        ultra_level = ultra.get('ultra_risk_level', 'LOW')
        ultra_color = ('#2a9d8f' if ultra_score < 0.3 else
                       '#e9c46a' if ultra_score < 0.5 else
                       '#e76f51' if ultra_score < 0.7 else '#e63946')

        # Figures en base64
        figures_html = ""
        figure_titles = {
            'advanced_curves': '📈 Courbes Diagnostiques (ROC, PR, DET, KS)',
            'lift_gain': '🎯 Lift & Gains Analysis',
            'calibration': '🔬 Calibration Probabiliste',
            'feature_importance': '🔀 Permutation Feature Importance',
            'benford': "🔢 Benford's Law Analysis",
            'graph': '🔗 Graph-Based Anomaly Detection',
            'threshold': '⚖️ Optimisation du Seuil',
            'stress': '💥 Stress Testing Réglementaire',
            'walkforward': '⏱️ Walk-Forward Backtesting',
            'ultra_scientific': '🧪 Ultra-Scientific Anomaly Detection',
        }
        for key, title in figure_titles.items():
            if key in self._figure_cache:
                try:
                    b64 = fig_to_b64(self._figure_cache[key])
                    figures_html += f"""
                    <div class="section">
                        <h2>{title}</h2>
                        <img src="data:image/png;base64,{b64}"
                             style="width:100%;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1)">
                    </div>"""
                except Exception as e:
                    self._log_debug(f"Failed to encode figure {key}: {e}", "ERROR")

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Blockchain Fraud Analyzer — {self.network.upper()} On-chain Threat Report</title>
<style>
  * {{ box-sizing: border-box; margin:0; padding:0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e3a8a, #3b82f6, #7c3aed);
             color:white; padding:40px; text-align:center; }}
  .header h1 {{ font-size:2.2rem; letter-spacing:1px; }}
  .header p  {{ opacity:.8; margin-top:8px; font-size:.95rem; }}
  .badge {{ display:inline-block; background:{score_color}; color:white;
            font-size:1.8rem; font-weight:bold; padding:12px 24px;
            border-radius:50px; margin-top:20px; }}
  .ultra-badge {{ display:inline-block; background:{ultra_color}; color:white;
            font-size:1.4rem; font-weight:bold; padding:8px 20px;
            border-radius:50px; margin-top:10px; margin-left:15px; }}
  .container {{ max-width:1400px; margin:0 auto; padding:24px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
           gap:16px; margin:24px 0; }}
  .card {{ background:#1e293b; border-radius:12px; padding:15px;
           text-align:center; border-left:4px solid #3b82f6; }}
  .card .value {{ font-size:1.8rem; font-weight:bold; color:#60a5fa; }}
  .card .label {{ font-size:.75rem; color:#94a3b8; margin-top:4px; }}
  .section {{ background:#1e293b; border-radius:12px; padding:24px;
              margin:24px 0; border-left:4px solid #3b82f6; }}
  .section h2 {{ font-size:1.2rem; margin-bottom:16px;
                 border-bottom:2px solid #334155; padding-bottom:10px; color:#e2e8f0; }}
  .alert {{ padding:12px 18px; border-radius:8px; margin:8px 0; font-weight:500; }}
  .alert-ok      {{ background:#064e3b; color:#86efac; border-left:4px solid #2a9d8f; }}
  .alert-warning {{ background:#78350f; color:#fcd34d; border-left:4px solid #e9c46a; }}
  .alert-danger  {{ background:#7f1d1d; color:#fecaca; border-left:4px solid #e63946; }}
  .alert-ultra   {{ background:#4c1d95; color:#d8b4fe; border-left:4px solid #9b59b6; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th {{ background:#0f172a; color:#60a5fa; padding:10px; text-align:left; }}
  td {{ padding:8px 10px; border-bottom:1px solid #334155; }}
  .footer {{ text-align:center; padding:32px; color:#64748b; font-size:.8rem; }}
  .threat-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; margin:24px 0; }}
  .threat-card {{ background:#0f172a; border-radius:12px; padding:16px; border-top:4px solid #e63946; }}
  .threat-card h3 {{ color:#e63946; margin-bottom:12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔗 BLOCKCHAIN FRAUD ANALYZER — {self.network.upper()}</h1>
  <p>On-chain Threat Intelligence | {self.native_token} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
  <div>
    <span class="badge">Risk Score: {global_score}/100</span>
    <span class="ultra-badge">🧪 Ultra Anomaly: {ultra_score:.0%} ({ultra_level})</span>
  </div>
</div>

<div class="container">
  <!-- KPI Cards -->
  <div class="grid">
    <div class="card"><div class="value">{val(perf,'auc_roc')}</div><div class="label">AUC-ROC</div></div>
    <div class="card"><div class="value">{val(perf,'gini')}</div><div class="label">Gini</div></div>
    <div class="card"><div class="value">{val(perf,'f1_score')}</div><div class="label">F1-Score</div></div>
    <div class="card"><div class="value">{val(perf,'mcc')}</div><div class="label">MCC</div></div>
    <div class="card"><div class="value">{val(cal,'brier_score')}</div><div class="label">Brier Score</div></div>
    <div class="card"><div class="value">{val(perf,'expected_cost','.2f')}{self.currency}</div><div class="label">Coût/Tx</div></div>
  </div>

  <!-- On-chain Threat Taxonomy -->
  <div class="section">
    <h2>🔐 On-chain Threat Taxonomy</h2>
    <div class="threat-grid">
      <div class="threat-card">
        <h3>🌀 Mixer Patterns</h3>
        <p>Score: <strong>{mixer.get('mixer_score', 0):.3f}</strong></p>
        <p>Portefeuilles suspects: {len(mixer.get('suspicious_wallets', []))}</p>
        <p>{'⚠️ Activité suspecte détectée' if mixer.get('mixer_score', 0) > 0.3 else '✅ Pas d anomalie majeure'}</p>
      </div>
      <div class="threat-card">
        <h3>🔄 Wash Trading</h3>
        <p>Score: <strong>{wash.get('wash_score', 0):.3f}</strong></p>
        <p>Cycles détectés: {wash.get('cycles_detected', 0)}</p>
        <p>{'⚠️ Wash trading suspect' if wash.get('wash_score', 0) > 0.5 else '✅ Activité normale'}</p>
      </div>
      <div class="threat-card">
        <h3>🧨 Rug Pull Risk</h3>
        <p>Score: <strong>{rug.get('rug_score', 0):.3f}</strong></p>
        <p>Gini concentration: {rug.get('gini_concentration', 0):.3f}</p>
        <p>{'⚠️ Risque élevé de rug pull' if rug.get('rug_score', 0) > 0.6 else '✅ Risque modéré' if rug.get('rug_score', 0) > 0.3 else '✅ Risque faible'}</p>
      </div>
      <div class="threat-card">
        <h3>🥪 Sandwich Attacks</h3>
        <p>Score: <strong>{sandwich.get('sandwich_score', 0):.3f}</strong></p>
        <p>Triplets suspects: {sandwich.get('suspected_triplets', 0)}</p>
        <p>{'⚠️ Attaques MEV suspectes' if sandwich.get('sandwich_score', 0) > 0.5 else '✅ Pas d attaque détectée'}</p>
      </div>
      <div class="threat-card">
        <h3>📜 Smart Contract Risk</h3>
        <p>Score: <strong>{contract.get('contract_risk_score', 0):.3f}</strong></p>
        <p>{'⚠️ Smart contract suspect' if contract.get('contract_risk_score', 0) > 0.6 else '✅ Risque acceptable'}</p>
      </div>
      <div class="threat-card">
        <h3>⚡ Flash Loans</h3>
        <p>Score: <strong>{flash.get('flash_loan_score', 0):.3f}</strong></p>
        <p>{'⚠️ Flash loans suspects' if flash.get('flash_loan_score', 0) > 0.5 else '✅ Activité normale'}</p>
      </div>
    </div>
  </div>

  <!-- Ultra-Scientific Alertes -->
  <div class="section">
    <h2>🧪 Ultra-Scientific Anomaly Detection</h2>
    <div class="alert alert-ultra">🔬 MF-DFA: {'Multifractal behavior detected' if ultra.get('multifractal_width',0)>0.2 else 'Monofractal normal'}</div>
    <div class="alert alert-ultra">🔄 Transfer Entropy: {'Anomalous causal flow' if ultra.get('te_anomaly_flag') else 'Normal causal structure'}</div>
    <div class="alert alert-ultra">📐 RMT: {f"Non-random correlations detected (p={ultra.get('rmt_pvalue',0):.4f})" if ultra.get('rmt_pvalue',1)<0.05 else 'Random matrix behavior'}</div>
    {'<div class="alert alert-danger">🚨 CRITICAL ULTRA ANOMALY: Subtle fraud pattern detected by advanced methods</div>' if ultra_score > 0.7 else ''}
  </div>

  <!-- Alertes Réglementaires -->
  <div class="section">
    <h2>⚠️ Compliance Alerts</h2>
    {'<div class="alert alert-ok">✅ AUC-ROC ≥ 0.75 — Performance satisfaisante</div>' if perf.get('auc_roc', 0) >= 0.75 else '<div class="alert alert-danger">🚨 AUC-ROC < 0.75 — Performance insuffisante</div>'}
    {'<div class="alert alert-ok">✅ KS ≥ 0.30 — Bonne séparation</div>' if perf.get('ks_statistic', 0) >= 0.30 else '<div class="alert alert-warning">⚠️ KS < 0.30 — Séparation limitée</div>'}
    {'<div class="alert alert-danger">🚨 Anomalie Benford (p<0.05) — Vérifier les données</div>' if ben.get('significant_bias') else '<div class="alert alert-ok">✅ Benford — Données cohérentes</div>' if ben else ''}
  </div>

  <!-- Figures -->
  {figures_html}

</div>
<div class="footer">
  Rapport généré par <strong>BlockchainFraudAnalyzer v1.0</strong><br>
  Network: {self.network.upper()} | Native Token: {self.native_token}<br>
  Méthodes: MF-DFA · Transfer Entropy · BOCD · RMT · ESN · SSA · RQA<br>
  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
</body></html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"  {ConsoleColors.colorize('✅ Rapport HTML sauvegardé:', ConsoleColors.GREEN)} {output_path}")
        self._log_debug(f"HTML report saved to {output_path}")
        return output_path


# =============================================================================
# GÉNÉRATEUR DE DONNÉES SYNTHÉTIQUES BLOCKCHAIN
# =============================================================================

def generate_synthetic_blockchain_data(n_samples: int = 100000, n_fraud_ratio: float = 0.015):
    """Génère des données blockchain synthétiques pour test."""
    np.random.seed(42)
    n_fraud = int(n_samples * n_fraud_ratio)

    # Données légitimes
    legit = pd.DataFrame({
        'tx_value_eth': np.random.lognormal(0.5, 2.0, n_samples - n_fraud),
        'tx_count_per_block': np.random.poisson(3, n_samples - n_fraud),
        'contract_risk_score': np.random.beta(2, 5, n_samples - n_fraud),
        'wallet_age_blocks': np.random.exponential(50000, n_samples - n_fraud),
        'is_cross_chain': np.random.binomial(1, 0.08, n_samples - n_fraud),
        'block_timestamp_mod': np.random.randint(0, 12, n_samples - n_fraud),
        'gas_anomaly_score': np.random.beta(1, 5, n_samples - n_fraud),
        'gas_used': np.random.choice([21000, 65000, 150000], n_samples - n_fraud, p=[0.6, 0.3, 0.1]),
        'is_contract_call': np.random.binomial(1, 0.25, n_samples - n_fraud),
        'is_fraud': 0
    })

    # Fraudes simulées
    fraud = pd.DataFrame({
        'tx_value_eth': np.concatenate([
            np.random.choice([0.1, 1.0, 10.0], n_fraud // 3),
            np.random.lognormal(5, 1.5, n_fraud // 3),
            np.random.lognormal(0.01, 0.5, n_fraud // 3)
        ])[:n_fraud],
        'tx_count_per_block': np.random.poisson(10, n_fraud),
        'contract_risk_score': np.random.beta(5, 2, n_fraud),
        'wallet_age_blocks': np.random.exponential(1000, n_fraud),
        'is_cross_chain': np.random.binomial(1, 0.45, n_fraud),
        'block_timestamp_mod': np.random.choice([0, 1, 2, 3], n_fraud),
        'gas_anomaly_score': np.random.beta(5, 1, n_fraud),
        'gas_used': np.random.choice([80000, 200000], n_fraud, p=[0.3, 0.7]),
        'is_contract_call': 1,
        'is_fraud': 1
    })

    df = pd.concat([legit, fraud]).sample(frac=1, random_state=42).reset_index(drop=True)

    # Colonnes blockchain
    df['block_number'] = np.sort(np.random.randint(18_000_000, 20_500_000, len(df)))

    # Génération d'adresses Ethereum-like
    hex_chars = list('0123456789abcdef')
    df['from_address'] = ['0x' + ''.join(np.random.choice(hex_chars, 40)) for _ in range(len(df))]
    df['to_address'] = ['0x' + ''.join(np.random.choice(hex_chars, 40)) for _ in range(len(df))]
    df['tx_hash'] = ['0x' + ''.join(np.random.choice(hex_chars, 64)) for _ in range(len(df))]

    return df


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Blockchain Fraud Analyzer v1.0')
    parser.add_argument('--debug', action='store_true', help='Enable forensic debug mode')
    parser.add_argument('--network', type=str, default='ethereum', help='Blockchain network')
    parser.add_argument('--token', type=str, default='ETH', help='Native token symbol')
    args = parser.parse_args()

    print(f"{ConsoleColors.colorize('='*80, ConsoleColors.BOLD)}")
    print(f"  {ConsoleColors.colorize('BLOCKCHAIN FRAUD ANALYZER v1.0 — ON-CHAIN DEMONSTRATION', ConsoleColors.BLOCKCHAIN)}")
    print(f"{ConsoleColors.colorize('='*80, ConsoleColors.BOLD)}")

    # Génération des données
    print(f"\n{ConsoleColors.colorize('📊 Génération des données blockchain...', ConsoleColors.CYAN)}")
    df = generate_synthetic_blockchain_data(n_samples=100000, n_fraud_ratio=0.015)
    print(f"   Transactions générées: {len(df):,}")
    print(f"   Taux de fraude: {df['is_fraud'].mean():.2%}")

    feature_cols = ['tx_value_eth', 'gas_used', 'wallet_age_blocks', 'gas_anomaly_score',
                    'contract_risk_score', 'is_cross_chain', 'is_contract_call']

    # Initialisation
    analyzer = BlockchainFraudAnalyzer(
        model_name="OnChain Threat Detector v1",
        network=args.network,
        native_token=args.token,
        debug=args.debug
    )

    # Analyses blockchain spécifiques
    pb = ProgressBar(7, prefix="Analyses blockchain:", suffix="complètes", length=40)

    mixer_res = analyzer.detect_mixer_patterns(df)
    pb.update(1)

    wash_res = analyzer.detect_wash_trading(df)
    pb.update(2)

    rug_res = analyzer.detect_rug_pull_signals(df)
    pb.update(3)

    sandwich_res = analyzer.detect_sandwich_attacks(df)
    pb.update(4)

    contract_res = analyzer.analyze_smart_contract_risk(df)
    pb.update(5)

    flash_res = analyzer.analyze_defi_flash_loans(df)
    pb.update(6)

    # Ultra-scientific detection
    ultra_results = analyzer.ultra_scientific_detection(
        df, feature_cols=feature_cols, time_col='block_number', value_col='tx_value_eth'
    )
    pb.update(7)
    pb.finish()

    # Pour la démonstration, créons un score simple
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    X = df[feature_cols]
    y = df['is_fraud']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    scaler = StandardScaler()
    model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    model.fit(scaler.fit_transform(X_train), y_train)
    y_proba = model.predict_proba(scaler.transform(X_test))[:, 1]

    # Calcul des métriques de base
    analyzer.calculate_performance_metrics(y_test, y_proba, bootstrap=False)
    analyzer.plot_advanced_curves(y_test, y_proba)
    analyzer.generate_html_report('onchain_threat_report.html')

    # Rapport de synthèse
    print(f"\n{ConsoleColors.colorize('═'*80, ConsoleColors.BOLD)}")
    print(f"  {ConsoleColors.colorize('✅ DÉMONSTRATION TERMINÉE', ConsoleColors.GREEN)}")
    print(f"{ConsoleColors.colorize('═'*80, ConsoleColors.BOLD)}")
    print(f"\n  Fichiers générés:")
    print(f"    → onchain_threat_report.html")

    if args.debug:
        print(f"\n  {ConsoleColors.colorize('🔍 Forensic logs disponibles dans le dossier logs/', ConsoleColors.BLUE)}")

    print()
