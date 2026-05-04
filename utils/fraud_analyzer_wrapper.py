"""
Fraud Analyzer Wrapper - Interface entre Streamlit et Blockchain_Fraud_Analyzer
Version complète avec intégration native
"""

import sys
import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import hashlib
import json

# Ajout du chemin parent pour importer l'analyseur
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import de l'analyseur blockchain
try:
    from blockchain_fraud_analyzer import BlockchainFraudAnalyzer as CoreAnalyzer
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ BlockchainFraudAnalyzer non trouvé: {e}")
    print("   Utilisation du mode dégradé (analyseur simulé)")
    ANALYZER_AVAILABLE = False


class FraudAnalyzerWrapper:
    """
    Wrapper pour BlockchainFraudAnalyzer avec interface adaptée à Streamlit
    Gère l'initialisation, la configuration et l'exécution des analyses
    """
    
    def __init__(self, network: str = "ethereum", native_token: str = "ETH",
                 debug: bool = False, config: Dict[str, Any] = None):
        """
        Initialise le wrapper et l'analyseur sous-jacent
        
        Args:
            network: Réseau blockchain (ethereum, polygon, bsc...)
            native_token: Symbole du token natif (ETH, MATIC, BNB...)
            debug: Mode debug avec logs détaillés
            config: Configuration personnalisée
        """
        self.network = network
        self.native_token = native_token
        self.debug = debug
        self.config = config or {}
        
        # Initialisation de l'analyseur core
        if ANALYZER_AVAILABLE:
            self.analyzer = CoreAnalyzer(
                model_name=f"StreamlitAnalyzer_{network}",
                network=network,
                native_token=native_token,
                debug=debug,
                cost_fn=self.config.get('cost_fn', 5000),
                cost_fp=self.config.get('cost_fp', 100)
            )
            self._log("Analyseur core initialisé avec succès")
        else:
            self.analyzer = None
            self._log("Mode dégradé - analyseur simulé", "WARNING")
        
        # Cache des résultats
        self.cache = {}
        
        # Seuils configurables
        self.thresholds = {
            'mixer': self.config.get('mixer_threshold', 0.3),
            'wash': self.config.get('wash_threshold', 0.4),
            'rug': self.config.get('rug_threshold', 0.5),
            'sandwich': self.config.get('sandwich_threshold', 0.5),
            'ultra': self.config.get('ultra_threshold', 0.6)
        }
    
    def _log(self, message: str, level: str = "INFO"):
        """Log interne avec horodatage"""
        if self.debug:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] [{level}] FraudAnalyzerWrapper: {message}")
    
    def analyze_transactions(self, df: pd.DataFrame, 
                            methods: List[str],
                            detection_level: str = "Approfondi",
                            ultra_params: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Analyse un DataFrame de transactions avec les méthodes spécifiées
        
        Args:
            df: DataFrame avec les transactions (colonnes normalisées)
            methods: Liste des méthodes à activer
            detection_level: Standard, Approfondi, Forensique, Ultra
            ultra_params: Paramètres pour l'analyse ultra-scientifique
        
        Returns:
            Dictionnaire contenant tous les résultats d'analyse
        """
        self._log(f"Analyse de {len(df)} transactions avec méthodes: {methods}")
        
        results = {}
        
        if df.empty:
            self._log("DataFrame vide, retour de résultats vides", "WARNING")
            return self._get_empty_results()
        
        # Vérification des colonnes nécessaires
        required_cols = ['from_address', 'to_address', 'tx_value_eth']
        missing_cols = [c for c in required_cols if c not in df.columns]
        if missing_cols:
            self._log(f"Colonnes manquantes: {missing_cols}", "ERROR")
            # Ajout de colonnes par défaut si nécessaire
            for col in missing_cols:
                if col == 'tx_value_eth':
                    df[col] = 1.0
                else:
                    df[col] = f"0x{np.random.randint(0, 2**160):040x}"
        
        # Mode dégradé si analyseur non disponible
        if not ANALYZER_AVAILABLE or self.analyzer is None:
            return self._simulate_analysis(df, methods, detection_level)
        
        # 1. Détection des patterns de mixer
        if "Mixer Detection" in methods:
            try:
                self._log("Exécution de detect_mixer_patterns...")
                mixer_result = self.analyzer.detect_mixer_patterns(df)
                # Ajout du seuil configuré
                mixer_result['is_suspicious'] = mixer_result.get('mixer_score', 0) > self.thresholds['mixer']
                results['mixer'] = mixer_result
                self._log(f"Mixer score: {mixer_result.get('mixer_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur mixer detection: {e}", "ERROR")
                results['mixer'] = self._get_error_result('mixer')
        
        # 2. Détection de wash trading
        if "Wash Trading" in methods:
            try:
                self._log("Exécution de detect_wash_trading...")
                wash_result = self.analyzer.detect_wash_trading(df)
                wash_result['is_suspicious'] = wash_result.get('wash_score', 0) > self.thresholds['wash']
                results['wash'] = wash_result
                self._log(f"Wash score: {wash_result.get('wash_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur wash trading: {e}", "ERROR")
                results['wash'] = self._get_error_result('wash')
        
        # 3. Détection de rug pull
        if "Rug Pull" in methods:
            try:
                self._log("Exécution de detect_rug_pull_signals...")
                rug_result = self.analyzer.detect_rug_pull_signals(df)
                rug_result['is_suspicious'] = rug_result.get('rug_score', 0) > self.thresholds['rug']
                results['rug'] = rug_result
                self._log(f"Rug score: {rug_result.get('rug_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur rug pull: {e}", "ERROR")
                results['rug'] = self._get_error_result('rug')
        
        # 4. Détection d'attaques sandwich
        if "Sandwich Attacks" in methods:
            try:
                self._log("Exécution de detect_sandwich_attacks...")
                sandwich_result = self.analyzer.detect_sandwich_attacks(df)
                sandwich_result['is_suspicious'] = sandwich_result.get('sandwich_score', 0) > self.thresholds['sandwich']
                results['sandwich'] = sandwich_result
                self._log(f"Sandwich score: {sandwich_result.get('sandwich_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur sandwich detection: {e}", "ERROR")
                results['sandwich'] = self._get_error_result('sandwich')
        
        # 5. Détection de flash loans
        if "Flash Loans" in methods:
            try:
                self._log("Exécution de analyze_defi_flash_loans...")
                flash_result = self.analyzer.analyze_defi_flash_loans(df)
                results['flash'] = flash_result
                self._log(f"Flash loan score: {flash_result.get('flash_loan_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur flash loans: {e}", "ERROR")
                results['flash'] = self._get_error_result('flash')
        
        # 6. Analyse ultra-scientifique
        if "Ultra-Scientific" in methods or detection_level == "Ultra":
            try:
                self._log("Exécution de ultra_scientific_detection...")
                
                # Préparation des colonnes features
                feature_cols = ['tx_value_eth']
                if 'gas_used' in df.columns:
                    feature_cols.append('gas_used')
                if 'contract_risk_score' in df.columns:
                    feature_cols.append('contract_risk_score')
                else:
                    # Création d'un proxy si absent
                    df['contract_risk_score'] = np.random.beta(2, 5, len(df))
                    feature_cols.append('contract_risk_score')
                
                ultra_result = self.analyzer.ultra_scientific_detection(
                    df, 
                    feature_cols=feature_cols,
                    time_col='block_number' if 'block_number' in df.columns else None,
                    value_col='tx_value_eth'
                )
                
                # Ajout du seuil
                ultra_result['is_critical'] = ultra_result.get('global_ultra_anomaly_score', 0) > self.thresholds['ultra']
                results['ultra'] = ultra_result
                self._log(f"Ultra anomaly score: {ultra_result.get('global_ultra_anomaly_score', 0):.4f}")
            except Exception as e:
                self._log(f"Erreur ultra-scientific: {e}", "ERROR")
                results['ultra'] = self._get_error_result('ultra')
        
        # 7. Analyse des smart contracts
        if detection_level in ["Forensique", "Ultra"]:
            try:
                self._log("Exécution de analyze_smart_contract_risk...")
                contract_result = self.analyzer.analyze_smart_contract_risk(df)
                results['contract'] = contract_result
            except Exception as e:
                self._log(f"Erreur contract analysis: {e}", "ERROR")
        
        # Calcul du score global
        results['global_score'] = self._compute_global_score(results)
        results['risk_level'] = self._get_risk_level(results['global_score'])
        
        # Ajout de métadonnées
        results['metadata'] = {
            'analyzer_version': '1.0',
            'network': self.network,
            'methods_used': methods,
            'detection_level': detection_level,
            'transactions_count': len(df),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        return results
    
    def _compute_global_score(self, results: Dict[str, Any]) -> float:
        """Calcule le score de risque global pondéré"""
        scores = []
        weights = []
        
        # Mixer
        if 'mixer' in results and 'mixer_score' in results['mixer']:
            scores.append(results['mixer']['mixer_score'])
            weights.append(0.25)
        
        # Wash trading
        if 'wash' in results and 'wash_score' in results['wash']:
            scores.append(results['wash']['wash_score'])
            weights.append(0.20)
        
        # Rug pull
        if 'rug' in results and 'rug_score' in results['rug']:
            scores.append(results['rug']['rug_score'])
            weights.append(0.30)
        
        # Sandwich
        if 'sandwich' in results and 'sandwich_score' in results['sandwich']:
            scores.append(results['sandwich']['sandwich_score'])
            weights.append(0.10)
        
        # Ultra
        if 'ultra' in results and 'global_ultra_anomaly_score' in results['ultra']:
            scores.append(results['ultra']['global_ultra_anomaly_score'])
            weights.append(0.15)
        
        if not scores:
            return 0.0
        
        # Score pondéré
        weighted_score = np.average(scores, weights=weights[:len(scores)])
        
        # Normalisation
        return float(np.clip(weighted_score, 0, 1))
    
    def _get_risk_level(self, score: float) -> str:
        """Convertit un score en niveau de risque textuel"""
        if score > 0.7:
            return "CRITICAL"
        elif score > 0.4:
            return "HIGH"
        elif score > 0.2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_empty_results(self) -> Dict[str, Any]:
        """Retourne des résultats vides"""
        return {
            'global_score': 0.0,
            'risk_level': 'LOW',
            'metadata': {'empty': True}
        }
    
    def _get_error_result(self, method: str) -> Dict[str, Any]:
        """Retourne un résultat d'erreur pour une méthode"""
        return {
            f'{method}_score': 0.0,
            'error': True,
            'error_message': f"Erreur lors de l'exécution de {method}"
        }
    
    def _simulate_analysis(self, df: pd.DataFrame, methods: List[str], 
                           detection_level: str) -> Dict[str, Any]:
        """
        Simulation d'analyse pour le mode dégradé (quand l'analyseur n'est pas disponible)
        """
        self._log("Mode simulation - génération de résultats synthétiques", "WARNING")
        
        results = {}
        
        # Génération de scores réalistes basés sur les données
        tx_values = df['tx_value_eth'].values if 'tx_value_eth' in df.columns else np.random.lognormal(1, 2, len(df))
        
        # Score de base influencé par les valeurs de transaction
        base_suspicion = min(0.8, max(0.05, np.std(np.log(tx_values + 1)) / 5))
        
        if "Mixer Detection" in methods:
            results['mixer'] = {
                'mixer_score': min(0.9, base_suspicion + np.random.random() * 0.3),
                'suspicious_wallets': [],
                'is_suspicious': base_suspicion > self.thresholds['mixer']
            }
        
        if "Wash Trading" in methods:
            # Compter les cycles potentiels
            pairs = df.groupby(['from_address', 'to_address']).size()
            cycle_count = len(pairs[pairs > 2])
            results['wash'] = {
                'wash_score': min(1.0, cycle_count / 50 + np.random.random() * 0.2),
                'cycles_detected': cycle_count,
                'is_suspicious': base_suspicion > self.thresholds['wash']
            }
        
        if "Rug Pull" in methods:
            # Simuler la concentration
            if 'to_address' in df.columns:
                holdings = df.groupby('to_address')['tx_value_eth'].sum()
                gini = self._compute_gini(holdings.values) if len(holdings) > 0 else 0.5
            else:
                gini = np.random.beta(2, 2)
            results['rug'] = {
                'rug_score': min(1.0, gini * 0.8 + np.random.random() * 0.2),
                'gini_concentration': gini,
                'is_suspicious': gini > self.thresholds['rug']
            }
        
        if "Sandwich Attacks" in methods:
            results['sandwich'] = {
                'sandwich_score': min(0.7, np.random.random() * 0.5),
                'suspected_triplets': np.random.poisson(2),
                'is_suspicious': np.random.random() > 0.8
            }
        
        if "Flash Loans" in methods:
            results['flash'] = {
                'flash_loan_score': min(0.6, np.random.random() * 0.4)
            }
        
        if "Ultra-Scientific" in methods or detection_level == "Ultra":
            ultra_score = min(0.9, base_suspicion * 1.2 + np.random.random() * 0.3)
            results['ultra'] = {
                'global_ultra_anomaly_score': ultra_score,
                'multifractal_width': np.random.random() * 0.5,
                'rmt_pvalue': np.random.random(),
                'ultra_risk_level': self._get_risk_level(ultra_score),
                'is_critical': ultra_score > self.thresholds['ultra']
            }
        
        # Score global
        global_score = self._compute_global_score(results)
        results['global_score'] = global_score
        results['risk_level'] = self._get_risk_level(global_score)
        
        results['metadata'] = {
            'analyzer_version': 'simulated',
            'network': self.network,
            'methods_used': methods,
            'detection_level': detection_level,
            'transactions_count': len(df),
            'analysis_timestamp': datetime.now().isoformat(),
            'simulated': True
        }
        
        return results
    
    def _compute_gini(self, x: np.ndarray) -> float:
        """Calcule le coefficient de Gini"""
        x = x[x > 0]
        if len(x) == 0:
            return 0.5
        x_sorted = np.sort(x)
        n = len(x_sorted)
        cumx = np.cumsum(x_sorted)
        return (n + 1 - 2 * cumx.sum() / cumx[-1]) / n if cumx[-1] > 0 else 0.5
    
    def generate_report(self, results: Dict[str, Any], output_path: str) -> str:
        """
        Génère un rapport HTML à partir des résultats d'analyse
        
        Args:
            results: Dictionnaire des résultats
            output_path: Chemin de sortie du fichier HTML
        
        Returns:
            Chemin du fichier généré
        """
        self._log(f"Génération du rapport vers {output_path}")
        
        if self.analyzer is not None and not results.get('metadata', {}).get('simulated', False):
            # Utilisation du générateur natif de l'analyseur
            return self.analyzer.generate_html_report(output_path)
        else:
            # Génération simplifiée pour le mode simulation
            return self._generate_simple_report(results, output_path)
    
    def _generate_simple_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Génère un rapport HTML simplifié pour le mode simulation"""
        
        global_score = results.get('global_score', 0)
        risk_level = results.get('risk_level', 'LOW')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Blockchain Fraud Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #e2e8f0; }}
        h1 {{ color: #60a5fa; }}
        .score {{ font-size: 48px; font-weight: bold; text-align: center; padding: 20px; }}
        .risk-low {{ color: #2e7d32; }}
        .risk-medium {{ color: #f9a825; }}
        .risk-high {{ color: #ef6c00; }}
        .risk-critical {{ color: #c62828; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #60a5fa; }}
    </style>
</head>
<body>
    <h1>🔗 Blockchain Fraud Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Network: {self.network} | Token: {self.native_token}</p>
    
    <div class="score risk-{risk_level.lower()}">
        Global Risk Score: {global_score:.1%}<br>
        Level: {risk_level}
    </div>
    
    <h2>📊 Detailed Scores</h2>
    <table>
        <tr><th>Method</th><th>Score</th><th>Status</th></tr>
"""
        
        for method, data in results.items():
            if method not in ['global_score', 'risk_level', 'metadata']:
                score_key = f"{method}_score" if f"{method}_score" in data else "global_ultra_anomaly_score"
                score = data.get(score_key, 0)
                status = "⚠️ Alert" if (method == 'ultra' and data.get('is_critical')) or data.get('is_suspicious') else "✅ Normal"
                html += f"<tr><td>{method}</td><td>{score:.1%}</td><td>{status}</td></tr>"
        
        html += """
    </table>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def get_available_methods(self) -> List[str]:
        """Retourne la liste des méthodes disponibles"""
        methods = [
            "Mixer Detection",
            "Wash Trading", 
            "Rug Pull",
            "Sandwich Attacks",
            "Flash Loans"
        ]
        
        if ANALYZER_AVAILABLE:
            methods.append("Ultra-Scientific")
        
        return methods
    
    def update_thresholds(self, thresholds: Dict[str, float]):
        """Met à jour les seuils de détection"""
        self.thresholds.update(thresholds)
        self._log(f"Seuils mis à jour: {self.thresholds}")


# Fonction de création de wrapper pour Streamlit
def create_analyzer_from_streamlit_config(config: Dict[str, Any] = None) -> FraudAnalyzerWrapper:
    """
    Fonction factory pour créer un analyseur à partir de la configuration Streamlit
    
    Args:
        config: Dictionnaire de configuration (peut venir de st.session_state)
    
    Returns:
        Instance configurée de FraudAnalyzerWrapper
    """
    if config is None:
        config = {}
    
    return FraudAnalyzerWrapper(
        network=config.get('network', 'ethereum'),
        native_token=config.get('native_token', 'ETH'),
        debug=config.get('debug', False),
        config={
            'cost_fn': config.get('cost_fn', 5000),
            'cost_fp': config.get('cost_fp', 100),
            'mixer_threshold': config.get('mixer_threshold', 0.3),
            'wash_threshold': config.get('wash_threshold', 0.4),
            'rug_threshold': config.get('rug_threshold', 0.5),
            'sandwich_threshold': config.get('sandwich_threshold', 0.5),
            'ultra_threshold': config.get('ultra_threshold', 0.6)
        }
    )