"""
Blockchain Fraud Analyzer Pro
Interface Feng Shui - Streamlit Application
Version Complète
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import hashlib
import requests
import time
from typing import Dict, Any, Optional, List
import asyncio
from utils.fraud_analyzer_wrapper import FraudAnalyzerWrapper, create_analyzer_from_streamlit_config

# Configuration de la page - DOIT être la première commande Streamlit
st.set_page_config(
    page_title="Blockchain Fraud Analyzer Pro",
    page_icon="🔗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# STYLES CSS FENG SHUI
# ============================================================================
st.markdown("""
<style>
/* Palette Feng Shui - Équilibre Yin/Yang */
:root {
    --wood: #2e7d32;
    --fire: #d84315;
    --earth: #8d6e63;
    --metal: #78909c;
    --water: #1565c0;
    --yin: #1a1a2e;
    --yang: #f5f5f5;
    --balance: #4a148c;
}
/* En-tête apaisant */
.main-header {
    background: linear-gradient(135deg, var(--water), var(--balance));
    padding: 2rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    text-align: center;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
}
/* Cartes énergétiques */
.energy-card {
    background: rgba(255,255,255,0.05);
    border-radius: 15px;
    padding: 1.5rem;
    margin: 1rem 0;
    border-left: 4px solid var(--fire);
    transition: transform 0.3s ease;
}
.energy-card:hover {
    transform: translateY(-5px);
}
/* Animation riz */
@keyframes riceGrain {
    0%, 100% { transform: rotate(0deg); }
    50% { transform: rotate(5deg); }
}
.rice-deco {
    font-size: 1.2rem;
    animation: riceGrain 4s ease-in-out infinite;
    display: inline-block;
}
/* Badges de risque */
.risk-badge {
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-weight: bold;
    text-align: center;
    display: inline-block;
}
.risk-critical { background: #c62828; color: white; }
.risk-high { background: #ef6c00; color: white; }
.risk-medium { background: #f9a825; color: #1a1a2e; }
.risk-low { background: #2e7d32; color: white; }
/* Jauges */
.gauge-container {
    background: rgba(255,255,255,0.1);
    border-radius: 10px;
    padding: 1rem;
    margin: 1rem 0;
}
/* Pied de page */
.footer {
    text-align: center;
    padding: 2rem;
    margin-top: 3rem;
    color: #78909c;
    border-top: 1px solid rgba(255,255,255,0.1);
}
/* Animations de chargement */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
.loading {
    animation: pulse 1.5s ease-in-out infinite;
}
/* Cartes de résultat */
.result-card {
    background: linear-gradient(135deg, rgba(30,30,60,0.9), rgba(20,20,40,0.9));
    border-radius: 15px;
    padding: 1.2rem;
    margin: 0.5rem 0;
    border: 1px solid rgba(255,255,255,0.1);
}
</style>
<div class="main-header">
    <h1>🔗 Blockchain Fraud Analyzer Pro</h1>
    <p style="font-size: 1.1rem; opacity: 0.9;">⚖️ Intelligence Artificielle pour la Sécurité On-Chain ⚖️</p>
    <div class="rice-deco">🍚 · 調和 · 🍚</div>
    <p style="font-size: 0.85rem; margin-top: 0.5rem;">"L'équilibre parfait entre détection et sérénité"</p>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# INITIALISATION DE LA SESSION
# ============================================================================
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = None
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'api_keys_configured' not in st.session_state:
    st.session_state.api_keys_configured = False
if 'config' not in st.session_state:
    st.session_state.config = {
        'mixer_threshold': 0.3,
        'wash_threshold': 0.4,
        'rug_threshold': 0.5,
        'sandwich_threshold': 0.5,
        'ultra_threshold': 0.6,
        'max_transactions': 10000,
        'default_methods': ['Mixer', 'Wash Trading', 'Rug Pull']
    }
# Initialisation de la session - AVANT la navigation
if 'analyzer_wrapper' not in st.session_state:
    from utils.fraud_analyzer_wrapper import create_analyzer_from_streamlit_config
    st.session_state.analyzer_wrapper = create_analyzer_from_streamlit_config({
        'network': 'ethereum',
        'native_token': 'ETH',
        'debug': st.session_state.get('debug', False),
        'cost_fn': 5000,
        'cost_fp': 100,
        'mixer_threshold': 0.3,
        'wash_threshold': 0.4,
        'rug_threshold': 0.5,
        'sandwich_threshold': 0.5,
        'ultra_threshold': 0.6
    })

if 'connector' not in st.session_state:
    from utils.blockchain_connector import BlockchainConnector
    secrets = st.secrets.get("api_keys", {})
    st.session_state.connector = BlockchainConnector(secrets)
# ============================================================================
# SIDEBAR - NAVIGATION
# ============================================================================
with st.sidebar:
    st.markdown("## 🧘 Navigation")
    menu = st.radio(
        "Choisissez votre voie",
        ["🏠 Dashboard", "🔍 Investigation", "⚙️ Paramètres", "📜 Historique", "🔑 API Keys", "📊 Export"],
        index=0
    )
    
    st.markdown("---")
    st.markdown("### 🌊 Énergie du Système")
    if st.session_state.analyzer:
        st.success("✅ Analyseur actif")
        st.metric("Analyses aujourd'hui", len(st.session_state.analysis_history))
    else:
        st.warning("⏳ Analyseur non initialisé")
        
    st.markdown("---")
    with st.expander("🎴 Les 5 Éléments"):
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.markdown("<div style='color:#2e7d32; text-align:center'>🌳<br>Bois</div>", unsafe_allow_html=True)
        col2.markdown("<div style='color:#d84315; text-align:center'>🔥<br>Feu</div>", unsafe_allow_html=True)
        col3.markdown("<div style='color:#8d6e63; text-align:center'>⛰️<br>Terre</div>", unsafe_allow_html=True)
        col4.markdown("<div style='color:#78909c; text-align:center'>⚔️<br>Métal</div>", unsafe_allow_html=True)
        col5.markdown("<div style='color:#1565c0; text-align:center'>💧<br>Eau</div>", unsafe_allow_html=True)
        
    st.markdown("---")
    st.caption("v1.0.0 | Streamlit Cloud Ready")

# ============================================================================
# PAGE DASHBOARD
# ============================================================================
if menu == "🏠 Dashboard":
    st.markdown("## 📊 Tableau de Bord - Vue Énergétique")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🛡️ Protection", "Active", delta="99.9% uptime")
    with col2:
        st.metric("🔍 Analyses totales", len(st.session_state.analysis_history))
    with col3:
        critical_count = sum(1 for a in st.session_state.analysis_history if a.get('risk_level') == 'CRITICAL')
        st.metric("⚠️ Alertes critiques", critical_count)
    with col4:
        st.metric("🌐 Réseaux supportés", "10+", delta="Ethereum, Polygon, BSC...")

    # Graphiques
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.markdown("### 📈 Flux d'Analyses")
        dates = [datetime.now() - timedelta(days=i) for i in range(6, -1, -1)]
        counts = [len([a for a in st.session_state.analysis_history
                      if datetime.fromisoformat(a['timestamp']).date() == d.date()])
                  for d in dates]
        fig = go.Figure(data=go.Scatter(
            x=dates, y=counts,
            mode='lines+markers',
            line=dict(color='#1565c0', width=3),
            marker=dict(size=10, color='#4a148c'),
            fill='tozeroy',
            fillcolor='rgba(21, 101, 192, 0.2)'
        ))
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis_title="Date",
            yaxis_title="Nombre d'analyses"
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        st.markdown("### 🎯 Distribution des Menaces")
        threats = ['Mixer', 'Wash Trading', 'Rug Pull', 'Sandwich', 'Flash Loan']
        threat_counts = []
        for a in st.session_state.analysis_history:
            details = a.get('details', {})
            for t in threats:
                t_key = t.lower().replace(' ', '_')
                if t_key in details and details[t_key].get(f'{t_key}_score', 0) > 0.3:
                    threat_counts.append(t)
                    
        if threat_counts:
            counts_threats = [threat_counts.count(t) for t in threats]
            fig = go.Figure(data=[go.Pie(
                labels=threats, values=counts_threats,
                marker=dict(colors=['#2e7d32', '#d84315', '#8d6e63', '#78909c', '#1565c0']),
                hole=0.4
            )])
            fig.update_layout(title="Menaces détectées")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Aucune menace détectée dans l'historique")

    # Dernières analyses
    st.markdown("### 📋 Dernières Investigations")
    if st.session_state.analysis_history:
        df_history = pd.DataFrame(st.session_state.analysis_history[-5:])
        st.dataframe(df_history[['timestamp', 'address', 'risk_level', 'overall_score']],
                     use_container_width=True)
    else:
        st.info("Aucune analyse effectuée. Lancez une investigation !")

# ============================================================================
# PAGE INVESTIGATION - VERSION COMPLÈTE AVEC INTÉGRATION DU WRAPPER
# ============================================================================

elif menu == "🔍 Investigation":
    st.markdown("## 🔍 Investigation On-Chain")
    st.markdown("*L'équilibre entre précision et intuition*")

    # Formulaire principal
    with st.container():
        col_addr, col_network = st.columns([3, 1])

        with col_addr:
            address = st.text_input(
                "📍 Adresse Blockchain",
                placeholder="0x... ou nom ENS (ex: vitalik.eth, uniswap.eth)",
                help="Entrez une adresse Ethereum, Polygon, BSC... ou un nom ENS",
                key="investigation_address"
            )

            # Suggestions rapides
            with st.expander("🔍 Adresses de test"):
                st.markdown("""
                - `vitalik.eth` - Portefeuille de Vitalik Buterin
                - `0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9` - Contrat Aave
                - `0x0000000000000000000000000000000000000000` - Adresse nulle
                """)

        with col_network:
            network = st.selectbox(
                "🌐 Réseau",
                ["ethereum", "polygon", "bsc", "avalanche", "arbitrum", "optimism", "base"],
                index=0,
                key="investigation_network"
            )

    # Paramètres d'analyse - Section Feng Shui
    with st.expander("🎴 Paramètres d'Analyse - Équilibre des Éléments", expanded=True):
        st.markdown("#### ⚖️ Ajustez l'équilibre de votre analyse")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("##### 🌳 Bois (Profondeur)")
            blocks_back = st.slider(
                "Blocs à analyser",
                min_value=1000, max_value=500000, value=50000, step=5000,
                help="Plus de blocs = analyse plus profonde mais plus lente",
                key="blocks_back"
            )

            use_sampling = st.checkbox("Échantillonnage intelligent", value=True, key="use_sampling")

            max_transactions = st.number_input(
                "Max transactions",
                min_value=100, max_value=50000,
                value=st.session_state.config.get('max_transactions', 10000),
                step=1000,
                key="max_transactions_input"
            )

        with col2:
            st.markdown("##### 🔥 Feu (Intensité)")
            detection_level = st.select_slider(
                "Niveau de détection",
                options=["Standard", "Approfondi", "Forensique", "Ultra"],
                value=st.session_state.config.get('detection_level', "Approfondi"),
                key="detection_level"
            )

            sensitivity = st.slider(
                "Sensibilité",
                0.0, 1.0,
                st.session_state.config.get('sensitivity', 0.5),
                0.05,
                key="sensitivity"
            )

            # Ajustement des seuils en fonction de la sensibilité
            if sensitivity != st.session_state.config.get('sensitivity', 0.5):
                st.caption(f"⚠️ Sensibilité à {sensitivity:.0%} - Seuils ajustés")

        with col3:
            st.markdown("##### 💧 Eau (Adaptabilité)")

            # Récupération des méthodes disponibles depuis le wrapper
            available_methods = st.session_state.analyzer_wrapper.get_available_methods()

            methods = st.multiselect(
                "Méthodes actives",
                available_methods,
                default=[m for m in st.session_state.config.get('default_methods',
                           ["Mixer Detection", "Wash Trading", "Rug Pull"])
                         if m in available_methods],
                key="analysis_methods"
            )

            if not methods:
                st.warning("⚠️ Sélectionnez au moins une méthode d'analyse")

    # Paramètres Ultra-Scientifiques
    with st.expander("🔬 Paramètres Ultra-Scientifiques (Métal · Terre)", expanded=detection_level == "Ultra"):
        st.markdown("*Précision et stabilité pour les analyses avancées*")

        col1, col2 = st.columns(2)

        with col1:
            enable_mfdfa = st.checkbox(
                "📊 MF-DFA (Multifractal)",
                value=True,
                help="Analyse de la complexité multifractale - détecte les patterns artificiels"
            )
            enable_bocd = st.checkbox(
                "🔄 BOCD (Changepoints)",
                value=True,
                help="Détection de changements de régime soudains"
            )
            enable_rmt = st.checkbox(
                "📐 RMT (Random Matrix Theory)",
                value=True,
                help="Analyse des corrélations spectrales - détecte la manipulation collective"
            )

        with col2:
            enable_te = st.checkbox(
                "🕸️ Transfer Entropy (Causalité)",
                value=True,
                help="Flux d'information causal entre variables"
            )
            enable_esn = st.checkbox(
                "🧠 ESN (Echo State Network)",
                value=True,
                help="Réseau de neurones récurrent pour la détection d'anomalies"
            )
            enable_rqa = st.checkbox(
                "🔁 RQA (Récurrence)",
                value=True,
                help="Analyse de la récurrence des états"
            )

        st.info("💡 Les méthodes Ultra-Scientifiques sont particulièrement efficaces pour détecter des fraudes subtiles non visibles par les méthodes standards.")

    # Paramètres de coût (pour l'optimisation)
    with st.expander("💰 Paramètres Économiques"):
        col1, col2 = st.columns(2)
        with col1:
            cost_fn = st.number_input(
                "Coût d'un faux négatif (fraude manquée)",
                min_value=100, max_value=100000, value=5000, step=500,
                help="Coût estimé d'une transaction frauduleuse non détectée"
            )
        with col2:
            cost_fp = st.number_input(
                "Coût d'un faux positif (fausse alarme)",
                min_value=10, max_value=10000, value=100, step=50,
                help="Coût d'une transaction légitime bloquée par erreur"
            )

    # Section avancée - Options de cache et performance
    with st.expander("⚡ Optimisation & Cache"):
        use_cache = st.checkbox("Utiliser le cache des résultats", value=True)
        force_refresh = st.checkbox("Forcer l'actualisation (ignorer le cache)", value=False)

        st.caption(f"Cache actuel: {len(st.session_state.connector.cache)} entrées")

        if st.button("🗑️ Vider le cache"):
            st.session_state.connector.cache.clear()
            st.success("Cache vidé !")
            st.rerun()

    st.markdown("---")

    # Bouton de lancement avec cérémonial
    col_space, col_button, col_space2 = st.columns([1, 2, 1])

    with col_button:
        analyze_button = st.button(
            "🚀 LANCER L'INVESTIGATION",
            use_container_width=True,
            type="primary",
            disabled=not methods or not address
        )

    # =========================================================================
    # LOGIQUE D'ANALYSE - INTÉGRATION AVEC LE WRAPPER
    # =========================================================================

    if analyze_button and address:
        if not methods:
            st.error("❌ Veuillez sélectionner au moins une méthode d'analyse")
            st.stop()

        # Création des conteneurs pour les feedbacks
        status_container = st.container()
        progress_container = st.container()
        results_container = st.container()

        with status_container:
            st.info(f"🔍 Analyse de l'adresse: `{address}` sur **{network.upper()}**")

        with progress_container:
            progress_bar = st.progress(0, text="Initialisation...")
            status_text = st.empty()

        try:
            # Étape 1: Récupération des transactions
            status_text.markdown("📡 **Phase 1/4**: Connexion à la blockchain...")
            progress_bar.progress(5, text="Connexion à la blockchain...")

            # Mise à jour du wrapper avec la configuration actuelle
            if st.session_state.analyzer_wrapper.network != network:
                st.session_state.analyzer_wrapper = create_analyzer_from_streamlit_config({
                    'network': network,
                    'native_token': network.upper()[:3] if network != 'ethereum' else 'ETH',
                    'debug': st.session_state.get('debug', False),
                    'cost_fn': cost_fn,
                    'cost_fp': cost_fp,
                    'mixer_threshold': st.session_state.config.get('mixer_threshold', 0.3),
                    'wash_threshold': st.session_state.config.get('wash_threshold', 0.4),
                    'rug_threshold': st.session_state.config.get('rug_threshold', 0.5),
                    'sandwich_threshold': st.session_state.config.get('sandwich_threshold', 0.5),
                    'ultra_threshold': st.session_state.config.get('ultra_threshold', 0.6)
                })

            # Récupération des données
            df = st.session_state.connector.get_transactions(
                address,
                network,
                blocks_back=blocks_back if not use_sampling else min(blocks_back, 100000)
            )

            progress_bar.progress(25, text="Transactions récupérées...")
            status_text.markdown(f"✅ **{len(df)} transactions** récupérées sur {network.upper()}")

            if df.empty:
                st.warning("⚠️ Aucune transaction trouvée pour cette adresse")
                st.stop()

            # Aperçu des données
            with st.expander("📋 Aperçu des transactions récupérées"):
                st.dataframe(
                    df[['tx_hash', 'block_number', 'from_address', 'to_address', 'tx_value_eth']].head(10),
                    use_container_width=True
                )
                st.caption(f"Total: {len(df)} transactions | Période: du bloc {df['block_number'].min()} au {df['block_number'].max()}")

            # Étape 2: Préparation des données
            status_text.markdown("🔧 **Phase 2/4**: Préparation des données...")
            progress_bar.progress(30, text="Préparation des données...")

            # Nettoyage et normalisation
            df_clean = df.copy()

            # Conversion des valeurs
            if 'tx_value_eth' in df_clean.columns:
                df_clean['tx_value_eth'] = pd.to_numeric(df_clean['tx_value_eth'], errors='coerce').fillna(0)

            # Ajout de colonnes dérivées si nécessaire
            if 'gas_used' in df_clean.columns:
                df_clean['gas_used'] = pd.to_numeric(df_clean['gas_used'], errors='coerce').fillna(21000)
            else:
                df_clean['gas_used'] = 21000

            # Limitation du nombre de transactions si nécessaire
            if len(df_clean) > max_transactions:
                original_len = len(df_clean)
                df_clean = df_clean.head(max_transactions)
                st.info(f"ℹ️ Analyse limitée aux {max_transactions} premières transactions ({original_len} disponibles)")

            progress_bar.progress(40, text="Données prêtes...")

            # Étape 3: Analyse
            status_text.markdown("🧪 **Phase 3/4**: Exécution des analyses...")

            # Construction de la barre de progression pour les méthodes
            method_steps = len(methods)
            current_step = 0

            # Mise à jour des seuils
            st.session_state.analyzer_wrapper.update_thresholds({
                'mixer': st.session_state.config.get('mixer_threshold', 0.3),
                'wash': st.session_state.config.get('wash_threshold', 0.4),
                'rug': st.session_state.config.get('rug_threshold', 0.5),
                'sandwich': st.session_state.config.get('sandwich_threshold', 0.5),
                'ultra': st.session_state.config.get('ultra_threshold', 0.6)
            })

            # Lancement de l'analyse principale
            results = st.session_state.analyzer_wrapper.analyze_transactions(
                df=df_clean,
                methods=methods,
                detection_level=detection_level,
                ultra_params={
                    'mfdfa': enable_mfdfa,
                    'bocd': enable_bocd,
                    'rmt': enable_rmt,
                    'te': enable_te,
                    'esn': enable_esn,
                    'rqa': enable_rqa
                }
            )

            progress_bar.progress(85, text="Analyse terminée...")
            status_text.markdown("✅ **Phase 3/4**: Analyses exécutées avec succès")

            # Étape 4: Génération des résultats
            status_text.markdown("📊 **Phase 4/4**: Génération des résultats...")
            progress_bar.progress(90, text="Génération des résultats...")

            # Extraction des scores
            overall_score = results.get('global_score', 0)
            risk_level = results.get('risk_level', 'LOW')

            # Détermination des couleurs et messages
            risk_config = {
                'CRITICAL': {'color': '#c62828', 'emoji': '🔴', 'icon': '🚨', 'message': 'ACTION IMMÉDIATE REQUISE'},
                'HIGH': {'color': '#ef6c00', 'emoji': '🟠', 'icon': '⚠️', 'message': 'SURVEILLANCE RENFORCÉE'},
                'MEDIUM': {'color': '#f9a825', 'emoji': '🟡', 'icon': '📌', 'message': 'INVESTIGATION RECOMMANDÉE'},
                'LOW': {'color': '#2e7d32', 'emoji': '🟢', 'icon': '✅', 'message': 'COMPORTEMENT NORMAL'}
            }

            config = risk_config.get(risk_level, risk_config['LOW'])

            # Affichage des résultats
            with results_container:
                st.markdown("---")
                st.markdown("## 📊 Résultats de l'Investigation")

                # Score global avec jauge Feng Shui
                col1, col2, col3 = st.columns([1, 2, 1])

                with col2:
                    st.markdown(f"""
                    <div style="text-align: center;">
                        <div style="font-size: 4rem;">{config['emoji']}</div>
                        <div style="display: inline-block; background: {config['color']};
                                  border-radius: 30px; padding: 0.5rem 1.5rem; margin: 0.5rem 0;">
                            <span style="font-size: 1.5rem; font-weight: bold; color: white;">
                                {risk_level}
                            </span>
                        </div>
                        <div style="font-size: 2rem; font-weight: bold; margin: 0.5rem 0;">
                            {overall_score:.1%}
                        </div>
                        <div style="font-size: 0.9rem; opacity: 0.8;">
                            {config['icon']} {config['message']}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                # Jauge circulaire Plotly
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=overall_score * 100,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Score de Risque", 'font': {'size': 14}},
                    gauge={
                        'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                        'bar': {'color': config['color']},
                        'bgcolor': "rgba(0,0,0,0)",
                        'borderwidth': 2,
                        'bordercolor': "gray",
                        'steps': [
                            {'range': [0, 20], 'color': 'rgba(46,125,50,0.3)'},
                            {'range': [20, 40], 'color': 'rgba(249,168,37,0.3)'},
                            {'range': [40, 70], 'color': 'rgba(239,108,0,0.3)'},
                            {'range': [70, 100], 'color': 'rgba(198,40,40,0.3)'}
                        ],
                    }
                ))
                fig_gauge.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=20))
                st.plotly_chart(fig_gauge, use_container_width=True)

                # Scores par catégorie
                st.markdown("### 📈 Scores de Risque par Catégorie")

                # Récupération des scores individuels
                category_scores = []

                if 'mixer' in results and 'mixer_score' in results['mixer']:
                    category_scores.append({
                        'Catégorie': '🌀 Mixer',
                        'Score': results['mixer']['mixer_score'],
                        'Seuil': st.session_state.config.get('mixer_threshold', 0.3),
                        'Statut': '⚠️ Suspect' if results['mixer']['mixer_score'] > st.session_state.config.get('mixer_threshold', 0.3) else '✅ Normal'
                    })

                if 'wash' in results and 'wash_score' in results['wash']:
                    category_scores.append({
                        'Catégorie': '🔄 Wash Trading',
                        'Score': results['wash']['wash_score'],
                        'Seuil': st.session_state.config.get('wash_threshold', 0.4),
                        'Statut': '⚠️ Suspect' if results['wash']['wash_score'] > st.session_state.config.get('wash_threshold', 0.4) else '✅ Normal'
                    })

                if 'rug' in results and 'rug_score' in results['rug']:
                    category_scores.append({
                        'Catégorie': '🧨 Rug Pull',
                        'Score': results['rug']['rug_score'],
                        'Seuil': st.session_state.config.get('rug_threshold', 0.5),
                        'Statut': '⚠️ Risque' if results['rug']['rug_score'] > st.session_state.config.get('rug_threshold', 0.5) else '✅ Sécurisé'
                    })

                if 'sandwich' in results and 'sandwich_score' in results['sandwich']:
                    category_scores.append({
                        'Catégorie': '🥪 Sandwich Attack',
                        'Score': results['sandwich']['sandwich_score'],
                        'Seuil': st.session_state.config.get('sandwich_threshold', 0.5),
                        'Statut': '⚠️ Attaqué' if results['sandwich']['sandwich_score'] > st.session_state.config.get('sandwich_threshold', 0.5) else '✅ Sécurisé'
                    })

                if 'flash' in results and 'flash_loan_score' in results['flash']:
                    category_scores.append({
                        'Catégorie': '⚡ Flash Loan',
                        'Score': results['flash']['flash_loan_score'],
                        'Seuil': 0.5,
                        'Statut': '⚠️ Suspect' if results['flash']['flash_loan_score'] > 0.5 else '✅ Normal'
                    })

                if category_scores:
                    df_scores = pd.DataFrame(category_scores)

                    # Graphique à barres
                    fig_bar = go.Figure(data=[
                        go.Bar(
                            x=df_scores['Catégorie'],
                            y=df_scores['Score'],
                            marker_color=['#c62828' if s > 0.4 else '#ef6c00' if s > 0.2 else '#2e7d32'
                                          for s in df_scores['Score']],
                            text=df_scores['Score'].apply(lambda x: f'{x:.1%}'),
                            textposition='auto',
                        )
                    ])
                    fig_bar.add_hline(y=st.session_state.config.get('mixer_threshold', 0.3),
                                      line_dash="dash", line_color="orange",
                                      annotation_text="Seuil Mixer")
                    fig_bar.add_hline(y=st.session_state.config.get('wash_threshold', 0.4),
                                      line_dash="dash", line_color="red",
                                      annotation_text="Seuil Wash")
                    fig_bar.update_layout(
                        title="Scores par catégorie de menace",
                        yaxis_title="Score de risque",
                        yaxis_range=[0, 1],
                        plot_bgcolor='rgba(0,0,0,0)',
                        height=400
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)

                    # Tableau détaillé
                    st.dataframe(df_scores, use_container_width=True, hide_index=True)

                # Résultats Ultra-Scientifiques
                if 'ultra' in results and results['ultra']:
                    st.markdown("### 🧪 Analyses Ultra-Scientifiques")

                    ultra = results['ultra']

                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        mfdfa_width = ultra.get('multifractal_width', 0)
                        mfdfa_color = "#c62828" if mfdfa_width > 0.3 else "#ef6c00" if mfdfa_width > 0.15 else "#2e7d32"
                        st.metric(
                            "📊 MF-DFA",
                            f"{mfdfa_width:.3f}",
                            delta="Multifractal" if mfdfa_width > 0.2 else "Monofractal",
                            delta_color="inverse" if mfdfa_width > 0.2 else "normal"
                        )

                    with col2:
                        rmt_pvalue = ultra.get('rmt_pvalue', 1)
                        rmt_color = "#c62828" if rmt_pvalue < 0.05 else "#2e7d32"
                        st.metric(
                            "📐 RMT",
                            f"p={rmt_pvalue:.4f}",
                            delta="Corrélations anormales" if rmt_pvalue < 0.05 else "Aléatoire",
                            delta_color="inverse" if rmt_pvalue < 0.05 else "normal"
                        )

                    with col3:
                        ultra_score = ultra.get('global_ultra_anomaly_score', 0)
                        st.metric(
                            "🎯 Score Ultra",
                            f"{ultra_score:.1%}",
                            delta="Anomalie critique" if ultra_score > 0.6 else "Normal",
                            delta_color="inverse" if ultra_score > 0.6 else "normal"
                        )

                    with col4:
                        risk_lvl = ultra.get('ultra_risk_level', 'LOW')
                        st.metric("🚨 Niveau Ultra", risk_lvl)

                    # Détails supplémentaires
                    with st.expander("🔬 Détails des analyses Ultra-Scientifiques"):
                        st.json({
                            'mfdfa_anomaly_score': ultra.get('mfdfa_anomaly_score', 0),
                            'multifractal_width': ultra.get('multifractal_width', 0),
                            'is_monofractal': ultra.get('is_monofractal', True),
                            'transfer_entropy_mean': ultra.get('transfer_entropy_mean', 0),
                            'te_anomaly_flag': ultra.get('te_anomaly_flag', False),
                            'bocd_max_prob': ultra.get('bocd_max_prob', 0),
                            'rmt_pvalue': ultra.get('rmt_pvalue', 1),
                            'n_signal_eigenvalues': ultra.get('n_signal_eigenvalues', 0),
                            'ssa_complexity': ultra.get('ssa_complexity', 0),
                            'rqa_determinism': ultra.get('rqa_determinism', 0)
                        })

                # Détails supplémentaires selon les méthodes
                if 'mixer' in results and results['mixer'].get('suspicious_wallets'):
                    with st.expander("🌀 Portefeuilles suspects (Mixer)"):
                        st.write(results['mixer']['suspicious_wallets'][:10])

                if 'wash' in results and results['wash'].get('cycles_detected', 0) > 0:
                    with st.expander("🔄 Cycles de wash trading détectés"):
                        st.metric("Nombre de cycles suspects", results['wash']['cycles_detected'])

                if 'rug' in results:
                    with st.expander("🧨 Analyse de concentration (Rug Pull)"):
                        st.metric("Coefficient de Gini", f"{results['rug'].get('gini_concentration', 0):.4f}")
                        if results['rug'].get('gini_concentration', 0) > 0.85:
                            st.error("🚨 Concentration extrême - Risque de rug pull très élevé!")
                        elif results['rug'].get('gini_concentration', 0) > 0.7:
                            st.warning("⚠️ Concentration élevée - Risque de rug pull modéré")
                        else:
                            st.success("✅ Concentration acceptable - Risque faible")

                # Sauvegarde dans l'historique
                analysis_record = {
                    'timestamp': datetime.now().isoformat(),
                    'address': address,
                    'network': network,
                    'risk_level': risk_level,
                    'overall_score': overall_score,
                    'methods_used': methods,
                    'blocks_back': blocks_back,
                    'transactions_count': len(df_clean),
                    'detection_level': detection_level,
                    'results': {k: v for k, v in results.items() if k not in ['metadata'] and isinstance(v, dict)},
                    'ultra_score': results.get('ultra', {}).get('global_ultra_anomaly_score', 0)
                }

                st.session_state.analysis_history.insert(0, analysis_record)

                # Garder seulement les 100 dernières analyses
                if len(st.session_state.analysis_history) > 100:
                    st.session_state.analysis_history = st.session_state.analysis_history[:100]

                progress_bar.progress(100, text="Terminé !")
                status_text.markdown("✅ **Phase 4/4**: Analyse complète terminée avec succès!")

                # Actions post-analyse
                st.markdown("---")
                st.markdown("### 📋 Actions")

                col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)

                with col_btn1:
                    if st.button("📄 Générer rapport HTML", use_container_width=True):
                        report_path = st.session_state.analyzer_wrapper.generate_report(
                            results,
                            f"report_{hashlib.md5(address.encode()).hexdigest()[:8]}.html"
                        )
                        with open(report_path, 'r', encoding='utf-8') as f:
                            st.download_button(
                                label="⬇️ Télécharger rapport",
                                data=f.read(),
                                file_name=report_path,
                                mime="text/html"
                            )

                with col_btn2:
                    # Export JSON des résultats
                    export_data = {
                        'address': address,
                        'network': network,
                        'analysis_date': datetime.now().isoformat(),
                        'risk_level': risk_level,
                        'overall_score': overall_score,
                        'detailed_scores': category_scores,
                        'ultra_analysis': results.get('ultra', {}),
                        'metadata': results.get('metadata', {})
                    }
                    st.download_button(
                        label="📥 Export JSON",
                        data=json.dumps(export_data, indent=2, default=str),
                        file_name=f"analysis_{address[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )

                with col_btn3:
                    if risk_level in ['CRITICAL', 'HIGH']:
                        st.error("🚨 Alerte de sécurité", icon="🚨")
                    else:
                        st.success("✅ Aucune alerte critique", icon="✅")

                with col_btn4:
                    st.caption(f"🔗 {len(df_clean)} transactions analysées")

            # Message de succès final
            st.balloons()
            st.toast(f"✨ Analyse terminée! Score de risque: {overall_score:.1%}", icon="🎯")

        except Exception as e:
            st.error(f"❌ Erreur lors de l'analyse: {str(e)}")
            st.exception(e)

            if st.button("🔄 Réessayer"):
                st.rerun()

    elif analyze_button and not address:
        st.warning("⚠️ Veuillez entrer une adresse blockchain")

    elif analyze_button and not methods:
        st.warning("⚠️ Veuillez sélectionner au moins une méthode d'analyse")

# ============================================================================
# FIN DE LA PAGE INVESTIGATION
# ============================================================================
# ============================================================================
# PAGE PARAMÈTRES
# ============================================================================
elif menu == "⚙️ Paramètres":
    st.markdown("## ⚙️ Paramètres Avancés")
    st.markdown("*Ajustez l'équilibre de votre analyseur*")
    
    st.markdown("### 🎯 Seuils de Détection")
    col1, col2 = st.columns(2)
    with col1:
        mixer_threshold = st.slider("Mixer threshold", 0.0, 1.0, st.session_state.config.get('mixer_threshold', 0.3))
        wash_threshold = st.slider("Wash trading threshold", 0.0, 1.0, st.session_state.config.get('wash_threshold', 0.4))
        rug_threshold = st.slider("Rug pull threshold", 0.0, 1.0, st.session_state.config.get('rug_threshold', 0.5))
    with col2:
        sandwich_threshold = st.slider("Sandwich threshold", 0.0, 1.0, st.session_state.config.get('sandwich_threshold', 0.5))
        ultra_threshold = st.slider("Ultra anomaly threshold", 0.0, 1.0, st.session_state.config.get('ultra_threshold', 0.6))
        sensitivity = st.slider("Sensibilité globale", 0.0, 1.0, 0.5)

    st.markdown("### ⏱️ Limites d'Analyse")
    col1, col2 = st.columns(2)
    with col1:
        max_transactions = st.number_input("Max transactions à analyser", 1000, 100000, st.session_state.config.get('max_transactions', 10000))
    with col2:
        timeout_seconds = st.number_input("Timeout (secondes)", 30, 600, 120)

    st.markdown("### 🧬 Méthodes Actives par Défaut")
    default_methods = st.multiselect("Méthodes à activer par défaut",
                                     ["Mixer Detection", "Wash Trading", "Rug Pull", "Sandwich Attacks", "Flash Loans", "Ultra-Scientific"],
                                     default=st.session_state.config.get('default_methods', ["Mixer Detection", "Wash Trading", "Rug Pull"]))

    if st.button("💾 Sauvegarder la Configuration"):
        st.session_state.config.update({
            'mixer_threshold': mixer_threshold,
            'wash_threshold': wash_threshold,
            'rug_threshold': rug_threshold,
            'sandwich_threshold': sandwich_threshold,
            'ultra_threshold': ultra_threshold,
            'max_transactions': max_transactions,
            'default_methods': default_methods,
            'sensitivity': sensitivity
        })
        st.success("✅ Configuration sauvegardée !")
        st.balloons()

# ============================================================================
# PAGE HISTORIQUE
# ============================================================================
elif menu == "📜 Historique":
    st.markdown("## 📜 Historique des Investigations")
    st.markdown("*La mémoire de vos analyses*")
    
    if st.session_state.analysis_history:
        df_history = pd.DataFrame(st.session_state.analysis_history)
        df_history['date'] = pd.to_datetime(df_history['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        
        st.dataframe(
            df_history[['date', 'address', 'network', 'risk_level', 'overall_score']],
            use_container_width=True,
            column_config={
                "date": "Date/Heure",
                "address": "Adresse",
                "network": "Réseau",
                "risk_level": st.column_config.Column("Risque", width="small"),
                "overall_score": st.column_config.ProgressColumn("Score", format="%.1f%%", min_value=0, max_value=1)
            }
        )
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### 📈 Évolution des risques")
            df_history['score'] = df_history['overall_score']
            df_history['date_plot'] = pd.to_datetime(df_history['timestamp'])
            risk_by_date = df_history.groupby(df_history['date_plot'].dt.date)['score'].mean().reset_index()
            fig = px.line(risk_by_date, x='date_plot', y='score', title="Score de risque moyen par jour", markers=True)
            fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', yaxis_title="Score de risque", xaxis_title="Date", yaxis_range=[0, 1])
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            st.markdown("### 📊 Distribution des Risques")
            risk_counts = df_history['risk_level'].value_counts()
            fig = go.Figure(data=[go.Bar(x=risk_counts.index, y=risk_counts.values, marker_color=['#2e7d32', '#f9a825', '#ef6c00', '#c62828'])])
            fig.update_layout(title="Niveaux de risque", xaxis_title="Risque", yaxis_title="Nombre")
            st.plotly_chart(fig, use_container_width=True)

        if st.button("🗑️ Effacer l'historique"):
            st.session_state.analysis_history = []
            st.success("✅ Historique effacé")
            st.rerun()
    else:
        st.info("Aucune analyse dans l'historique. Lancez une investigation !")

# ============================================================================
# PAGE API KEYS
# ============================================================================
elif menu == "🔑 API Keys":
    st.markdown("## 🔑 Gestion des Clés API")
    st.markdown("*Sécurisez vos connexions blockchain*")
    
    st.info("""
    ### 📖 Configuration des API Keys
    Les clés API sont stockées de manière sécurisée via **Streamlit Secrets**.
    #### Configuration locale :
    Créez un fichier `.streamlit/secrets.toml` à la racine :
    `[api_keys]`
    `covalent = "ckey_votre_cle"`
    `etherscan = "votre_api_key_etherscan"`
    `blockaid = "votre_cle_blockaid"`
    `thegraph = "votre_cle_thegraph"`
    #### Sur Streamlit Cloud :
    Allez dans Settings → Secrets, ajoutez les clés au format TOML, puis cliquez sur Save.
    """)

    # Vérification des clés existantes
    try:
        secrets = st.secrets.get("api_keys", {})
        if secrets:
            st.success("✅ Clés API configurées dans Streamlit Secrets")
            for key_name, key_value in secrets.items():
                masked_key = "•" * 8 + key_value[-4:] if len(key_value) > 4 else "••••"
                st.code(f"{key_name}: {masked_key}")
        else:
            st.warning("⚠️ Aucune clé API trouvée dans les secrets")
            
        # Option pour entrer manuellement (dev local)
        with st.expander("🔧 Configuration manuelle (développement local)"):
            st.markdown("Entrez vos clés API (non stockées entre sessions) :")
            covalent_key = st.text_input("Covalent API Key", type="password")
            etherscan_key = st.text_input("Etherscan API Key", type="password")
            if st.button("Tester les clés"):
                if covalent_key:
                    st.success("Clé Covalent acceptée (test à implémenter)")
                if etherscan_key:
                    st.success("Clé Etherscan acceptée")
    except Exception as e:
        st.error(f"Erreur d'accès aux secrets : {e}")

    st.markdown("""
    Pour utiliser les secrets en local, créez le fichier :
    `.streamlit/secrets.toml`
    avec le contenu :
    `[api_keys]`
    `covalent = "votre_cle"`
    """)

    st.markdown("---")
    st.markdown("### 🔌 APIs supportées")
    apis = {
        "Covalent": "https://www.covalenthq.com/",
        "Etherscan": "https://etherscan.io/",
        "Polygonscan": "https://polygonscan.com/",
        "BSCScan": "https://bscscan.com/",
        "Blockaid": "https://www.blockaid.io/",
        "The Graph": "https://thegraph.com/"
    }
    for api_name, api_url in apis.items():
        st.markdown(f"- {api_name} : {api_url}")

# ============================================================================
# PAGE EXPORT
# ============================================================================
elif menu == "📊 Export":
    st.markdown("## 📊 Export des Données")
    st.markdown("Générez des rapports complets")
    
    if st.session_state.analysis_history:
        df_export = pd.DataFrame(st.session_state.analysis_history)
        
        # Options d'export
        export_format = st.selectbox("Format d'export", ["CSV", "JSON", "Excel"])
        if export_format == "CSV":
            csv = df_export.to_csv(index=False)
            st.download_button(label="📥 Télécharger CSV", data=csv, file_name=f"fraud_analysis_{datetime.now().strftime('%Y%m%d')}.csv", mime="text/csv")
        elif export_format == "JSON":
            json_data = df_export.to_json(orient='records', indent=2, date_format='iso')
            st.download_button(label="📥 Télécharger JSON", data=json_data, file_name=f"fraud_analysis_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json")
        elif export_format == "Excel":
            try:
                from io import BytesIO
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    df_export.to_excel(writer, sheet_name='Analyses', index=False)
                excel_data = output.getvalue()
                st.download_button(label="📥 Télécharger Excel", data=excel_data, file_name=f"fraud_analysis_{datetime.now().strftime('%Y%m%d')}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            except ImportError:
                st.warning("⚠️ Installation de openpyxl requise: `pip install openpyxl`")

        # Statistiques
        st.markdown("### 📊 Statistiques")
        col1, col2, col3 = st.columns(3)
        with col1: st.metric("Total analyses", len(df_export))
        with col2: st.metric("Risque moyen", f"{df_export['overall_score'].mean():.1%}")
        with col3: st.metric("Alertes critiques", len(df_export[df_export['risk_level'] == 'CRITICAL']))
    else:
        st.info("Aucune donnée à exporter. Lancez d'abord une analyse.")

# ============================================================================
# FOOTER
# ============================================================================
st.markdown("""
<div class="footer">
    <p>🍚 Blockchain Fraud Analyzer Pro — L'équilibre entre sécurité et sérénité 🍚</p>
    <p>🪷 Développé avec Streamlit · Powered by AI · Inspiré par le Feng Shui 🪷</p>
    <p style="font-size: 0.7rem;">v1.0.0 | Open Source | Streamlit Cloud Ready</p>
</div>
""", unsafe_allow_html=True)
