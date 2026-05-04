# 🔗 Blockchain Fraud Analyzer Pro

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![Python](https://img.shields.io/badge/Python-3.9+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Intelligence Artificielle pour la Sécurité On-Chain**  
*L'équilibre parfait entre détection et sérénité*

[Installation](#installation) • [Utilisation](#utilisation) • [Configuration](#configuration) • [API](#api-keys) • [Déploiement](#déploiement)

</div>

---

## 🎯 Vision

**Blockchain Fraud Analyzer Pro** est une plateforme d'investigation on-chain qui combine des méthodes traditionnelles de détection de fraude avec des techniques **ultra-scientifiques** (MF-DFA, Transfer Entropy, RMT, ESN) pour identifier les comportements frauduleux les plus subtils.

> *"Dans le chaos de la blockchain, notre outil trouve l'harmonie."*

---

## ✨ Fonctionnalités

### 🔍 Détection Spécifique

| Type de Fraude | Méthode | Score de Confiance |
|----------------|---------|-------------------|
| 🌀 **Mixers** (Tornado Cash) | Pattern matching + Graph analysis | 0-100% |
| 🔄 **Wash Trading** | Cycle detection + Transfer Entropy | 0-100% |
| 🧨 **Rug Pull** | Gini concentration + BOCD | 0-100% |
| 🥪 **Sandwich Attacks** | MEV pattern detection | 0-100% |
| ⚡ **Flash Loans** | Anomaly detection + RMT | 0-100% |

### 🧪 Méthodes Ultra-Scientifiques

| Méthode | Application | Détecte |
|---------|-------------|---------|
| **MF-DFA** | Multifractal analysis | Patterns artificiels, lissage |
| **Transfer Entropy** | Causal information flow | Liens anormaux entre variables |
| **BOCD** | Bayesian changepoint | Changements de régime soudains |
| **RMT** | Random Matrix Theory | Corrélations non-naturelles |
| **ESN** | Echo State Network | Dynamique non-linéaire cachée |
| **SSA** | Singular Spectrum Analysis | Persistance spectrale anormale |
| **RQA** | Recurrence Analysis | Comportements trop réguliers |

### 📊 Interface Feng Shui

- **5 Éléments** : Navigation inspirée des principes du Feng Shui
- **Jauges énergétiques** : Visualisation intuitive des risques
- **Thème sombre apaisant** : Réduction de la fatigue visuelle
- **Animations fluides** : Feedback utilisateur en temps réel

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit Frontend                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Dashboard │ │Investigation│ │Historique│ │Paramètres│       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 FraudAnalyzerWrapper                         │
│         • Orchestration des analyses                         │
│         • Gestion des erreurs                                │
│         • Cache des résultats                                │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              BlockchainFraudAnalyzer (Core)                  │
│  • detect_mixer_patterns()   • detect_wash_trading()        │
│  • detect_rug_pull_signals() • ultra_scientific_detection() │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                  BlockchainConnector                         │
│    Covalent │ Etherscan │ Polygonscan │ BSCScan             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prérequis

```bash
Python 3.9+
pip 21.0+
Git
```

### Installation Locale

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-compte/blockchain-fraud-analyzer.git
cd blockchain-fraud-analyzer

# 2. Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les clés API (optionnel)
mkdir .streamlit
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Éditer .streamlit/secrets.toml avec vos clés

# 5. Lancer l'application
streamlit run app.py
```

### Dépendances

```txt
streamlit>=1.28.0
pandas>=2.0.0
numpy>=1.24.0
plotly>=5.17.0
requests>=2.31.0
scipy>=1.10.0
scikit-learn>=1.3.0
statsmodels>=0.14.0
matplotlib>=3.7.0
networkx>=3.0
openpyxl>=3.1.0
python-dotenv>=1.0.0
```

---

## 🔑 API Keys

### Services Supportés

| Service | Utilité | Obtention |
|---------|---------|-----------|
| **Covalent** | Données multi-chain | [covalenthq.com](https://www.covalenthq.com/) |
| **Etherscan** | Transactions Ethereum | [etherscan.io](https://etherscan.io/) |
| **Polygonscan** | Transactions Polygon | [polygonscan.com](https://polygonscan.com/) |
| **BSCScan** | Transactions BSC | [bscscan.com](https://bscscan.com/) |

### Configuration des Secrets

Créez `.streamlit/secrets.toml` :

```toml
[api_keys]
covalent = "ckey_votre_cle_ici"
etherscan = "votre_api_key_etherscan"
polygonscan = "votre_api_key_polygonscan"
bscscan = "votre_api_key_bscscan"

[blockchain]
default_network = "ethereum"
max_blocks_back = 50000
rate_limit_delay = 0.1

[analysis]
default_sensitivity = 0.5
enable_ultra_scientific = true
max_transactions = 10000
```

---

## 🚀 Utilisation

### 1. Lancement de l'application

```bash
streamlit run app.py
```

L'application sera accessible à : `http://localhost:8501`

### 2. Investigation d'une adresse

```python
# Exemple d'adresse à analyser
address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
network = "ethereum"

# Paramètres recommandés
blocks_back = 50000        # Derniers 50,000 blocs
detection_level = "Ultra"  # Analyse complète
methods = [
    "Mixer Detection",
    "Wash Trading",
    "Rug Pull",
    "Sandwich Attacks",
    "Ultra-Scientific"
]
```

### 3. Interprétation des Résultats

| Score | Niveau | Interprétation | Action |
|-------|--------|----------------|--------|
| 0-20% | 🟢 LOW | Comportement normal | Aucune action |
| 20-40% | 🟡 MEDIUM | Activité inhabituelle | Surveillance |
| 40-70% | 🟠 HIGH | Activité suspecte | Investigation |
| 70-100% | 🔴 CRITICAL | Fraude probable | Action immédiate |

---

## 📊 Exemples d'Analyse

### Cas 1: Détection de Mixer

```python
# Adresse ayant interagi avec Tornado Cash
address = "0x47ce0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"

# Résultats attendus
mixer_score: 0.78 (HIGH)
suspicious_wallets: ["0x...", "0x..."]
patterns: ["round_values", "hub_and_spokes"]
```

### Cas 2: Analyse Ultra-Scientifique

```python
# Détection de manipulation subtile
ultra_results = {
    'multifractal_width': 0.42,     # >0.3 = anomalie
    'transfer_entropy_mean': 0.35,  # >0.3 = causalité anormale
    'rmt_pvalue': 0.003,            # <0.05 = corrélations non-aléatoires
    'global_ultra_anomaly_score': 0.68
}
```

---

## 🧪 Mode DEBUG (Forensique)

Pour les investigations approfondies avec logs détaillés :

```bash
streamlit run app.py -- --debug
```

Ou dans le code :

```python
analyzer = BlockchainFraudAnalyzer(debug=True)
```

Les logs sont sauvegardés dans `logs/blockchain_fraud_forensic_YYYYMMDD_HHMMSS.log`

---

## 📁 Structure du Projet

```
blockchain_fraud_app/
├── app.py                          # Application Streamlit principale
├── blockchain_fraud_analyzer.py    # Core de détection (à copier)
├── requirements.txt                # Dépendances
├── README.md                       # Ce fichier
├── .streamlit/
│   ├── secrets.toml               # Clés API (ignoré par git)
│   ├── config.toml                # Configuration Streamlit
│   └── secrets.toml.example       # Template des secrets
├── utils/
│   ├── __init__.py
│   ├── blockchain_connector.py    # Connexion aux APIs
│   └── fraud_analyzer_wrapper.py  # Wrapper d'intégration
├── logs/                          # Logs forensiques
└── reports/                       # Rapports générés
```

---

## 🚢 Déploiement

### Streamlit Cloud (Recommandé)

1. **Pousser le code sur GitHub**
```bash
git add .
git commit -m "Initial commit"
git push origin main
```

2. **Connecter sur Streamlit Cloud**
   - Aller sur [share.streamlit.io](https://share.streamlit.io)
   - Cliquer "New app"
   - Sélectionner votre dépôt GitHub
   - Branche: `main`
   - Fichier principal: `app.py`

3. **Configurer les Secrets**
   - Aller dans `Settings → Secrets`
   - Ajouter le contenu de `.streamlit/secrets.toml`

4. **Déployer** 🚀

### Docker

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

```bash
docker build -t blockchain-fraud-analyzer .
docker run -p 8501:8501 blockchain-fraud-analyzer
```

### Heroku

```bash
# Procfile
web: streamlit run app.py --server.port=$PORT --server.address=0.0.0.0

# Déploiement
heroku create blockchain-fraud-analyzer
git push heroku main
heroku config:set STREAMLIT_SERVER_MAX_UPLOAD_SIZE=10
```

---

## 🔧 Configuration Avancée

### Ajustement des Seuils

```python
# Dans l'interface Paramètres
mixer_threshold: 0.3      # Seuil de suspicion mixer
wash_threshold: 0.4        # Seuil wash trading
rug_threshold: 0.5         # Seuil rug pull
ultra_threshold: 0.6       # Seuil ultra-scientific
```

### Optimisation des Performances

```python
# Pour les analyses de masse
use_sampling = True
max_transactions = 5000
blocks_back = 10000

# Pour les analyses forensiques
use_sampling = False
max_transactions = 50000
blocks_back = 500000
```

---

## 📈 Roadmap

- [ ] Support Solana et autres blockchains
- [ ] Analyse en temps réel (WebSocket)
- [ ] Modèle ML personnalisable
- [ ] API REST pour intégration externe
- [ ] Dashboard d'alertes push
- [ ] Export PDF des rapports
- [ ] Mode batch pour analyse de masse

---

## 🤝 Contribution

Les contributions sont les bienvenues !

```bash
# Fork le projet
# Créer une branche
git checkout -b feature/amazing-feature

# Commit les changements
git commit -m 'Add amazing feature'

# Push
git push origin feature/amazing-feature

# Ouvrir une Pull Request
```

---

## 📄 License

Distribué sous licence MIT. Voir `LICENSE` pour plus d'informations.

---

## 🙏 Remerciements

- **Streamlit** - Framework frontend exceptionnel
- **Covalent** - API blockchain de qualité
- **Etherscan** - Données on-chain fiables
- **Communauté** - Tests et retours précieux

---

## 📞 Support

| Canal | Lien |
|-------|------|
| Issues GitHub | [github.com/.../issues](https://github.com) |
| Documentation | [docs.blockchain-fraud-analyzer.io](https://docs.example.com) |
| Email | support@blockchain-fraud-analyzer.io |

---

## ⚖️ Avertissement Légal

Cet outil est fourni à des fins éducatives et d'investigation légitime. L'utilisateur est seul responsable de l'utilisation conforme aux lois applicables (AML, KYC, RGPD). L'outil ne constitue pas un avis juridique.

---

<div align="center">

**🍚 Blockchain Fraud Analyzer Pro — L'équilibre entre sécurité et sérénité 🍚**

*Développé avec 🧠 et 🧘 | Inspiré par le Feng Shui | Propulsé par l'IA*

[⬆ Retour en haut](#-blockchain-fraud-analyzer-pro)

</div>

---

## 📄 Fichier supplémentaire : `.streamlit/secrets.toml.example`

```toml
# ====================================================================
# BLOCKCHAIN FRAUD ANALYZER PRO - SECRETS TEMPLATE
# ====================================================================
# Copiez ce fichier vers .streamlit/secrets.toml et ajoutez vos clés
# NE JAMAIS COMMIT secrets.toml !

[api_keys]
# Covalent API (https://www.covalenthq.com/)
covalent = "ckey_votre_cle_covalent"

# Etherscan API (https://etherscan.io/)
etherscan = "votre_api_key_etherscan"

# Polygonscan API (https://polygonscan.com/)
polygonscan = "votre_api_key_polygonscan"

# BSCScan API (https://bscscan.com/)
bscscan = "votre_api_key_bscscan"

# Blockaid API (optionnel - https://www.blockaid.io/)
blockaid = "votre_cle_blockaid"

# The Graph API (optionnel - https://thegraph.com/)
thegraph = "votre_cle_thegraph"

[blockchain]
default_network = "ethereum"
max_blocks_back = 50000
rate_limit_delay = 0.1

[analysis]
default_sensitivity = 0.5
enable_ultra_scientific = true
max_transactions = 10000

# Seuils de détection
mixer_threshold = 0.3
wash_threshold = 0.4
rug_threshold = 0.5
sandwich_threshold = 0.5
ultra_threshold = 0.6

# Paramètres de coût (en USD)
cost_fn = 5000   # Coût d'une fraude manquée
cost_fp = 100    # Coût d'une fausse alerte
```
