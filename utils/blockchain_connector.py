"""
Blockchain Connector Module
Connexion aux APIs blockchain réelles
"""

import requests
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, List
from datetime import datetime
import time
import hashlib
import secrets

# URL unique de l'API Etherscan V2 (unifiée multi-chaînes)
ETHERSCAN_V2_BASE_URL = "https://api.etherscan.io/v2/api"

# Chain IDs V2 (https://docs.etherscan.io/supported-chains)
CHAIN_IDS = {
    'ethereum':  1,
    'polygon':   137,
    'bsc':       56,
    'avalanche': 43114,
    'arbitrum':  42161,
    'optimism':  10,
}


class BlockchainConnector:
    """Connecteur multi-blockchain pour les données on-chain"""
    
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.cache = {}
        self.rate_limit_delay = 0.1
        
    def get_transactions(self, address: str, network: str, 
                         blocks_back: int = 50000) -> pd.DataFrame:
        """
        Récupère les transactions d'une adresse sur un réseau donné.

        Args:
            address: Adresse blockchain (0x... ou nom ENS)
            network: ethereum, polygon, bsc, avalanche, arbitrum, optimism
            blocks_back: Nombre de blocs à analyser en arrière

        Returns:
            DataFrame avec les transactions
        """
        # Vérification du cache
        cache_key = f"{address}_{network}_{blocks_back}"
        if cache_key in self.cache:
            cache_time, cache_data = self.cache[cache_key]
            if (datetime.now() - cache_time).seconds < 300:  # Cache 5 minutes
                return cache_data
        
        # Conversion ENS si nécessaire
        if not address.startswith('0x') and '.' in address:
            address = self._resolve_ens(address, network)
        
        # Récupération selon le réseau
        if network == "ethereum":
            df = self._get_ethereum_transactions(address, blocks_back)
        elif network == "polygon":
            df = self._get_polygon_transactions(address, blocks_back)
        elif network == "bsc":
            df = self._get_bsc_transactions(address, blocks_back)
        elif network == "avalanche":
            df = self._get_avalanche_transactions(address, blocks_back)
        else:
            # Fallback sur Covalent API si disponible
            df = self._get_covalent_transactions(address, network, blocks_back)
        
        # Mise en cache
        self.cache[cache_key] = (datetime.now(), df)
        
        return df

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _etherscan_v2_get(self, chain_id: int, params: dict, timeout: int = 30) -> dict:
        """
        Effectue un appel GET vers l'endpoint unifié Etherscan API V2.
        Injecte automatiquement chainid et apikey.
        """
        api_key = self.api_keys.get('etherscan', '')
        full_params = {'chainid': chain_id, 'apikey': api_key, **params}
        time.sleep(self.rate_limit_delay)
        response = requests.get(ETHERSCAN_V2_BASE_URL, params=full_params, timeout=timeout)
        return response.json()

    def _resolve_ens(self, ens_name: str, network: str) -> str:
        """Résout un nom ENS en adresse via Etherscan API V2."""
        api_key = self.api_keys.get('etherscan', '')
        if api_key and network == 'ethereum':
            # V2 : endpoint unifié + chainid=1 (Ethereum)
            try:
                data = self._etherscan_v2_get(
                    chain_id=1,
                    params={'module': 'ens', 'action': 'lookup', 'name': ens_name},
                    timeout=10
                )
                if data.get('status') == '1':
                    return data.get('result', '')
            except Exception:
                pass
        
        # Adresse de démonstration (fallback)
        return f"0x{hashlib.md5(ens_name.encode()).hexdigest()[:40]}"

    def _get_ethereum_transactions(self, address: str, blocks_back: int) -> pd.DataFrame:
        """Récupère les transactions Ethereum via Etherscan API V2 (chainid=1)."""
        api_key = self.api_keys.get('etherscan', '')
        
        if not api_key:
            return self._generate_synthetic_data(address, 'ethereum', blocks_back)
        
        # Récupérer le dernier bloc  (V2 : chainid=1)
        data = self._etherscan_v2_get(
            chain_id=1,
            params={'module': 'proxy', 'action': 'eth_blockNumber'},
            timeout=10
        )
        latest_block = int(data.get('result', '0x0'), 16)
        start_block = max(0, latest_block - blocks_back)
        
        # Récupérer les transactions  (V2 : chainid=1)
        data = self._etherscan_v2_get(
            chain_id=1,
            params={
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': start_block,
                'endblock': 99999999,
                'sort': 'asc',
            }
        )
        
        if data.get('status') == '1':
            return self._process_transactions(data.get('result', []))
        else:
            return self._generate_synthetic_data(address, 'ethereum', blocks_back)
    
    def _get_polygon_transactions(self, address: str, blocks_back: int) -> pd.DataFrame:
        """
        Récupère les transactions Polygon via Etherscan API V2 (chainid=137).

        Migration V2 : l'URL Polygonscan (https://api.polygonscan.com/api) et sa clé
        dédiée sont remplacées par l'endpoint unifié avec chainid=137 et une clé
        Etherscan standard.
        """
        api_key = self.api_keys.get('etherscan', '')
        
        if not api_key:
            return self._generate_synthetic_data(address, 'polygon', blocks_back)
        
        data = self._etherscan_v2_get(
            chain_id=CHAIN_IDS['polygon'],
            params={
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'sort': 'asc',
            }
        )
        
        if data.get('status') == '1':
            return self._process_transactions(data.get('result', []))
        else:
            return self._generate_synthetic_data(address, 'polygon', blocks_back)
    
    def _get_bsc_transactions(self, address: str, blocks_back: int) -> pd.DataFrame:
        """
        Récupère les transactions BSC via Etherscan API V2 (chainid=56).

        Migration V2 : l'URL BSCScan (https://api.bscscan.com/api) et sa clé dédiée
        sont remplacées par l'endpoint unifié avec chainid=56 et une clé Etherscan
        standard.
        """
        api_key = self.api_keys.get('etherscan', '')
        
        if not api_key:
            return self._generate_synthetic_data(address, 'bsc', blocks_back)
        
        data = self._etherscan_v2_get(
            chain_id=CHAIN_IDS['bsc'],
            params={
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': 0,
                'endblock': 99999999,
                'sort': 'asc',
            }
        )
        
        if data.get('status') == '1':
            return self._process_transactions(data.get('result', []))
        else:
            return self._generate_synthetic_data(address, 'bsc', blocks_back)
    
    def _get_avalanche_transactions(self, address: str, blocks_back: int) -> pd.DataFrame:
        """Récupère les transactions Avalanche (simulation - API limitée)."""
        return self._generate_synthetic_data(address, 'avalanche', blocks_back)
    
    def _get_covalent_transactions(self, address: str, network: str, blocks_back: int) -> pd.DataFrame:
        """Récupère les transactions via Covalent API (non-Etherscan, inchangé)."""
        api_key = self.api_keys.get('covalent', '')
        
        if not api_key:
            return self._generate_synthetic_data(address, network, blocks_back)
        
        chain_id = CHAIN_IDS.get(network, 1)
        url = f"https://api.covalenthq.com/v1/{chain_id}/address/{address}/transactions_v2/"
        params = {
            'key': api_key,
            'quote-currency': 'USD',
            'block-signed-at-asc': 'true'
        }
        
        time.sleep(self.rate_limit_delay)
        response = requests.get(url, params=params, timeout=30)
        data = response.json()
        
        if data.get('error') is False:
            items = data.get('data', {}).get('items', [])
            return self._process_covalent_transactions(items)
        else:
            return self._generate_synthetic_data(address, network, blocks_back)
    
    def _process_transactions(self, txs: List[Dict]) -> pd.DataFrame:
        """Traite les transactions brutes en DataFrame normalisé."""
        processed = []
        
        for tx in txs:
            value_eth = float(tx.get('value', 0)) / 1e18
            gas_used = int(tx.get('gasUsed', 0))
            gas_price = int(tx.get('gasPrice', 0))
            
            processed.append({
                'tx_hash': tx.get('hash'),
                'block_number': int(tx.get('blockNumber', 0)),
                'from_address': tx.get('from'),
                'to_address': tx.get('to'),
                'tx_value_eth': value_eth,
                'gas_used': gas_used,
                'gas_price': gas_price,
                'timestamp': datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                'is_contract_call': len(tx.get('input', '')) > 2 and tx.get('input', '') != '0x'
            })
        
        return pd.DataFrame(processed)
    
    def _process_covalent_transactions(self, items: List[Dict]) -> pd.DataFrame:
        """Traite les transactions Covalent en DataFrame."""
        processed = []
        
        for item in items:
            processed.append({
                'tx_hash': item.get('tx_hash'),
                'block_number': item.get('block_height'),
                'from_address': item.get('from_address'),
                'to_address': item.get('to_address'),
                'tx_value_eth': item.get('value', 0) / 1e18,
                'gas_used': item.get('gas_spent', 0),
                'gas_price': item.get('gas_price', 0),
                'timestamp': datetime.fromisoformat(item.get('block_signed_at').replace('Z', '+00:00')),
                'is_contract_call': item.get('to_address', '').startswith('0x') and len(item.get('log_events', [])) > 0
            })
        
        return pd.DataFrame(processed)
    
    def _generate_synthetic_data(self, address: str, network: str, blocks_back: int) -> pd.DataFrame:
        """Génère des données synthétiques pour les tests (quand API non disponible)."""
        seed = int(hashlib.md5(f"{address}_{network}".encode()).hexdigest()[-8:], 16)
        np.random.seed(seed)
        
        n_transactions = min(np.random.poisson(50), 5000)
        
        data = []
        current_block = 19000000 if network == 'ethereum' else 40000000
        safe_blocks_back = min(blocks_back, 1_000_000)
        
        for i in range(n_transactions):
            data.append({
                'tx_hash': f"0x{hashlib.md5(f'{address}_{i}'.encode()).hexdigest()[:64]}",
                'block_number': current_block - np.random.randint(0, safe_blocks_back),
                'from_address': address if np.random.random() < 0.7 else f"0x{secrets.token_hex(20)}",
                'to_address': address if np.random.random() < 0.3 else f"0x{secrets.token_hex(20)}",
                'tx_value_eth': np.random.lognormal(0.5, 2.0),
                'gas_used': np.random.choice([21000, 65000, 150000, 200000]),
                'gas_price': np.random.randint(10, 200),
                'timestamp': datetime.now() - pd.Timedelta(days=np.random.randint(0, 90)),
                'is_contract_call': np.random.random() < 0.3
            })
        
        return pd.DataFrame(data)
