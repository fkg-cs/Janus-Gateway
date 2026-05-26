import os
import requests
import yaml
from stix2 import MemoryStore

# Calcola il percorso corretto (due cartelle indietro: backend/engines/..)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
STIX_PATH = os.path.join(BASE_DIR, "knowledge_base", "mitre_atlas.json")
YAML_PATH = os.path.join(BASE_DIR, "knowledge_base", "mitre_atlas.yaml")
OWASP_PATH = os.path.join(BASE_DIR, "knowledge_base", "owasp_llm_kb.json")

ATLAS_STIX_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

def update_atlas_knowledge_base():
    print("⏳ Controllo aggiornamenti MITRE ATLAS in corso...")
    try:
        res_stix = requests.get(ATLAS_STIX_URL, timeout=10)
        res_stix.raise_for_status()
        with open(STIX_PATH, "w", encoding="utf-8") as f:
            f.write(res_stix.text)
        print("✅ Struttura STIX aggiornata con successo.")
    except Exception as e:
        print(f"⚠️ Impossibile scaricare STIX. Uso cache locale. Errore: {e}")

    try:
        res_yaml = requests.get(ATLAS_YAML_URL, timeout=10)
        res_yaml.raise_for_status()
        with open(YAML_PATH, "w", encoding="utf-8") as f:
            f.write(res_yaml.text)
        print("✅ Database YAML aggiornato con successo.")
    except Exception as e:
        print(f"⚠️ Impossibile scaricare YAML. Uso cache locale. Errore: {e}")

# Inizializza i database in RAM
update_atlas_knowledge_base()

store = MemoryStore()
if os.path.exists(STIX_PATH):
    store.load_from_file(STIX_PATH)

atlas_yaml_db = {}
if os.path.exists(YAML_PATH):
    try:
        with open(YAML_PATH, "r", encoding="utf-8") as f:
            atlas_yaml_db = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Errore nel caricamento del file YAML: {e}")