import json
from stix2 import MemoryStore, Filter  # <-- Aggiunto Filter qui


def load_mitre_atlas():
    print("Caricamento Knowledge Base MITRE ATLAS...")
    filepath = "../../knowledge_base/mitre_atlas.json"

    # Carichiamo il file nel MemoryStore della libreria stix2
    store = MemoryStore()
    store.load_from_file(filepath)

    # Estraiamo tutte le Tecniche di Attacco usando stix2.Filter
    techniques = store.query([
        Filter("type", "=", "attack-pattern")
    ])

    print(f"✅ Ingestione completata: Trovate {len(techniques)} tecniche ATLAS.")


    for t in techniques:

        # Attenzione: alcune tecniche potrebbero non avere external_references, gestiamo l'eccezione
        if hasattr(t, "external_references"):
            external_id = next((ext.external_id for ext in t.external_references if ext.source_name == "mitre-atlas"),
                               None)
            if external_id == "AML.T0051":
                print(f"\n🔍 Trovata Tecnica Target:")
                print(f"ID: {external_id}")
                print(f"Nome: {t.name}")
                print(f"Descrizione: {t.description}...")
                break


if __name__ == "__main__":
    load_mitre_atlas()