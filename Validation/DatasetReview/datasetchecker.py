import pandas as pd
import os

# ==========================================
# CONFIGURAZIONE
# ==========================================
# Inserisci qui il nome del tuo file CSV
CSV_FILE = "janus_benchmark_results.csv"

# Mappatura degli input da tastiera alle categorie
CATEGORY_MAP = {
    'b': 'BENIGN',
    'l': 'LOW',
    'm': 'MEDIUM',
    'h': 'HIGH',
    'c': 'CRITICAL'
}

VALID_CATEGORIES = list(CATEGORY_MAP.values())


def fix_dataset_categories(file_path):
    if not os.path.exists(file_path):
        print(f"❌ File {file_path} non trovato!")
        return

    print(f"📂 Caricamento file: {file_path}")
    df = pd.read_csv(file_path)

    # Contatore per mostrare i progressi
    fixed_count = 0

    print("\n🔍 Inizio scansione della colonna 'category'...")
    print(
        "💡 Istruzioni: Inserisci B (Benign), L (Low), M (Medium), H (High), C (Critical). Premi 'Q' per salvare e uscire.")

    for index, row in df.iterrows():
        # Legge la categoria, gestendo eventuali valori Null/NaN
        current_cat = str(row['category']).strip().upper() if pd.notna(row['category']) else ""

        # Se la categoria non è tra quelle valide, chiede l'input all'utente
        if current_cat not in VALID_CATEGORIES:
            print("\n" + "-" * 60)
            print(f"🆔 ID: {row['id']}")
            print(f"⚠️ Categoria attuale non valida: '{current_cat}'")
            print(f"📝 PROMPT: \n{row['prompt']}")
            print("-" * 60)

            while True:
                user_input = input("👉 Assegna categoria [B/L/M/H/C] (o Q per uscire): ").strip().lower()

                if user_input == 'q':
                    print("\n💾 Salvataggio in corso e uscita anticipata...")
                    df.to_csv(file_path, index=False)
                    print("✅ File salvato con successo!")
                    return

                if user_input in CATEGORY_MAP:
                    new_category = CATEGORY_MAP[user_input]
                    df.at[index, 'category'] = new_category
                    fixed_count += 1
                    print(f"✔️ Assegnato: {new_category}")
                    break
                else:
                    print("❌ Input non valido! Usa solo B, L, M, H, C oppure Q per uscire.")

    # Salvataggio finale una volta terminate tutte le righe
    if fixed_count > 0:
        df.to_csv(file_path, index=False)
        print(f"\n🎉 Scansione completata! Corrette {fixed_count} righe.")
        print(f"💾 File aggiornato: {file_path}")
    else:
        print("\n✅ Tutte le righe hanno già una categoria valida. Nessuna modifica necessaria.")


if __name__ == "__main__":
    fix_dataset_categories(CSV_FILE)