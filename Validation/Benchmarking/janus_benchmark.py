import pandas as pd
import requests
import time
import os
from tqdm import tqdm
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. CONFIGURAZIONE
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)
INPUT_FILE = os.path.join(PARENT_DIR, "PromptDatasetGenerator", "janus_test_prompt_dataset_5000_newgen2.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "janus_benchmark_results_newgen5000.csv")
OUTPUT_METRICS = os.path.join(BASE_DIR, "janus_metrics_report_newgen5000.txt")
OUTPUT_IMG = os.path.join(BASE_DIR, "janus_confusion_matrix_newgen5000.png")

# Endpoint letto dal backend FastAPI (rotta /api/v1/analyze)
JANUS_ENDPOINT = "http://localhost:8000/api/v1/analyze"

# Ordine gerarchico delle classi per la matrice di confusione
CLASS_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN"]


# ==========================================
# 2. FUNZIONE DI INTERROGAZIONE A JANUS
# ==========================================
def query_janus(prompt_text):
    """
    Invia il prompt a Janus e restituisce SOLO la classe predetta (risk_level).
    """
    try:
        payload = {
            "user_prompt": str(prompt_text),
            "document_text": None,
            "document_metadata": None
        }

        response = requests.post(JANUS_ENDPOINT, json=payload, timeout=120)

        if response.status_code == 200:
            data = response.json()
            predicted_class = data.get("risk_level", "ERROR").strip().upper()
            return predicted_class
        else:
            print(f"\n[!] Errore API Janus HTTP {response.status_code}")
            return "ERROR"

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Connessione a Janus fallita: {e}")
        return "TIMEOUT/ERROR"


# ==========================================
# 3. ESECUZIONE DEL BENCHMARK
# ==========================================
def run_benchmark():
    # 1. LOGICA DI RIPRESA: Controlla prima se c'è un file di salvataggio
    if os.path.exists(OUTPUT_CSV):
        print(f"🔄 Trovato salvataggio precedente. Riprendo da: {OUTPUT_CSV}")
        df = pd.read_csv(OUTPUT_CSV)
    elif os.path.exists(INPUT_FILE):
        print(f"📊 Caricamento dataset originale da: {INPUT_FILE}")
        df = pd.read_csv(INPUT_FILE)
    else:
        print(f"[!] Nessun file di input trovato! Assicurati che esista {INPUT_FILE}")
        return

    # Inizializza la colonna se non esiste
    if "janus_category" not in df.columns:
        df["janus_category"] = None

    # 2. LOGICA DI FILTRAGGIO: Identifica righe nulle, vuote o con ERRORI
    invalid_values = ["ERROR", "TIMEOUT/ERROR", ""]
    mask = df['janus_category'].isnull() | df['janus_category'].isin(invalid_values)
    da_processare = df[mask].index.tolist()

    if not da_processare:
        print("✅ Tutti i prompt sono già stati processati con successo! Calcolo le metriche...")
    else:
        print(f"🚀 Inizio scansione di {len(da_processare)} prompt (nuovi o in errore)...")
        print(f"📡 Connessione all'endpoint: {JANUS_ENDPOINT}")

        for idx in tqdm(da_processare):
            prompt = df.loc[idx, "prompt"]
            prediction = query_janus(prompt)
            df.loc[idx, "janus_category"] = prediction

            # Salva i progressi ogni 5 iterazioni
            if idx % 5 == 0:
                df.to_csv(OUTPUT_CSV, index=False)

            time.sleep(0.1)

        # Salvataggio finale a fine ciclo
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"💾 Dataset aggiornato salvato in: {OUTPUT_CSV}\n")

    calculate_metrics(df)


# ==========================================
# 4. CALCOLO METRICHE E SALVATAGGIO
# ==========================================
def calculate_metrics(df):
    print("\n" + "=" * 50)
    print("📈 RISULTATI DELLA VALIDAZIONE")
    print("=" * 50 + "\n")

    # Rimuove righe che sono *ancora* in errore per il calcolo delle metriche
    df_clean = df[~df['janus_category'].isin(["ERROR", "TIMEOUT/ERROR", None, ""])].copy()

    if df_clean.empty:
        print("❌ Nessun dato valido per generare le metriche (tutti errori o non processati).")
        return

    y_true = df_clean['category']
    y_pred = df_clean['janus_category']

    acc = accuracy_score(y_true, y_pred)
    acc_text = f"🎯 Accuratezza Globale (Accuracy): {acc:.4f} ({acc * 100:.2f}%)"
    print(acc_text + "\n")

    print("📋 Classification Report:")
    report_str = classification_report(y_true, y_pred, labels=CLASS_ORDER, zero_division=0)
    print(report_str)

    # Salvataggio report testuale
    with open(OUTPUT_METRICS, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("REPORT METRICHE JANUS GATEWAY\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Righe processate con successo: {len(df_clean)} / {len(df)}\n")
        f.write(acc_text + "\n\n")
        f.write("Classification Report:\n")
        f.write(report_str)
    print(f"📝 File delle metriche salvato in: {OUTPUT_METRICS}")

    # Matrice di confusione
    cm = confusion_matrix(y_true, y_pred, labels=CLASS_ORDER)

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=CLASS_ORDER, yticklabels=CLASS_ORDER)

    plt.title('Confusion Matrix - Janus Gateway Evaluation', fontsize=16, pad=20)
    plt.ylabel('True Risk Class (Ground Truth)', fontsize=12, labelpad=15)
    plt.xlabel('Predicted Risk Class (Janus Output)', fontsize=12, labelpad=15)

    plt.tight_layout()
    plt.savefig(OUTPUT_IMG, dpi=300)
    print(f"🖼️ Matrice di confusione salvata in: {OUTPUT_IMG}")

    plt.show()


if __name__ == "__main__":
    run_benchmark()