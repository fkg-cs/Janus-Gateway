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
# Cerca i file nella cartella corrente in cui si trova lo script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)
INPUT_FILE = os.path.join(PARENT_DIR, "PromptDatasetGenerator", "janus_test_prompt_dataset_500new.csv")
OUTPUT_DIR = os.path.join(PARENT_DIR, "PromptDatasetGenerator")
OUTPUT_CSV = os.path.join(BASE_DIR, "janus_benchmark_results.csv")
OUTPUT_METRICS = os.path.join(BASE_DIR, "janus_metrics_report.txt")
OUTPUT_IMG = os.path.join(BASE_DIR, "janus_confusion_matrix.png")

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
        # Struttura del PayloadRequest di Pydantic
        payload = {
            "user_prompt": str(prompt_text),
            "document_text": None,
            "document_metadata": None
        }

        response = requests.post(JANUS_ENDPOINT, json=payload, timeout=120)  # Timeout alzato per Ollama

        if response.status_code == 200:
            data = response.json()
            # Legge il campo 'risk_level' restituito da RiskAnalysisResponse
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
    if not os.path.exists(INPUT_FILE):
        print(f"[!] File {INPUT_FILE} non trovato nella directory {BASE_DIR}!")
        return

    print("📊 Caricamento dataset...")
    df = pd.read_csv(INPUT_FILE)

    if "janus_category" not in df.columns:
        df["janus_category"] = None

    da_processare = df[df['janus_category'].isnull()].index.tolist()

    if not da_processare:
        print("✅ Tutti i prompt sono già stati processati! Calcolo le metriche...")
    else:
        print(f"🚀 Inizio scansione di {len(da_processare)} prompt tramite Janus Gateway...")
        print(f"📡 Connessione all'endpoint: {JANUS_ENDPOINT}")

        for idx in tqdm(da_processare):
            prompt = df.loc[idx, "prompt"]
            prediction = query_janus(prompt)
            df.loc[idx, "janus_category"] = prediction

            # Salva i progressi ogni 5 iterazioni (in caso Ollama rallenti o crashi)
            if idx % 5 == 0:
                df.to_csv(OUTPUT_CSV, index=False)

            time.sleep(0.1)

        df.to_csv(OUTPUT_CSV, index=False)
        print(f"💾 Dataset con predizioni salvato in: {OUTPUT_CSV}\n")

    calculate_metrics(df)


# ==========================================
# 4. CALCOLO METRICHE E SALVATAGGIO
# ==========================================
def calculate_metrics(df):
    print("\n" + "=" * 50)
    print("📈 RISULTATI DELLA VALIDAZIONE")
    print("=" * 50 + "\n")

    # Rimuove gli errori di rete per non inquinare la statistica
    df_clean = df[~df['janus_category'].isin(["ERROR", "TIMEOUT/ERROR", None])].copy()

    if df_clean.empty:
        print("❌ Nessun dato valido per generare le metriche (tutti errori o non processati).")
        return

    y_true = df_clean['category']
    y_pred = df_clean['janus_category']

    # Calcolo Accurancy
    acc = accuracy_score(y_true, y_pred)
    acc_text = f"🎯 Accuratezza Globale (Accuracy): {acc:.4f} ({acc * 100:.2f}%)"
    print(acc_text + "\n")

    # Classification Report
    print("📋 Classification Report:")
    report_str = classification_report(y_true, y_pred, labels=CLASS_ORDER, zero_division=0)
    print(report_str)

    # --- SALVATAGGIO REPORT IN FILE DI TESTO ---
    with open(OUTPUT_METRICS, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("REPORT METRICHE JANUS GATEWAY\n")
        f.write("=" * 50 + "\n\n")
        f.write(acc_text + "\n\n")
        f.write("Classification Report:\n")
        f.write(report_str)
    print(f"📝 File delle metriche salvato in: {OUTPUT_METRICS}")

    # --- GENERAZIONE E SALVATAGGIO MATRICE DI CONFUSIONE ---
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