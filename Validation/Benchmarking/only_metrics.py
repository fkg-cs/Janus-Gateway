import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix
import sys
import os


def generate_report(csv_path):
    if not os.path.exists(csv_path):
        print(f"❌ Errore: File '{csv_path}' non trovato.")
        sys.exit(1)

    print(f"📊 Caricamento dati da: {csv_path}")
    df = pd.read_csv(csv_path)

    # Pulizia dati: rimuove le righe non processate o con errori
    invalid_values = ["ERROR", "TIMEOUT/ERROR", ""]
    df_clean = df[~df['janus_category'].isnull() & ~df['janus_category'].isin(invalid_values)].copy()

    if df_clean.empty:
        print("❌ Errore: Nessun dato valido trovato nel CSV per l'analisi.")
        sys.exit(1)

    y_true = df_clean['category'].str.strip().str.upper()
    y_pred = df_clean['janus_category'].str.strip().str.upper()

    class_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN"]

    # ==========================================
    # 1. REPORT DI CLASSIFICAZIONE
    # ==========================================
    print("\n" + "=" * 50)
    print("📈 CLASSIFICATION REPORT")
    print("=" * 50 + "\n")
    print("CLASSIFICATION REPORT:\n")
    report = classification_report(y_true, y_pred, labels=class_order, zero_division=0)
    print(report)

    output_dir = os.path.dirname(csv_path)

    # ==========================================
    # 2. ANALISI DEI TEMPI E LATENZA (NOVITÀ)
    # ==========================================
    if 'elaboration_time' in df_clean.columns:
        # Converte i tempi in formato numerico ignorando eventuali errori
        df_clean['elaboration_time'] = pd.to_numeric(df_clean['elaboration_time'], errors='coerce')
        valid_times = df_clean['elaboration_time'].dropna()

        if not valid_times.empty:
            mean_time = valid_times.mean()
            p95_time = valid_times.quantile(0.95)

            print("\n" + "=" * 50)
            print("⏱️ ANALISI PRESTAZIONALE E LATENZA")
            print("=" * 50)
            print(f"Media dei Tempi (RTT): {mean_time:.2f} ms")
            print(f"95° Percentile (P95):  {p95_time:.2f} ms\n")

            # --- GRAFICO DELLA LATENZA ---
            print("🎨 Generazione del grafico della Latenza in corso...")
            plt.figure(figsize=(12, 6))

            # Scatter plot dei tempi per mostrare la distribuzione reale
            plt.plot(valid_times.values, marker='o', linestyle='', alpha=0.6, markersize=3, color='#1f77b4',
                     label='Tempo di Inferenza (ms)')

            # Linee per Media e 95° Percentile
            plt.axhline(y=mean_time, color='red', linestyle='-', linewidth=2, label=f'Media ({mean_time:.2f} ms)')
            plt.axhline(y=p95_time, color='orange', linestyle='--', linewidth=2, label=f'P95 ({p95_time:.2f} ms)')

            plt.title('Distribuzione della Latenza di Inferenza (Llama 3.1 8B)', fontsize=15, pad=15)
            plt.xlabel('Indice Richiesta nel Dataset', fontsize=12)
            plt.ylabel('Latenza in Millisecondi (ms)', fontsize=12)
            plt.legend(loc='upper right', fontsize=10)
            plt.grid(True, linestyle=':', alpha=0.7)
            plt.tight_layout()

            output_latency_filename = os.path.join(output_dir, "latenza_report.png")
            plt.savefig(output_latency_filename, dpi=300)
            print(f"✅ Grafico della latenza salvato in: {output_latency_filename}")
        else:
            print("⚠️ Nessun dato valido trovato nella colonna 'elaboration_time'.")

    # ==========================================
    # 3. MATRICE DI CONFUSIONE
    # ==========================================
    print("\n🎨 Generazione del grafico della Matrice di Confusione in corso...")
    cm = confusion_matrix(y_true, y_pred, labels=class_order)

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_order, yticklabels=class_order)

    plt.title('Confusion Matrix - Janus Gateway Evaluation', fontsize=16, pad=20)
    plt.ylabel('True Risk Class (Ground Truth)', fontsize=12, labelpad=15)
    plt.xlabel('Predicted Risk Class (Janus Output)', fontsize=12, labelpad=15)

    plt.tight_layout()

    output_cm_filename = os.path.join(output_dir, "confusion_matrix_report.png")
    plt.savefig(output_cm_filename, dpi=300)
    print(f"✅ Matrice di confusione salvata in: {output_cm_filename}")

    # ==========================================
    # 4. MOSTRA A SCHERMO TUTTI I GRAFICI
    # ==========================================
    print("\n🚀 Analisi completata! Chiusura script una volta chiuse le finestre dei grafici.")
    plt.show()


if __name__ == "__main__":
    # Inserisci qui il percorso del tuo file.
    MIO_FILE_CSV = r"C:\Users\franc\OneDrive - Università degli Studi di Bari\Tesi Magistrale GUARINI FRANCESCO\JanusGateway\Validation\Benchmarking\janus_benchmark_10000_FINAL.csv"
    generate_report(MIO_FILE_CSV)