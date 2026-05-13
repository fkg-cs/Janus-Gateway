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

    print("\n" + "=" * 50)
    print("📈 CLASSIFICATION REPORT")
    print("=" * 50 + "\n")

    # Stampa il report a video
    report = classification_report(y_true, y_pred, labels=class_order, zero_division=0)
    print(report)

    # Genera la matrice di confusione
    print("\n🎨 Generazione del grafico della Matrice di Confusione in corso...")
    cm = confusion_matrix(y_true, y_pred, labels=class_order)

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_order, yticklabels=class_order)

    plt.title('Confusion Matrix - Janus Gateway Evaluation', fontsize=16, pad=20)
    plt.ylabel('True Risk Class (Ground Truth)', fontsize=12, labelpad=15)
    plt.xlabel('Predicted Risk Class (Janus Output)', fontsize=12, labelpad=15)

    plt.tight_layout()

    # Salva il file nella stessa cartella in cui si trova il tuo CSV
    output_dir = os.path.dirname(csv_path)
    output_filename = os.path.join(output_dir, "confusion_matrix_report.png")

    plt.savefig(output_filename, dpi=300)
    print(f"✅ Matrice di confusione salvata in: {output_filename}")

    # Mostra l'immagine a schermo
    plt.show()


if __name__ == "__main__":
    # Inserisci qui il percorso del tuo file.
    # La 'r' prima delle virgolette (raw string) impedisce a Python di leggere \U come errore.
    MIO_FILE_CSV = r"C:\Users\franc\Desktop\temp tesi mag\csv_generated\MERGED.csv"
    generate_report(MIO_FILE_CSV)