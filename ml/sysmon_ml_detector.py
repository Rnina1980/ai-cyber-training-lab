import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

# ============================
#   LOAD AND PREPARE DATA
# ============================

def load_sysmon_json(path):
    """Load Sysmon JSON logs exported from EvtxECmd."""
    with open(path, encoding="utf-8-sig") as f:
        logs = [json.loads(line) for line in f]
    return pd.json_normalize(logs)

def prepare_process_creation(df):
    """Filter only Sysmon Process Creation (Event ID = 1) and combine text fields."""
    proc_df = df[df["EventId"] == 1].copy()

    proc_df["combined"] = (
        proc_df["PayloadData1"].astype(str) + " " +
        proc_df["PayloadData2"].astype(str) + " " +
        proc_df["PayloadData4"].astype(str) + " " +
        proc_df["PayloadData6"].astype(str)
    )

    # Auto-label suspicious entries based on MITRE techniques
    proc_df["label"] = proc_df["PayloadData2"].str.contains(
        "T1047|T1059|T1543|T1021|T1003", na=False
    ).astype(int)

    return proc_df

# ============================
#      TRAIN MODEL
# ============================

def train_model(proc_df):
    X_train, X_test, y_train, y_test = train_test_split(
        proc_df["combined"], proc_df["label"], test_size=0.3, random_state=42
    )

    model = Pipeline([
        ("vectorizer", CountVectorizer()),
        ("clf", RandomForestClassifier(n_estimators=200))
    ])

    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    print("\n==================================")
    print("        MODEL PERFORMANCE")
    print("==================================")
    print(classification_report(y_test, preds))

    return model

# ============================
#     RUN DETECTIONS
# ============================

def run_predictions(model, proc_df):
    proc_df["prediction"] = model.predict(proc_df["combined"])
    print("\n==================================")
    print("         SAMPLE PREDICTIONS")
    print("==================================")
    print(proc_df[["TimeCreated", "PayloadData2", "prediction"]].head(20))

# ============================
#           MAIN
# ============================

if __name__ == "__main__":
    print("Loading Sysmon logs...")
    df = load_sysmon_json("../data/sysmon.json")

    print("Preparing process creation events...")
    proc_df = prepare_process_creation(df)

    print("Training detection model...")
    model = train_model(proc_df)

    print("Running final predictions...")
    run_predictions(model, proc_df)

    print("\nDone.")
