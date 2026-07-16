from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
BASE_DIR=Path(__file__).resolve().parent
DATASET_PATH=BASE_DIR/"AmanCheck_URL_Dataset.csv"
MODEL_PATH=BASE_DIR/"models"/"risk_model.pkl"
AI_FEATURES=["url_length","n_dots","n_hyphens","n_underline","n_slash","n_questionmark","n_equal","n_at","n_and","n_exclamation","n_space","n_tilde","n_comma","n_plus","n_asterisk","n_hashtag","n_dollar","n_percent","n_redirection"]

def load_dataset():
    if not DATASET_PATH.exists(): raise FileNotFoundError("لم يتم العثور على AmanCheck_URL_Dataset.csv")
    data=pd.read_csv(DATASET_PATH)
    required=AI_FEATURES+["classification"]
    missing=[c for c in required if c not in data.columns]
    if missing: raise ValueError("أعمدة ناقصة: "+", ".join(missing))
    data=data[required].drop_duplicates().copy()
    data["classification"]=data["classification"].astype(str).str.strip().str.lower()
    data=data[data["classification"].isin(["legitimate","suspicious"])].copy()
    for feature in AI_FEATURES: data[feature]=pd.to_numeric(data[feature],errors="coerce").fillna(0)
    return data

def train():
    data=load_dataset().sample(frac=1,random_state=42).reset_index(drop=True)
    print("إجمالي السجلات:",len(data)); print(data["classification"].value_counts())
    X=data[AI_FEATURES]; y=data["classification"].map({"legitimate":0,"suspicious":1})
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.20,random_state=42,stratify=y)
    model=RandomForestClassifier(n_estimators=250,max_depth=14,min_samples_split=4,min_samples_leaf=2,class_weight={0:1.8,1:1.0},random_state=42,n_jobs=-1)
    model.fit(X_train,y_train); predictions=model.predict(X_test)
    print("\nConfusion Matrix:"); print(confusion_matrix(y_test,predictions))
    print("\nClassification Report:"); print(classification_report(y_test,predictions,target_names=["Legitimate","Suspicious"],zero_division=0))
    importance=pd.DataFrame({"feature":AI_FEATURES,"importance":model.feature_importances_}).sort_values("importance",ascending=False)
    print("\nFeature Importance:"); print(importance.to_string(index=False))
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({"model":model,"features":AI_FEATURES,"labels":{0:"legitimate",1:"suspicious"},"dataset":"AmanCheck_URL_Dataset.csv"},MODEL_PATH)
    print("\nتم حفظ المودل في:",MODEL_PATH)
if __name__=="__main__": train()
