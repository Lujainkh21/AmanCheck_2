from pathlib import Path
import sqlite3, joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from database import DATABASE_PATH
BASE_DIR=Path(__file__).resolve().parent
MODEL_PATH=BASE_DIR/"models"/"content_risk_model.pkl"
FEATURES=["credential_abuse","data_destination","social_engineering","suspicious_behavior","context_inconsistency","has_password","has_otp","has_identity","has_card","has_cvv","has_expiry","redirect_count","iframe_count","hidden_inputs_count","hidden_forms_count"]

def train_content_model():
    with sqlite3.connect(DATABASE_PATH) as connection:
        data=pd.read_sql_query(f"SELECT {', '.join(FEATURES)}, classification FROM scans WHERE classification IN ('legitimate','suspicious')",connection)
    data=data.drop_duplicates(); counts=data["classification"].value_counts()
    print("Reviewed records:",len(data)); print(counts)
    if counts.get("legitimate",0)<20 or counts.get("suspicious",0)<20:
        raise RuntimeError("يلزم 20 سجلًا شرعيًا و20 سجلًا مشبوهًا على الأقل بعد المراجعة")
    X=data[FEATURES]; y=data["classification"].map({"legitimate":0,"suspicious":1})
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.20,random_state=42,stratify=y)
    model=RandomForestClassifier(n_estimators=200,max_depth=10,class_weight="balanced",random_state=42)
    model.fit(X_train,y_train); predictions=model.predict(X_test)
    print(classification_report(y_test,predictions,target_names=["Legitimate","Suspicious"],zero_division=0))
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({"model":model,"features":FEATURES,"labels":{0:"legitimate",1:"suspicious"},"source":"amancheck.db reviewed scans"},MODEL_PATH)
    print("Content model saved to:",MODEL_PATH)
if __name__=="__main__": train_content_model()
