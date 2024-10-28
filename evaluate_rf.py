import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from joblib import load
import sys


model_filename = "trained_rf.joblib"
model = load(model_filename)

#filename = "/home/fabio/Desktop/iotrim/piombo-framework/devices/echo-dot-3/windowed/2024-02-03_17.58.11_13.10.0.16.csv"
filename = sys.argv[1]
df = pd.read_csv(filename)


to_drop = ["time_window","domain","Label","server_ip","Device"]

x_eval = df.drop(to_drop,axis=1,errors="ignore")

y_pred = model.predict(x_eval)
df["Predicted"] = y_pred

if "Label" in df.columns:
    y_eval = df["Label"]
    print("Predicted accuracy",metrics.balanced_accuracy_score(y_pred,y_eval))

print(df.head())
for d in df["domain"].unique():
    print(f"Domain: {d}, Required: {df.loc[(df['domain']==d)&(df['Predicted']=='Required')].shape[0]}, Non-Required: {df.loc[(df['domain']==d)&(df['Predicted']=='Non-Required')].shape[0]}")

