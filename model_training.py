import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load the network traffic data
data = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')


features = [' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',' Fwd Packet Length Max']


X = data[features]


# Train the Isolation Forest model
model = IsolationForest(contamination=0.01, random_state=42)
# model.fit(data)

X = data[features]
print(X.dtypes)  # This should show only int or float types
model.fit(X) 

# Save the trained model to disk
joblib.dump(model, 'anomaly_model.pkl')

print("Model trained and saved as anomaly_model.pkl")
