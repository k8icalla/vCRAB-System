import pandas as pd
import joblib
import mysql.connector
from sklearn.ensemble import RandomForestClassifier

# Connect to MySQL (adjust these settings if needed)
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  # or your root password
    database="vcrab_db"  # use your actual database name
)

# Read sensor data from the table
query = """
SELECT temperature, ph_level, tds_value, turbidity
FROM sensor_readings
WHERE temperature IS NOT NULL 
  AND ph_level IS NOT NULL 
  AND tds_value IS NOT NULL 
  AND turbidity IS NOT NULL
"""
df = pd.read_sql(query, conn)
conn.close()

# Add labels based on safe thresholds (can adjust as needed)
df["label"] = ((df["temperature"].between(25, 30)) &
               (df["ph_level"].between(6.5, 7.5)) &
               (df["tds_value"].between(400, 600)) &
               (df["turbidity"] < 2.5)).astype(int)

# Train model
X = df[["temperature", "ph_level", "tds_value", "turbidity"]]
y = df["label"]

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save model
joblib.dump(model, 'model_v1.7.0.pkl')


print("✅ Model trained on real sensor data and saved as ml_model.pkl")
