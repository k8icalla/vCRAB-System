import mysql.connector
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

# Connect to MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="vcrab_db"
)

# Query recent valid data
query = """
    SELECT temperature, ph_level, tds_value, turbidity
    FROM sensor_readings
    WHERE temperature IS NOT NULL AND ph_level IS NOT NULL 
      AND tds_value IS NOT NULL AND turbidity IS NOT NULL
"""
df = pd.read_sql(query, conn)
conn.close()

# Rule-based labeling
df["label"] = ((df["temperature"].between(25, 30)) &
               (df["ph_level"].between(6.5, 7.5)) &
               (df["tds_value"].between(400, 600)) &
               (df["turbidity"] < 2.5)).astype(int)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
X = df[["temperature", "ph_level", "tds_value", "turbidity"]]
y = df["label"]
model.fit(X, y)

# Save the model
joblib.dump(model, 'model_v1.7.0.pkl')

print("✅ Model retrained and saved.")
