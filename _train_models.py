import pandas as pd
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier

# --- 1. LOAD DATA ---
base_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(base_dir, "dataset_automotive.csv")

if not os.path.exists(csv_path):
    print("ERROR: 'dataset_automotive.csv' not found! Please run the pcap_to_csv script first.")
    exit()

print("Loading dataset...")
df = pd.read_csv(csv_path)
print(f"Original Data Size: {len(df)}")

# --- 2. DATA CLEANING & SAMPLING ---
# Drop duplicates & missing values
df.drop_duplicates(inplace=True)
df.dropna(inplace=True)

# We set the data to 2000000 to avoid tiring the computer and to get quick results.
TARGET_SIZE = 2000000 

if len(df) > TARGET_SIZE:
    print(f"\nOptimization: Dataset is too large ({len(df)}). Selecting random {TARGET_SIZE} samples...")
    df = df.sample(n=TARGET_SIZE, random_state=42)

print(f"Final Training Data Size: {len(df)}")

# --- 3. PREPARE DATA ---
feature_columns = ['DeltaTime', 'Length', 'Protocol']

X = df[feature_columns]
y = df['Label']

# Split Data (80% Train, 20% Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --- 4. DATA NORMALIZATION ---
# StandardScaler is crucial for KNN and Logistic Regression
scaler = StandardScaler()

# Fit on training data, transform both
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Data normalized successfully.\n")

# --- 5. DEFINE MODELS ---
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Decision Tree": DecisionTreeClassifier(),
    "Random Forest": RandomForestClassifier(n_estimators=50),
    "K-Nearest Neighbors (KNN)": KNeighborsClassifier(n_neighbors=5)
}

best_model = None
best_accuracy = 0.0
best_model_name = ""

# --- 6. TRAIN AND COMPARE MODELS ---
print("--- MODEL TRAINING STARTED ---")

for name, model in models.items():
    print(f"\nTraining: {name}...")
    
    # Train using SCALED data
    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"   -> {name} Accuracy: %{acc * 100:.2f}")
    
    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model
        best_model_name = name

print("-" * 30)
print(f"\n🏆 WINNER MODEL: {best_model_name}")
print(f"🏆 ACCURACY: %{best_accuracy * 100:.2f}")

print(f"\nDetailed Report for {best_model_name}:")
print(classification_report(y_test, best_model.predict(X_test_scaled), target_names=['Normal', 'Attack']))

# --- 7. SAVE MODEL AND SCALER ---
# Save the Model
model_filename = os.path.join(base_dir, "best_model.pkl")
joblib.dump(best_model, model_filename)

# Save the Scaler (CRITICAL for API)
scaler_filename = os.path.join(base_dir, "scaler.pkl")
joblib.dump(scaler, scaler_filename)

print(f"\nFiles saved successfully:")
print(f"1. Model: {model_filename}")
print(f"2. Scaler: {scaler_filename}")
print("Ready for FastAPI deployment!")