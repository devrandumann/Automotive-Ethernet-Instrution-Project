# 🚗 Automotive Ethernet IDS

**ML-based Intrusion Detection System for Automotive Ethernet networks — detects packet injection attacks using FastAPI, scikit-learn & PCAP analysis.**

---

## 📌 About the Project

This project implements a Machine Learning-based **Intrusion Detection System (IDS)** for Automotive Ethernet networks. It analyzes network packet features to classify traffic as **Normal** or **Attack (Injected)**.

### Key Features
- 🔍 Real-time packet analysis via REST API
- 🤖 Trains and compares 4 ML models (Random Forest, Decision Tree, KNN, Logistic Regression)
- 📊 Full CRUD logging with SQLite
- 🖥️ Web dashboard (dark/light mode)
- ⚡ FastAPI + Uvicorn backend

---

## 🏗️ Project Structure

```
├── 3_api_app.py          # FastAPI backend (CRUD + ML inference)
├── _pcap_to_csv.py       # Converts PCAP files → CSV dataset
├── _train_models.py      # Trains & saves the best ML model
├── frontend.html         # Web dashboard UI
├── requirements.txt      # Python dependencies
```

> **Note:** Large files (`.pcap`, `.csv`, `.pkl`, `logs.db`) are excluded from the repository via `.gitignore`.  
> Run the scripts in order to regenerate them locally.

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Prepare Dataset (from PCAP files)
```bash
python _pcap_to_csv.py
```

### 3. Train the Model
```bash
python _train_models.py
```

### 4. Start the API Server
```bash
python 3_api_app.py
```
API will be available at: `http://127.0.0.1:8000`  
Interactive docs: `http://127.0.0.1:8000/docs`

### 5. Open the Dashboard
Open `frontend.html` in your browser.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/predict` | Analyze a packet & log result |
| `GET` | `/logs` | List all detection logs |
| `PUT` | `/logs/{id}` | Update a log entry |
| `DELETE` | `/logs/{id}` | Delete a log entry |

### Example Request
```json
POST /predict
{
  "DeltaTime": 0.05,
  "Length": 60,
  "Protocol": 6
}
```

---

## 🤖 ML Models Compared

| Model | Notes |
|-------|-------|
| Random Forest | Usually best accuracy |
| Decision Tree | Fast, interpretable |
| K-Nearest Neighbors | Good baseline |
| Logistic Regression | Simple linear model |

The best-performing model is automatically saved as `best_model.pkl`.

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **ML:** scikit-learn, pandas, joblib
- **Database:** SQLite (via SQLAlchemy)
- **Network:** Scapy (PCAP parsing)
- **Frontend:** HTML, CSS, Vanilla JS

---

## 👤 Author

**Devran Duman**
