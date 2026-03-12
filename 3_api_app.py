import pandas as pd
import joblib
import os
import datetime
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime
from sqlalchemy.orm import declarative_base  # SQLAlchemy 2.x compatible (migrated from ext.declarative)
from sqlalchemy.orm import sessionmaker, Session
import uvicorn

# --- 1. SETTINGS AND MODEL LOADING ---
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, "best_model.pkl")
scaler_path = os.path.join(base_dir, "scaler.pkl")

# Load Models
try:
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    print("✅ Model and Scaler loaded successfully.")
except Exception as e:
    print(f"❌ ERROR: Model files not found. Please run training first.\nError: {e}")
    # exit() # Uncomment to stop execution if models are missing.

# --- 2. DATABASE SETUP (SQLITE) ---
DATABASE_URL = "sqlite:///./logs.db" # logs.db file will be created in the current directory
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Table Model
class DetectionLog(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    delta_time = Column(Float)
    length = Column(Integer)
    protocol = Column(Integer)
    prediction = Column(String)     # "Normal" or "Attack"
    confidence = Column(String)     # e.g., "99.5%"

# Create Database (Create Tables)
Base.metadata.create_all(bind=engine)

# --- 3. FASTAPI APPLICATION ---
app = FastAPI(
    title="Automotive IDS API (CRUD)",
    description="Intrusion Detection System - Create, Read, Update, Delete Features",
    version="2.0"
)

# --- CORS SETTINGS ---
# Allow requests from any origin during development (e.g., React, Vue, Mobile App)
origins = [
    "http://localhost",
    "http://localhost:3000",  # React default
    "http://localhost:8080",  # Vue default
    "http://localhost:5173",  # Vite default
    "*"                       # Allow all origins (use with caution in production)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allow all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"], # Allow all headers
)
# ---------------------

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 4. DATA MODELS (PYDANTIC) ---
# Templates for receiving user data
class PacketData(BaseModel):
    DeltaTime: float
    Length: int
    Protocol: int

class LogUpdate(BaseModel):
    prediction: str # Allow updating only the prediction result

# --- 5. ENDPOINTS (CRUD OPERATIONS) ---

# [CREATE] - Make Prediction and Log
@app.post("/predict", tags=["CRUD: Create"])
def predict_and_log(data: PacketData, db: Session = Depends(get_db)):
    try:
        # 1. Make Prediction
        input_df = pd.DataFrame([{'DeltaTime': data.DeltaTime, 'Length': data.Length, 'Protocol': data.Protocol}])
        scaled_data = scaler.transform(input_df)
        pred = model.predict(scaled_data)[0]
        
        # Calculate Probability
        confidence = "N/A"
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(scaled_data)
            confidence = f"{max(probs[0]) * 100:.2f}%"

        result_label = "Attack" if pred == 1 else "Normal"

        # 2. Save to Database (LOGGING)
        new_log = DetectionLog(
            delta_time=data.DeltaTime,
            length=data.Length,
            protocol=data.Protocol,
            prediction=result_label,
            confidence=confidence
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log) # Refresh to get the generated ID

        return {"status": "success", "result": result_label, "log_id": new_log.id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# [READ] - List All Past Logs
@app.get("/logs", tags=["CRUD: Read"])
def read_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(DetectionLog).order_by(DetectionLog.id.desc()).offset(skip).limit(limit).all()
    return logs

# [UPDATE] - Correct a Wrong Prediction
@app.put("/logs/{log_id}", tags=["CRUD: Update"])
def update_log(log_id: int, update_data: LogUpdate, db: Session = Depends(get_db)):
    log = db.query(DetectionLog).filter(DetectionLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    log.prediction = update_data.prediction
    db.commit()
    return {"status": "updated", "log_id": log_id, "new_prediction": log.prediction}

# [DELETE] - Delete a Log Entry
@app.delete("/logs/{log_id}", tags=["CRUD: Delete"])
def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.query(DetectionLog).filter(DetectionLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    db.delete(log)
    db.commit()
    return {"status": "deleted", "log_id": log_id}

# --- START SERVER ---
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)