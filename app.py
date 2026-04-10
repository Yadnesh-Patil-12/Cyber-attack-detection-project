import boto3
import pandas as pd
import datetime
import streamlit as st
import joblib
import numpy as np
import time

# Load ML model
model = joblib.load("cyber_attack_pipeline.pkl")

# AWS S3 connection
s3 = boto3.client(
    "s3",
    aws_access_key_id="addown",
    aws_secret_access_key="addown",
    region_name="ap-south-1"
)

bucket_name = "cyber-attack-logs-bucket"

st.set_page_config(page_title="Cyber Attack Detection SOC", layout="wide")

st.title("🔐 AI Cyber Attack Detection System (SOC Dashboard)")
st.write("Enter network traffic features to monitor potential cyber attacks.")

# Session state for history
if "history" not in st.session_state:
    st.session_state.history = []

# Example data loader
if st.button("Load Example Data"):
    st.session_state.duration = 0
    st.session_state.src_bytes = 181
    st.session_state.dst_bytes = 5450
    st.session_state.land = 0
    st.session_state.wrong_fragment = 0
    st.session_state.urgent = 0
    st.session_state.hot = 0
    st.session_state.num_failed_logins = 0
    st.session_state.logged_in = 1
    st.session_state.num_compromised = 0
    st.session_state.root_shell = 0
    st.session_state.su_attempted = 0
    st.session_state.num_root = 0
    st.session_state.num_file_creations = 0
    st.session_state.num_shells = 0

# Layout
col1, col2, col3 = st.columns(3)

with col1:
    duration = st.number_input("duration", value=st.session_state.get("duration",0.0))
    src_bytes = st.number_input("src_bytes", value=st.session_state.get("src_bytes",0.0))
    dst_bytes = st.number_input("dst_bytes", value=st.session_state.get("dst_bytes",0.0))
    land = st.number_input("land", value=st.session_state.get("land",0.0))
    wrong_fragment = st.number_input("wrong_fragment", value=st.session_state.get("wrong_fragment",0.0))

with col2:
    urgent = st.number_input("urgent", value=st.session_state.get("urgent",0.0))
    hot = st.number_input("hot", value=st.session_state.get("hot",0.0))
    num_failed_logins = st.number_input("num_failed_logins", value=st.session_state.get("num_failed_logins",0.0))
    logged_in = st.number_input("logged_in", value=st.session_state.get("logged_in",0.0))
    num_compromised = st.number_input("num_compromised", value=st.session_state.get("num_compromised",0.0))

with col3:
    root_shell = st.number_input("root_shell", value=st.session_state.get("root_shell",0.0))
    su_attempted = st.number_input("su_attempted", value=st.session_state.get("su_attempted",0.0))
    num_root = st.number_input("num_root", value=st.session_state.get("num_root",0.0))
    num_file_creations = st.number_input("num_file_creations", value=st.session_state.get("num_file_creations",0.0))
    num_shells = st.number_input("num_shells", value=st.session_state.get("num_shells",0.0))

# -----------------------------
# PREDICTION SECTION
# -----------------------------

if st.button("🚀 Predict Attack"):

    data = np.array([[duration, src_bytes, dst_bytes, land, wrong_fragment,
                      urgent, hot, num_failed_logins, logged_in,
                      num_compromised, root_shell, su_attempted,
                      num_root, num_file_creations, num_shells]])

    prediction = model.predict(data)
    prob = model.predict_proba(data)[0]

    result = "Attack" if prediction[0] == 1 else "Normal"

    # Save history for SOC dashboard
    st.session_state.history.append({
        "duration":duration,
        "src_bytes":src_bytes,
        "dst_bytes":dst_bytes,
        "result":result,
        "attack_prob":prob[1],
        "normal_prob":prob[0],
        "time":time.strftime("%H:%M:%S")
    })

    # Show result
    if result == "Attack":
        st.error("⚠️ Cyber Attack Detected")
    else:
        st.success("✅ Normal Network Traffic")

    st.subheader("Prediction Confidence")

    st.progress(float(prob[0]))
    st.write(f"Normal Traffic: {prob[0]*100:.2f}%")

    st.progress(float(prob[1]))
    st.write(f"Cyber Attack Probability: {prob[1]*100:.2f}%")

    # -----------------------------
    # CLOUD LOGGING TO S3
    # -----------------------------

    log = {
        "time": str(datetime.datetime.now()),
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "result": result,
        "attack_prob": float(prob[1]),
        "normal_prob": float(prob[0])
    }

    df_log = pd.DataFrame([log])

    df_log.to_csv("attack_logs.csv", mode="a", header=False, index=False)

    s3.upload_file(
        "attack_logs.csv",
        bucket_name,
        "logs/attack_logs.csv"
    )

# -----------------------------
# SOC DASHBOARD
# -----------------------------

st.divider()
st.header("📊 Security Operations Center (SOC) Dashboard")

if len(st.session_state.history) > 0:

    df = pd.DataFrame(st.session_state.history)

    colA, colB = st.columns(2)

    with colA:
        st.subheader("Attack Detection Chart")
        attack_counts = df["result"].value_counts()
        st.bar_chart(attack_counts)

    with colB:
        st.subheader("Traffic Analytics (src_bytes vs dst_bytes)")
        st.scatter_chart(df[["src_bytes","dst_bytes"]])

    st.subheader("Prediction History Log")
    st.dataframe(df)

else:
    st.info("No predictions yet. Run a prediction to generate SOC analytics.")

# -----------------------------
# REAL-TIME MONITOR SIMULATION
# -----------------------------

st.divider()
st.header("📡 Real-Time Monitoring Simulation")

if st.button("Start Monitoring"):

    placeholder = st.empty()

    for i in range(10):

        random_data = np.random.rand(1,15)*100

        pred = model.predict(random_data)[0]

        if pred == 1:
            placeholder.error("⚠️ Suspicious Network Activity Detected")
        else:
            placeholder.success("✅ Network Traffic Normal")

        time.sleep(1)
