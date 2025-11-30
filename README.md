🧠 AI-Cyber Training Lab

Hands-on cybersecurity investigation and detection lab using Sysmon telemetry, Python automation, and machine-learning-based threat classification.

This project is part of my ongoing professional development as a Cybersecurity Analyst preparing for roles involving AI-driven security, threat hunting, automation, and SOC engineering.
It includes:

Sysmon log collection & parsing

JSON normalization using Pandas

Python-based detection logic

ML classification of suspicious activity

Experimentation with adversarial behavior detection

Real-world log analysis from a virtualized lab environment

This repository will grow as I continue training and expanding skills in:
CrowdStrike, Qualys, Splunk/SOAR, Python security automations, and AI-assisted cyber defense tooling.
______________________________________________________________________________________________________________________________________________________

🔥 LSTM-Based Anomaly Detection (Sysmon Process Behavior)

This module trains a lightweight LSTM Autoencoder to detect unusual process behavior using Sysmon Event ID 1 logs collected from my Windows lab.

What features were analyzed

The model converts process execution data into numeric behavioral features:

SHA-1 hash length

Parent command-line length

These features act as simple behavioral signatures representing how processes normally look.

How the model works

Extract Sysmon logs → normalize to a dataframe

Build numeric behavioral features

Scale all features

Train a 1-layer LSTM Autoencoder

Compute reconstruction error

Flag the top 5% worst-reconstructed processes as anomalies

What this detects

This LSTM catches:

Unusual parent command-lines

Strange hash patterns

Possibly injected or tampered processes

Abuse of system utilities (e.g., net stop/start, reg add, sc.exe)

Outputs stored in this repo

lstm_anomaly_results.csv → Full anomaly detection output

lstm_anomaly_plot.png → Visual anomaly score distribution

lstm_anomaly_detector.py → The model source code

This module represents my work toward building AI-assisted detection pipelines for real-world blue-team environments.
