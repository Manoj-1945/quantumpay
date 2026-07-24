# ⚛️ QuantumPay — World's First Post-Quantum UPI Payment Platform

![QuantumPay Banner](https://img.shields.io/badge/Security-Post--Quantum%20Kyber--768-00f5ff?style=for-the-badge)
![NIST Standard](https://img.shields.io/badge/NIST-FIPS%20203%20%2F%20204-7b2fff?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20Qiskit-00ffaa?style=for-the-badge)
![Status](https://img.shields.io/badge/RBI%20Sandbox-Cohort%206%20Compliant-ffcc00?style=for-the-badge)

QuantumPay is a next-generation, post-quantum cryptography (PQC) secured payment ecosystem built to protect financial infrastructure against quantum computing threats. It features real-time ANU Quantum Random Number Generation (QRNG), NIST FIPS 203 (CRYSTALS-Kyber-768) lattice-based encryption, and an immutable SHA-256 blockchain audit trail.

---

## 🌟 Key Features

- **🎲 Real Quantum Randomness (QRNG)**: Seeding transaction tokens from ANU Quantum Lab's photonic vacuum fluctuations.
- **🔐 NIST Post-Quantum Cryptography**: Quantum-safe key encapsulation (Kyber-768) and signatures (Dilithium-3).
- **🛡 QuantumShield Command Center**: Live attack detection, zero-trust RBAC access, and Grover's algorithm fraud scanning.
- **🔬 IBM Qiskit Integration**: Runnable quantum circuits for QRNG, Bell State entanglement, Grover's search, and BB84 QKD.
- **🏛 RBI Sandbox & NPCI Switch Ready**: Built-in regulatory compliance endpoints (`/api/rbi/sandbox-verify`) and NPCI settlement switch simulator.
- **📱 Cross-Platform Mobile App**: React Native Expo app prototype in `/mobile`.

---

## 🚀 Quick Start

### 1. Run Backend Server (Python FastAPI)

```bash
cd backend
pip install -r requirements.txt
python main.py
```

- **API Documentation**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/health`

### 2. Launch Interfaces in Browser

Open any of the built web applications directly:
- **Landing Page**: `index.html`
- **Auth & Register**: `login.html`
- **Payment App**: `pay.html`
- **Security Dashboard**: `shield.html`
- **Admin Console & Quantum Lab**: `admin.html`
- **Investor Pitch Deck**: `pitch.html`
- **RBI Compliance Portal**: `compliance.html`

### 3. Docker Deployment

```bash
docker-compose up --build -d
```

---

## 🏛 Architecture

```
[Mobile App / Web App]
         │
         ▼ (PQC Kyber-768 Tunnel)
[FastAPI API Gateway] ───► [ANU Vacuum Fluctuation QRNG]
         │
         ├─► [CRYSTALS-Dilithium Signatures]
         ├─► [Immutable Blockchain Ledger]
         └─► [IBM Qiskit Quantum Simulator]
```

---

## 📜 License

MIT License. Developed for Quantum Financial Security.
