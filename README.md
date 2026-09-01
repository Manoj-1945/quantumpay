# AnuPradaan v5.1 — World's First Quantum-Secured Payment Platform

[![Live](https://img.shields.io/badge/Live-Railway-green)](https://quantumpay-api-production.up.railway.app)
[![Version](https://img.shields.io/badge/Version-5.1-blue)](https://quantumpay-api-production.up.railway.app/docs)
[![PQC](https://img.shields.io/badge/PQC-NIST%20Level%205-purple)](https://quantumpay-api-production.up.railway.app)
[![RBI](https://img.shields.io/badge/RBI-Sandbox%20Cohort%206-orange)](https://quantumpay-api-production.up.railway.app/api/rbi/sandbox-verify)

> AnuPradaan makes payments permanently unhackable using post-quantum cryptography — even against future quantum computers. Built for India's financial infrastructure.

## Live Links

| Resource | URL |
|----------|-----|
| B2B Enterprise Portal | https://quantumpay-api-production.up.railway.app/ |
| API Documentation | https://quantumpay-api-production.up.railway.app/docs |
| Health Check | https://quantumpay-api-production.up.railway.app/health |
| RBI Sandbox Verify | https://quantumpay-api-production.up.railway.app/api/rbi/sandbox-verify |
| B2B Metrics | https://quantumpay-api-production.up.railway.app/api/v1/b2b/metrics |

## Security Stack (v5.1)

| Layer | Technology | Standard |
|-------|-----------|----------|
| Key Encapsulation | CRYSTALS-Kyber-1024 | NIST FIPS 203 Level 5 |
| Digital Signature | CRYSTALS-Dilithium-3 | NIST FIPS 204 |
| Quantum Randomness | ANU Quantum Lab QRNG | Photon Vacuum Fluctuation |
| Password Hashing | bcrypt (per-user salt) | OWASP Recommended |
| Authentication | JWT + Refresh Tokens (7 day) | RFC 7519 |
| Rate Limiting | slowapi 10 login/5 register per min | OWASP |
| Financial Format | ISO 20022 pacs.008.001.08 | SWIFT / NPCI |
| Entanglement Proof | CHSH Bell Inequality S=2.8284 | Quantum Mechanics |

## Quick Start — B2B Integration

### 1. Register as Partner
```bash
curl -X POST https://quantumpay-api-production.up.railway.app/api/v1/b2b/register-partner \
  -H "Content-Type: application/json" \
  -d '{"partner_name": "HDFC Bank", "webhook_url": "https://your-bank.com/callback"}'
```

### 2. Generate Quantum Proof Token
```bash
curl -X POST https://quantumpay-api-production.up.railway.app/api/v1/b2b/generate-token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "qp.b2b.v5.YOUR_KEY", "amount": 50000, "currency": "INR"}'
```

### 3. Verify Token
```bash
curl -X POST https://quantumpay-api-production.up.railway.app/api/v1/b2b/verify \
  -H "Content-Type: application/json" \
  -d '{"quantum_proof_token": "qp.v50.LEVEL5.1024.YOUR_TOKEN"}'
```

## API Endpoints (v5.1)

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register user (5/min limit) |
| POST | /api/auth/login | Login (10/min limit) |
| POST | /api/auth/refresh | Refresh JWT token |

### Payments
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/payment/send | Send quantum-secured payment |
| GET | /api/transactions | Transaction history |
| GET | /api/transactions/{id}/receipt | Quantum-proof receipt |

### B2B Gateway
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/b2b/register-partner | Issue QRNG API key |
| POST | /api/v1/b2b/generate-token | Generate Level 5 proof token |
| POST | /api/v1/b2b/verify | Verify token |
| POST | /api/v1/b2b/iso20022-convert | ISO 20022 quantum encapsulator |
| GET | /api/v1/b2b/metrics | Gateway metrics |
| GET | /api/v1/b2b/audit-export | RBI compliance certificate |

## Compliance
- RBI Regulatory Sandbox — Cohort 6
- NIST FIPS 203 (Kyber-1024) + FIPS 204 (Dilithium-3)
- ISO 20022 pacs.008.001.08
- RBI Data Localization (India-only storage)
- CERT-In Post-Quantum Audit Level 4

## About
**AnuPradaan CyberSec Technologies Pvt Ltd**
Bengaluru, Karnataka, India | Founded 2026
Inventor: Manoj Kumar G K

Contact: business@quantumpay.in | api@quantumpay.in
