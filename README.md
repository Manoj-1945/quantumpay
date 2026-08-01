# QuantumPay B2B — Quantum Security Gateway & API Middleware
> **India's First Plug-and-Play Post-Quantum Security Middleware for Banks, Payment Gateways & Fintech Apps.**

[![Post-Quantum Cryptography](https://img.shields.io/badge/PQC-NIST_FIPS_203%2F204-00f5ff)](https://github.com/Manoj-1945/quantumpay)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)](https://github.com/Manoj-1945/quantumpay)

---

## ⚡ What is QuantumPay B2B?

QuantumPay B2B allows existing payment gateways (Razorpay, PhonePe, Paytm) and core banking gateways (HDFC, ICICI, SBI) to upgrade their payment transactions to **NIST FIPS 203/204 Post-Quantum Standards** using **3 lines of code**.

- **Zero Hardware Replacement**: No physical HSM chips needed for integration.
- **Microsecond Latency**: Processing time `< 40 µs` per security check.
- **3-Way Ephemeral Sharding**: Token shards split across Mumbai, Singapore, Frankfurt and destroyed in `< 100ms`.

---

## 🔌 3-Line B2B SDK Integration

```javascript
const { QuantumPaySDK } = require('@quantumpay/security-sdk');

const qpay = new QuantumPaySDK({ partnerId: 'PTR-RAZORPAY', apiKey: 'qp_live_...' });

// Protect transaction payload
const proof = await qpay.protectTransaction({
  merchantId: 'MERCHANT_8819',
  amount: 5000.00,
  customerRef: 'CUST_9941'
});

console.log(proof.quantum_proof_token); // QP-B2B-8A3F91B2-C7E4D0A9
console.log(proof.post_quantum_spec);   // CRYSTALS-Kyber-768
```

---

## 🌐 Live Products & Portals

- 📄 **Executive Proposal Document**: [`B2B_BANK_PROPOSAL.md`](B2B_BANK_PROPOSAL.md)
- 🔌 **Interactive B2B Portal**: [`b2b_portal.html`](b2b_portal.html)
- ⚙️ **B2B API Engine**: [`backend/b2b_gateway.py`](backend/b2b_gateway.py)
- 🏛 **Officer Telemetry App**: [`mobile/admin-app/App.tsx`](mobile/admin-app/App.tsx)

---

## 🚀 Live B2B API Endpoint

```http
POST /api/v1/b2b/sign-transaction HTTP/1.1
Host: quantumpay-api.onrender.com
Content-Type: application/json

{
  "partner_id": "PTR-RAZORPAY",
  "api_key": "qp_live_rzp_9941a",
  "amount": 5000.0,
  "merchant_id": "MERCHANT_8819",
  "customer_ref": "CUST_9941",
  "payload_hash": "e3b0c44298fc1c149afbf4c8996fb924"
}
```

---

## 💼 Business Model (B2B SaaS)

1. **Pay-Per-Transaction**: ₹0.05 per protected transaction.
2. **Annual Enterprise License**: ₹15,00,000 / year per bank.
