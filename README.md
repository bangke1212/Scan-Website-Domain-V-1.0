# ��� CryptoGuard — Scam & Risk Analyzer

A browser-based tool that analyzes cryptocurrency tokens, contract addresses, and websites to assess their risk level and identify potential red flags for scams.

## 🚀 Quick Start

```bash
npm install
npm run dev
```

## ✨ Features

- __Smart Input Detection__ — Auto-detects contract addresses (EVM & Solana), website URLs, transaction hashes, and token names
- __Risk Scoring (0-100)__ — Four tiers: Low → Medium → High → Critical
- __30+ Heuristic Checks__ — Typosquat detection, phishing keywords, suspicious TLDs, burn address patterns, vanity patterns, entropy analysis
- __Scan History__ — Track all past scans locally
- __Dark US__ — Clean, security-focused dark theme

## ➜ Security

This tool runs entirely in your browser. No data is sent to any server.

## 🛧️ Built With

- React + Vite
- Lucide Icons
- Pure CSS (no framework)

## ⚠️ Disclaimer

Not financial advice. This tool performs static heuristic checks only — it does NOT query live blockchain data or smart contract source code. Always verify independently on Etherscan/Solscan before trading.