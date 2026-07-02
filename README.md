# 🛡️ CryptoGuard — Scam & Risk Analyzer

A browser-based tool that analyzes cryptocurrency tokens, contract addresses, and websites to assess their risk level and identify potential red flags for scams.

## 🚀 Quick Start

```bash
npm install
npm run dev
```

## ✨ Features

- **Smart Input Detection** — Auto-detects contract addresses (EVM & Solana), website URLs, transaction hashes, and token names
- **Risk Scoring (0-100)** — Four tiers: Low → Medium → High → Critical
- **30+ Heuristic Checks** — Typosquat detection, phishing keywords, suspicious TLDs, burn address patterns, vanity patterns, entropy analysis
- **Scan History** — Track past scans locally in your browser
- **Dark UI** — Clean, security-focused dark theme

## 🔒 Security

This tool runs entirely in your browser. No data is sent to any server.

## 🛠️ Built With

- React + Vite
- Lucide Icons
- Pure CSS (no framework)

## 🚢 Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/bangke1212/Scan-Website-Domain-V-1.0)

Or manually:

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import `bangke1212/Scan-Website-Domain-V-1.0`
3. Vercel auto-detects Vite — no config needed
4. Click **Deploy**

## ⚠️ Disclaimer

Not financial advice. This tool performs static heuristic checks only — it does NOT query live blockchain data or smart contract source code. Always verify independently on Etherscan/Solscan before trading.
