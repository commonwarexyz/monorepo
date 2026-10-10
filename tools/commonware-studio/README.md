# 🛠️ Commonware Studio & Modular Primitives Suite

An interactive BFT consensus visualizer, **Simplex BFT Engine (~200ms finality)**, and **BLS12-381 Threshold DKG Keygen Studio** for **Commonware Primitives**.

---

## 🌟 Key Features

- ⚡ **consensus::simplex BFT Engine**: Simulate ~200ms view round block commitments and threshold signature aggregation.
- 🔐 **BLS12-381 Threshold DKG**: Distributed Key Generation without requiring a public board.
- 🌐 **Interactive Web Studio**: Real-time consensus round visualizer and keygen terminal on `http://localhost:3419`.
- ⌨️ **Universal CLI (`commonware-cli`)**: Terminal utility for committing Simplex BFT blocks and generating DKG keys.

---

## 🚀 Quickstart

```bash
# Launch Commonware Studio
npm start
# Open http://localhost:3419

# Or run via CLI
node bin/commonware-cli.js commit
node bin/commonware-cli.js dkg
```
