# Signing Latency Probes

This repository contains [k6](https://grafana.com/docs/k6/latest/)-based benchmarks comparing wallet signing performance across Turnkey, Privy, and Coinbase Developer Platform (CDP) from multiple geographic regions.

## Overview

The scripts measure end-to-end transaction signing latency across geographic regions.

They are designed to evaluate how distributed signing infrastructure impacts performance, and to provide a reproducible view of latency across providers.

## Reproducibility

This benchmark is designed to be reproducible. Results may vary based on network conditions and region selection.

You can run these locally by:
1. Creating a new `secrets.env` file (see `secrets.env.example`)
2. Running `k6 run turnkey_sig.js --secret-source=file=secrets.env`

To run these scripts in Grafana you'll have view/add/modify secrets via https://turnkey.grafana.net/a/grafana-synthetic-monitoring-app/config/secrets.

## About Turnkey

[Turnkey](https://www.turnkey.com/) provides secure, programmable crypto wallet infrastructure using Trusted Execution Environments (TEEs). Signing operations execute inside these secure enclaves, providing hardware-isolated key protection and efficient cryptographic execution across distributed regions.

This architecture is designed for global scale, delivering fast, verifiable cryptographic operations with consistent performance and security guarantees across all regions. Learn more about Turnkey with our [whitepaper](https://whitepaper.turnkey.com/). 