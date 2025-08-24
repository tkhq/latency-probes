# Turnkey v Privy Watch Tower

This repo contains a selection of scripts to compare Turnkey and Privy's raw signing performance.

You can run these locally by:
1. Creating a new `secrets.env` file (see `secrets.env.example`)
2. Running `k6 run turnkey_sig.js --secret-source=file=secrets.env`

When running in Grafana you can view/add/modify secrets via https://turnkey.grafana.net/a/grafana-synthetic-monitoring-app/config/secrets.
