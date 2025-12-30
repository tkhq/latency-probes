# SLAP: Simple LAtency Probes

This repo contains a collection of scripts to compare Turnkey, Privy and CDP wallet signing performance.

You can run these locally by:
1. Creating a new `secrets.env` file (see `secrets.env.example`)
2. Running `k6 run turnkey_sig.js --secret-source=file=secrets.env`

To run these scripts in Grafana you'll have view/add/modify secrets via https://turnkey.grafana.net/a/grafana-synthetic-monitoring-app/config/secrets.
