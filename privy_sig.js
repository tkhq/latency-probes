import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import secrets from 'k6/secrets';
import encoding from 'k6/encoding';

const latency = new Trend('privy_sig_latency');
const MESSAGE_B64  = "HELLO FROM TURNKEY HQ. How fast _are you_ today?";

export default async function () {
  const PRIVY_APP_ID = await secrets.get('privy-app-id');
  const PRIVY_APP_SECRET = await secrets.get('privy-app-secret');
  const WALLET_ID = await secrets.get('wallet-id');

  const url = `https://api.privy.io/v1/wallets/${WALLET_ID}/rpc`;
  const payload = JSON.stringify({
    method: 'signMessage',
    params: { message: MESSAGE_B64, encoding: 'base64' },
  });

  const authHeaderInner = encoding.b64encode(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`);
  const authHeader = `Basic ${authHeaderInner}`;

  const headers = {
    'Content-Type': 'application/json',
    'privy-app-id': PRIVY_APP_ID,
    Authorization: authHeader,
  };

  const res = http.post(url, payload, { headers });
  latency.add(res.timings.duration);

  check(res, {
    'status 200': (r) => r.status === 200,
    'has signature': (r) => {
      return !!r.json('data.signature')
    },
    'encoding=base64': (r) => r.json('data.encoding') === 'base64',
  });
}
