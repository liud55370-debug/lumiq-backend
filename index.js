const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const EK = process.env.ENCRYPTION_KEY || 'lumiq-default-key-32-chars-long!!';
function enc(t) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(EK.padEnd(32).slice(0, 32)), iv);
  let e = c.update(t, 'utf8', 'base64');
  e += c.final('base64');
  return iv.toString('base64') + ':' + c.getAuthTag().toString('base64') + ':' + e;
}
function dec(d) {
  const [iv, at, b] = d.split(':');
  const de = crypto.createDecipheriv('aes-256-gcm', Buffer.from(EK.padEnd(32).slice(0, 32)), Buffer.from(iv, 'base64'));
  de.setAuthTag(Buffer.from(at, 'base64'));
  let t = de.update(b, 'base64', 'utf8');
  return t + de.final('utf8');
}
const mem = { key: null, orders: [] };

async function bSign(sec, q) {
  const ts = Date.now(), sq = q ? `${q}&timestamp=${ts}` : `timestamp=${ts}`;
  return `${sq}&signature=${crypto.createHmac('sha256', sec).update(sq).digest('hex')}`;
}
async function oSign(sec, ts, m, p, b) {
  return crypto.createHmac('sha256', sec).update(ts + m + p + (b || '')).digest('base64');
}

app.get('/', (_, r) => r.json({ status: 'ok', service: 'LUMIQ' }));
app.post('/api/keys', (q, r) => {
  const { x, a, s, p, t } = q.body;
  if (!a || !s) return r.status(400).json({ error: 'key required' });
  mem.key = { x, a, s: enc(s), p: p ? enc(p) : undefined, t: t ?? 1 };
  r.json({ ok: 1 });
});
app.get('/api/keys', (_, r) => {
  if (!mem.key) return r.status(404).json({ error: 'none' });
  r.json({ x: mem.key.x, a: mem.key.a.slice(0, 8) + '...' + mem.key.a.slice(-4), t: mem.key.t });
});
app.delete('/api/keys', (_, r) => { mem.key = null; r.json({ ok: 1 }); });

app.get('/api/keys/test', async (_, r) => {
  if (!mem.key) return r.status(400).json({ e: 'no key' });
  const { x, a, s, p, t } = mem.key;
  try {
    if (x === 'binance') {
      const b = t ? 'https://testnet.binance.vision' : 'https://api.binance.com';
      const q = await bSign(dec(s), '');
      const res = await fetch(`${b}/api/v3/account?${q}`, { headers: { 'X-MBX-APIKEY': a } });
      r.json({ ok: res.ok, x: 'binance', t });
    } else {
      const ts = new Date().toISOString(), pa = '/api/v5/account/balance';
      const si = await oSign(dec(s), ts, 'GET', pa);
      const h = { 'OK-ACCESS-KEY': a, 'OK-ACCESS-SIGN': si, 'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': p ? dec(p) : '' };
      if (t) h['x-simulated-trading'] = '1';
      const res = await fetch('https://www.okx.com' + pa, { headers: h });
      const d = await res.json();
      r.json({ ok: d.code === '0', x: 'okx', t });
    }
  } catch (e) { r.status(500).json({ e: e.message }); }
});

app.post('/api/orders', async (q, r) => {
  const { sym, side, type, qty, price } = q.body;
  if (!mem.key) return r.status(400).json({ e: 'no key' });
  const { x, a, s, p, t } = mem.key;
  try {
    let rs;
    if (x === 'binance') {
      const b = t ? 'https://testnet.binance.vision' : 'https://api.binance.com';
      let qu = `symbol=${sym}&side=${side.toUpperCase()}&type=${type || 'MARKET'}&quantity=${qty}&newOrderRespType=RESULT`;
      if (type === 'LIMIT' && price) qu += `&price=${price}&timeInForce=GTC`;
      const sq = await bSign(dec(s), qu);
      const res = await fetch(`${b}/api/v3/order?${sq}`, { method: 'POST', headers: { 'X-MBX-APIKEY': a, 'Content-Type': 'application/x-www-form-urlencoded' } });
      rs = await res.json();
    } else {
      const ts = new Date().toISOString(), pa = '/api/v5/trade/order';
      const bo = JSON.stringify({ instId: sym.includes('-') ? sym : `${sym.replace('USDT', '')}-USDT`, tdMode: 'cash', side: side.toLowerCase(), ordType: (type || 'market').toLowerCase(), sz: String(qty), ...(price ? { px: String(price) } : {}), ...(t ? { simulating: '1' } : {}) });
      const si = await oSign(dec(s), ts, 'POST', pa, bo);
      const h = { 'OK-ACCESS-KEY': a, 'OK-ACCESS-SIGN': si, 'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': p ? dec(p) : '', 'Content-Type': 'application/json' };
      if (t) h['x-simulated-trading'] = '1';
      const res = await fetch('https://www.okx.com' + pa, { method: 'POST', headers: h, body: bo });
      rs = await res.json();
    }
    mem.orders.unshift({ id: Date.now().toString(), x, sym, side, qty, price, rs, t: new Date().toISOString() });
    if (mem.orders.length > 100) mem.orders.pop();
    r.json({ ok: 1, order: rs, x });
  } catch (e) { r.status(500).json({ e: e.message }); }
});

app.get('/api/orders', (_, r) => r.json({ orders: mem.orders }));
app.get('/api/balance', async (_, r) => {
  if (!mem.key) return r.status(400).json({ e: 'no key' });
  const { x, a, s, p, t } = mem.key;
  try {
    if (x === 'binance') {
      const b = t ? 'https://testnet.binance.vision' : 'https://api.binance.com';
      const q = await bSign(dec(s), '');
      const res = await fetch(`${b}/api/v3/account?${q}`, { headers: { 'X-MBX-APIKEY': a } });
      r.json({ bal: await res.json(), x: 'binance' });
    } else {
      const ts = new Date().toISOString(), pa = '/api/v5/account/balance';
      const si = await oSign(dec(s), ts, 'GET', pa);
      const h = { 'OK-ACCESS-KEY': a, 'OK-ACCESS-SIGN': si, 'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': p ? dec(p) : '' };
      if (t) h['x-simulated-trading'] = '1';
      const res = await fetch('https://www.okx.com' + pa, { headers: h });
      r.json({ bal: await res.json(), x: 'okx' });
    }
  } catch (e) { r.status(500).json({ e: e.message }); }
});

app.listen(3000, '0.0.0.0', () => console.log('LUMIQ on 3000'));
