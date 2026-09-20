const crypto = require('crypto');
function verify(k, m, sig) {
  // ruleid: constant-time-compare
  if (crypto.createHmac('sha256', k).update(m).digest('hex') === sig) return true;
  // ruleid: constant-time-compare
  if (sig != crypto.createHmac('sha256', k).update(m).digest('hex')) return false;
  // ok: constant-time-compare
  const expected = Buffer.from(crypto.createHmac('sha256', k).update(m).digest('hex'));
  return crypto.timingSafeEqual(expected, Buffer.from(sig));
}
