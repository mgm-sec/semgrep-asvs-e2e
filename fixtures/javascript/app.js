const crypto = require('crypto');

function handler(req) {
  const result = eval(req.query.expr);
  return result;
}

function verify(k, m, sig) {
  return crypto.createHmac('sha256', k).update(m).digest('hex') === sig;
}
