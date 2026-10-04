// Sample JS service with mixed cryptographic posture
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function legacyDigest(data) {
  return crypto.createHash('md5').update(data).digest('hex'); // broken
}

function legacyDigest2(data) {
  return crypto.createHash('sha1').update(data).digest('hex'); // broken
}

function modernDigest(data) {
  return crypto.createHash('sha256').update(data).digest('hex'); // fine
}

function makeRsaKey() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }); // quantum-vulnerable
}

function makeEcKey() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); // quantum-vulnerable
}

function makeEdKey() {
  return crypto.generateKeyPairSync('ed25519'); // quantum-vulnerable
}

function encrypt(data, key, iv) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv); // adequate
  return c.update(data);
}

function legacyEncrypt(data, key, iv) {
  const c = crypto.createCipheriv('des-ede3-cbc', key, iv); // broken
  return c.update(data);
}

function signToken(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256' }); // RSA
}
