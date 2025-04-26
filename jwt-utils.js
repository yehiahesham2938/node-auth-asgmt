const crypto = require('crypto');

function createToken(userData, secretKey, expiresIn = 3600) {
  const tokenHeader = {
    alg: 'HS256',
    type: 'JWT'
  };
  const tokenData = { ...userData };
  tokenData.exp = Math.floor(Date.now() / 1000) + expiresIn;

  const headerBase64 = convertToBase64(tokenHeader);
  const payloadBase64 = convertToBase64(tokenData);


  const unsignedToken = headerBase64 + '.' + payloadBase64;
  const signature = makeSignature(unsignedToken, secretKey);

  return unsignedToken + '.' + signature;
}

function checkToken(token, secretKey) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Bad token format');

  const [header, payload, signature] = parts;
  const expectedSig = makeSignature(header + '.' + payload, secretKey);
  if (expectedSig !== signature) throw new Error('Invalid signature');

  const tokenData = parseBase64(payload);
  if (tokenData.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }

  return tokenData;
}

function convertToBase64(data) {
  return Buffer.from(JSON.stringify(data))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function parseBase64(str) {
  return JSON.parse(Buffer.from(str, 'base64').toString());
}

function makeSignature(data, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

module.exports = {
  createToken,
  checkToken
};