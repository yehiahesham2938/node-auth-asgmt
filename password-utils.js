const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, storedHash) {
  const parts = storedHash.split(':');
  const salt = parts[0];
  const originalHash = parts[1];
  
  const newHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  
  return newHash === originalHash;
}

module.exports = { hashPassword, verifyPassword };