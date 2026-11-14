// CommonJS: the package `main` is the CryptoApi object (`require('crypto-api-ng')`).
const CryptoApi = require('..');

console.log('sha256:', CryptoApi.hash('sha256', 'message'));
console.log('hmac-md5:', CryptoApi.hmac('key', 'message', CryptoApi.getHasher('md5')));
