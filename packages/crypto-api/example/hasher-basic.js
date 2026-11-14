'use strict';

// Uses the global build (../crypto-api.js defines `CryptoApi`), so this page also works from file://.
var hasher = CryptoApi.getHasher('md2');
hasher.update('test message');
document.getElementById('result').textContent = CryptoApi.encoder.toHex(hasher.finalize());
