'use strict';

// Runs the hash and HMAC test vectors of the original crypto-api test suite against the global
// build. Each vector is given as hex bytes (`input`, `key`) and converted to the binary string
// the library works with.
function fromHex(hex) {
  var s = '';
  for (var i = 0; i < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return s;
}

var passed = 0;
var failed = 0;
var list = document.getElementById('results');

function report(ok, name, detail) {
  if (ok) passed++; else failed++;
  var li = document.createElement('li');
  li.className = ok ? 'pass' : 'fail';
  li.textContent = (ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : ' ' + detail);
  list.appendChild(li);
}

CRYPTO_API_VECTORS.forEach(function (group) {
  if (!group.name) {
    // Not reachable through CryptoApi.getHasher() (kept from crypto-api 0.8.5): sm3.
    return;
  }
  group.hash.forEach(function (v) {
    var hasher = CryptoApi.getHasher(group.name);
    hasher.update(fromHex(v.input));
    var actual = CryptoApi.encoder.toHex(hasher.finalize());
    report(actual === v.hex, group.name + ' ' + v.title, 'expected ' + v.hex + ' got ' + actual);
  });
  (group.hmac || []).forEach(function (v) {
    var mac = CryptoApi.getHmac(fromHex(v.key), CryptoApi.getHasher(group.name));
    mac.update(fromHex(v.input));
    var actual = CryptoApi.encoder.toHex(mac.finalize());
    report(actual === v.hex, 'hmac-' + group.name + ' ' + v.title, 'expected ' + v.hex + ' got ' + actual);
  });
});

document.getElementById('summary').textContent = passed + ' passed, ' + failed + ' failed';
document.getElementById('summary').className = failed ? 'fail' : 'pass';
document.title = (failed ? 'FAIL ' : 'PASS ') + document.title;
