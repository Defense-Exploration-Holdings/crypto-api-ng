// Deep imports under native Node ESM. Run from an installed package:
//   node node_modules/{{name}}/example/node.mjs
import Sha256 from '../src/hasher/sha256.mjs';
import Md5 from '../src/hasher/md5.mjs';
import Hmac from '../src/mac/hmac.mjs';
import { toHex } from '../src/encoder/hex.mjs';
import { fromUtf } from '../src/encoder/utf.mjs';

const sha256 = new Sha256();
sha256.update(fromUtf('message'));
console.log('sha256:', toHex(sha256.finalize()));

const hmac = new Hmac(fromUtf('key'), new Md5());
hmac.update(fromUtf('message'));
console.log('hmac-md5:', toHex(hmac.finalize()));
