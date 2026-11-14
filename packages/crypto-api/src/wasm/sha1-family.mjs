// crypto-api-ng:facade
'use strict';

import {wasmBytes} from "../../wasm/sha1.mjs";
import {createFamily} from "./be32.mjs";

// One wasm module serves SHA-0 and SHA-1, so both facades share its instance.
// 104 = sizeof(sha1.State) in src/hash/sha1.zig.
export default createFamily(wasmBytes, {sha0: 104, sha1: 104});
