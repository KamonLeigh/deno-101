function trim(val) {
    return val.trim();
}
function compact(obj) {
    return Object.keys(obj).reduce((result, key)=>{
        if (obj[key]) {
            result[key] = obj[key];
        }
        return result;
    }, {
    });
}
function difference(arrA, arrB) {
    return arrA.filter((a)=>arrB.indexOf(a) < 0
    );
}
function isVariableStart(str) {
    return /^\s*?[a-zA-Z_][a-zA-Z_0-9 ]*=/.test(str);
}
function cleanQuotes(value = "") {
    return value.replace(/^['"]([\s\S]*)['"]$/gm, "$1");
}
function expandNewlines(str) {
    return str.replace("\\n", "\n");
}
const matchCache = {
};
const FIELD_CONTENT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
const KEY_REGEXP = /(?:^|;) *([^=]*)=[^;]*/g;
const SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;
function getPattern(name) {
    if (name in matchCache) {
        return matchCache[name];
    }
    return matchCache[name] = new RegExp(`(?:^|;) *${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`);
}
function pushCookie(headers, cookie) {
    if (cookie.overwrite) {
        for(let i = headers.length - 1; i >= 0; i--){
            if (headers[i].indexOf(`${cookie.name}=`) === 0) {
                headers.splice(i, 1);
            }
        }
    }
    headers.push(cookie.toHeader());
}
function validateCookieProperty(key, value) {
    if (value && !FIELD_CONTENT_REGEXP.test(value)) {
        throw new TypeError(`The ${key} of the cookie (${value}) is invalid.`);
    }
}
class Cookie {
    httpOnly = true;
    overwrite = false;
    path = "/";
    sameSite = false;
    secure = false;
    constructor(name1, value1, attributes){
        validateCookieProperty("name", name1);
        validateCookieProperty("value", value1);
        this.name = name1;
        this.value = value1 ?? "";
        Object.assign(this, attributes);
        if (!this.value) {
            this.expires = new Date(0);
            this.maxAge = undefined;
        }
        validateCookieProperty("path", this.path);
        validateCookieProperty("domain", this.domain);
        if (this.sameSite && typeof this.sameSite === "string" && !SAME_SITE_REGEXP.test(this.sameSite)) {
            throw new TypeError(`The sameSite of the cookie ("${this.sameSite}") is invalid.`);
        }
    }
    toHeader() {
        let header = this.toString();
        if (this.maxAge) {
            this.expires = new Date(Date.now() + this.maxAge * 1000);
        }
        if (this.path) {
            header += `; path=${this.path}`;
        }
        if (this.expires) {
            header += `; expires=${this.expires.toUTCString()}`;
        }
        if (this.domain) {
            header += `; domain=${this.domain}`;
        }
        if (this.sameSite) {
            header += `; samesite=${this.sameSite === true ? "strict" : this.sameSite.toLowerCase()}`;
        }
        if (this.secure) {
            header += "; secure";
        }
        if (this.httpOnly) {
            header += "; httponly";
        }
        return header;
    }
    toString() {
        return `${this.name}=${this.value}`;
    }
}
class Cookies {
    #cookieKeys;
    #keys;
    #request;
    #response;
    #secure;
    #requestKeys=()=>{
        if (this.#cookieKeys) {
            return this.#cookieKeys;
        }
        const result = this.#cookieKeys = [];
        const header = this.#request.headers.get("cookie");
        if (!header) {
            return result;
        }
        let matches;
        while(matches = KEY_REGEXP.exec(header)){
            const [, key] = matches;
            result.push(key);
        }
        return result;
    };
    constructor(request, response, options1 = {
    }){
        const { keys: keys2 , secure  } = options1;
        this.#keys = keys2;
        this.#request = request;
        this.#response = response;
        this.#secure = secure;
    }
    delete(name, options = {
    }) {
        this.set(name, null, options);
        return true;
    }
    *entries() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                yield [
                    key,
                    value1
                ];
            }
        }
    }
    forEach(callback, thisArg = null) {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                callback.call(thisArg, key, value1, this);
            }
        }
    }
    get(name, options = {
    }) {
        const signed = options.signed ?? !!this.#keys;
        const nameSig = `${name}.sig`;
        const header = this.#request.headers.get("cookie");
        if (!header) {
            return;
        }
        const match = header.match(getPattern(name));
        if (!match) {
            return;
        }
        const [, value1] = match;
        if (!signed) {
            return value1;
        }
        const digest = this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return;
        }
        const data = `${name}=${value1}`;
        if (!this.#keys) {
            throw new TypeError("keys required for signed cookies");
        }
        const index = this.#keys.indexOf(data, digest);
        if (index < 0) {
            this.delete(nameSig, {
                path: "/",
                signed: false
            });
        } else {
            if (index) {
                this.set(nameSig, this.#keys.sign(data), {
                    signed: false
                });
            }
            return value1;
        }
    }
    *keys() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value1 = this.get(key);
            if (value1) {
                yield key;
            }
        }
    }
    set(name, value, options = {
    }) {
        const request1 = this.#request;
        const response1 = this.#response;
        let headers = response1.headers.get("Set-Cookie") ?? [];
        if (typeof headers === "string") {
            headers = [
                headers
            ];
        }
        const secure1 = this.#secure !== undefined ? this.#secure : request1.secure;
        const signed = options.signed ?? !!this.#keys;
        if (!secure1 && options.secure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(name, value, options);
        cookie.secure = options.secure ?? secure1;
        pushCookie(headers, cookie);
        if (signed) {
            if (!this.#keys) {
                throw new TypeError(".keys required for signed cookies.");
            }
            cookie.value = this.#keys.sign(cookie.toString());
            cookie.name += ".sig";
            pushCookie(headers, cookie);
        }
        for (const header of headers){
            response1.headers.append("Set-Cookie", header);
        }
        return this;
    }
    *values() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value2 = this.get(key);
            if (value2) {
                yield value2;
            }
        }
    }
    *[Symbol.iterator]() {
        const keys1 = this.#requestKeys();
        for (const key of keys1){
            const value2 = this.get(key);
            if (value2) {
                yield [
                    key,
                    value2
                ];
            }
        }
    }
}
function findIndex(source, pat) {
    const s = pat[0];
    for(let i = 0; i < source.length; i++){
        if (source[i] !== s) continue;
        const pin = i;
        let matched = 1;
        let j = i;
        while(matched < pat.length){
            j++;
            if (source[j] !== pat[j - i]) {
                break;
            }
            matched++;
        }
        if (matched === pat.length) {
            return i;
        }
    }
    return -1;
}
function equal(source, match) {
    if (source.length !== match.length) return false;
    for(let i = 0; i < match.length; i++){
        if (source[i] !== match[i]) return false;
    }
    return true;
}
function concat(origin, b) {
    const output = new Uint8Array(origin.length + b.length);
    output.set(origin, 0);
    output.set(b, origin.length);
    return output;
}
function copyBytes(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
const HEX_CHARS = "0123456789abcdef".split("");
const EXTRA = [
    -2147483648,
    8388608,
    32768,
    128
];
const SHIFT = [
    24,
    16,
    8,
    0
];
const blocks = [];
class Sha1 {
    #blocks;
    #block;
    #start;
    #bytes;
    #hBytes;
    #finalized;
    #hashed;
    #h0=1732584193;
    #h1=4023233417;
    #h2=2562383102;
    #h3=271733878;
    #h4=3285377520;
    #lastByteIndex=0;
    constructor(sharedMemory2 = false){
        if (sharedMemory2) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            this.#blocks = blocks;
        } else {
            this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ];
        }
        this.#h0 = 1732584193;
        this.#h1 = 4023233417;
        this.#h2 = 2562383102;
        this.#h3 = 271733878;
        this.#h4 = 3285377520;
        this.#block = this.#start = this.#bytes = this.#hBytes = 0;
        this.#finalized = this.#hashed = false;
    }
    update(message) {
        if (this.#finalized) {
            return this;
        }
        let msg;
        if (message instanceof ArrayBuffer) {
            msg = new Uint8Array(message);
        } else {
            msg = message;
        }
        let index = 0;
        const length = msg.length;
        const blocks1 = this.#blocks;
        while(index < length){
            let i;
            if (this.#hashed) {
                this.#hashed = false;
                blocks1[0] = this.#block;
                blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
            }
            if (typeof msg !== "string") {
                for(i = this.#start; index < length && i < 64; ++index){
                    blocks1[i >> 2] |= msg[index] << SHIFT[(i++) & 3];
                }
            } else {
                for(i = this.#start; index < length && i < 64; ++index){
                    let code = msg.charCodeAt(index);
                    if (code < 128) {
                        blocks1[i >> 2] |= code << SHIFT[(i++) & 3];
                    } else if (code < 2048) {
                        blocks1[i >> 2] |= (192 | code >> 6) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    } else if (code < 55296 || code >= 57344) {
                        blocks1[i >> 2] |= (224 | code >> 12) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    } else {
                        code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
                        blocks1[i >> 2] |= (240 | code >> 18) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 12 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[(i++) & 3];
                        blocks1[i >> 2] |= (128 | code & 63) << SHIFT[(i++) & 3];
                    }
                }
            }
            this.#lastByteIndex = i;
            this.#bytes += i - this.#start;
            if (i >= 64) {
                this.#block = blocks1[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
            } else {
                this.#start = i;
            }
        }
        if (this.#bytes > 4294967295) {
            this.#hBytes += this.#bytes / 4294967296 >>> 0;
            this.#bytes = this.#bytes >>> 0;
        }
        return this;
    }
    finalize() {
        if (this.#finalized) {
            return;
        }
        this.#finalized = true;
        const blocks1 = this.#blocks;
        const i = this.#lastByteIndex;
        blocks1[16] = this.#block;
        blocks1[i >> 2] |= EXTRA[i & 3];
        this.#block = blocks1[16];
        if (i >= 56) {
            if (!this.#hashed) {
                this.hash();
            }
            blocks1[0] = this.#block;
            blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
        }
        blocks1[14] = this.#hBytes << 3 | this.#bytes >>> 29;
        blocks1[15] = this.#bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f;
        let j;
        let t;
        const blocks1 = this.#blocks;
        for(j = 16; j < 80; ++j){
            t = blocks1[j - 3] ^ blocks1[j - 8] ^ blocks1[j - 14] ^ blocks1[j - 16];
            blocks1[j] = t << 1 | t >>> 31;
        }
        for(j = 0; j < 20; j += 5){
            f = b & c | ~b & d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1518500249 + blocks1[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | ~a & c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1518500249 + blocks1[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | ~e & b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1518500249 + blocks1[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | ~d & a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1518500249 + blocks1[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | ~c & e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1518500249 + blocks1[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 40; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e + 1859775393 + blocks1[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d + 1859775393 + blocks1[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c + 1859775393 + blocks1[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b + 1859775393 + blocks1[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a + 1859775393 + blocks1[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 60; j += 5){
            f = b & c | b & d | c & d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 1894007588 + blocks1[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a & b | a & c | b & c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 1894007588 + blocks1[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e & a | e & b | a & b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 1894007588 + blocks1[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d & e | d & a | e & a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 1894007588 + blocks1[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c & d | c & e | d & e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 1894007588 + blocks1[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        for(; j < 80; j += 5){
            f = b ^ c ^ d;
            t = a << 5 | a >>> 27;
            e = t + f + e - 899497514 + blocks1[j] >>> 0;
            b = b << 30 | b >>> 2;
            f = a ^ b ^ c;
            t = e << 5 | e >>> 27;
            d = t + f + d - 899497514 + blocks1[j + 1] >>> 0;
            a = a << 30 | a >>> 2;
            f = e ^ a ^ b;
            t = d << 5 | d >>> 27;
            c = t + f + c - 899497514 + blocks1[j + 2] >>> 0;
            e = e << 30 | e >>> 2;
            f = d ^ e ^ a;
            t = c << 5 | c >>> 27;
            b = t + f + b - 899497514 + blocks1[j + 3] >>> 0;
            d = d << 30 | d >>> 2;
            f = c ^ d ^ e;
            t = b << 5 | b >>> 27;
            a = t + f + a - 899497514 + blocks1[j + 4] >>> 0;
            c = c << 30 | c >>> 2;
        }
        this.#h0 = this.#h0 + a >>> 0;
        this.#h1 = this.#h1 + b >>> 0;
        this.#h2 = this.#h2 + c >>> 0;
        this.#h3 = this.#h3 + d >>> 0;
        this.#h4 = this.#h4 + e >>> 0;
    }
    hex() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return HEX_CHARS[h0 >> 28 & 15] + HEX_CHARS[h0 >> 24 & 15] + HEX_CHARS[h0 >> 20 & 15] + HEX_CHARS[h0 >> 16 & 15] + HEX_CHARS[h0 >> 12 & 15] + HEX_CHARS[h0 >> 8 & 15] + HEX_CHARS[h0 >> 4 & 15] + HEX_CHARS[h0 & 15] + HEX_CHARS[h1 >> 28 & 15] + HEX_CHARS[h1 >> 24 & 15] + HEX_CHARS[h1 >> 20 & 15] + HEX_CHARS[h1 >> 16 & 15] + HEX_CHARS[h1 >> 12 & 15] + HEX_CHARS[h1 >> 8 & 15] + HEX_CHARS[h1 >> 4 & 15] + HEX_CHARS[h1 & 15] + HEX_CHARS[h2 >> 28 & 15] + HEX_CHARS[h2 >> 24 & 15] + HEX_CHARS[h2 >> 20 & 15] + HEX_CHARS[h2 >> 16 & 15] + HEX_CHARS[h2 >> 12 & 15] + HEX_CHARS[h2 >> 8 & 15] + HEX_CHARS[h2 >> 4 & 15] + HEX_CHARS[h2 & 15] + HEX_CHARS[h3 >> 28 & 15] + HEX_CHARS[h3 >> 24 & 15] + HEX_CHARS[h3 >> 20 & 15] + HEX_CHARS[h3 >> 16 & 15] + HEX_CHARS[h3 >> 12 & 15] + HEX_CHARS[h3 >> 8 & 15] + HEX_CHARS[h3 >> 4 & 15] + HEX_CHARS[h3 & 15] + HEX_CHARS[h4 >> 28 & 15] + HEX_CHARS[h4 >> 24 & 15] + HEX_CHARS[h4 >> 20 & 15] + HEX_CHARS[h4 >> 16 & 15] + HEX_CHARS[h4 >> 12 & 15] + HEX_CHARS[h4 >> 8 & 15] + HEX_CHARS[h4 >> 4 & 15] + HEX_CHARS[h4 & 15];
    }
    toString() {
        return this.hex();
    }
    digest() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        return [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255, 
        ];
    }
    array() {
        return this.digest();
    }
    arrayBuffer() {
        this.finalize();
        const buffer = new ArrayBuffer(20);
        const dataView = new DataView(buffer);
        dataView.setUint32(0, this.#h0);
        dataView.setUint32(4, this.#h1);
        dataView.setUint32(8, this.#h2);
        dataView.setUint32(12, this.#h3);
        dataView.setUint32(16, this.#h4);
        return buffer;
    }
}
const HEX_CHARS1 = "0123456789abcdef".split("");
const EXTRA1 = [
    -2147483648,
    8388608,
    32768,
    128
];
const SHIFT1 = [
    24,
    16,
    8,
    0
];
const K = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298, 
];
const blocks1 = [];
class Sha256 {
    #block;
    #blocks;
    #bytes;
    #finalized;
    #first;
    #h0;
    #h1;
    #h2;
    #h3;
    #h4;
    #h5;
    #h6;
    #h7;
    #hashed;
    #hBytes;
    #is224;
    #lastByteIndex=0;
    #start;
    constructor(is2241 = false, sharedMemory1 = false){
        this.init(is2241, sharedMemory1);
    }
    init(is224, sharedMemory) {
        if (sharedMemory) {
            blocks1[0] = blocks1[16] = blocks1[1] = blocks1[2] = blocks1[3] = blocks1[4] = blocks1[5] = blocks1[6] = blocks1[7] = blocks1[8] = blocks1[9] = blocks1[10] = blocks1[11] = blocks1[12] = blocks1[13] = blocks1[14] = blocks1[15] = 0;
            this.#blocks = blocks1;
        } else {
            this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ];
        }
        if (is224) {
            this.#h0 = 3238371032;
            this.#h1 = 914150663;
            this.#h2 = 812702999;
            this.#h3 = 4144912697;
            this.#h4 = 4290775857;
            this.#h5 = 1750603025;
            this.#h6 = 1694076839;
            this.#h7 = 3204075428;
        } else {
            this.#h0 = 1779033703;
            this.#h1 = 3144134277;
            this.#h2 = 1013904242;
            this.#h3 = 2773480762;
            this.#h4 = 1359893119;
            this.#h5 = 2600822924;
            this.#h6 = 528734635;
            this.#h7 = 1541459225;
        }
        this.#block = this.#start = this.#bytes = this.#hBytes = 0;
        this.#finalized = this.#hashed = false;
        this.#first = true;
        this.#is224 = is224;
    }
    update(message) {
        if (this.#finalized) {
            return this;
        }
        let msg;
        if (message instanceof ArrayBuffer) {
            msg = new Uint8Array(message);
        } else {
            msg = message;
        }
        let index = 0;
        const length = msg.length;
        const blocks2 = this.#blocks;
        while(index < length){
            let i;
            if (this.#hashed) {
                this.#hashed = false;
                blocks2[0] = this.#block;
                blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
            }
            if (typeof msg !== "string") {
                for(i = this.#start; index < length && i < 64; ++index){
                    blocks2[i >> 2] |= msg[index] << SHIFT1[(i++) & 3];
                }
            } else {
                for(i = this.#start; index < length && i < 64; ++index){
                    let code = msg.charCodeAt(index);
                    if (code < 128) {
                        blocks2[i >> 2] |= code << SHIFT1[(i++) & 3];
                    } else if (code < 2048) {
                        blocks2[i >> 2] |= (192 | code >> 6) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code & 63) << SHIFT1[(i++) & 3];
                    } else if (code < 55296 || code >= 57344) {
                        blocks2[i >> 2] |= (224 | code >> 12) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code & 63) << SHIFT1[(i++) & 3];
                    } else {
                        code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
                        blocks2[i >> 2] |= (240 | code >> 18) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code >> 12 & 63) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT1[(i++) & 3];
                        blocks2[i >> 2] |= (128 | code & 63) << SHIFT1[(i++) & 3];
                    }
                }
            }
            this.#lastByteIndex = i;
            this.#bytes += i - this.#start;
            if (i >= 64) {
                this.#block = blocks2[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
            } else {
                this.#start = i;
            }
        }
        if (this.#bytes > 4294967295) {
            this.#hBytes += this.#bytes / 4294967296 << 0;
            this.#bytes = this.#bytes % 4294967296;
        }
        return this;
    }
    finalize() {
        if (this.#finalized) {
            return;
        }
        this.#finalized = true;
        const blocks2 = this.#blocks;
        const i = this.#lastByteIndex;
        blocks2[16] = this.#block;
        blocks2[i >> 2] |= EXTRA1[i & 3];
        this.#block = blocks2[16];
        if (i >= 56) {
            if (!this.#hashed) {
                this.hash();
            }
            blocks2[0] = this.#block;
            blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
        }
        blocks2[14] = this.#hBytes << 3 | this.#bytes >>> 29;
        blocks2[15] = this.#bytes << 3;
        this.hash();
    }
    hash() {
        let a = this.#h0;
        let b = this.#h1;
        let c = this.#h2;
        let d = this.#h3;
        let e = this.#h4;
        let f = this.#h5;
        let g = this.#h6;
        let h = this.#h7;
        const blocks2 = this.#blocks;
        let s0;
        let s1;
        let maj;
        let t1;
        let t2;
        let ch;
        let ab;
        let da;
        let cd;
        let bc;
        for(let j = 16; j < 64; ++j){
            t1 = blocks2[j - 15];
            s0 = (t1 >>> 7 | t1 << 25) ^ (t1 >>> 18 | t1 << 14) ^ t1 >>> 3;
            t1 = blocks2[j - 2];
            s1 = (t1 >>> 17 | t1 << 15) ^ (t1 >>> 19 | t1 << 13) ^ t1 >>> 10;
            blocks2[j] = blocks2[j - 16] + s0 + blocks2[j - 7] + s1 << 0;
        }
        bc = b & c;
        for(let j1 = 0; j1 < 64; j1 += 4){
            if (this.#first) {
                if (this.#is224) {
                    ab = 300032;
                    t1 = blocks2[0] - 1413257819;
                    h = t1 - 150054599 << 0;
                    d = t1 + 24177077 << 0;
                } else {
                    ab = 704751109;
                    t1 = blocks2[0] - 210244248;
                    h = t1 - 1521486534 << 0;
                    d = t1 + 143694565 << 0;
                }
                this.#first = false;
            } else {
                s0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
                s1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
                ab = a & b;
                maj = ab ^ a & c ^ bc;
                ch = e & f ^ ~e & g;
                t1 = h + s1 + ch + K[j1] + blocks2[j1];
                t2 = s0 + maj;
                h = d + t1 << 0;
                d = t1 + t2 << 0;
            }
            s0 = (d >>> 2 | d << 30) ^ (d >>> 13 | d << 19) ^ (d >>> 22 | d << 10);
            s1 = (h >>> 6 | h << 26) ^ (h >>> 11 | h << 21) ^ (h >>> 25 | h << 7);
            da = d & a;
            maj = da ^ d & b ^ ab;
            ch = h & e ^ ~h & f;
            t1 = g + s1 + ch + K[j1 + 1] + blocks2[j1 + 1];
            t2 = s0 + maj;
            g = c + t1 << 0;
            c = t1 + t2 << 0;
            s0 = (c >>> 2 | c << 30) ^ (c >>> 13 | c << 19) ^ (c >>> 22 | c << 10);
            s1 = (g >>> 6 | g << 26) ^ (g >>> 11 | g << 21) ^ (g >>> 25 | g << 7);
            cd = c & d;
            maj = cd ^ c & a ^ da;
            ch = g & h ^ ~g & e;
            t1 = f + s1 + ch + K[j1 + 2] + blocks2[j1 + 2];
            t2 = s0 + maj;
            f = b + t1 << 0;
            b = t1 + t2 << 0;
            s0 = (b >>> 2 | b << 30) ^ (b >>> 13 | b << 19) ^ (b >>> 22 | b << 10);
            s1 = (f >>> 6 | f << 26) ^ (f >>> 11 | f << 21) ^ (f >>> 25 | f << 7);
            bc = b & c;
            maj = bc ^ b & d ^ cd;
            ch = f & g ^ ~f & h;
            t1 = e + s1 + ch + K[j1 + 3] + blocks2[j1 + 3];
            t2 = s0 + maj;
            e = a + t1 << 0;
            a = t1 + t2 << 0;
        }
        this.#h0 = this.#h0 + a << 0;
        this.#h1 = this.#h1 + b << 0;
        this.#h2 = this.#h2 + c << 0;
        this.#h3 = this.#h3 + d << 0;
        this.#h4 = this.#h4 + e << 0;
        this.#h5 = this.#h5 + f << 0;
        this.#h6 = this.#h6 + g << 0;
        this.#h7 = this.#h7 + h << 0;
    }
    hex() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        const h5 = this.#h5;
        const h6 = this.#h6;
        const h7 = this.#h7;
        let hex = HEX_CHARS1[h0 >> 28 & 15] + HEX_CHARS1[h0 >> 24 & 15] + HEX_CHARS1[h0 >> 20 & 15] + HEX_CHARS1[h0 >> 16 & 15] + HEX_CHARS1[h0 >> 12 & 15] + HEX_CHARS1[h0 >> 8 & 15] + HEX_CHARS1[h0 >> 4 & 15] + HEX_CHARS1[h0 & 15] + HEX_CHARS1[h1 >> 28 & 15] + HEX_CHARS1[h1 >> 24 & 15] + HEX_CHARS1[h1 >> 20 & 15] + HEX_CHARS1[h1 >> 16 & 15] + HEX_CHARS1[h1 >> 12 & 15] + HEX_CHARS1[h1 >> 8 & 15] + HEX_CHARS1[h1 >> 4 & 15] + HEX_CHARS1[h1 & 15] + HEX_CHARS1[h2 >> 28 & 15] + HEX_CHARS1[h2 >> 24 & 15] + HEX_CHARS1[h2 >> 20 & 15] + HEX_CHARS1[h2 >> 16 & 15] + HEX_CHARS1[h2 >> 12 & 15] + HEX_CHARS1[h2 >> 8 & 15] + HEX_CHARS1[h2 >> 4 & 15] + HEX_CHARS1[h2 & 15] + HEX_CHARS1[h3 >> 28 & 15] + HEX_CHARS1[h3 >> 24 & 15] + HEX_CHARS1[h3 >> 20 & 15] + HEX_CHARS1[h3 >> 16 & 15] + HEX_CHARS1[h3 >> 12 & 15] + HEX_CHARS1[h3 >> 8 & 15] + HEX_CHARS1[h3 >> 4 & 15] + HEX_CHARS1[h3 & 15] + HEX_CHARS1[h4 >> 28 & 15] + HEX_CHARS1[h4 >> 24 & 15] + HEX_CHARS1[h4 >> 20 & 15] + HEX_CHARS1[h4 >> 16 & 15] + HEX_CHARS1[h4 >> 12 & 15] + HEX_CHARS1[h4 >> 8 & 15] + HEX_CHARS1[h4 >> 4 & 15] + HEX_CHARS1[h4 & 15] + HEX_CHARS1[h5 >> 28 & 15] + HEX_CHARS1[h5 >> 24 & 15] + HEX_CHARS1[h5 >> 20 & 15] + HEX_CHARS1[h5 >> 16 & 15] + HEX_CHARS1[h5 >> 12 & 15] + HEX_CHARS1[h5 >> 8 & 15] + HEX_CHARS1[h5 >> 4 & 15] + HEX_CHARS1[h5 & 15] + HEX_CHARS1[h6 >> 28 & 15] + HEX_CHARS1[h6 >> 24 & 15] + HEX_CHARS1[h6 >> 20 & 15] + HEX_CHARS1[h6 >> 16 & 15] + HEX_CHARS1[h6 >> 12 & 15] + HEX_CHARS1[h6 >> 8 & 15] + HEX_CHARS1[h6 >> 4 & 15] + HEX_CHARS1[h6 & 15];
        if (!this.#is224) {
            hex += HEX_CHARS1[h7 >> 28 & 15] + HEX_CHARS1[h7 >> 24 & 15] + HEX_CHARS1[h7 >> 20 & 15] + HEX_CHARS1[h7 >> 16 & 15] + HEX_CHARS1[h7 >> 12 & 15] + HEX_CHARS1[h7 >> 8 & 15] + HEX_CHARS1[h7 >> 4 & 15] + HEX_CHARS1[h7 & 15];
        }
        return hex;
    }
    toString() {
        return this.hex();
    }
    digest() {
        this.finalize();
        const h0 = this.#h0;
        const h1 = this.#h1;
        const h2 = this.#h2;
        const h3 = this.#h3;
        const h4 = this.#h4;
        const h5 = this.#h5;
        const h6 = this.#h6;
        const h7 = this.#h7;
        const arr = [
            h0 >> 24 & 255,
            h0 >> 16 & 255,
            h0 >> 8 & 255,
            h0 & 255,
            h1 >> 24 & 255,
            h1 >> 16 & 255,
            h1 >> 8 & 255,
            h1 & 255,
            h2 >> 24 & 255,
            h2 >> 16 & 255,
            h2 >> 8 & 255,
            h2 & 255,
            h3 >> 24 & 255,
            h3 >> 16 & 255,
            h3 >> 8 & 255,
            h3 & 255,
            h4 >> 24 & 255,
            h4 >> 16 & 255,
            h4 >> 8 & 255,
            h4 & 255,
            h5 >> 24 & 255,
            h5 >> 16 & 255,
            h5 >> 8 & 255,
            h5 & 255,
            h6 >> 24 & 255,
            h6 >> 16 & 255,
            h6 >> 8 & 255,
            h6 & 255, 
        ];
        if (!this.#is224) {
            arr.push(h7 >> 24 & 255, h7 >> 16 & 255, h7 >> 8 & 255, h7 & 255);
        }
        return arr;
    }
    array() {
        return this.digest();
    }
    arrayBuffer() {
        this.finalize();
        const buffer = new ArrayBuffer(this.#is224 ? 28 : 32);
        const dataView = new DataView(buffer);
        dataView.setUint32(0, this.#h0);
        dataView.setUint32(4, this.#h1);
        dataView.setUint32(8, this.#h2);
        dataView.setUint32(12, this.#h3);
        dataView.setUint32(16, this.#h4);
        dataView.setUint32(20, this.#h5);
        dataView.setUint32(24, this.#h6);
        if (!this.#is224) {
            dataView.setUint32(28, this.#h7);
        }
        return buffer;
    }
}
class HmacSha256 extends Sha256 {
    #inner;
    #is224;
    #oKeyPad;
    #sharedMemory;
    constructor(secretKey, is2242 = false, sharedMemory3 = false){
        super(is2242, sharedMemory3);
        let key;
        if (typeof secretKey === "string") {
            const bytes = [];
            const length = secretKey.length;
            let index = 0;
            for(let i = 0; i < length; ++i){
                let code = secretKey.charCodeAt(i);
                if (code < 128) {
                    bytes[index++] = code;
                } else if (code < 2048) {
                    bytes[index++] = 192 | code >> 6;
                    bytes[index++] = 128 | code & 63;
                } else if (code < 55296 || code >= 57344) {
                    bytes[index++] = 224 | code >> 12;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                } else {
                    code = 65536 + ((code & 1023) << 10 | secretKey.charCodeAt(++i) & 1023);
                    bytes[index++] = 240 | code >> 18;
                    bytes[index++] = 128 | code >> 12 & 63;
                    bytes[index++] = 128 | code >> 6 & 63;
                    bytes[index++] = 128 | code & 63;
                }
            }
            key = bytes;
        } else {
            if (secretKey instanceof ArrayBuffer) {
                key = new Uint8Array(secretKey);
            } else {
                key = secretKey;
            }
        }
        if (key.length > 64) {
            key = new Sha256(is2242, true).update(key).array();
        }
        const oKeyPad = [];
        const iKeyPad = [];
        for(let i = 0; i < 64; ++i){
            const b = key[i] || 0;
            oKeyPad[i] = 92 ^ b;
            iKeyPad[i] = 54 ^ b;
        }
        this.update(iKeyPad);
        this.#oKeyPad = oKeyPad;
        this.#inner = true;
        this.#is224 = is2242;
        this.#sharedMemory = sharedMemory3;
    }
    finalize() {
        super.finalize();
        if (this.#inner) {
            this.#inner = false;
            const innerHash = this.array();
            super.init(this.#is224, this.#sharedMemory);
            this.update(this.#oKeyPad);
            this.update(innerHash);
            super.finalize();
        }
    }
}
var DiffType;
(function(DiffType1) {
    DiffType1["removed"] = "removed";
    DiffType1["common"] = "common";
    DiffType1["added"] = "added";
})(DiffType || (DiffType = {
}));
function createCommon(A, B, reverse) {
    const common = [];
    if (A.length === 0 || B.length === 0) return [];
    for(let i1 = 0; i1 < Math.min(A.length, B.length); i1 += 1){
        if (A[reverse ? A.length - i1 - 1 : i1] === B[reverse ? B.length - i1 - 1 : i1]) {
            common.push(A[reverse ? A.length - i1 - 1 : i1]);
        } else {
            return common;
        }
    }
    return common;
}
function diff(A, B) {
    const prefixCommon = createCommon(A, B);
    const suffixCommon = createCommon(A.slice(prefixCommon.length), B.slice(prefixCommon.length), true).reverse();
    A = suffixCommon.length ? A.slice(prefixCommon.length, -suffixCommon.length) : A.slice(prefixCommon.length);
    B = suffixCommon.length ? B.slice(prefixCommon.length, -suffixCommon.length) : B.slice(prefixCommon.length);
    const swapped = B.length > A.length;
    [A, B] = swapped ? [
        B,
        A
    ] : [
        A,
        B
    ];
    const M = A.length;
    const N = B.length;
    if (!M && !N && !suffixCommon.length && !prefixCommon.length) return [];
    if (!N) {
        return [
            ...prefixCommon.map((c)=>({
                    type: DiffType.common,
                    value: c
                })
            ),
            ...A.map((a)=>({
                    type: swapped ? DiffType.added : DiffType.removed,
                    value: a
                })
            ),
            ...suffixCommon.map((c)=>({
                    type: DiffType.common,
                    value: c
                })
            ), 
        ];
    }
    const offset = N;
    const delta = M - N;
    const size = M + N + 1;
    const fp = new Array(size).fill({
        y: -1
    });
    const routes = new Uint32Array((M * N + size + 1) * 2);
    const diffTypesPtrOffset = routes.length / 2;
    let ptr = 0;
    let p = -1;
    function backTrace(A1, B1, current, swapped1) {
        const M1 = A1.length;
        const N1 = B1.length;
        const result = [];
        let a = M1 - 1;
        let b = N1 - 1;
        let j = routes[current.id];
        let type = routes[current.id + diffTypesPtrOffset];
        while(true){
            if (!j && !type) break;
            const prev = j;
            if (type === 1) {
                result.unshift({
                    type: swapped1 ? DiffType.removed : DiffType.added,
                    value: B1[b]
                });
                b -= 1;
            } else if (type === 3) {
                result.unshift({
                    type: swapped1 ? DiffType.added : DiffType.removed,
                    value: A1[a]
                });
                a -= 1;
            } else {
                result.unshift({
                    type: DiffType.common,
                    value: A1[a]
                });
                a -= 1;
                b -= 1;
            }
            j = routes[j];
            type = routes[j + diffTypesPtrOffset];
        }
        return result;
    }
    function createFP(slide, down, k, M1) {
        if (slide && slide.y === -1 && down && down.y === -1) {
            return {
                y: 0,
                id: 0
            };
        }
        if (down && down.y === -1 || k === M1 || (slide && slide.y) > (down && down.y) + 1) {
            const prev = slide.id;
            ptr++;
            routes[ptr] = prev;
            routes[ptr + diffTypesPtrOffset] = 3;
            return {
                y: slide.y,
                id: ptr
            };
        } else {
            const prev = down.id;
            ptr++;
            routes[ptr] = prev;
            routes[ptr + diffTypesPtrOffset] = 1;
            return {
                y: down.y + 1,
                id: ptr
            };
        }
    }
    function snake(k, slide, down, _offset, A1, B1) {
        const M1 = A1.length;
        const N1 = B1.length;
        if (k < -N1 || M1 < k) return {
            y: -1,
            id: -1
        };
        const fp1 = createFP(slide, down, k, M1);
        while(fp1.y + k < M1 && fp1.y < N1 && A1[fp1.y + k] === B1[fp1.y]){
            const prev = fp1.id;
            ptr++;
            fp1.id = ptr;
            fp1.y += 1;
            routes[ptr] = prev;
            routes[ptr + diffTypesPtrOffset] = 2;
        }
        return fp1;
    }
    while(fp[delta + N].y < N){
        p = p + 1;
        for(let k = -p; k < delta; ++k){
            fp[k + N] = snake(k, fp[k - 1 + N], fp[k + 1 + N], N, A, B);
        }
        for(let k1 = delta + p; k1 > delta; --k1){
            fp[k1 + N] = snake(k1, fp[k1 - 1 + N], fp[k1 + 1 + N], N, A, B);
        }
        fp[delta + N] = snake(delta, fp[delta - 1 + N], fp[delta + 1 + N], N, A, B);
    }
    return [
        ...prefixCommon.map((c)=>({
                type: DiffType.common,
                value: c
            })
        ),
        ...backTrace(A, B, fp[delta + N], swapped),
        ...suffixCommon.map((c)=>({
                type: DiffType.common,
                value: c
            })
        ), 
    ];
}
const CAN_NOT_DISPLAY = "[Cannot display]";
function _format(v) {
    return globalThis.Deno ? Deno.inspect(v, {
        depth: Infinity,
        sorted: true,
        trailingComma: true,
        compact: false,
        iterableLimit: Infinity
    }) : `"${String(v).replace(/(?=["\\])/g, "\\")}"`;
}
function createSign(diffType) {
    switch(diffType){
        case DiffType.added:
            return "+   ";
        case DiffType.removed:
            return "-   ";
        default:
            return "    ";
    }
}
function isKeyedCollection(x) {
    return [
        Symbol.iterator,
        "size"
    ].every((k)=>k in x
    );
}
function equal1(c, d) {
    const seen = new Map();
    return (function compare(a, b) {
        if (a && b && (a instanceof RegExp && b instanceof RegExp || a instanceof URL && b instanceof URL)) {
            return String(a) === String(b);
        }
        if (a instanceof Date && b instanceof Date) {
            const aTime = a.getTime();
            const bTime = b.getTime();
            if (Number.isNaN(aTime) && Number.isNaN(bTime)) {
                return true;
            }
            return a.getTime() === b.getTime();
        }
        if (Object.is(a, b)) {
            return true;
        }
        if (a && typeof a === "object" && b && typeof b === "object") {
            if (seen.get(a) === b) {
                return true;
            }
            if (Object.keys(a || {
            }).length !== Object.keys(b || {
            }).length) {
                return false;
            }
            if (isKeyedCollection(a) && isKeyedCollection(b)) {
                if (a.size !== b.size) {
                    return false;
                }
                let unmatchedEntries = a.size;
                for (const [aKey, aValue] of a.entries()){
                    for (const [bKey, bValue] of b.entries()){
                        if (aKey === aValue && bKey === bValue && compare(aKey, bKey) || compare(aKey, bKey) && compare(aValue, bValue)) {
                            unmatchedEntries--;
                        }
                    }
                }
                return unmatchedEntries === 0;
            }
            const merged = {
                ...a,
                ...b
            };
            for(const key1 in merged){
                if (!compare(a && a[key1], b && b[key1])) {
                    return false;
                }
            }
            seen.set(a, b);
            return true;
        }
        return false;
    })(c, d);
}
function assert(expr, msg = "") {
    if (!expr) {
        throw new AssertionError(msg);
    }
}
function hasOwnProperty(obj, v) {
    if (obj == null) {
        return false;
    }
    return Object.prototype.hasOwnProperty.call(obj, v);
}
const DEFAULT_BUFFER_SIZE = 32 * 1024;
async function readShort(buf) {
    const high = await buf.readByte();
    if (high === null) return null;
    const low = await buf.readByte();
    if (low === null) throw new Deno.errors.UnexpectedEof();
    return high << 8 | low;
}
async function readInt(buf) {
    const high = await readShort(buf);
    if (high === null) return null;
    const low = await readShort(buf);
    if (low === null) throw new Deno.errors.UnexpectedEof();
    return high << 16 | low;
}
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
async function readLong(buf) {
    const high = await readInt(buf);
    if (high === null) return null;
    const low = await readInt(buf);
    if (low === null) throw new Deno.errors.UnexpectedEof();
    const big = BigInt(high) << 32n | BigInt(low);
    if (big > MAX_SAFE_INTEGER) {
        throw new RangeError("Long value too big to be represented as a JavaScript number.");
    }
    return Number(big);
}
function sliceLongToBytes(d, dest = new Array(8)) {
    let big = BigInt(d);
    for(let i1 = 0; i1 < 8; i1++){
        dest[7 - i1] = Number(big & 255n);
        big >>= 8n;
    }
    return dest;
}
const invalidHeaderCharRegex = /[^\t\x20-\x7e\x80-\xff]/g;
function charCode(s) {
    return s.charCodeAt(0);
}
var OpCode;
(function(OpCode1) {
    OpCode1[OpCode1["Continue"] = 0] = "Continue";
    OpCode1[OpCode1["TextFrame"] = 1] = "TextFrame";
    OpCode1[OpCode1["BinaryFrame"] = 2] = "BinaryFrame";
    OpCode1[OpCode1["Close"] = 8] = "Close";
    OpCode1[OpCode1["Ping"] = 9] = "Ping";
    OpCode1[OpCode1["Pong"] = 10] = "Pong";
})(OpCode || (OpCode = {
}));
function unmask(payload, mask) {
    if (mask) {
        for(let i1 = 0, len = payload.length; i1 < len; i1++){
            payload[i1] ^= mask[i1 & 3];
        }
    }
}
function acceptable(req) {
    const upgrade = req.headers.get("upgrade");
    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
        return false;
    }
    const secKey = req.headers.get("sec-websocket-key");
    return req.headers.has("sec-websocket-key") && typeof secKey === "string" && secKey.length > 0;
}
const kGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
function createSecAccept(nonce) {
    const sha1 = new Sha1();
    sha1.update(nonce + kGUID);
    const bytes = sha1.digest();
    return btoa(String.fromCharCode(...bytes));
}
const kSecChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-.~_";
function createSecKey() {
    let key1 = "";
    for(let i1 = 0; i1 < 16; i1++){
        const j = Math.floor(Math.random() * kSecChars.length);
        key1 += kSecChars[j];
    }
    return btoa(key1);
}
const db = JSON.parse(`{\n  "application/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "application/3gpdash-qoe-report+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/3gpp-ims+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/a2l": {\n    "source": "iana"\n  },\n  "application/activemessage": {\n    "source": "iana"\n  },\n  "application/activity+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-costmap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-costmapfilter+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-directory+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointcost+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointcostparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointprop+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-endpointpropparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-error+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-networkmap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-networkmapfilter+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-updatestreamcontrol+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/alto-updatestreamparams+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/aml": {\n    "source": "iana"\n  },\n  "application/andrew-inset": {\n    "source": "iana",\n    "extensions": ["ez"]\n  },\n  "application/applefile": {\n    "source": "iana"\n  },\n  "application/applixware": {\n    "source": "apache",\n    "extensions": ["aw"]\n  },\n  "application/atf": {\n    "source": "iana"\n  },\n  "application/atfx": {\n    "source": "iana"\n  },\n  "application/atom+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atom"]\n  },\n  "application/atomcat+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomcat"]\n  },\n  "application/atomdeleted+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomdeleted"]\n  },\n  "application/atomicmail": {\n    "source": "iana"\n  },\n  "application/atomsvc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["atomsvc"]\n  },\n  "application/atsc-dwd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dwd"]\n  },\n  "application/atsc-dynamic-event-message": {\n    "source": "iana"\n  },\n  "application/atsc-held+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["held"]\n  },\n  "application/atsc-rdt+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/atsc-rsat+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rsat"]\n  },\n  "application/atxml": {\n    "source": "iana"\n  },\n  "application/auth-policy+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/bacnet-xdd+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/batch-smtp": {\n    "source": "iana"\n  },\n  "application/bdoc": {\n    "compressible": false,\n    "extensions": ["bdoc"]\n  },\n  "application/beep+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/calendar+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/calendar+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xcs"]\n  },\n  "application/call-completion": {\n    "source": "iana"\n  },\n  "application/cals-1840": {\n    "source": "iana"\n  },\n  "application/captive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cbor": {\n    "source": "iana"\n  },\n  "application/cbor-seq": {\n    "source": "iana"\n  },\n  "application/cccex": {\n    "source": "iana"\n  },\n  "application/ccmp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ccxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ccxml"]\n  },\n  "application/cdfx+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["cdfx"]\n  },\n  "application/cdmi-capability": {\n    "source": "iana",\n    "extensions": ["cdmia"]\n  },\n  "application/cdmi-container": {\n    "source": "iana",\n    "extensions": ["cdmic"]\n  },\n  "application/cdmi-domain": {\n    "source": "iana",\n    "extensions": ["cdmid"]\n  },\n  "application/cdmi-object": {\n    "source": "iana",\n    "extensions": ["cdmio"]\n  },\n  "application/cdmi-queue": {\n    "source": "iana",\n    "extensions": ["cdmiq"]\n  },\n  "application/cdni": {\n    "source": "iana"\n  },\n  "application/cea": {\n    "source": "iana"\n  },\n  "application/cea-2018+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cellml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cfw": {\n    "source": "iana"\n  },\n  "application/clue+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/clue_info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cms": {\n    "source": "iana"\n  },\n  "application/cnrp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/coap-group+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/coap-payload": {\n    "source": "iana"\n  },\n  "application/commonground": {\n    "source": "iana"\n  },\n  "application/conference-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cose": {\n    "source": "iana"\n  },\n  "application/cose-key": {\n    "source": "iana"\n  },\n  "application/cose-key-set": {\n    "source": "iana"\n  },\n  "application/cpl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/csrattrs": {\n    "source": "iana"\n  },\n  "application/csta+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cstadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/csvm+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/cu-seeme": {\n    "source": "apache",\n    "extensions": ["cu"]\n  },\n  "application/cwt": {\n    "source": "iana"\n  },\n  "application/cybercash": {\n    "source": "iana"\n  },\n  "application/dart": {\n    "compressible": true\n  },\n  "application/dash+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mpd"]\n  },\n  "application/dashdelta": {\n    "source": "iana"\n  },\n  "application/davmount+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["davmount"]\n  },\n  "application/dca-rft": {\n    "source": "iana"\n  },\n  "application/dcd": {\n    "source": "iana"\n  },\n  "application/dec-dx": {\n    "source": "iana"\n  },\n  "application/dialog-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dicom": {\n    "source": "iana"\n  },\n  "application/dicom+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dicom+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dii": {\n    "source": "iana"\n  },\n  "application/dit": {\n    "source": "iana"\n  },\n  "application/dns": {\n    "source": "iana"\n  },\n  "application/dns+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dns-message": {\n    "source": "iana"\n  },\n  "application/docbook+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["dbk"]\n  },\n  "application/dots+cbor": {\n    "source": "iana"\n  },\n  "application/dskpp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/dssc+der": {\n    "source": "iana",\n    "extensions": ["dssc"]\n  },\n  "application/dssc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdssc"]\n  },\n  "application/dvcs": {\n    "source": "iana"\n  },\n  "application/ecmascript": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ecma","es"]\n  },\n  "application/edi-consent": {\n    "source": "iana"\n  },\n  "application/edi-x12": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/edifact": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/efi": {\n    "source": "iana"\n  },\n  "application/emergencycalldata.cap+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/emergencycalldata.comment+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.deviceinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.ecall.msd": {\n    "source": "iana"\n  },\n  "application/emergencycalldata.providerinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.serviceinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.subscriberinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emergencycalldata.veds+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/emma+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["emma"]\n  },\n  "application/emotionml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["emotionml"]\n  },\n  "application/encaprtp": {\n    "source": "iana"\n  },\n  "application/epp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/epub+zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["epub"]\n  },\n  "application/eshop": {\n    "source": "iana"\n  },\n  "application/exi": {\n    "source": "iana",\n    "extensions": ["exi"]\n  },\n  "application/expect-ct-report+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/fastinfoset": {\n    "source": "iana"\n  },\n  "application/fastsoap": {\n    "source": "iana"\n  },\n  "application/fdt+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["fdt"]\n  },\n  "application/fhir+json": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/fhir+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/fido.trusted-apps+json": {\n    "compressible": true\n  },\n  "application/fits": {\n    "source": "iana"\n  },\n  "application/flexfec": {\n    "source": "iana"\n  },\n  "application/font-sfnt": {\n    "source": "iana"\n  },\n  "application/font-tdpfr": {\n    "source": "iana",\n    "extensions": ["pfr"]\n  },\n  "application/font-woff": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/framework-attributes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/geo+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["geojson"]\n  },\n  "application/geo+json-seq": {\n    "source": "iana"\n  },\n  "application/geopackage+sqlite3": {\n    "source": "iana"\n  },\n  "application/geoxacml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/gltf-buffer": {\n    "source": "iana"\n  },\n  "application/gml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["gml"]\n  },\n  "application/gpx+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["gpx"]\n  },\n  "application/gxf": {\n    "source": "apache",\n    "extensions": ["gxf"]\n  },\n  "application/gzip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["gz"]\n  },\n  "application/h224": {\n    "source": "iana"\n  },\n  "application/held+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/hjson": {\n    "extensions": ["hjson"]\n  },\n  "application/http": {\n    "source": "iana"\n  },\n  "application/hyperstudio": {\n    "source": "iana",\n    "extensions": ["stk"]\n  },\n  "application/ibe-key-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ibe-pkg-reply+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ibe-pp-data": {\n    "source": "iana"\n  },\n  "application/iges": {\n    "source": "iana"\n  },\n  "application/im-iscomposing+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/index": {\n    "source": "iana"\n  },\n  "application/index.cmd": {\n    "source": "iana"\n  },\n  "application/index.obj": {\n    "source": "iana"\n  },\n  "application/index.response": {\n    "source": "iana"\n  },\n  "application/index.vnd": {\n    "source": "iana"\n  },\n  "application/inkml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ink","inkml"]\n  },\n  "application/iotp": {\n    "source": "iana"\n  },\n  "application/ipfix": {\n    "source": "iana",\n    "extensions": ["ipfix"]\n  },\n  "application/ipp": {\n    "source": "iana"\n  },\n  "application/isup": {\n    "source": "iana"\n  },\n  "application/its+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["its"]\n  },\n  "application/java-archive": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["jar","war","ear"]\n  },\n  "application/java-serialized-object": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["ser"]\n  },\n  "application/java-vm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["class"]\n  },\n  "application/javascript": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["js","mjs"]\n  },\n  "application/jf2feed+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jose": {\n    "source": "iana"\n  },\n  "application/jose+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jrd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/json": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["json","map"]\n  },\n  "application/json-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/json-seq": {\n    "source": "iana"\n  },\n  "application/json5": {\n    "extensions": ["json5"]\n  },\n  "application/jsonml+json": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["jsonml"]\n  },\n  "application/jwk+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jwk-set+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/jwt": {\n    "source": "iana"\n  },\n  "application/kpml-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/kpml-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/ld+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["jsonld"]\n  },\n  "application/lgr+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lgr"]\n  },\n  "application/link-format": {\n    "source": "iana"\n  },\n  "application/load-control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/lost+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lostxml"]\n  },\n  "application/lostsync+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/lpf+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/lxf": {\n    "source": "iana"\n  },\n  "application/mac-binhex40": {\n    "source": "iana",\n    "extensions": ["hqx"]\n  },\n  "application/mac-compactpro": {\n    "source": "apache",\n    "extensions": ["cpt"]\n  },\n  "application/macwriteii": {\n    "source": "iana"\n  },\n  "application/mads+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mads"]\n  },\n  "application/manifest+json": {\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["webmanifest"]\n  },\n  "application/marc": {\n    "source": "iana",\n    "extensions": ["mrc"]\n  },\n  "application/marcxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mrcx"]\n  },\n  "application/mathematica": {\n    "source": "iana",\n    "extensions": ["ma","nb","mb"]\n  },\n  "application/mathml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mathml"]\n  },\n  "application/mathml-content+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mathml-presentation+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-associated-procedure-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-deregister+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-envelope+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-msk+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-msk-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-protection-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-reception-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-register+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-register-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-schedule+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbms-user-service-description+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mbox": {\n    "source": "iana",\n    "extensions": ["mbox"]\n  },\n  "application/media-policy-dataset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/media_control+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/mediaservercontrol+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mscml"]\n  },\n  "application/merge-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/metalink+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["metalink"]\n  },\n  "application/metalink4+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["meta4"]\n  },\n  "application/mets+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mets"]\n  },\n  "application/mf4": {\n    "source": "iana"\n  },\n  "application/mikey": {\n    "source": "iana"\n  },\n  "application/mipc": {\n    "source": "iana"\n  },\n  "application/mmt-aei+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["maei"]\n  },\n  "application/mmt-usd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["musd"]\n  },\n  "application/mods+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mods"]\n  },\n  "application/moss-keys": {\n    "source": "iana"\n  },\n  "application/moss-signature": {\n    "source": "iana"\n  },\n  "application/mosskey-data": {\n    "source": "iana"\n  },\n  "application/mosskey-request": {\n    "source": "iana"\n  },\n  "application/mp21": {\n    "source": "iana",\n    "extensions": ["m21","mp21"]\n  },\n  "application/mp4": {\n    "source": "iana",\n    "extensions": ["mp4s","m4p"]\n  },\n  "application/mpeg4-generic": {\n    "source": "iana"\n  },\n  "application/mpeg4-iod": {\n    "source": "iana"\n  },\n  "application/mpeg4-iod-xmt": {\n    "source": "iana"\n  },\n  "application/mrb-consumer+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdf"]\n  },\n  "application/mrb-publish+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdf"]\n  },\n  "application/msc-ivr+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/msc-mixer+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/msword": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["doc","dot"]\n  },\n  "application/mud+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/multipart-core": {\n    "source": "iana"\n  },\n  "application/mxf": {\n    "source": "iana",\n    "extensions": ["mxf"]\n  },\n  "application/n-quads": {\n    "source": "iana",\n    "extensions": ["nq"]\n  },\n  "application/n-triples": {\n    "source": "iana",\n    "extensions": ["nt"]\n  },\n  "application/nasdata": {\n    "source": "iana"\n  },\n  "application/news-checkgroups": {\n    "source": "iana",\n    "charset": "US-ASCII"\n  },\n  "application/news-groupinfo": {\n    "source": "iana",\n    "charset": "US-ASCII"\n  },\n  "application/news-transmission": {\n    "source": "iana"\n  },\n  "application/nlsml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/node": {\n    "source": "iana",\n    "extensions": ["cjs"]\n  },\n  "application/nss": {\n    "source": "iana"\n  },\n  "application/ocsp-request": {\n    "source": "iana"\n  },\n  "application/ocsp-response": {\n    "source": "iana"\n  },\n  "application/octet-stream": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["bin","dms","lrf","mar","so","dist","distz","pkg","bpk","dump","elc","deploy","exe","dll","deb","dmg","iso","img","msi","msp","msm","buffer"]\n  },\n  "application/oda": {\n    "source": "iana",\n    "extensions": ["oda"]\n  },\n  "application/odm+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/odx": {\n    "source": "iana"\n  },\n  "application/oebps-package+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["opf"]\n  },\n  "application/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ogx"]\n  },\n  "application/omdoc+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["omdoc"]\n  },\n  "application/onenote": {\n    "source": "apache",\n    "extensions": ["onetoc","onetoc2","onetmp","onepkg"]\n  },\n  "application/opc-nodeset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/oscore": {\n    "source": "iana"\n  },\n  "application/oxps": {\n    "source": "iana",\n    "extensions": ["oxps"]\n  },\n  "application/p2p-overlay+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["relo"]\n  },\n  "application/parityfec": {\n    "source": "iana"\n  },\n  "application/passport": {\n    "source": "iana"\n  },\n  "application/patch-ops-error+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xer"]\n  },\n  "application/pdf": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pdf"]\n  },\n  "application/pdx": {\n    "source": "iana"\n  },\n  "application/pem-certificate-chain": {\n    "source": "iana"\n  },\n  "application/pgp-encrypted": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pgp"]\n  },\n  "application/pgp-keys": {\n    "source": "iana"\n  },\n  "application/pgp-signature": {\n    "source": "iana",\n    "extensions": ["asc","sig"]\n  },\n  "application/pics-rules": {\n    "source": "apache",\n    "extensions": ["prf"]\n  },\n  "application/pidf+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/pidf-diff+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/pkcs10": {\n    "source": "iana",\n    "extensions": ["p10"]\n  },\n  "application/pkcs12": {\n    "source": "iana"\n  },\n  "application/pkcs7-mime": {\n    "source": "iana",\n    "extensions": ["p7m","p7c"]\n  },\n  "application/pkcs7-signature": {\n    "source": "iana",\n    "extensions": ["p7s"]\n  },\n  "application/pkcs8": {\n    "source": "iana",\n    "extensions": ["p8"]\n  },\n  "application/pkcs8-encrypted": {\n    "source": "iana"\n  },\n  "application/pkix-attr-cert": {\n    "source": "iana",\n    "extensions": ["ac"]\n  },\n  "application/pkix-cert": {\n    "source": "iana",\n    "extensions": ["cer"]\n  },\n  "application/pkix-crl": {\n    "source": "iana",\n    "extensions": ["crl"]\n  },\n  "application/pkix-pkipath": {\n    "source": "iana",\n    "extensions": ["pkipath"]\n  },\n  "application/pkixcmp": {\n    "source": "iana",\n    "extensions": ["pki"]\n  },\n  "application/pls+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["pls"]\n  },\n  "application/poc-settings+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/postscript": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ai","eps","ps"]\n  },\n  "application/ppsp-tracker+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/problem+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/problem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/provenance+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["provx"]\n  },\n  "application/prs.alvestrand.titrax-sheet": {\n    "source": "iana"\n  },\n  "application/prs.cww": {\n    "source": "iana",\n    "extensions": ["cww"]\n  },\n  "application/prs.hpub+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/prs.nprend": {\n    "source": "iana"\n  },\n  "application/prs.plucker": {\n    "source": "iana"\n  },\n  "application/prs.rdf-xml-crypt": {\n    "source": "iana"\n  },\n  "application/prs.xsf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/pskc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["pskcxml"]\n  },\n  "application/pvd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/qsig": {\n    "source": "iana"\n  },\n  "application/raml+yaml": {\n    "compressible": true,\n    "extensions": ["raml"]\n  },\n  "application/raptorfec": {\n    "source": "iana"\n  },\n  "application/rdap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/rdf+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rdf","owl"]\n  },\n  "application/reginfo+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rif"]\n  },\n  "application/relax-ng-compact-syntax": {\n    "source": "iana",\n    "extensions": ["rnc"]\n  },\n  "application/remote-printing": {\n    "source": "iana"\n  },\n  "application/reputon+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/resource-lists+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rl"]\n  },\n  "application/resource-lists-diff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rld"]\n  },\n  "application/rfc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/riscos": {\n    "source": "iana"\n  },\n  "application/rlmi+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/rls-services+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rs"]\n  },\n  "application/route-apd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rapd"]\n  },\n  "application/route-s-tsid+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sls"]\n  },\n  "application/route-usd+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rusd"]\n  },\n  "application/rpki-ghostbusters": {\n    "source": "iana",\n    "extensions": ["gbr"]\n  },\n  "application/rpki-manifest": {\n    "source": "iana",\n    "extensions": ["mft"]\n  },\n  "application/rpki-publication": {\n    "source": "iana"\n  },\n  "application/rpki-roa": {\n    "source": "iana",\n    "extensions": ["roa"]\n  },\n  "application/rpki-updown": {\n    "source": "iana"\n  },\n  "application/rsd+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["rsd"]\n  },\n  "application/rss+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["rss"]\n  },\n  "application/rtf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtf"]\n  },\n  "application/rtploopback": {\n    "source": "iana"\n  },\n  "application/rtx": {\n    "source": "iana"\n  },\n  "application/samlassertion+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/samlmetadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sarif+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sbe": {\n    "source": "iana"\n  },\n  "application/sbml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sbml"]\n  },\n  "application/scaip+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/scim+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/scvp-cv-request": {\n    "source": "iana",\n    "extensions": ["scq"]\n  },\n  "application/scvp-cv-response": {\n    "source": "iana",\n    "extensions": ["scs"]\n  },\n  "application/scvp-vp-request": {\n    "source": "iana",\n    "extensions": ["spq"]\n  },\n  "application/scvp-vp-response": {\n    "source": "iana",\n    "extensions": ["spp"]\n  },\n  "application/sdp": {\n    "source": "iana",\n    "extensions": ["sdp"]\n  },\n  "application/secevent+jwt": {\n    "source": "iana"\n  },\n  "application/senml+cbor": {\n    "source": "iana"\n  },\n  "application/senml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/senml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["senmlx"]\n  },\n  "application/senml-etch+cbor": {\n    "source": "iana"\n  },\n  "application/senml-etch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/senml-exi": {\n    "source": "iana"\n  },\n  "application/sensml+cbor": {\n    "source": "iana"\n  },\n  "application/sensml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sensml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sensmlx"]\n  },\n  "application/sensml-exi": {\n    "source": "iana"\n  },\n  "application/sep+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sep-exi": {\n    "source": "iana"\n  },\n  "application/session-info": {\n    "source": "iana"\n  },\n  "application/set-payment": {\n    "source": "iana"\n  },\n  "application/set-payment-initiation": {\n    "source": "iana",\n    "extensions": ["setpay"]\n  },\n  "application/set-registration": {\n    "source": "iana"\n  },\n  "application/set-registration-initiation": {\n    "source": "iana",\n    "extensions": ["setreg"]\n  },\n  "application/sgml": {\n    "source": "iana"\n  },\n  "application/sgml-open-catalog": {\n    "source": "iana"\n  },\n  "application/shf+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["shf"]\n  },\n  "application/sieve": {\n    "source": "iana",\n    "extensions": ["siv","sieve"]\n  },\n  "application/simple-filter+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/simple-message-summary": {\n    "source": "iana"\n  },\n  "application/simplesymbolcontainer": {\n    "source": "iana"\n  },\n  "application/sipc": {\n    "source": "iana"\n  },\n  "application/slate": {\n    "source": "iana"\n  },\n  "application/smil": {\n    "source": "iana"\n  },\n  "application/smil+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["smi","smil"]\n  },\n  "application/smpte336m": {\n    "source": "iana"\n  },\n  "application/soap+fastinfoset": {\n    "source": "iana"\n  },\n  "application/soap+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sparql-query": {\n    "source": "iana",\n    "extensions": ["rq"]\n  },\n  "application/sparql-results+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["srx"]\n  },\n  "application/spirits-event+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/sql": {\n    "source": "iana"\n  },\n  "application/srgs": {\n    "source": "iana",\n    "extensions": ["gram"]\n  },\n  "application/srgs+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["grxml"]\n  },\n  "application/sru+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sru"]\n  },\n  "application/ssdl+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ssdl"]\n  },\n  "application/ssml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ssml"]\n  },\n  "application/stix+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/swid+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["swidtag"]\n  },\n  "application/tamp-apex-update": {\n    "source": "iana"\n  },\n  "application/tamp-apex-update-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-community-update": {\n    "source": "iana"\n  },\n  "application/tamp-community-update-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-error": {\n    "source": "iana"\n  },\n  "application/tamp-sequence-adjust": {\n    "source": "iana"\n  },\n  "application/tamp-sequence-adjust-confirm": {\n    "source": "iana"\n  },\n  "application/tamp-status-query": {\n    "source": "iana"\n  },\n  "application/tamp-status-response": {\n    "source": "iana"\n  },\n  "application/tamp-update": {\n    "source": "iana"\n  },\n  "application/tamp-update-confirm": {\n    "source": "iana"\n  },\n  "application/tar": {\n    "compressible": true\n  },\n  "application/taxii+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/td+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/tei+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tei","teicorpus"]\n  },\n  "application/tetra_isi": {\n    "source": "iana"\n  },\n  "application/thraud+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tfi"]\n  },\n  "application/timestamp-query": {\n    "source": "iana"\n  },\n  "application/timestamp-reply": {\n    "source": "iana"\n  },\n  "application/timestamped-data": {\n    "source": "iana",\n    "extensions": ["tsd"]\n  },\n  "application/tlsrpt+gzip": {\n    "source": "iana"\n  },\n  "application/tlsrpt+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/tnauthlist": {\n    "source": "iana"\n  },\n  "application/toml": {\n    "compressible": true,\n    "extensions": ["toml"]\n  },\n  "application/trickle-ice-sdpfrag": {\n    "source": "iana"\n  },\n  "application/trig": {\n    "source": "iana"\n  },\n  "application/ttml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ttml"]\n  },\n  "application/tve-trigger": {\n    "source": "iana"\n  },\n  "application/tzif": {\n    "source": "iana"\n  },\n  "application/tzif-leap": {\n    "source": "iana"\n  },\n  "application/ubjson": {\n    "compressible": false,\n    "extensions": ["ubj"]\n  },\n  "application/ulpfec": {\n    "source": "iana"\n  },\n  "application/urc-grpsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/urc-ressheet+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rsheet"]\n  },\n  "application/urc-targetdesc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["td"]\n  },\n  "application/urc-uisocketdesc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vcard+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vcard+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vemmi": {\n    "source": "iana"\n  },\n  "application/vividence.scriptfile": {\n    "source": "apache"\n  },\n  "application/vnd.1000minds.decision-model+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["1km"]\n  },\n  "application/vnd.3gpp-prose+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp-prose-pc3ch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp-v2x-local-service-information": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.access-transfer-events+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.bsf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.gmop+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mc-signalling-ear": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-payload": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-signalling": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.mcdata-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcdata-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-floor-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-location-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-signed+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-ue-init-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcptt-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-affiliation-command+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-affiliation-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-location-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-service-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-transmission-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-ue-config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mcvideo-user-profile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.mid-call+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.pic-bw-large": {\n    "source": "iana",\n    "extensions": ["plb"]\n  },\n  "application/vnd.3gpp.pic-bw-small": {\n    "source": "iana",\n    "extensions": ["psb"]\n  },\n  "application/vnd.3gpp.pic-bw-var": {\n    "source": "iana",\n    "extensions": ["pvb"]\n  },\n  "application/vnd.3gpp.sms": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp.sms+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.srvcc-ext+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.srvcc-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.state-and-event-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp.ussd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp2.bcmcsinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.3gpp2.sms": {\n    "source": "iana"\n  },\n  "application/vnd.3gpp2.tcap": {\n    "source": "iana",\n    "extensions": ["tcap"]\n  },\n  "application/vnd.3lightssoftware.imagescal": {\n    "source": "iana"\n  },\n  "application/vnd.3m.post-it-notes": {\n    "source": "iana",\n    "extensions": ["pwn"]\n  },\n  "application/vnd.accpac.simply.aso": {\n    "source": "iana",\n    "extensions": ["aso"]\n  },\n  "application/vnd.accpac.simply.imp": {\n    "source": "iana",\n    "extensions": ["imp"]\n  },\n  "application/vnd.acucobol": {\n    "source": "iana",\n    "extensions": ["acu"]\n  },\n  "application/vnd.acucorp": {\n    "source": "iana",\n    "extensions": ["atc","acutc"]\n  },\n  "application/vnd.adobe.air-application-installer-package+zip": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["air"]\n  },\n  "application/vnd.adobe.flash.movie": {\n    "source": "iana"\n  },\n  "application/vnd.adobe.formscentral.fcdt": {\n    "source": "iana",\n    "extensions": ["fcdt"]\n  },\n  "application/vnd.adobe.fxp": {\n    "source": "iana",\n    "extensions": ["fxp","fxpl"]\n  },\n  "application/vnd.adobe.partial-upload": {\n    "source": "iana"\n  },\n  "application/vnd.adobe.xdp+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdp"]\n  },\n  "application/vnd.adobe.xfdf": {\n    "source": "iana",\n    "extensions": ["xfdf"]\n  },\n  "application/vnd.aether.imp": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.afplinedata": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.afplinedata-pagedef": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-charset": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-codedfont": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.foca-codepage": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-formdef": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-mediummap": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-objectcontainer": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-overlay": {\n    "source": "iana"\n  },\n  "application/vnd.afpc.modca-pagesegment": {\n    "source": "iana"\n  },\n  "application/vnd.ah-barcode": {\n    "source": "iana"\n  },\n  "application/vnd.ahead.space": {\n    "source": "iana",\n    "extensions": ["ahead"]\n  },\n  "application/vnd.airzip.filesecure.azf": {\n    "source": "iana",\n    "extensions": ["azf"]\n  },\n  "application/vnd.airzip.filesecure.azs": {\n    "source": "iana",\n    "extensions": ["azs"]\n  },\n  "application/vnd.amadeus+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.amazon.ebook": {\n    "source": "apache",\n    "extensions": ["azw"]\n  },\n  "application/vnd.amazon.mobi8-ebook": {\n    "source": "iana"\n  },\n  "application/vnd.americandynamics.acc": {\n    "source": "iana",\n    "extensions": ["acc"]\n  },\n  "application/vnd.amiga.ami": {\n    "source": "iana",\n    "extensions": ["ami"]\n  },\n  "application/vnd.amundsen.maze+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.android.ota": {\n    "source": "iana"\n  },\n  "application/vnd.android.package-archive": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["apk"]\n  },\n  "application/vnd.anki": {\n    "source": "iana"\n  },\n  "application/vnd.anser-web-certificate-issue-initiation": {\n    "source": "iana",\n    "extensions": ["cii"]\n  },\n  "application/vnd.anser-web-funds-transfer-initiation": {\n    "source": "apache",\n    "extensions": ["fti"]\n  },\n  "application/vnd.antix.game-component": {\n    "source": "iana",\n    "extensions": ["atx"]\n  },\n  "application/vnd.apache.thrift.binary": {\n    "source": "iana"\n  },\n  "application/vnd.apache.thrift.compact": {\n    "source": "iana"\n  },\n  "application/vnd.apache.thrift.json": {\n    "source": "iana"\n  },\n  "application/vnd.api+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.aplextor.warrp+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.apothekende.reservation+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.apple.installer+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mpkg"]\n  },\n  "application/vnd.apple.keynote": {\n    "source": "iana",\n    "extensions": ["key"]\n  },\n  "application/vnd.apple.mpegurl": {\n    "source": "iana",\n    "extensions": ["m3u8"]\n  },\n  "application/vnd.apple.numbers": {\n    "source": "iana",\n    "extensions": ["numbers"]\n  },\n  "application/vnd.apple.pages": {\n    "source": "iana",\n    "extensions": ["pages"]\n  },\n  "application/vnd.apple.pkpass": {\n    "compressible": false,\n    "extensions": ["pkpass"]\n  },\n  "application/vnd.arastra.swi": {\n    "source": "iana"\n  },\n  "application/vnd.aristanetworks.swi": {\n    "source": "iana",\n    "extensions": ["swi"]\n  },\n  "application/vnd.artisan+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.artsquare": {\n    "source": "iana"\n  },\n  "application/vnd.astraea-software.iota": {\n    "source": "iana",\n    "extensions": ["iota"]\n  },\n  "application/vnd.audiograph": {\n    "source": "iana",\n    "extensions": ["aep"]\n  },\n  "application/vnd.autopackage": {\n    "source": "iana"\n  },\n  "application/vnd.avalon+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.avistar+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.balsamiq.bmml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["bmml"]\n  },\n  "application/vnd.balsamiq.bmpr": {\n    "source": "iana"\n  },\n  "application/vnd.banana-accounting": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.error": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.msg": {\n    "source": "iana"\n  },\n  "application/vnd.bbf.usp.msg+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.bekitzur-stech+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.bint.med-content": {\n    "source": "iana"\n  },\n  "application/vnd.biopax.rdf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.blink-idb-value-wrapper": {\n    "source": "iana"\n  },\n  "application/vnd.blueice.multipass": {\n    "source": "iana",\n    "extensions": ["mpm"]\n  },\n  "application/vnd.bluetooth.ep.oob": {\n    "source": "iana"\n  },\n  "application/vnd.bluetooth.le.oob": {\n    "source": "iana"\n  },\n  "application/vnd.bmi": {\n    "source": "iana",\n    "extensions": ["bmi"]\n  },\n  "application/vnd.bpf": {\n    "source": "iana"\n  },\n  "application/vnd.bpf3": {\n    "source": "iana"\n  },\n  "application/vnd.businessobjects": {\n    "source": "iana",\n    "extensions": ["rep"]\n  },\n  "application/vnd.byu.uapi+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cab-jscript": {\n    "source": "iana"\n  },\n  "application/vnd.canon-cpdl": {\n    "source": "iana"\n  },\n  "application/vnd.canon-lips": {\n    "source": "iana"\n  },\n  "application/vnd.capasystems-pg+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cendio.thinlinc.clientconf": {\n    "source": "iana"\n  },\n  "application/vnd.century-systems.tcp_stream": {\n    "source": "iana"\n  },\n  "application/vnd.chemdraw+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["cdxml"]\n  },\n  "application/vnd.chess-pgn": {\n    "source": "iana"\n  },\n  "application/vnd.chipnuts.karaoke-mmd": {\n    "source": "iana",\n    "extensions": ["mmd"]\n  },\n  "application/vnd.ciedi": {\n    "source": "iana"\n  },\n  "application/vnd.cinderella": {\n    "source": "iana",\n    "extensions": ["cdy"]\n  },\n  "application/vnd.cirpack.isdn-ext": {\n    "source": "iana"\n  },\n  "application/vnd.citationstyles.style+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["csl"]\n  },\n  "application/vnd.claymore": {\n    "source": "iana",\n    "extensions": ["cla"]\n  },\n  "application/vnd.cloanto.rp9": {\n    "source": "iana",\n    "extensions": ["rp9"]\n  },\n  "application/vnd.clonk.c4group": {\n    "source": "iana",\n    "extensions": ["c4g","c4d","c4f","c4p","c4u"]\n  },\n  "application/vnd.cluetrust.cartomobile-config": {\n    "source": "iana",\n    "extensions": ["c11amc"]\n  },\n  "application/vnd.cluetrust.cartomobile-config-pkg": {\n    "source": "iana",\n    "extensions": ["c11amz"]\n  },\n  "application/vnd.coffeescript": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.document": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.document-template": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.presentation": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.presentation-template": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.spreadsheet": {\n    "source": "iana"\n  },\n  "application/vnd.collabio.xodocuments.spreadsheet-template": {\n    "source": "iana"\n  },\n  "application/vnd.collection+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.collection.doc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.collection.next+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.comicbook+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.comicbook-rar": {\n    "source": "iana"\n  },\n  "application/vnd.commerce-battelle": {\n    "source": "iana"\n  },\n  "application/vnd.commonspace": {\n    "source": "iana",\n    "extensions": ["csp"]\n  },\n  "application/vnd.contact.cmsg": {\n    "source": "iana",\n    "extensions": ["cdbcmsg"]\n  },\n  "application/vnd.coreos.ignition+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cosmocaller": {\n    "source": "iana",\n    "extensions": ["cmc"]\n  },\n  "application/vnd.crick.clicker": {\n    "source": "iana",\n    "extensions": ["clkx"]\n  },\n  "application/vnd.crick.clicker.keyboard": {\n    "source": "iana",\n    "extensions": ["clkk"]\n  },\n  "application/vnd.crick.clicker.palette": {\n    "source": "iana",\n    "extensions": ["clkp"]\n  },\n  "application/vnd.crick.clicker.template": {\n    "source": "iana",\n    "extensions": ["clkt"]\n  },\n  "application/vnd.crick.clicker.wordbank": {\n    "source": "iana",\n    "extensions": ["clkw"]\n  },\n  "application/vnd.criticaltools.wbs+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wbs"]\n  },\n  "application/vnd.cryptii.pipe+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.crypto-shade-file": {\n    "source": "iana"\n  },\n  "application/vnd.ctc-posml": {\n    "source": "iana",\n    "extensions": ["pml"]\n  },\n  "application/vnd.ctct.ws+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cups-pdf": {\n    "source": "iana"\n  },\n  "application/vnd.cups-postscript": {\n    "source": "iana"\n  },\n  "application/vnd.cups-ppd": {\n    "source": "iana",\n    "extensions": ["ppd"]\n  },\n  "application/vnd.cups-raster": {\n    "source": "iana"\n  },\n  "application/vnd.cups-raw": {\n    "source": "iana"\n  },\n  "application/vnd.curl": {\n    "source": "iana"\n  },\n  "application/vnd.curl.car": {\n    "source": "apache",\n    "extensions": ["car"]\n  },\n  "application/vnd.curl.pcurl": {\n    "source": "apache",\n    "extensions": ["pcurl"]\n  },\n  "application/vnd.cyan.dean.root+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.cybank": {\n    "source": "iana"\n  },\n  "application/vnd.d2l.coursepackage1p0+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.d3m-dataset": {\n    "source": "iana"\n  },\n  "application/vnd.d3m-problem": {\n    "source": "iana"\n  },\n  "application/vnd.dart": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dart"]\n  },\n  "application/vnd.data-vision.rdz": {\n    "source": "iana",\n    "extensions": ["rdz"]\n  },\n  "application/vnd.datapackage+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dataresource+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dbf": {\n    "source": "iana",\n    "extensions": ["dbf"]\n  },\n  "application/vnd.debian.binary-package": {\n    "source": "iana"\n  },\n  "application/vnd.dece.data": {\n    "source": "iana",\n    "extensions": ["uvf","uvvf","uvd","uvvd"]\n  },\n  "application/vnd.dece.ttml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uvt","uvvt"]\n  },\n  "application/vnd.dece.unspecified": {\n    "source": "iana",\n    "extensions": ["uvx","uvvx"]\n  },\n  "application/vnd.dece.zip": {\n    "source": "iana",\n    "extensions": ["uvz","uvvz"]\n  },\n  "application/vnd.denovo.fcselayout-link": {\n    "source": "iana",\n    "extensions": ["fe_launch"]\n  },\n  "application/vnd.desmume.movie": {\n    "source": "iana"\n  },\n  "application/vnd.dir-bi.plate-dl-nosuffix": {\n    "source": "iana"\n  },\n  "application/vnd.dm.delegation+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dna": {\n    "source": "iana",\n    "extensions": ["dna"]\n  },\n  "application/vnd.document+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dolby.mlp": {\n    "source": "apache",\n    "extensions": ["mlp"]\n  },\n  "application/vnd.dolby.mobile.1": {\n    "source": "iana"\n  },\n  "application/vnd.dolby.mobile.2": {\n    "source": "iana"\n  },\n  "application/vnd.doremir.scorecloud-binary-document": {\n    "source": "iana"\n  },\n  "application/vnd.dpgraph": {\n    "source": "iana",\n    "extensions": ["dpg"]\n  },\n  "application/vnd.dreamfactory": {\n    "source": "iana",\n    "extensions": ["dfac"]\n  },\n  "application/vnd.drive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ds-keypoint": {\n    "source": "apache",\n    "extensions": ["kpxx"]\n  },\n  "application/vnd.dtg.local": {\n    "source": "iana"\n  },\n  "application/vnd.dtg.local.flash": {\n    "source": "iana"\n  },\n  "application/vnd.dtg.local.html": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ait": {\n    "source": "iana",\n    "extensions": ["ait"]\n  },\n  "application/vnd.dvb.dvbisl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.dvbj": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.esgcontainer": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcdftnotifaccess": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgaccess": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgaccess2": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcesgpdd": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.ipdcroaming": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.iptv.alfec-base": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.iptv.alfec-enhancement": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.notif-aggregate-root+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-container+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-generic+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-msglist+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-registration-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-ia-registration-response+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.notif-init+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.dvb.pfr": {\n    "source": "iana"\n  },\n  "application/vnd.dvb.service": {\n    "source": "iana",\n    "extensions": ["svc"]\n  },\n  "application/vnd.dxr": {\n    "source": "iana"\n  },\n  "application/vnd.dynageo": {\n    "source": "iana",\n    "extensions": ["geo"]\n  },\n  "application/vnd.dzr": {\n    "source": "iana"\n  },\n  "application/vnd.easykaraoke.cdgdownload": {\n    "source": "iana"\n  },\n  "application/vnd.ecdis-update": {\n    "source": "iana"\n  },\n  "application/vnd.ecip.rlp": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.chart": {\n    "source": "iana",\n    "extensions": ["mag"]\n  },\n  "application/vnd.ecowin.filerequest": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.fileupdate": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.series": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.seriesrequest": {\n    "source": "iana"\n  },\n  "application/vnd.ecowin.seriesupdate": {\n    "source": "iana"\n  },\n  "application/vnd.efi.img": {\n    "source": "iana"\n  },\n  "application/vnd.efi.iso": {\n    "source": "iana"\n  },\n  "application/vnd.emclient.accessrequest+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.enliven": {\n    "source": "iana",\n    "extensions": ["nml"]\n  },\n  "application/vnd.enphase.envoy": {\n    "source": "iana"\n  },\n  "application/vnd.eprints.data+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.epson.esf": {\n    "source": "iana",\n    "extensions": ["esf"]\n  },\n  "application/vnd.epson.msf": {\n    "source": "iana",\n    "extensions": ["msf"]\n  },\n  "application/vnd.epson.quickanime": {\n    "source": "iana",\n    "extensions": ["qam"]\n  },\n  "application/vnd.epson.salt": {\n    "source": "iana",\n    "extensions": ["slt"]\n  },\n  "application/vnd.epson.ssf": {\n    "source": "iana",\n    "extensions": ["ssf"]\n  },\n  "application/vnd.ericsson.quickcall": {\n    "source": "iana"\n  },\n  "application/vnd.espass-espass+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.eszigno3+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["es3","et3"]\n  },\n  "application/vnd.etsi.aoc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.asic-e+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.etsi.asic-s+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.etsi.cug+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvcommand+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvdiscovery+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-bc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-cod+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsad-npvr+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvservice+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvsync+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.iptvueprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.mcid+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.mheg5": {\n    "source": "iana"\n  },\n  "application/vnd.etsi.overload-control-policy-dataset+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.pstn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.sci+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.simservs+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.timestamp-token": {\n    "source": "iana"\n  },\n  "application/vnd.etsi.tsl+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.etsi.tsl.der": {\n    "source": "iana"\n  },\n  "application/vnd.eudora.data": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.profile": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.settings": {\n    "source": "iana"\n  },\n  "application/vnd.evolv.ecig.theme": {\n    "source": "iana"\n  },\n  "application/vnd.exstream-empower+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.exstream-package": {\n    "source": "iana"\n  },\n  "application/vnd.ezpix-album": {\n    "source": "iana",\n    "extensions": ["ez2"]\n  },\n  "application/vnd.ezpix-package": {\n    "source": "iana",\n    "extensions": ["ez3"]\n  },\n  "application/vnd.f-secure.mobile": {\n    "source": "iana"\n  },\n  "application/vnd.fastcopy-disk-image": {\n    "source": "iana"\n  },\n  "application/vnd.fdf": {\n    "source": "iana",\n    "extensions": ["fdf"]\n  },\n  "application/vnd.fdsn.mseed": {\n    "source": "iana",\n    "extensions": ["mseed"]\n  },\n  "application/vnd.fdsn.seed": {\n    "source": "iana",\n    "extensions": ["seed","dataless"]\n  },\n  "application/vnd.ffsns": {\n    "source": "iana"\n  },\n  "application/vnd.ficlab.flb+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.filmit.zfc": {\n    "source": "iana"\n  },\n  "application/vnd.fints": {\n    "source": "iana"\n  },\n  "application/vnd.firemonkeys.cloudcell": {\n    "source": "iana"\n  },\n  "application/vnd.flographit": {\n    "source": "iana",\n    "extensions": ["gph"]\n  },\n  "application/vnd.fluxtime.clip": {\n    "source": "iana",\n    "extensions": ["ftc"]\n  },\n  "application/vnd.font-fontforge-sfd": {\n    "source": "iana"\n  },\n  "application/vnd.framemaker": {\n    "source": "iana",\n    "extensions": ["fm","frame","maker","book"]\n  },\n  "application/vnd.frogans.fnc": {\n    "source": "iana",\n    "extensions": ["fnc"]\n  },\n  "application/vnd.frogans.ltf": {\n    "source": "iana",\n    "extensions": ["ltf"]\n  },\n  "application/vnd.fsc.weblaunch": {\n    "source": "iana",\n    "extensions": ["fsc"]\n  },\n  "application/vnd.fujitsu.oasys": {\n    "source": "iana",\n    "extensions": ["oas"]\n  },\n  "application/vnd.fujitsu.oasys2": {\n    "source": "iana",\n    "extensions": ["oa2"]\n  },\n  "application/vnd.fujitsu.oasys3": {\n    "source": "iana",\n    "extensions": ["oa3"]\n  },\n  "application/vnd.fujitsu.oasysgp": {\n    "source": "iana",\n    "extensions": ["fg5"]\n  },\n  "application/vnd.fujitsu.oasysprs": {\n    "source": "iana",\n    "extensions": ["bh2"]\n  },\n  "application/vnd.fujixerox.art-ex": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.art4": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.ddd": {\n    "source": "iana",\n    "extensions": ["ddd"]\n  },\n  "application/vnd.fujixerox.docuworks": {\n    "source": "iana",\n    "extensions": ["xdw"]\n  },\n  "application/vnd.fujixerox.docuworks.binder": {\n    "source": "iana",\n    "extensions": ["xbd"]\n  },\n  "application/vnd.fujixerox.docuworks.container": {\n    "source": "iana"\n  },\n  "application/vnd.fujixerox.hbpl": {\n    "source": "iana"\n  },\n  "application/vnd.fut-misnet": {\n    "source": "iana"\n  },\n  "application/vnd.futoin+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.futoin+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.fuzzysheet": {\n    "source": "iana",\n    "extensions": ["fzs"]\n  },\n  "application/vnd.genomatix.tuxedo": {\n    "source": "iana",\n    "extensions": ["txd"]\n  },\n  "application/vnd.gentics.grd+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geo+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geocube+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.geogebra.file": {\n    "source": "iana",\n    "extensions": ["ggb"]\n  },\n  "application/vnd.geogebra.tool": {\n    "source": "iana",\n    "extensions": ["ggt"]\n  },\n  "application/vnd.geometry-explorer": {\n    "source": "iana",\n    "extensions": ["gex","gre"]\n  },\n  "application/vnd.geonext": {\n    "source": "iana",\n    "extensions": ["gxt"]\n  },\n  "application/vnd.geoplan": {\n    "source": "iana",\n    "extensions": ["g2w"]\n  },\n  "application/vnd.geospace": {\n    "source": "iana",\n    "extensions": ["g3w"]\n  },\n  "application/vnd.gerber": {\n    "source": "iana"\n  },\n  "application/vnd.globalplatform.card-content-mgt": {\n    "source": "iana"\n  },\n  "application/vnd.globalplatform.card-content-mgt-response": {\n    "source": "iana"\n  },\n  "application/vnd.gmx": {\n    "source": "iana",\n    "extensions": ["gmx"]\n  },\n  "application/vnd.google-apps.document": {\n    "compressible": false,\n    "extensions": ["gdoc"]\n  },\n  "application/vnd.google-apps.presentation": {\n    "compressible": false,\n    "extensions": ["gslides"]\n  },\n  "application/vnd.google-apps.spreadsheet": {\n    "compressible": false,\n    "extensions": ["gsheet"]\n  },\n  "application/vnd.google-earth.kml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["kml"]\n  },\n  "application/vnd.google-earth.kmz": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["kmz"]\n  },\n  "application/vnd.gov.sk.e-form+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.gov.sk.e-form+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.gov.sk.xmldatacontainer+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.grafeq": {\n    "source": "iana",\n    "extensions": ["gqf","gqs"]\n  },\n  "application/vnd.gridmp": {\n    "source": "iana"\n  },\n  "application/vnd.groove-account": {\n    "source": "iana",\n    "extensions": ["gac"]\n  },\n  "application/vnd.groove-help": {\n    "source": "iana",\n    "extensions": ["ghf"]\n  },\n  "application/vnd.groove-identity-message": {\n    "source": "iana",\n    "extensions": ["gim"]\n  },\n  "application/vnd.groove-injector": {\n    "source": "iana",\n    "extensions": ["grv"]\n  },\n  "application/vnd.groove-tool-message": {\n    "source": "iana",\n    "extensions": ["gtm"]\n  },\n  "application/vnd.groove-tool-template": {\n    "source": "iana",\n    "extensions": ["tpl"]\n  },\n  "application/vnd.groove-vcard": {\n    "source": "iana",\n    "extensions": ["vcg"]\n  },\n  "application/vnd.hal+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hal+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["hal"]\n  },\n  "application/vnd.handheld-entertainment+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["zmm"]\n  },\n  "application/vnd.hbci": {\n    "source": "iana",\n    "extensions": ["hbci"]\n  },\n  "application/vnd.hc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hcl-bireports": {\n    "source": "iana"\n  },\n  "application/vnd.hdt": {\n    "source": "iana"\n  },\n  "application/vnd.heroku+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hhe.lesson-player": {\n    "source": "iana",\n    "extensions": ["les"]\n  },\n  "application/vnd.hp-hpgl": {\n    "source": "iana",\n    "extensions": ["hpgl"]\n  },\n  "application/vnd.hp-hpid": {\n    "source": "iana",\n    "extensions": ["hpid"]\n  },\n  "application/vnd.hp-hps": {\n    "source": "iana",\n    "extensions": ["hps"]\n  },\n  "application/vnd.hp-jlyt": {\n    "source": "iana",\n    "extensions": ["jlt"]\n  },\n  "application/vnd.hp-pcl": {\n    "source": "iana",\n    "extensions": ["pcl"]\n  },\n  "application/vnd.hp-pclxl": {\n    "source": "iana",\n    "extensions": ["pclxl"]\n  },\n  "application/vnd.httphone": {\n    "source": "iana"\n  },\n  "application/vnd.hydrostatix.sof-data": {\n    "source": "iana",\n    "extensions": ["sfd-hdstx"]\n  },\n  "application/vnd.hyper+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hyper-item+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hyperdrive+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.hzn-3d-crossword": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.afplinedata": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.electronic-media": {\n    "source": "iana"\n  },\n  "application/vnd.ibm.minipay": {\n    "source": "iana",\n    "extensions": ["mpy"]\n  },\n  "application/vnd.ibm.modcap": {\n    "source": "iana",\n    "extensions": ["afp","listafp","list3820"]\n  },\n  "application/vnd.ibm.rights-management": {\n    "source": "iana",\n    "extensions": ["irm"]\n  },\n  "application/vnd.ibm.secure-container": {\n    "source": "iana",\n    "extensions": ["sc"]\n  },\n  "application/vnd.iccprofile": {\n    "source": "iana",\n    "extensions": ["icc","icm"]\n  },\n  "application/vnd.ieee.1905": {\n    "source": "iana"\n  },\n  "application/vnd.igloader": {\n    "source": "iana",\n    "extensions": ["igl"]\n  },\n  "application/vnd.imagemeter.folder+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.imagemeter.image+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.immervision-ivp": {\n    "source": "iana",\n    "extensions": ["ivp"]\n  },\n  "application/vnd.immervision-ivu": {\n    "source": "iana",\n    "extensions": ["ivu"]\n  },\n  "application/vnd.ims.imsccv1p1": {\n    "source": "iana"\n  },\n  "application/vnd.ims.imsccv1p2": {\n    "source": "iana"\n  },\n  "application/vnd.ims.imsccv1p3": {\n    "source": "iana"\n  },\n  "application/vnd.ims.lis.v2.result+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolconsumerprofile+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolproxy+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolproxy.id+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolsettings+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ims.lti.v2.toolsettings.simple+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.informedcontrol.rms+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.informix-visionary": {\n    "source": "iana"\n  },\n  "application/vnd.infotech.project": {\n    "source": "iana"\n  },\n  "application/vnd.infotech.project+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.innopath.wamp.notification": {\n    "source": "iana"\n  },\n  "application/vnd.insors.igm": {\n    "source": "iana",\n    "extensions": ["igm"]\n  },\n  "application/vnd.intercon.formnet": {\n    "source": "iana",\n    "extensions": ["xpw","xpx"]\n  },\n  "application/vnd.intergeo": {\n    "source": "iana",\n    "extensions": ["i2g"]\n  },\n  "application/vnd.intertrust.digibox": {\n    "source": "iana"\n  },\n  "application/vnd.intertrust.nncp": {\n    "source": "iana"\n  },\n  "application/vnd.intu.qbo": {\n    "source": "iana",\n    "extensions": ["qbo"]\n  },\n  "application/vnd.intu.qfx": {\n    "source": "iana",\n    "extensions": ["qfx"]\n  },\n  "application/vnd.iptc.g2.catalogitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.conceptitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.knowledgeitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.newsitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.newsmessage+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.packageitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.iptc.g2.planningitem+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ipunplugged.rcprofile": {\n    "source": "iana",\n    "extensions": ["rcprofile"]\n  },\n  "application/vnd.irepository.package+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["irp"]\n  },\n  "application/vnd.is-xpr": {\n    "source": "iana",\n    "extensions": ["xpr"]\n  },\n  "application/vnd.isac.fcs": {\n    "source": "iana",\n    "extensions": ["fcs"]\n  },\n  "application/vnd.iso11783-10+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.jam": {\n    "source": "iana",\n    "extensions": ["jam"]\n  },\n  "application/vnd.japannet-directory-service": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-jpnstore-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-payment-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-registration": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-registration-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-setstore-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-verification": {\n    "source": "iana"\n  },\n  "application/vnd.japannet-verification-wakeup": {\n    "source": "iana"\n  },\n  "application/vnd.jcp.javame.midlet-rms": {\n    "source": "iana",\n    "extensions": ["rms"]\n  },\n  "application/vnd.jisp": {\n    "source": "iana",\n    "extensions": ["jisp"]\n  },\n  "application/vnd.joost.joda-archive": {\n    "source": "iana",\n    "extensions": ["joda"]\n  },\n  "application/vnd.jsk.isdn-ngn": {\n    "source": "iana"\n  },\n  "application/vnd.kahootz": {\n    "source": "iana",\n    "extensions": ["ktz","ktr"]\n  },\n  "application/vnd.kde.karbon": {\n    "source": "iana",\n    "extensions": ["karbon"]\n  },\n  "application/vnd.kde.kchart": {\n    "source": "iana",\n    "extensions": ["chrt"]\n  },\n  "application/vnd.kde.kformula": {\n    "source": "iana",\n    "extensions": ["kfo"]\n  },\n  "application/vnd.kde.kivio": {\n    "source": "iana",\n    "extensions": ["flw"]\n  },\n  "application/vnd.kde.kontour": {\n    "source": "iana",\n    "extensions": ["kon"]\n  },\n  "application/vnd.kde.kpresenter": {\n    "source": "iana",\n    "extensions": ["kpr","kpt"]\n  },\n  "application/vnd.kde.kspread": {\n    "source": "iana",\n    "extensions": ["ksp"]\n  },\n  "application/vnd.kde.kword": {\n    "source": "iana",\n    "extensions": ["kwd","kwt"]\n  },\n  "application/vnd.kenameaapp": {\n    "source": "iana",\n    "extensions": ["htke"]\n  },\n  "application/vnd.kidspiration": {\n    "source": "iana",\n    "extensions": ["kia"]\n  },\n  "application/vnd.kinar": {\n    "source": "iana",\n    "extensions": ["kne","knp"]\n  },\n  "application/vnd.koan": {\n    "source": "iana",\n    "extensions": ["skp","skd","skt","skm"]\n  },\n  "application/vnd.kodak-descriptor": {\n    "source": "iana",\n    "extensions": ["sse"]\n  },\n  "application/vnd.las": {\n    "source": "iana"\n  },\n  "application/vnd.las.las+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.las.las+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lasxml"]\n  },\n  "application/vnd.laszip": {\n    "source": "iana"\n  },\n  "application/vnd.leap+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.liberty-request+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.llamagraphics.life-balance.desktop": {\n    "source": "iana",\n    "extensions": ["lbd"]\n  },\n  "application/vnd.llamagraphics.life-balance.exchange+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["lbe"]\n  },\n  "application/vnd.logipipe.circuit+zip": {\n    "source": "iana",\n    "compressible": false\n  },\n  "application/vnd.loom": {\n    "source": "iana"\n  },\n  "application/vnd.lotus-1-2-3": {\n    "source": "iana",\n    "extensions": ["123"]\n  },\n  "application/vnd.lotus-approach": {\n    "source": "iana",\n    "extensions": ["apr"]\n  },\n  "application/vnd.lotus-freelance": {\n    "source": "iana",\n    "extensions": ["pre"]\n  },\n  "application/vnd.lotus-notes": {\n    "source": "iana",\n    "extensions": ["nsf"]\n  },\n  "application/vnd.lotus-organizer": {\n    "source": "iana",\n    "extensions": ["org"]\n  },\n  "application/vnd.lotus-screencam": {\n    "source": "iana",\n    "extensions": ["scm"]\n  },\n  "application/vnd.lotus-wordpro": {\n    "source": "iana",\n    "extensions": ["lwp"]\n  },\n  "application/vnd.macports.portpkg": {\n    "source": "iana",\n    "extensions": ["portpkg"]\n  },\n  "application/vnd.mapbox-vector-tile": {\n    "source": "iana"\n  },\n  "application/vnd.marlin.drm.actiontoken+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.conftoken+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.license+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.marlin.drm.mdcf": {\n    "source": "iana"\n  },\n  "application/vnd.mason+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.maxmind.maxmind-db": {\n    "source": "iana"\n  },\n  "application/vnd.mcd": {\n    "source": "iana",\n    "extensions": ["mcd"]\n  },\n  "application/vnd.medcalcdata": {\n    "source": "iana",\n    "extensions": ["mc1"]\n  },\n  "application/vnd.mediastation.cdkey": {\n    "source": "iana",\n    "extensions": ["cdkey"]\n  },\n  "application/vnd.meridian-slingshot": {\n    "source": "iana"\n  },\n  "application/vnd.mfer": {\n    "source": "iana",\n    "extensions": ["mwf"]\n  },\n  "application/vnd.mfmp": {\n    "source": "iana",\n    "extensions": ["mfm"]\n  },\n  "application/vnd.micro+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.micrografx.flo": {\n    "source": "iana",\n    "extensions": ["flo"]\n  },\n  "application/vnd.micrografx.igx": {\n    "source": "iana",\n    "extensions": ["igx"]\n  },\n  "application/vnd.microsoft.portable-executable": {\n    "source": "iana"\n  },\n  "application/vnd.microsoft.windows.thumbnail-cache": {\n    "source": "iana"\n  },\n  "application/vnd.miele+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.mif": {\n    "source": "iana",\n    "extensions": ["mif"]\n  },\n  "application/vnd.minisoft-hp3000-save": {\n    "source": "iana"\n  },\n  "application/vnd.mitsubishi.misty-guard.trustweb": {\n    "source": "iana"\n  },\n  "application/vnd.mobius.daf": {\n    "source": "iana",\n    "extensions": ["daf"]\n  },\n  "application/vnd.mobius.dis": {\n    "source": "iana",\n    "extensions": ["dis"]\n  },\n  "application/vnd.mobius.mbk": {\n    "source": "iana",\n    "extensions": ["mbk"]\n  },\n  "application/vnd.mobius.mqy": {\n    "source": "iana",\n    "extensions": ["mqy"]\n  },\n  "application/vnd.mobius.msl": {\n    "source": "iana",\n    "extensions": ["msl"]\n  },\n  "application/vnd.mobius.plc": {\n    "source": "iana",\n    "extensions": ["plc"]\n  },\n  "application/vnd.mobius.txf": {\n    "source": "iana",\n    "extensions": ["txf"]\n  },\n  "application/vnd.mophun.application": {\n    "source": "iana",\n    "extensions": ["mpn"]\n  },\n  "application/vnd.mophun.certificate": {\n    "source": "iana",\n    "extensions": ["mpc"]\n  },\n  "application/vnd.motorola.flexsuite": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.adsi": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.fis": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.gotap": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.kmr": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.ttc": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.flexsuite.wem": {\n    "source": "iana"\n  },\n  "application/vnd.motorola.iprm": {\n    "source": "iana"\n  },\n  "application/vnd.mozilla.xul+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xul"]\n  },\n  "application/vnd.ms-3mfdocument": {\n    "source": "iana"\n  },\n  "application/vnd.ms-artgalry": {\n    "source": "iana",\n    "extensions": ["cil"]\n  },\n  "application/vnd.ms-asf": {\n    "source": "iana"\n  },\n  "application/vnd.ms-cab-compressed": {\n    "source": "iana",\n    "extensions": ["cab"]\n  },\n  "application/vnd.ms-color.iccprofile": {\n    "source": "apache"\n  },\n  "application/vnd.ms-excel": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xls","xlm","xla","xlc","xlt","xlw"]\n  },\n  "application/vnd.ms-excel.addin.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlam"]\n  },\n  "application/vnd.ms-excel.sheet.binary.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlsb"]\n  },\n  "application/vnd.ms-excel.sheet.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xlsm"]\n  },\n  "application/vnd.ms-excel.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["xltm"]\n  },\n  "application/vnd.ms-fontobject": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["eot"]\n  },\n  "application/vnd.ms-htmlhelp": {\n    "source": "iana",\n    "extensions": ["chm"]\n  },\n  "application/vnd.ms-ims": {\n    "source": "iana",\n    "extensions": ["ims"]\n  },\n  "application/vnd.ms-lrm": {\n    "source": "iana",\n    "extensions": ["lrm"]\n  },\n  "application/vnd.ms-office.activex+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-officetheme": {\n    "source": "iana",\n    "extensions": ["thmx"]\n  },\n  "application/vnd.ms-opentype": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/vnd.ms-outlook": {\n    "compressible": false,\n    "extensions": ["msg"]\n  },\n  "application/vnd.ms-package.obfuscated-opentype": {\n    "source": "apache"\n  },\n  "application/vnd.ms-pki.seccat": {\n    "source": "apache",\n    "extensions": ["cat"]\n  },\n  "application/vnd.ms-pki.stl": {\n    "source": "apache",\n    "extensions": ["stl"]\n  },\n  "application/vnd.ms-playready.initiator+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-powerpoint": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ppt","pps","pot"]\n  },\n  "application/vnd.ms-powerpoint.addin.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["ppam"]\n  },\n  "application/vnd.ms-powerpoint.presentation.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["pptm"]\n  },\n  "application/vnd.ms-powerpoint.slide.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["sldm"]\n  },\n  "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["ppsm"]\n  },\n  "application/vnd.ms-powerpoint.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["potm"]\n  },\n  "application/vnd.ms-printdevicecapabilities+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-printing.printticket+xml": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/vnd.ms-printschematicket+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.ms-project": {\n    "source": "iana",\n    "extensions": ["mpp","mpt"]\n  },\n  "application/vnd.ms-tnef": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.devicepairing": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.nwprinting.oob": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.printerpairing": {\n    "source": "iana"\n  },\n  "application/vnd.ms-windows.wsd.oob": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.lic-chlg-req": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.lic-resp": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.meter-chlg-req": {\n    "source": "iana"\n  },\n  "application/vnd.ms-wmdrm.meter-resp": {\n    "source": "iana"\n  },\n  "application/vnd.ms-word.document.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["docm"]\n  },\n  "application/vnd.ms-word.template.macroenabled.12": {\n    "source": "iana",\n    "extensions": ["dotm"]\n  },\n  "application/vnd.ms-works": {\n    "source": "iana",\n    "extensions": ["wps","wks","wcm","wdb"]\n  },\n  "application/vnd.ms-wpl": {\n    "source": "iana",\n    "extensions": ["wpl"]\n  },\n  "application/vnd.ms-xpsdocument": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xps"]\n  },\n  "application/vnd.msa-disk-image": {\n    "source": "iana"\n  },\n  "application/vnd.mseq": {\n    "source": "iana",\n    "extensions": ["mseq"]\n  },\n  "application/vnd.msign": {\n    "source": "iana"\n  },\n  "application/vnd.multiad.creator": {\n    "source": "iana"\n  },\n  "application/vnd.multiad.creator.cif": {\n    "source": "iana"\n  },\n  "application/vnd.music-niff": {\n    "source": "iana"\n  },\n  "application/vnd.musician": {\n    "source": "iana",\n    "extensions": ["mus"]\n  },\n  "application/vnd.muvee.style": {\n    "source": "iana",\n    "extensions": ["msty"]\n  },\n  "application/vnd.mynfc": {\n    "source": "iana",\n    "extensions": ["taglet"]\n  },\n  "application/vnd.ncd.control": {\n    "source": "iana"\n  },\n  "application/vnd.ncd.reference": {\n    "source": "iana"\n  },\n  "application/vnd.nearst.inv+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nervana": {\n    "source": "iana"\n  },\n  "application/vnd.netfpx": {\n    "source": "iana"\n  },\n  "application/vnd.neurolanguage.nlu": {\n    "source": "iana",\n    "extensions": ["nlu"]\n  },\n  "application/vnd.nimn": {\n    "source": "iana"\n  },\n  "application/vnd.nintendo.nitro.rom": {\n    "source": "iana"\n  },\n  "application/vnd.nintendo.snes.rom": {\n    "source": "iana"\n  },\n  "application/vnd.nitf": {\n    "source": "iana",\n    "extensions": ["ntf","nitf"]\n  },\n  "application/vnd.noblenet-directory": {\n    "source": "iana",\n    "extensions": ["nnd"]\n  },\n  "application/vnd.noblenet-sealer": {\n    "source": "iana",\n    "extensions": ["nns"]\n  },\n  "application/vnd.noblenet-web": {\n    "source": "iana",\n    "extensions": ["nnw"]\n  },\n  "application/vnd.nokia.catalogs": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.conml+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.conml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.iptv.config+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.isds-radio-presets": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.landmark+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.landmark+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.landmarkcollection+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.n-gage.ac+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ac"]\n  },\n  "application/vnd.nokia.n-gage.data": {\n    "source": "iana",\n    "extensions": ["ngdat"]\n  },\n  "application/vnd.nokia.n-gage.symbian.install": {\n    "source": "iana",\n    "extensions": ["n-gage"]\n  },\n  "application/vnd.nokia.ncd": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.pcd+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.nokia.pcd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.nokia.radio-preset": {\n    "source": "iana",\n    "extensions": ["rpst"]\n  },\n  "application/vnd.nokia.radio-presets": {\n    "source": "iana",\n    "extensions": ["rpss"]\n  },\n  "application/vnd.novadigm.edm": {\n    "source": "iana",\n    "extensions": ["edm"]\n  },\n  "application/vnd.novadigm.edx": {\n    "source": "iana",\n    "extensions": ["edx"]\n  },\n  "application/vnd.novadigm.ext": {\n    "source": "iana",\n    "extensions": ["ext"]\n  },\n  "application/vnd.ntt-local.content-share": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.file-transfer": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.ogw_remote-access": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.sip-ta_remote": {\n    "source": "iana"\n  },\n  "application/vnd.ntt-local.sip-ta_tcp_stream": {\n    "source": "iana"\n  },\n  "application/vnd.oasis.opendocument.chart": {\n    "source": "iana",\n    "extensions": ["odc"]\n  },\n  "application/vnd.oasis.opendocument.chart-template": {\n    "source": "iana",\n    "extensions": ["otc"]\n  },\n  "application/vnd.oasis.opendocument.database": {\n    "source": "iana",\n    "extensions": ["odb"]\n  },\n  "application/vnd.oasis.opendocument.formula": {\n    "source": "iana",\n    "extensions": ["odf"]\n  },\n  "application/vnd.oasis.opendocument.formula-template": {\n    "source": "iana",\n    "extensions": ["odft"]\n  },\n  "application/vnd.oasis.opendocument.graphics": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odg"]\n  },\n  "application/vnd.oasis.opendocument.graphics-template": {\n    "source": "iana",\n    "extensions": ["otg"]\n  },\n  "application/vnd.oasis.opendocument.image": {\n    "source": "iana",\n    "extensions": ["odi"]\n  },\n  "application/vnd.oasis.opendocument.image-template": {\n    "source": "iana",\n    "extensions": ["oti"]\n  },\n  "application/vnd.oasis.opendocument.presentation": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odp"]\n  },\n  "application/vnd.oasis.opendocument.presentation-template": {\n    "source": "iana",\n    "extensions": ["otp"]\n  },\n  "application/vnd.oasis.opendocument.spreadsheet": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ods"]\n  },\n  "application/vnd.oasis.opendocument.spreadsheet-template": {\n    "source": "iana",\n    "extensions": ["ots"]\n  },\n  "application/vnd.oasis.opendocument.text": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["odt"]\n  },\n  "application/vnd.oasis.opendocument.text-master": {\n    "source": "iana",\n    "extensions": ["odm"]\n  },\n  "application/vnd.oasis.opendocument.text-template": {\n    "source": "iana",\n    "extensions": ["ott"]\n  },\n  "application/vnd.oasis.opendocument.text-web": {\n    "source": "iana",\n    "extensions": ["oth"]\n  },\n  "application/vnd.obn": {\n    "source": "iana"\n  },\n  "application/vnd.ocf+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.oci.image.manifest.v1+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oftn.l10n+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.contentaccessdownload+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.contentaccessstreaming+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.cspg-hexbinary": {\n    "source": "iana"\n  },\n  "application/vnd.oipf.dae.svg+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.dae.xhtml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.mippvcontrolmessage+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.pae.gem": {\n    "source": "iana"\n  },\n  "application/vnd.oipf.spdiscovery+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.spdlist+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.ueprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oipf.userprofile+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.olpc-sugar": {\n    "source": "iana",\n    "extensions": ["xo"]\n  },\n  "application/vnd.oma-scws-config": {\n    "source": "iana"\n  },\n  "application/vnd.oma-scws-http-request": {\n    "source": "iana"\n  },\n  "application/vnd.oma-scws-http-response": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.associated-procedure-parameter+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.drm-trigger+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.imd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.ltkm": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.notification+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.provisioningtrigger": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.sgboot": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.sgdd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.sgdu": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.simple-symbol-container": {\n    "source": "iana"\n  },\n  "application/vnd.oma.bcast.smartcard-trigger+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.sprov+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.bcast.stkm": {\n    "source": "iana"\n  },\n  "application/vnd.oma.cab-address-book+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-feature-handler+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-pcc+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-subs-invite+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.cab-user-prefs+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.dcd": {\n    "source": "iana"\n  },\n  "application/vnd.oma.dcdc": {\n    "source": "iana"\n  },\n  "application/vnd.oma.dd2+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dd2"]\n  },\n  "application/vnd.oma.drm.risd+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.group-usage-list+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.lwm2m+cbor": {\n    "source": "iana"\n  },\n  "application/vnd.oma.lwm2m+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.lwm2m+tlv": {\n    "source": "iana"\n  },\n  "application/vnd.oma.pal+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.detailed-progress-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.final-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.groups+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.invocation-descriptor+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.poc.optimized-progress-report+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.push": {\n    "source": "iana"\n  },\n  "application/vnd.oma.scidm.messages+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oma.xcap-directory+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.omads-email+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omads-file+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omads-folder+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.omaloc-supl-init": {\n    "source": "iana"\n  },\n  "application/vnd.onepager": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertamp": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertamx": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertat": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertatp": {\n    "source": "iana"\n  },\n  "application/vnd.onepagertatx": {\n    "source": "iana"\n  },\n  "application/vnd.openblox.game+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["obgx"]\n  },\n  "application/vnd.openblox.game-binary": {\n    "source": "iana"\n  },\n  "application/vnd.openeye.oeb": {\n    "source": "iana"\n  },\n  "application/vnd.openofficeorg.extension": {\n    "source": "apache",\n    "extensions": ["oxt"]\n  },\n  "application/vnd.openstreetmap.data+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["osm"]\n  },\n  "application/vnd.openxmlformats-officedocument.custom-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawing+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.extended-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presentation": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["pptx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slide": {\n    "source": "iana",\n    "extensions": ["sldx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideshow": {\n    "source": "iana",\n    "extensions": ["ppsx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.template": {\n    "source": "iana",\n    "extensions": ["potx"]\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["xlsx"]\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.template": {\n    "source": "iana",\n    "extensions": ["xltx"]\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.theme+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.themeoverride+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.vmldrawing": {\n    "source": "iana"\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["docx"]\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.template": {\n    "source": "iana",\n    "extensions": ["dotx"]\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.core-properties+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.openxmlformats-package.relationships+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oracle.resource+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.orange.indata": {\n    "source": "iana"\n  },\n  "application/vnd.osa.netdeploy": {\n    "source": "iana"\n  },\n  "application/vnd.osgeo.mapguide.package": {\n    "source": "iana",\n    "extensions": ["mgp"]\n  },\n  "application/vnd.osgi.bundle": {\n    "source": "iana"\n  },\n  "application/vnd.osgi.dp": {\n    "source": "iana",\n    "extensions": ["dp"]\n  },\n  "application/vnd.osgi.subsystem": {\n    "source": "iana",\n    "extensions": ["esa"]\n  },\n  "application/vnd.otps.ct-kip+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.oxli.countgraph": {\n    "source": "iana"\n  },\n  "application/vnd.pagerduty+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.palm": {\n    "source": "iana",\n    "extensions": ["pdb","pqa","oprc"]\n  },\n  "application/vnd.panoply": {\n    "source": "iana"\n  },\n  "application/vnd.paos.xml": {\n    "source": "iana"\n  },\n  "application/vnd.patentdive": {\n    "source": "iana"\n  },\n  "application/vnd.patientecommsdoc": {\n    "source": "iana"\n  },\n  "application/vnd.pawaafile": {\n    "source": "iana",\n    "extensions": ["paw"]\n  },\n  "application/vnd.pcos": {\n    "source": "iana"\n  },\n  "application/vnd.pg.format": {\n    "source": "iana",\n    "extensions": ["str"]\n  },\n  "application/vnd.pg.osasli": {\n    "source": "iana",\n    "extensions": ["ei6"]\n  },\n  "application/vnd.piaccess.application-licence": {\n    "source": "iana"\n  },\n  "application/vnd.picsel": {\n    "source": "iana",\n    "extensions": ["efif"]\n  },\n  "application/vnd.pmi.widget": {\n    "source": "iana",\n    "extensions": ["wg"]\n  },\n  "application/vnd.poc.group-advertisement+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.pocketlearn": {\n    "source": "iana",\n    "extensions": ["plf"]\n  },\n  "application/vnd.powerbuilder6": {\n    "source": "iana",\n    "extensions": ["pbd"]\n  },\n  "application/vnd.powerbuilder6-s": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder7": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder7-s": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder75": {\n    "source": "iana"\n  },\n  "application/vnd.powerbuilder75-s": {\n    "source": "iana"\n  },\n  "application/vnd.preminet": {\n    "source": "iana"\n  },\n  "application/vnd.previewsystems.box": {\n    "source": "iana",\n    "extensions": ["box"]\n  },\n  "application/vnd.proteus.magazine": {\n    "source": "iana",\n    "extensions": ["mgz"]\n  },\n  "application/vnd.psfs": {\n    "source": "iana"\n  },\n  "application/vnd.publishare-delta-tree": {\n    "source": "iana",\n    "extensions": ["qps"]\n  },\n  "application/vnd.pvi.ptid1": {\n    "source": "iana",\n    "extensions": ["ptid"]\n  },\n  "application/vnd.pwg-multiplexed": {\n    "source": "iana"\n  },\n  "application/vnd.pwg-xhtml-print+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.qualcomm.brew-app-res": {\n    "source": "iana"\n  },\n  "application/vnd.quarantainenet": {\n    "source": "iana"\n  },\n  "application/vnd.quark.quarkxpress": {\n    "source": "iana",\n    "extensions": ["qxd","qxt","qwd","qwt","qxl","qxb"]\n  },\n  "application/vnd.quobject-quoxdocument": {\n    "source": "iana"\n  },\n  "application/vnd.radisys.moml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-conf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-conn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-dialog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-audit-stream+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-conf+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-base+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-fax-detect+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-group+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-speech+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.radisys.msml-dialog-transform+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.rainstor.data": {\n    "source": "iana"\n  },\n  "application/vnd.rapid": {\n    "source": "iana"\n  },\n  "application/vnd.rar": {\n    "source": "iana",\n    "extensions": ["rar"]\n  },\n  "application/vnd.realvnc.bed": {\n    "source": "iana",\n    "extensions": ["bed"]\n  },\n  "application/vnd.recordare.musicxml": {\n    "source": "iana",\n    "extensions": ["mxl"]\n  },\n  "application/vnd.recordare.musicxml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["musicxml"]\n  },\n  "application/vnd.renlearn.rlprint": {\n    "source": "iana"\n  },\n  "application/vnd.restful+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.rig.cryptonote": {\n    "source": "iana",\n    "extensions": ["cryptonote"]\n  },\n  "application/vnd.rim.cod": {\n    "source": "apache",\n    "extensions": ["cod"]\n  },\n  "application/vnd.rn-realmedia": {\n    "source": "apache",\n    "extensions": ["rm"]\n  },\n  "application/vnd.rn-realmedia-vbr": {\n    "source": "apache",\n    "extensions": ["rmvb"]\n  },\n  "application/vnd.route66.link66+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["link66"]\n  },\n  "application/vnd.rs-274x": {\n    "source": "iana"\n  },\n  "application/vnd.ruckus.download": {\n    "source": "iana"\n  },\n  "application/vnd.s3sms": {\n    "source": "iana"\n  },\n  "application/vnd.sailingtracker.track": {\n    "source": "iana",\n    "extensions": ["st"]\n  },\n  "application/vnd.sar": {\n    "source": "iana"\n  },\n  "application/vnd.sbm.cid": {\n    "source": "iana"\n  },\n  "application/vnd.sbm.mid2": {\n    "source": "iana"\n  },\n  "application/vnd.scribus": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.3df": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.csf": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.doc": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.eml": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.mht": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.net": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.ppt": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.tiff": {\n    "source": "iana"\n  },\n  "application/vnd.sealed.xls": {\n    "source": "iana"\n  },\n  "application/vnd.sealedmedia.softseal.html": {\n    "source": "iana"\n  },\n  "application/vnd.sealedmedia.softseal.pdf": {\n    "source": "iana"\n  },\n  "application/vnd.seemail": {\n    "source": "iana",\n    "extensions": ["see"]\n  },\n  "application/vnd.sema": {\n    "source": "iana",\n    "extensions": ["sema"]\n  },\n  "application/vnd.semd": {\n    "source": "iana",\n    "extensions": ["semd"]\n  },\n  "application/vnd.semf": {\n    "source": "iana",\n    "extensions": ["semf"]\n  },\n  "application/vnd.shade-save-file": {\n    "source": "iana"\n  },\n  "application/vnd.shana.informed.formdata": {\n    "source": "iana",\n    "extensions": ["ifm"]\n  },\n  "application/vnd.shana.informed.formtemplate": {\n    "source": "iana",\n    "extensions": ["itp"]\n  },\n  "application/vnd.shana.informed.interchange": {\n    "source": "iana",\n    "extensions": ["iif"]\n  },\n  "application/vnd.shana.informed.package": {\n    "source": "iana",\n    "extensions": ["ipk"]\n  },\n  "application/vnd.shootproof+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.shopkick+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.shp": {\n    "source": "iana"\n  },\n  "application/vnd.shx": {\n    "source": "iana"\n  },\n  "application/vnd.sigrok.session": {\n    "source": "iana"\n  },\n  "application/vnd.simtech-mindmapper": {\n    "source": "iana",\n    "extensions": ["twd","twds"]\n  },\n  "application/vnd.siren+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.smaf": {\n    "source": "iana",\n    "extensions": ["mmf"]\n  },\n  "application/vnd.smart.notebook": {\n    "source": "iana"\n  },\n  "application/vnd.smart.teacher": {\n    "source": "iana",\n    "extensions": ["teacher"]\n  },\n  "application/vnd.snesdev-page-table": {\n    "source": "iana"\n  },\n  "application/vnd.software602.filler.form+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["fo"]\n  },\n  "application/vnd.software602.filler.form-xml-zip": {\n    "source": "iana"\n  },\n  "application/vnd.solent.sdkm+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["sdkm","sdkd"]\n  },\n  "application/vnd.spotfire.dxp": {\n    "source": "iana",\n    "extensions": ["dxp"]\n  },\n  "application/vnd.spotfire.sfs": {\n    "source": "iana",\n    "extensions": ["sfs"]\n  },\n  "application/vnd.sqlite3": {\n    "source": "iana"\n  },\n  "application/vnd.sss-cod": {\n    "source": "iana"\n  },\n  "application/vnd.sss-dtf": {\n    "source": "iana"\n  },\n  "application/vnd.sss-ntf": {\n    "source": "iana"\n  },\n  "application/vnd.stardivision.calc": {\n    "source": "apache",\n    "extensions": ["sdc"]\n  },\n  "application/vnd.stardivision.draw": {\n    "source": "apache",\n    "extensions": ["sda"]\n  },\n  "application/vnd.stardivision.impress": {\n    "source": "apache",\n    "extensions": ["sdd"]\n  },\n  "application/vnd.stardivision.math": {\n    "source": "apache",\n    "extensions": ["smf"]\n  },\n  "application/vnd.stardivision.writer": {\n    "source": "apache",\n    "extensions": ["sdw","vor"]\n  },\n  "application/vnd.stardivision.writer-global": {\n    "source": "apache",\n    "extensions": ["sgl"]\n  },\n  "application/vnd.stepmania.package": {\n    "source": "iana",\n    "extensions": ["smzip"]\n  },\n  "application/vnd.stepmania.stepchart": {\n    "source": "iana",\n    "extensions": ["sm"]\n  },\n  "application/vnd.street-stream": {\n    "source": "iana"\n  },\n  "application/vnd.sun.wadl+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wadl"]\n  },\n  "application/vnd.sun.xml.calc": {\n    "source": "apache",\n    "extensions": ["sxc"]\n  },\n  "application/vnd.sun.xml.calc.template": {\n    "source": "apache",\n    "extensions": ["stc"]\n  },\n  "application/vnd.sun.xml.draw": {\n    "source": "apache",\n    "extensions": ["sxd"]\n  },\n  "application/vnd.sun.xml.draw.template": {\n    "source": "apache",\n    "extensions": ["std"]\n  },\n  "application/vnd.sun.xml.impress": {\n    "source": "apache",\n    "extensions": ["sxi"]\n  },\n  "application/vnd.sun.xml.impress.template": {\n    "source": "apache",\n    "extensions": ["sti"]\n  },\n  "application/vnd.sun.xml.math": {\n    "source": "apache",\n    "extensions": ["sxm"]\n  },\n  "application/vnd.sun.xml.writer": {\n    "source": "apache",\n    "extensions": ["sxw"]\n  },\n  "application/vnd.sun.xml.writer.global": {\n    "source": "apache",\n    "extensions": ["sxg"]\n  },\n  "application/vnd.sun.xml.writer.template": {\n    "source": "apache",\n    "extensions": ["stw"]\n  },\n  "application/vnd.sus-calendar": {\n    "source": "iana",\n    "extensions": ["sus","susp"]\n  },\n  "application/vnd.svd": {\n    "source": "iana",\n    "extensions": ["svd"]\n  },\n  "application/vnd.swiftview-ics": {\n    "source": "iana"\n  },\n  "application/vnd.sycle+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.symbian.install": {\n    "source": "apache",\n    "extensions": ["sis","sisx"]\n  },\n  "application/vnd.syncml+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["xsm"]\n  },\n  "application/vnd.syncml.dm+wbxml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["bdm"]\n  },\n  "application/vnd.syncml.dm+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["xdm"]\n  },\n  "application/vnd.syncml.dm.notification": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmddf+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmddf+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["ddf"]\n  },\n  "application/vnd.syncml.dmtnds+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.syncml.dmtnds+xml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true\n  },\n  "application/vnd.syncml.ds.notification": {\n    "source": "iana"\n  },\n  "application/vnd.tableschema+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tao.intent-module-archive": {\n    "source": "iana",\n    "extensions": ["tao"]\n  },\n  "application/vnd.tcpdump.pcap": {\n    "source": "iana",\n    "extensions": ["pcap","cap","dmp"]\n  },\n  "application/vnd.think-cell.ppttc+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tmd.mediaflex.api+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.tml": {\n    "source": "iana"\n  },\n  "application/vnd.tmobile-livetv": {\n    "source": "iana",\n    "extensions": ["tmo"]\n  },\n  "application/vnd.tri.onesource": {\n    "source": "iana"\n  },\n  "application/vnd.trid.tpt": {\n    "source": "iana",\n    "extensions": ["tpt"]\n  },\n  "application/vnd.triscape.mxs": {\n    "source": "iana",\n    "extensions": ["mxs"]\n  },\n  "application/vnd.trueapp": {\n    "source": "iana",\n    "extensions": ["tra"]\n  },\n  "application/vnd.truedoc": {\n    "source": "iana"\n  },\n  "application/vnd.ubisoft.webplayer": {\n    "source": "iana"\n  },\n  "application/vnd.ufdl": {\n    "source": "iana",\n    "extensions": ["ufd","ufdl"]\n  },\n  "application/vnd.uiq.theme": {\n    "source": "iana",\n    "extensions": ["utz"]\n  },\n  "application/vnd.umajin": {\n    "source": "iana",\n    "extensions": ["umj"]\n  },\n  "application/vnd.unity": {\n    "source": "iana",\n    "extensions": ["unityweb"]\n  },\n  "application/vnd.uoml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uoml"]\n  },\n  "application/vnd.uplanet.alert": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.alert-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.bearer-choice": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.bearer-choice-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.cacheop": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.cacheop-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.channel": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.channel-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.list": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.list-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.listcmd": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.listcmd-wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.uplanet.signal": {\n    "source": "iana"\n  },\n  "application/vnd.uri-map": {\n    "source": "iana"\n  },\n  "application/vnd.valve.source.material": {\n    "source": "iana"\n  },\n  "application/vnd.vcx": {\n    "source": "iana",\n    "extensions": ["vcx"]\n  },\n  "application/vnd.vd-study": {\n    "source": "iana"\n  },\n  "application/vnd.vectorworks": {\n    "source": "iana"\n  },\n  "application/vnd.vel+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.verimatrix.vcas": {\n    "source": "iana"\n  },\n  "application/vnd.veryant.thin": {\n    "source": "iana"\n  },\n  "application/vnd.ves.encrypted": {\n    "source": "iana"\n  },\n  "application/vnd.vidsoft.vidconference": {\n    "source": "iana"\n  },\n  "application/vnd.visio": {\n    "source": "iana",\n    "extensions": ["vsd","vst","vss","vsw"]\n  },\n  "application/vnd.visionary": {\n    "source": "iana",\n    "extensions": ["vis"]\n  },\n  "application/vnd.vividence.scriptfile": {\n    "source": "iana"\n  },\n  "application/vnd.vsf": {\n    "source": "iana",\n    "extensions": ["vsf"]\n  },\n  "application/vnd.wap.sic": {\n    "source": "iana"\n  },\n  "application/vnd.wap.slc": {\n    "source": "iana"\n  },\n  "application/vnd.wap.wbxml": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["wbxml"]\n  },\n  "application/vnd.wap.wmlc": {\n    "source": "iana",\n    "extensions": ["wmlc"]\n  },\n  "application/vnd.wap.wmlscriptc": {\n    "source": "iana",\n    "extensions": ["wmlsc"]\n  },\n  "application/vnd.webturbo": {\n    "source": "iana",\n    "extensions": ["wtb"]\n  },\n  "application/vnd.wfa.p2p": {\n    "source": "iana"\n  },\n  "application/vnd.wfa.wsc": {\n    "source": "iana"\n  },\n  "application/vnd.windows.devicepairing": {\n    "source": "iana"\n  },\n  "application/vnd.wmc": {\n    "source": "iana"\n  },\n  "application/vnd.wmf.bootstrap": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.mathematica": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.mathematica.package": {\n    "source": "iana"\n  },\n  "application/vnd.wolfram.player": {\n    "source": "iana",\n    "extensions": ["nbp"]\n  },\n  "application/vnd.wordperfect": {\n    "source": "iana",\n    "extensions": ["wpd"]\n  },\n  "application/vnd.wqd": {\n    "source": "iana",\n    "extensions": ["wqd"]\n  },\n  "application/vnd.wrq-hp3000-labelled": {\n    "source": "iana"\n  },\n  "application/vnd.wt.stf": {\n    "source": "iana",\n    "extensions": ["stf"]\n  },\n  "application/vnd.wv.csp+wbxml": {\n    "source": "iana"\n  },\n  "application/vnd.wv.csp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.wv.ssp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xacml+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xara": {\n    "source": "iana",\n    "extensions": ["xar"]\n  },\n  "application/vnd.xfdl": {\n    "source": "iana",\n    "extensions": ["xfdl"]\n  },\n  "application/vnd.xfdl.webform": {\n    "source": "iana"\n  },\n  "application/vnd.xmi+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vnd.xmpie.cpkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.dpkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.plan": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.ppkg": {\n    "source": "iana"\n  },\n  "application/vnd.xmpie.xlim": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.hv-dic": {\n    "source": "iana",\n    "extensions": ["hvd"]\n  },\n  "application/vnd.yamaha.hv-script": {\n    "source": "iana",\n    "extensions": ["hvs"]\n  },\n  "application/vnd.yamaha.hv-voice": {\n    "source": "iana",\n    "extensions": ["hvp"]\n  },\n  "application/vnd.yamaha.openscoreformat": {\n    "source": "iana",\n    "extensions": ["osf"]\n  },\n  "application/vnd.yamaha.openscoreformat.osfpvg+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["osfpvg"]\n  },\n  "application/vnd.yamaha.remote-setup": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.smaf-audio": {\n    "source": "iana",\n    "extensions": ["saf"]\n  },\n  "application/vnd.yamaha.smaf-phrase": {\n    "source": "iana",\n    "extensions": ["spf"]\n  },\n  "application/vnd.yamaha.through-ngn": {\n    "source": "iana"\n  },\n  "application/vnd.yamaha.tunnel-udpencap": {\n    "source": "iana"\n  },\n  "application/vnd.yaoweme": {\n    "source": "iana"\n  },\n  "application/vnd.yellowriver-custom-menu": {\n    "source": "iana",\n    "extensions": ["cmp"]\n  },\n  "application/vnd.youtube.yt": {\n    "source": "iana"\n  },\n  "application/vnd.zul": {\n    "source": "iana",\n    "extensions": ["zir","zirz"]\n  },\n  "application/vnd.zzazz.deck+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["zaz"]\n  },\n  "application/voicexml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["vxml"]\n  },\n  "application/voucher-cms+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/vq-rtcpxr": {\n    "source": "iana"\n  },\n  "application/wasm": {\n    "compressible": true,\n    "extensions": ["wasm"]\n  },\n  "application/watcherinfo+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/webpush-options+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/whoispp-query": {\n    "source": "iana"\n  },\n  "application/whoispp-response": {\n    "source": "iana"\n  },\n  "application/widget": {\n    "source": "iana",\n    "extensions": ["wgt"]\n  },\n  "application/winhlp": {\n    "source": "apache",\n    "extensions": ["hlp"]\n  },\n  "application/wita": {\n    "source": "iana"\n  },\n  "application/wordperfect5.1": {\n    "source": "iana"\n  },\n  "application/wsdl+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wsdl"]\n  },\n  "application/wspolicy+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["wspolicy"]\n  },\n  "application/x-7z-compressed": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["7z"]\n  },\n  "application/x-abiword": {\n    "source": "apache",\n    "extensions": ["abw"]\n  },\n  "application/x-ace-compressed": {\n    "source": "apache",\n    "extensions": ["ace"]\n  },\n  "application/x-amf": {\n    "source": "apache"\n  },\n  "application/x-apple-diskimage": {\n    "source": "apache",\n    "extensions": ["dmg"]\n  },\n  "application/x-arj": {\n    "compressible": false,\n    "extensions": ["arj"]\n  },\n  "application/x-authorware-bin": {\n    "source": "apache",\n    "extensions": ["aab","x32","u32","vox"]\n  },\n  "application/x-authorware-map": {\n    "source": "apache",\n    "extensions": ["aam"]\n  },\n  "application/x-authorware-seg": {\n    "source": "apache",\n    "extensions": ["aas"]\n  },\n  "application/x-bcpio": {\n    "source": "apache",\n    "extensions": ["bcpio"]\n  },\n  "application/x-bdoc": {\n    "compressible": false,\n    "extensions": ["bdoc"]\n  },\n  "application/x-bittorrent": {\n    "source": "apache",\n    "extensions": ["torrent"]\n  },\n  "application/x-blorb": {\n    "source": "apache",\n    "extensions": ["blb","blorb"]\n  },\n  "application/x-bzip": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["bz"]\n  },\n  "application/x-bzip2": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["bz2","boz"]\n  },\n  "application/x-cbr": {\n    "source": "apache",\n    "extensions": ["cbr","cba","cbt","cbz","cb7"]\n  },\n  "application/x-cdlink": {\n    "source": "apache",\n    "extensions": ["vcd"]\n  },\n  "application/x-cfs-compressed": {\n    "source": "apache",\n    "extensions": ["cfs"]\n  },\n  "application/x-chat": {\n    "source": "apache",\n    "extensions": ["chat"]\n  },\n  "application/x-chess-pgn": {\n    "source": "apache",\n    "extensions": ["pgn"]\n  },\n  "application/x-chrome-extension": {\n    "extensions": ["crx"]\n  },\n  "application/x-cocoa": {\n    "source": "nginx",\n    "extensions": ["cco"]\n  },\n  "application/x-compress": {\n    "source": "apache"\n  },\n  "application/x-conference": {\n    "source": "apache",\n    "extensions": ["nsc"]\n  },\n  "application/x-cpio": {\n    "source": "apache",\n    "extensions": ["cpio"]\n  },\n  "application/x-csh": {\n    "source": "apache",\n    "extensions": ["csh"]\n  },\n  "application/x-deb": {\n    "compressible": false\n  },\n  "application/x-debian-package": {\n    "source": "apache",\n    "extensions": ["deb","udeb"]\n  },\n  "application/x-dgc-compressed": {\n    "source": "apache",\n    "extensions": ["dgc"]\n  },\n  "application/x-director": {\n    "source": "apache",\n    "extensions": ["dir","dcr","dxr","cst","cct","cxt","w3d","fgd","swa"]\n  },\n  "application/x-doom": {\n    "source": "apache",\n    "extensions": ["wad"]\n  },\n  "application/x-dtbncx+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ncx"]\n  },\n  "application/x-dtbook+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["dtb"]\n  },\n  "application/x-dtbresource+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["res"]\n  },\n  "application/x-dvi": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["dvi"]\n  },\n  "application/x-envoy": {\n    "source": "apache",\n    "extensions": ["evy"]\n  },\n  "application/x-eva": {\n    "source": "apache",\n    "extensions": ["eva"]\n  },\n  "application/x-font-bdf": {\n    "source": "apache",\n    "extensions": ["bdf"]\n  },\n  "application/x-font-dos": {\n    "source": "apache"\n  },\n  "application/x-font-framemaker": {\n    "source": "apache"\n  },\n  "application/x-font-ghostscript": {\n    "source": "apache",\n    "extensions": ["gsf"]\n  },\n  "application/x-font-libgrx": {\n    "source": "apache"\n  },\n  "application/x-font-linux-psf": {\n    "source": "apache",\n    "extensions": ["psf"]\n  },\n  "application/x-font-pcf": {\n    "source": "apache",\n    "extensions": ["pcf"]\n  },\n  "application/x-font-snf": {\n    "source": "apache",\n    "extensions": ["snf"]\n  },\n  "application/x-font-speedo": {\n    "source": "apache"\n  },\n  "application/x-font-sunos-news": {\n    "source": "apache"\n  },\n  "application/x-font-type1": {\n    "source": "apache",\n    "extensions": ["pfa","pfb","pfm","afm"]\n  },\n  "application/x-font-vfont": {\n    "source": "apache"\n  },\n  "application/x-freearc": {\n    "source": "apache",\n    "extensions": ["arc"]\n  },\n  "application/x-futuresplash": {\n    "source": "apache",\n    "extensions": ["spl"]\n  },\n  "application/x-gca-compressed": {\n    "source": "apache",\n    "extensions": ["gca"]\n  },\n  "application/x-glulx": {\n    "source": "apache",\n    "extensions": ["ulx"]\n  },\n  "application/x-gnumeric": {\n    "source": "apache",\n    "extensions": ["gnumeric"]\n  },\n  "application/x-gramps-xml": {\n    "source": "apache",\n    "extensions": ["gramps"]\n  },\n  "application/x-gtar": {\n    "source": "apache",\n    "extensions": ["gtar"]\n  },\n  "application/x-gzip": {\n    "source": "apache"\n  },\n  "application/x-hdf": {\n    "source": "apache",\n    "extensions": ["hdf"]\n  },\n  "application/x-httpd-php": {\n    "compressible": true,\n    "extensions": ["php"]\n  },\n  "application/x-install-instructions": {\n    "source": "apache",\n    "extensions": ["install"]\n  },\n  "application/x-iso9660-image": {\n    "source": "apache",\n    "extensions": ["iso"]\n  },\n  "application/x-java-archive-diff": {\n    "source": "nginx",\n    "extensions": ["jardiff"]\n  },\n  "application/x-java-jnlp-file": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["jnlp"]\n  },\n  "application/x-javascript": {\n    "compressible": true\n  },\n  "application/x-keepass2": {\n    "extensions": ["kdbx"]\n  },\n  "application/x-latex": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["latex"]\n  },\n  "application/x-lua-bytecode": {\n    "extensions": ["luac"]\n  },\n  "application/x-lzh-compressed": {\n    "source": "apache",\n    "extensions": ["lzh","lha"]\n  },\n  "application/x-makeself": {\n    "source": "nginx",\n    "extensions": ["run"]\n  },\n  "application/x-mie": {\n    "source": "apache",\n    "extensions": ["mie"]\n  },\n  "application/x-mobipocket-ebook": {\n    "source": "apache",\n    "extensions": ["prc","mobi"]\n  },\n  "application/x-mpegurl": {\n    "compressible": false\n  },\n  "application/x-ms-application": {\n    "source": "apache",\n    "extensions": ["application"]\n  },\n  "application/x-ms-shortcut": {\n    "source": "apache",\n    "extensions": ["lnk"]\n  },\n  "application/x-ms-wmd": {\n    "source": "apache",\n    "extensions": ["wmd"]\n  },\n  "application/x-ms-wmz": {\n    "source": "apache",\n    "extensions": ["wmz"]\n  },\n  "application/x-ms-xbap": {\n    "source": "apache",\n    "extensions": ["xbap"]\n  },\n  "application/x-msaccess": {\n    "source": "apache",\n    "extensions": ["mdb"]\n  },\n  "application/x-msbinder": {\n    "source": "apache",\n    "extensions": ["obd"]\n  },\n  "application/x-mscardfile": {\n    "source": "apache",\n    "extensions": ["crd"]\n  },\n  "application/x-msclip": {\n    "source": "apache",\n    "extensions": ["clp"]\n  },\n  "application/x-msdos-program": {\n    "extensions": ["exe"]\n  },\n  "application/x-msdownload": {\n    "source": "apache",\n    "extensions": ["exe","dll","com","bat","msi"]\n  },\n  "application/x-msmediaview": {\n    "source": "apache",\n    "extensions": ["mvb","m13","m14"]\n  },\n  "application/x-msmetafile": {\n    "source": "apache",\n    "extensions": ["wmf","wmz","emf","emz"]\n  },\n  "application/x-msmoney": {\n    "source": "apache",\n    "extensions": ["mny"]\n  },\n  "application/x-mspublisher": {\n    "source": "apache",\n    "extensions": ["pub"]\n  },\n  "application/x-msschedule": {\n    "source": "apache",\n    "extensions": ["scd"]\n  },\n  "application/x-msterminal": {\n    "source": "apache",\n    "extensions": ["trm"]\n  },\n  "application/x-mswrite": {\n    "source": "apache",\n    "extensions": ["wri"]\n  },\n  "application/x-netcdf": {\n    "source": "apache",\n    "extensions": ["nc","cdf"]\n  },\n  "application/x-ns-proxy-autoconfig": {\n    "compressible": true,\n    "extensions": ["pac"]\n  },\n  "application/x-nzb": {\n    "source": "apache",\n    "extensions": ["nzb"]\n  },\n  "application/x-perl": {\n    "source": "nginx",\n    "extensions": ["pl","pm"]\n  },\n  "application/x-pilot": {\n    "source": "nginx",\n    "extensions": ["prc","pdb"]\n  },\n  "application/x-pkcs12": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["p12","pfx"]\n  },\n  "application/x-pkcs7-certificates": {\n    "source": "apache",\n    "extensions": ["p7b","spc"]\n  },\n  "application/x-pkcs7-certreqresp": {\n    "source": "apache",\n    "extensions": ["p7r"]\n  },\n  "application/x-pki-message": {\n    "source": "iana"\n  },\n  "application/x-rar-compressed": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["rar"]\n  },\n  "application/x-redhat-package-manager": {\n    "source": "nginx",\n    "extensions": ["rpm"]\n  },\n  "application/x-research-info-systems": {\n    "source": "apache",\n    "extensions": ["ris"]\n  },\n  "application/x-sea": {\n    "source": "nginx",\n    "extensions": ["sea"]\n  },\n  "application/x-sh": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["sh"]\n  },\n  "application/x-shar": {\n    "source": "apache",\n    "extensions": ["shar"]\n  },\n  "application/x-shockwave-flash": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["swf"]\n  },\n  "application/x-silverlight-app": {\n    "source": "apache",\n    "extensions": ["xap"]\n  },\n  "application/x-sql": {\n    "source": "apache",\n    "extensions": ["sql"]\n  },\n  "application/x-stuffit": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["sit"]\n  },\n  "application/x-stuffitx": {\n    "source": "apache",\n    "extensions": ["sitx"]\n  },\n  "application/x-subrip": {\n    "source": "apache",\n    "extensions": ["srt"]\n  },\n  "application/x-sv4cpio": {\n    "source": "apache",\n    "extensions": ["sv4cpio"]\n  },\n  "application/x-sv4crc": {\n    "source": "apache",\n    "extensions": ["sv4crc"]\n  },\n  "application/x-t3vm-image": {\n    "source": "apache",\n    "extensions": ["t3"]\n  },\n  "application/x-tads": {\n    "source": "apache",\n    "extensions": ["gam"]\n  },\n  "application/x-tar": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["tar"]\n  },\n  "application/x-tcl": {\n    "source": "apache",\n    "extensions": ["tcl","tk"]\n  },\n  "application/x-tex": {\n    "source": "apache",\n    "extensions": ["tex"]\n  },\n  "application/x-tex-tfm": {\n    "source": "apache",\n    "extensions": ["tfm"]\n  },\n  "application/x-texinfo": {\n    "source": "apache",\n    "extensions": ["texinfo","texi"]\n  },\n  "application/x-tgif": {\n    "source": "apache",\n    "extensions": ["obj"]\n  },\n  "application/x-ustar": {\n    "source": "apache",\n    "extensions": ["ustar"]\n  },\n  "application/x-virtualbox-hdd": {\n    "compressible": true,\n    "extensions": ["hdd"]\n  },\n  "application/x-virtualbox-ova": {\n    "compressible": true,\n    "extensions": ["ova"]\n  },\n  "application/x-virtualbox-ovf": {\n    "compressible": true,\n    "extensions": ["ovf"]\n  },\n  "application/x-virtualbox-vbox": {\n    "compressible": true,\n    "extensions": ["vbox"]\n  },\n  "application/x-virtualbox-vbox-extpack": {\n    "compressible": false,\n    "extensions": ["vbox-extpack"]\n  },\n  "application/x-virtualbox-vdi": {\n    "compressible": true,\n    "extensions": ["vdi"]\n  },\n  "application/x-virtualbox-vhd": {\n    "compressible": true,\n    "extensions": ["vhd"]\n  },\n  "application/x-virtualbox-vmdk": {\n    "compressible": true,\n    "extensions": ["vmdk"]\n  },\n  "application/x-wais-source": {\n    "source": "apache",\n    "extensions": ["src"]\n  },\n  "application/x-web-app-manifest+json": {\n    "compressible": true,\n    "extensions": ["webapp"]\n  },\n  "application/x-www-form-urlencoded": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/x-x509-ca-cert": {\n    "source": "iana",\n    "extensions": ["der","crt","pem"]\n  },\n  "application/x-x509-ca-ra-cert": {\n    "source": "iana"\n  },\n  "application/x-x509-next-ca-cert": {\n    "source": "iana"\n  },\n  "application/x-xfig": {\n    "source": "apache",\n    "extensions": ["fig"]\n  },\n  "application/x-xliff+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xlf"]\n  },\n  "application/x-xpinstall": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["xpi"]\n  },\n  "application/x-xz": {\n    "source": "apache",\n    "extensions": ["xz"]\n  },\n  "application/x-zmachine": {\n    "source": "apache",\n    "extensions": ["z1","z2","z3","z4","z5","z6","z7","z8"]\n  },\n  "application/x400-bp": {\n    "source": "iana"\n  },\n  "application/xacml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xaml+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xaml"]\n  },\n  "application/xcap-att+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xav"]\n  },\n  "application/xcap-caps+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xca"]\n  },\n  "application/xcap-diff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xdf"]\n  },\n  "application/xcap-el+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xel"]\n  },\n  "application/xcap-error+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xer"]\n  },\n  "application/xcap-ns+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xns"]\n  },\n  "application/xcon-conference-info+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xcon-conference-info-diff+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xenc+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xenc"]\n  },\n  "application/xhtml+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xhtml","xht"]\n  },\n  "application/xhtml-voice+xml": {\n    "source": "apache",\n    "compressible": true\n  },\n  "application/xliff+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xlf"]\n  },\n  "application/xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xml","xsl","xsd","rng"]\n  },\n  "application/xml-dtd": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dtd"]\n  },\n  "application/xml-external-parsed-entity": {\n    "source": "iana"\n  },\n  "application/xml-patch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xmpp+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/xop+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xop"]\n  },\n  "application/xproc+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xpl"]\n  },\n  "application/xslt+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xsl","xslt"]\n  },\n  "application/xspf+xml": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["xspf"]\n  },\n  "application/xv+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["mxml","xhvml","xvml","xvm"]\n  },\n  "application/yang": {\n    "source": "iana",\n    "extensions": ["yang"]\n  },\n  "application/yang-data+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-data+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-patch+json": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yang-patch+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "application/yin+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["yin"]\n  },\n  "application/zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["zip"]\n  },\n  "application/zlib": {\n    "source": "iana"\n  },\n  "application/zstd": {\n    "source": "iana"\n  },\n  "audio/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "audio/32kadpcm": {\n    "source": "iana"\n  },\n  "audio/3gpp": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["3gpp"]\n  },\n  "audio/3gpp2": {\n    "source": "iana"\n  },\n  "audio/aac": {\n    "source": "iana"\n  },\n  "audio/ac3": {\n    "source": "iana"\n  },\n  "audio/adpcm": {\n    "source": "apache",\n    "extensions": ["adp"]\n  },\n  "audio/amr": {\n    "source": "iana"\n  },\n  "audio/amr-wb": {\n    "source": "iana"\n  },\n  "audio/amr-wb+": {\n    "source": "iana"\n  },\n  "audio/aptx": {\n    "source": "iana"\n  },\n  "audio/asc": {\n    "source": "iana"\n  },\n  "audio/atrac-advanced-lossless": {\n    "source": "iana"\n  },\n  "audio/atrac-x": {\n    "source": "iana"\n  },\n  "audio/atrac3": {\n    "source": "iana"\n  },\n  "audio/basic": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["au","snd"]\n  },\n  "audio/bv16": {\n    "source": "iana"\n  },\n  "audio/bv32": {\n    "source": "iana"\n  },\n  "audio/clearmode": {\n    "source": "iana"\n  },\n  "audio/cn": {\n    "source": "iana"\n  },\n  "audio/dat12": {\n    "source": "iana"\n  },\n  "audio/dls": {\n    "source": "iana"\n  },\n  "audio/dsr-es201108": {\n    "source": "iana"\n  },\n  "audio/dsr-es202050": {\n    "source": "iana"\n  },\n  "audio/dsr-es202211": {\n    "source": "iana"\n  },\n  "audio/dsr-es202212": {\n    "source": "iana"\n  },\n  "audio/dv": {\n    "source": "iana"\n  },\n  "audio/dvi4": {\n    "source": "iana"\n  },\n  "audio/eac3": {\n    "source": "iana"\n  },\n  "audio/encaprtp": {\n    "source": "iana"\n  },\n  "audio/evrc": {\n    "source": "iana"\n  },\n  "audio/evrc-qcp": {\n    "source": "iana"\n  },\n  "audio/evrc0": {\n    "source": "iana"\n  },\n  "audio/evrc1": {\n    "source": "iana"\n  },\n  "audio/evrcb": {\n    "source": "iana"\n  },\n  "audio/evrcb0": {\n    "source": "iana"\n  },\n  "audio/evrcb1": {\n    "source": "iana"\n  },\n  "audio/evrcnw": {\n    "source": "iana"\n  },\n  "audio/evrcnw0": {\n    "source": "iana"\n  },\n  "audio/evrcnw1": {\n    "source": "iana"\n  },\n  "audio/evrcwb": {\n    "source": "iana"\n  },\n  "audio/evrcwb0": {\n    "source": "iana"\n  },\n  "audio/evrcwb1": {\n    "source": "iana"\n  },\n  "audio/evs": {\n    "source": "iana"\n  },\n  "audio/flexfec": {\n    "source": "iana"\n  },\n  "audio/fwdred": {\n    "source": "iana"\n  },\n  "audio/g711-0": {\n    "source": "iana"\n  },\n  "audio/g719": {\n    "source": "iana"\n  },\n  "audio/g722": {\n    "source": "iana"\n  },\n  "audio/g7221": {\n    "source": "iana"\n  },\n  "audio/g723": {\n    "source": "iana"\n  },\n  "audio/g726-16": {\n    "source": "iana"\n  },\n  "audio/g726-24": {\n    "source": "iana"\n  },\n  "audio/g726-32": {\n    "source": "iana"\n  },\n  "audio/g726-40": {\n    "source": "iana"\n  },\n  "audio/g728": {\n    "source": "iana"\n  },\n  "audio/g729": {\n    "source": "iana"\n  },\n  "audio/g7291": {\n    "source": "iana"\n  },\n  "audio/g729d": {\n    "source": "iana"\n  },\n  "audio/g729e": {\n    "source": "iana"\n  },\n  "audio/gsm": {\n    "source": "iana"\n  },\n  "audio/gsm-efr": {\n    "source": "iana"\n  },\n  "audio/gsm-hr-08": {\n    "source": "iana"\n  },\n  "audio/ilbc": {\n    "source": "iana"\n  },\n  "audio/ip-mr_v2.5": {\n    "source": "iana"\n  },\n  "audio/isac": {\n    "source": "apache"\n  },\n  "audio/l16": {\n    "source": "iana"\n  },\n  "audio/l20": {\n    "source": "iana"\n  },\n  "audio/l24": {\n    "source": "iana",\n    "compressible": false\n  },\n  "audio/l8": {\n    "source": "iana"\n  },\n  "audio/lpc": {\n    "source": "iana"\n  },\n  "audio/melp": {\n    "source": "iana"\n  },\n  "audio/melp1200": {\n    "source": "iana"\n  },\n  "audio/melp2400": {\n    "source": "iana"\n  },\n  "audio/melp600": {\n    "source": "iana"\n  },\n  "audio/mhas": {\n    "source": "iana"\n  },\n  "audio/midi": {\n    "source": "apache",\n    "extensions": ["mid","midi","kar","rmi"]\n  },\n  "audio/mobile-xmf": {\n    "source": "iana",\n    "extensions": ["mxmf"]\n  },\n  "audio/mp3": {\n    "compressible": false,\n    "extensions": ["mp3"]\n  },\n  "audio/mp4": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["m4a","mp4a"]\n  },\n  "audio/mp4a-latm": {\n    "source": "iana"\n  },\n  "audio/mpa": {\n    "source": "iana"\n  },\n  "audio/mpa-robust": {\n    "source": "iana"\n  },\n  "audio/mpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mpga","mp2","mp2a","mp3","m2a","m3a"]\n  },\n  "audio/mpeg4-generic": {\n    "source": "iana"\n  },\n  "audio/musepack": {\n    "source": "apache"\n  },\n  "audio/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["oga","ogg","spx"]\n  },\n  "audio/opus": {\n    "source": "iana"\n  },\n  "audio/parityfec": {\n    "source": "iana"\n  },\n  "audio/pcma": {\n    "source": "iana"\n  },\n  "audio/pcma-wb": {\n    "source": "iana"\n  },\n  "audio/pcmu": {\n    "source": "iana"\n  },\n  "audio/pcmu-wb": {\n    "source": "iana"\n  },\n  "audio/prs.sid": {\n    "source": "iana"\n  },\n  "audio/qcelp": {\n    "source": "iana"\n  },\n  "audio/raptorfec": {\n    "source": "iana"\n  },\n  "audio/red": {\n    "source": "iana"\n  },\n  "audio/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "audio/rtp-midi": {\n    "source": "iana"\n  },\n  "audio/rtploopback": {\n    "source": "iana"\n  },\n  "audio/rtx": {\n    "source": "iana"\n  },\n  "audio/s3m": {\n    "source": "apache",\n    "extensions": ["s3m"]\n  },\n  "audio/silk": {\n    "source": "apache",\n    "extensions": ["sil"]\n  },\n  "audio/smv": {\n    "source": "iana"\n  },\n  "audio/smv-qcp": {\n    "source": "iana"\n  },\n  "audio/smv0": {\n    "source": "iana"\n  },\n  "audio/sofa": {\n    "source": "iana"\n  },\n  "audio/sp-midi": {\n    "source": "iana"\n  },\n  "audio/speex": {\n    "source": "iana"\n  },\n  "audio/t140c": {\n    "source": "iana"\n  },\n  "audio/t38": {\n    "source": "iana"\n  },\n  "audio/telephone-event": {\n    "source": "iana"\n  },\n  "audio/tetra_acelp": {\n    "source": "iana"\n  },\n  "audio/tetra_acelp_bb": {\n    "source": "iana"\n  },\n  "audio/tone": {\n    "source": "iana"\n  },\n  "audio/tsvcis": {\n    "source": "iana"\n  },\n  "audio/uemclip": {\n    "source": "iana"\n  },\n  "audio/ulpfec": {\n    "source": "iana"\n  },\n  "audio/usac": {\n    "source": "iana"\n  },\n  "audio/vdvi": {\n    "source": "iana"\n  },\n  "audio/vmr-wb": {\n    "source": "iana"\n  },\n  "audio/vnd.3gpp.iufp": {\n    "source": "iana"\n  },\n  "audio/vnd.4sb": {\n    "source": "iana"\n  },\n  "audio/vnd.audiokoz": {\n    "source": "iana"\n  },\n  "audio/vnd.celp": {\n    "source": "iana"\n  },\n  "audio/vnd.cisco.nse": {\n    "source": "iana"\n  },\n  "audio/vnd.cmles.radio-events": {\n    "source": "iana"\n  },\n  "audio/vnd.cns.anp1": {\n    "source": "iana"\n  },\n  "audio/vnd.cns.inf1": {\n    "source": "iana"\n  },\n  "audio/vnd.dece.audio": {\n    "source": "iana",\n    "extensions": ["uva","uvva"]\n  },\n  "audio/vnd.digital-winds": {\n    "source": "iana",\n    "extensions": ["eol"]\n  },\n  "audio/vnd.dlna.adts": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.heaac.1": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.heaac.2": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.mlp": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.mps": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2x": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pl2z": {\n    "source": "iana"\n  },\n  "audio/vnd.dolby.pulse.1": {\n    "source": "iana"\n  },\n  "audio/vnd.dra": {\n    "source": "iana",\n    "extensions": ["dra"]\n  },\n  "audio/vnd.dts": {\n    "source": "iana",\n    "extensions": ["dts"]\n  },\n  "audio/vnd.dts.hd": {\n    "source": "iana",\n    "extensions": ["dtshd"]\n  },\n  "audio/vnd.dts.uhd": {\n    "source": "iana"\n  },\n  "audio/vnd.dvb.file": {\n    "source": "iana"\n  },\n  "audio/vnd.everad.plj": {\n    "source": "iana"\n  },\n  "audio/vnd.hns.audio": {\n    "source": "iana"\n  },\n  "audio/vnd.lucent.voice": {\n    "source": "iana",\n    "extensions": ["lvp"]\n  },\n  "audio/vnd.ms-playready.media.pya": {\n    "source": "iana",\n    "extensions": ["pya"]\n  },\n  "audio/vnd.nokia.mobile-xmf": {\n    "source": "iana"\n  },\n  "audio/vnd.nortel.vbk": {\n    "source": "iana"\n  },\n  "audio/vnd.nuera.ecelp4800": {\n    "source": "iana",\n    "extensions": ["ecelp4800"]\n  },\n  "audio/vnd.nuera.ecelp7470": {\n    "source": "iana",\n    "extensions": ["ecelp7470"]\n  },\n  "audio/vnd.nuera.ecelp9600": {\n    "source": "iana",\n    "extensions": ["ecelp9600"]\n  },\n  "audio/vnd.octel.sbc": {\n    "source": "iana"\n  },\n  "audio/vnd.presonus.multitrack": {\n    "source": "iana"\n  },\n  "audio/vnd.qcelp": {\n    "source": "iana"\n  },\n  "audio/vnd.rhetorex.32kadpcm": {\n    "source": "iana"\n  },\n  "audio/vnd.rip": {\n    "source": "iana",\n    "extensions": ["rip"]\n  },\n  "audio/vnd.rn-realaudio": {\n    "compressible": false\n  },\n  "audio/vnd.sealedmedia.softseal.mpeg": {\n    "source": "iana"\n  },\n  "audio/vnd.vmx.cvsd": {\n    "source": "iana"\n  },\n  "audio/vnd.wave": {\n    "compressible": false\n  },\n  "audio/vorbis": {\n    "source": "iana",\n    "compressible": false\n  },\n  "audio/vorbis-config": {\n    "source": "iana"\n  },\n  "audio/wav": {\n    "compressible": false,\n    "extensions": ["wav"]\n  },\n  "audio/wave": {\n    "compressible": false,\n    "extensions": ["wav"]\n  },\n  "audio/webm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["weba"]\n  },\n  "audio/x-aac": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["aac"]\n  },\n  "audio/x-aiff": {\n    "source": "apache",\n    "extensions": ["aif","aiff","aifc"]\n  },\n  "audio/x-caf": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["caf"]\n  },\n  "audio/x-flac": {\n    "source": "apache",\n    "extensions": ["flac"]\n  },\n  "audio/x-m4a": {\n    "source": "nginx",\n    "extensions": ["m4a"]\n  },\n  "audio/x-matroska": {\n    "source": "apache",\n    "extensions": ["mka"]\n  },\n  "audio/x-mpegurl": {\n    "source": "apache",\n    "extensions": ["m3u"]\n  },\n  "audio/x-ms-wax": {\n    "source": "apache",\n    "extensions": ["wax"]\n  },\n  "audio/x-ms-wma": {\n    "source": "apache",\n    "extensions": ["wma"]\n  },\n  "audio/x-pn-realaudio": {\n    "source": "apache",\n    "extensions": ["ram","ra"]\n  },\n  "audio/x-pn-realaudio-plugin": {\n    "source": "apache",\n    "extensions": ["rmp"]\n  },\n  "audio/x-realaudio": {\n    "source": "nginx",\n    "extensions": ["ra"]\n  },\n  "audio/x-tta": {\n    "source": "apache"\n  },\n  "audio/x-wav": {\n    "source": "apache",\n    "extensions": ["wav"]\n  },\n  "audio/xm": {\n    "source": "apache",\n    "extensions": ["xm"]\n  },\n  "chemical/x-cdx": {\n    "source": "apache",\n    "extensions": ["cdx"]\n  },\n  "chemical/x-cif": {\n    "source": "apache",\n    "extensions": ["cif"]\n  },\n  "chemical/x-cmdf": {\n    "source": "apache",\n    "extensions": ["cmdf"]\n  },\n  "chemical/x-cml": {\n    "source": "apache",\n    "extensions": ["cml"]\n  },\n  "chemical/x-csml": {\n    "source": "apache",\n    "extensions": ["csml"]\n  },\n  "chemical/x-pdb": {\n    "source": "apache"\n  },\n  "chemical/x-xyz": {\n    "source": "apache",\n    "extensions": ["xyz"]\n  },\n  "font/collection": {\n    "source": "iana",\n    "extensions": ["ttc"]\n  },\n  "font/otf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["otf"]\n  },\n  "font/sfnt": {\n    "source": "iana"\n  },\n  "font/ttf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["ttf"]\n  },\n  "font/woff": {\n    "source": "iana",\n    "extensions": ["woff"]\n  },\n  "font/woff2": {\n    "source": "iana",\n    "extensions": ["woff2"]\n  },\n  "image/aces": {\n    "source": "iana",\n    "extensions": ["exr"]\n  },\n  "image/apng": {\n    "compressible": false,\n    "extensions": ["apng"]\n  },\n  "image/avci": {\n    "source": "iana"\n  },\n  "image/avcs": {\n    "source": "iana"\n  },\n  "image/avif": {\n    "compressible": false,\n    "extensions": ["avif"]\n  },\n  "image/bmp": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["bmp"]\n  },\n  "image/cgm": {\n    "source": "iana",\n    "extensions": ["cgm"]\n  },\n  "image/dicom-rle": {\n    "source": "iana",\n    "extensions": ["drle"]\n  },\n  "image/emf": {\n    "source": "iana",\n    "extensions": ["emf"]\n  },\n  "image/fits": {\n    "source": "iana",\n    "extensions": ["fits"]\n  },\n  "image/g3fax": {\n    "source": "iana",\n    "extensions": ["g3"]\n  },\n  "image/gif": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["gif"]\n  },\n  "image/heic": {\n    "source": "iana",\n    "extensions": ["heic"]\n  },\n  "image/heic-sequence": {\n    "source": "iana",\n    "extensions": ["heics"]\n  },\n  "image/heif": {\n    "source": "iana",\n    "extensions": ["heif"]\n  },\n  "image/heif-sequence": {\n    "source": "iana",\n    "extensions": ["heifs"]\n  },\n  "image/hej2k": {\n    "source": "iana",\n    "extensions": ["hej2"]\n  },\n  "image/hsj2": {\n    "source": "iana",\n    "extensions": ["hsj2"]\n  },\n  "image/ief": {\n    "source": "iana",\n    "extensions": ["ief"]\n  },\n  "image/jls": {\n    "source": "iana",\n    "extensions": ["jls"]\n  },\n  "image/jp2": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jp2","jpg2"]\n  },\n  "image/jpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpeg","jpg","jpe"]\n  },\n  "image/jph": {\n    "source": "iana",\n    "extensions": ["jph"]\n  },\n  "image/jphc": {\n    "source": "iana",\n    "extensions": ["jhc"]\n  },\n  "image/jpm": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpm"]\n  },\n  "image/jpx": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["jpx","jpf"]\n  },\n  "image/jxr": {\n    "source": "iana",\n    "extensions": ["jxr"]\n  },\n  "image/jxra": {\n    "source": "iana",\n    "extensions": ["jxra"]\n  },\n  "image/jxrs": {\n    "source": "iana",\n    "extensions": ["jxrs"]\n  },\n  "image/jxs": {\n    "source": "iana",\n    "extensions": ["jxs"]\n  },\n  "image/jxsc": {\n    "source": "iana",\n    "extensions": ["jxsc"]\n  },\n  "image/jxsi": {\n    "source": "iana",\n    "extensions": ["jxsi"]\n  },\n  "image/jxss": {\n    "source": "iana",\n    "extensions": ["jxss"]\n  },\n  "image/ktx": {\n    "source": "iana",\n    "extensions": ["ktx"]\n  },\n  "image/ktx2": {\n    "source": "iana",\n    "extensions": ["ktx2"]\n  },\n  "image/naplps": {\n    "source": "iana"\n  },\n  "image/pjpeg": {\n    "compressible": false\n  },\n  "image/png": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["png"]\n  },\n  "image/prs.btif": {\n    "source": "iana",\n    "extensions": ["btif"]\n  },\n  "image/prs.pti": {\n    "source": "iana",\n    "extensions": ["pti"]\n  },\n  "image/pwg-raster": {\n    "source": "iana"\n  },\n  "image/sgi": {\n    "source": "apache",\n    "extensions": ["sgi"]\n  },\n  "image/svg+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["svg","svgz"]\n  },\n  "image/t38": {\n    "source": "iana",\n    "extensions": ["t38"]\n  },\n  "image/tiff": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["tif","tiff"]\n  },\n  "image/tiff-fx": {\n    "source": "iana",\n    "extensions": ["tfx"]\n  },\n  "image/vnd.adobe.photoshop": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["psd"]\n  },\n  "image/vnd.airzip.accelerator.azv": {\n    "source": "iana",\n    "extensions": ["azv"]\n  },\n  "image/vnd.cns.inf2": {\n    "source": "iana"\n  },\n  "image/vnd.dece.graphic": {\n    "source": "iana",\n    "extensions": ["uvi","uvvi","uvg","uvvg"]\n  },\n  "image/vnd.djvu": {\n    "source": "iana",\n    "extensions": ["djvu","djv"]\n  },\n  "image/vnd.dvb.subtitle": {\n    "source": "iana",\n    "extensions": ["sub"]\n  },\n  "image/vnd.dwg": {\n    "source": "iana",\n    "extensions": ["dwg"]\n  },\n  "image/vnd.dxf": {\n    "source": "iana",\n    "extensions": ["dxf"]\n  },\n  "image/vnd.fastbidsheet": {\n    "source": "iana",\n    "extensions": ["fbs"]\n  },\n  "image/vnd.fpx": {\n    "source": "iana",\n    "extensions": ["fpx"]\n  },\n  "image/vnd.fst": {\n    "source": "iana",\n    "extensions": ["fst"]\n  },\n  "image/vnd.fujixerox.edmics-mmr": {\n    "source": "iana",\n    "extensions": ["mmr"]\n  },\n  "image/vnd.fujixerox.edmics-rlc": {\n    "source": "iana",\n    "extensions": ["rlc"]\n  },\n  "image/vnd.globalgraphics.pgb": {\n    "source": "iana"\n  },\n  "image/vnd.microsoft.icon": {\n    "source": "iana",\n    "extensions": ["ico"]\n  },\n  "image/vnd.mix": {\n    "source": "iana"\n  },\n  "image/vnd.mozilla.apng": {\n    "source": "iana"\n  },\n  "image/vnd.ms-dds": {\n    "extensions": ["dds"]\n  },\n  "image/vnd.ms-modi": {\n    "source": "iana",\n    "extensions": ["mdi"]\n  },\n  "image/vnd.ms-photo": {\n    "source": "apache",\n    "extensions": ["wdp"]\n  },\n  "image/vnd.net-fpx": {\n    "source": "iana",\n    "extensions": ["npx"]\n  },\n  "image/vnd.pco.b16": {\n    "source": "iana",\n    "extensions": ["b16"]\n  },\n  "image/vnd.radiance": {\n    "source": "iana"\n  },\n  "image/vnd.sealed.png": {\n    "source": "iana"\n  },\n  "image/vnd.sealedmedia.softseal.gif": {\n    "source": "iana"\n  },\n  "image/vnd.sealedmedia.softseal.jpg": {\n    "source": "iana"\n  },\n  "image/vnd.svf": {\n    "source": "iana"\n  },\n  "image/vnd.tencent.tap": {\n    "source": "iana",\n    "extensions": ["tap"]\n  },\n  "image/vnd.valve.source.texture": {\n    "source": "iana",\n    "extensions": ["vtf"]\n  },\n  "image/vnd.wap.wbmp": {\n    "source": "iana",\n    "extensions": ["wbmp"]\n  },\n  "image/vnd.xiff": {\n    "source": "iana",\n    "extensions": ["xif"]\n  },\n  "image/vnd.zbrush.pcx": {\n    "source": "iana",\n    "extensions": ["pcx"]\n  },\n  "image/webp": {\n    "source": "apache",\n    "extensions": ["webp"]\n  },\n  "image/wmf": {\n    "source": "iana",\n    "extensions": ["wmf"]\n  },\n  "image/x-3ds": {\n    "source": "apache",\n    "extensions": ["3ds"]\n  },\n  "image/x-cmu-raster": {\n    "source": "apache",\n    "extensions": ["ras"]\n  },\n  "image/x-cmx": {\n    "source": "apache",\n    "extensions": ["cmx"]\n  },\n  "image/x-freehand": {\n    "source": "apache",\n    "extensions": ["fh","fhc","fh4","fh5","fh7"]\n  },\n  "image/x-icon": {\n    "source": "apache",\n    "compressible": true,\n    "extensions": ["ico"]\n  },\n  "image/x-jng": {\n    "source": "nginx",\n    "extensions": ["jng"]\n  },\n  "image/x-mrsid-image": {\n    "source": "apache",\n    "extensions": ["sid"]\n  },\n  "image/x-ms-bmp": {\n    "source": "nginx",\n    "compressible": true,\n    "extensions": ["bmp"]\n  },\n  "image/x-pcx": {\n    "source": "apache",\n    "extensions": ["pcx"]\n  },\n  "image/x-pict": {\n    "source": "apache",\n    "extensions": ["pic","pct"]\n  },\n  "image/x-portable-anymap": {\n    "source": "apache",\n    "extensions": ["pnm"]\n  },\n  "image/x-portable-bitmap": {\n    "source": "apache",\n    "extensions": ["pbm"]\n  },\n  "image/x-portable-graymap": {\n    "source": "apache",\n    "extensions": ["pgm"]\n  },\n  "image/x-portable-pixmap": {\n    "source": "apache",\n    "extensions": ["ppm"]\n  },\n  "image/x-rgb": {\n    "source": "apache",\n    "extensions": ["rgb"]\n  },\n  "image/x-tga": {\n    "source": "apache",\n    "extensions": ["tga"]\n  },\n  "image/x-xbitmap": {\n    "source": "apache",\n    "extensions": ["xbm"]\n  },\n  "image/x-xcf": {\n    "compressible": false\n  },\n  "image/x-xpixmap": {\n    "source": "apache",\n    "extensions": ["xpm"]\n  },\n  "image/x-xwindowdump": {\n    "source": "apache",\n    "extensions": ["xwd"]\n  },\n  "message/cpim": {\n    "source": "iana"\n  },\n  "message/delivery-status": {\n    "source": "iana"\n  },\n  "message/disposition-notification": {\n    "source": "iana",\n    "extensions": [\n      "disposition-notification"\n    ]\n  },\n  "message/external-body": {\n    "source": "iana"\n  },\n  "message/feedback-report": {\n    "source": "iana"\n  },\n  "message/global": {\n    "source": "iana",\n    "extensions": ["u8msg"]\n  },\n  "message/global-delivery-status": {\n    "source": "iana",\n    "extensions": ["u8dsn"]\n  },\n  "message/global-disposition-notification": {\n    "source": "iana",\n    "extensions": ["u8mdn"]\n  },\n  "message/global-headers": {\n    "source": "iana",\n    "extensions": ["u8hdr"]\n  },\n  "message/http": {\n    "source": "iana",\n    "compressible": false\n  },\n  "message/imdn+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "message/news": {\n    "source": "iana"\n  },\n  "message/partial": {\n    "source": "iana",\n    "compressible": false\n  },\n  "message/rfc822": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["eml","mime"]\n  },\n  "message/s-http": {\n    "source": "iana"\n  },\n  "message/sip": {\n    "source": "iana"\n  },\n  "message/sipfrag": {\n    "source": "iana"\n  },\n  "message/tracking-status": {\n    "source": "iana"\n  },\n  "message/vnd.si.simp": {\n    "source": "iana"\n  },\n  "message/vnd.wfa.wsc": {\n    "source": "iana",\n    "extensions": ["wsc"]\n  },\n  "model/3mf": {\n    "source": "iana",\n    "extensions": ["3mf"]\n  },\n  "model/e57": {\n    "source": "iana"\n  },\n  "model/gltf+json": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["gltf"]\n  },\n  "model/gltf-binary": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["glb"]\n  },\n  "model/iges": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["igs","iges"]\n  },\n  "model/mesh": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["msh","mesh","silo"]\n  },\n  "model/mtl": {\n    "source": "iana",\n    "extensions": ["mtl"]\n  },\n  "model/obj": {\n    "source": "iana",\n    "extensions": ["obj"]\n  },\n  "model/stl": {\n    "source": "iana",\n    "extensions": ["stl"]\n  },\n  "model/vnd.collada+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["dae"]\n  },\n  "model/vnd.dwf": {\n    "source": "iana",\n    "extensions": ["dwf"]\n  },\n  "model/vnd.flatland.3dml": {\n    "source": "iana"\n  },\n  "model/vnd.gdl": {\n    "source": "iana",\n    "extensions": ["gdl"]\n  },\n  "model/vnd.gs-gdl": {\n    "source": "apache"\n  },\n  "model/vnd.gs.gdl": {\n    "source": "iana"\n  },\n  "model/vnd.gtw": {\n    "source": "iana",\n    "extensions": ["gtw"]\n  },\n  "model/vnd.moml+xml": {\n    "source": "iana",\n    "compressible": true\n  },\n  "model/vnd.mts": {\n    "source": "iana",\n    "extensions": ["mts"]\n  },\n  "model/vnd.opengex": {\n    "source": "iana",\n    "extensions": ["ogex"]\n  },\n  "model/vnd.parasolid.transmit.binary": {\n    "source": "iana",\n    "extensions": ["x_b"]\n  },\n  "model/vnd.parasolid.transmit.text": {\n    "source": "iana",\n    "extensions": ["x_t"]\n  },\n  "model/vnd.rosette.annotated-data-model": {\n    "source": "iana"\n  },\n  "model/vnd.usdz+zip": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["usdz"]\n  },\n  "model/vnd.valve.source.compiled-map": {\n    "source": "iana",\n    "extensions": ["bsp"]\n  },\n  "model/vnd.vtu": {\n    "source": "iana",\n    "extensions": ["vtu"]\n  },\n  "model/vrml": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["wrl","vrml"]\n  },\n  "model/x3d+binary": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["x3db","x3dbz"]\n  },\n  "model/x3d+fastinfoset": {\n    "source": "iana",\n    "extensions": ["x3db"]\n  },\n  "model/x3d+vrml": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["x3dv","x3dvz"]\n  },\n  "model/x3d+xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["x3d","x3dz"]\n  },\n  "model/x3d-vrml": {\n    "source": "iana",\n    "extensions": ["x3dv"]\n  },\n  "multipart/alternative": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/appledouble": {\n    "source": "iana"\n  },\n  "multipart/byteranges": {\n    "source": "iana"\n  },\n  "multipart/digest": {\n    "source": "iana"\n  },\n  "multipart/encrypted": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/form-data": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/header-set": {\n    "source": "iana"\n  },\n  "multipart/mixed": {\n    "source": "iana"\n  },\n  "multipart/multilingual": {\n    "source": "iana"\n  },\n  "multipart/parallel": {\n    "source": "iana"\n  },\n  "multipart/related": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/report": {\n    "source": "iana"\n  },\n  "multipart/signed": {\n    "source": "iana",\n    "compressible": false\n  },\n  "multipart/vnd.bint.med-plus": {\n    "source": "iana"\n  },\n  "multipart/voice-message": {\n    "source": "iana"\n  },\n  "multipart/x-mixed-replace": {\n    "source": "iana"\n  },\n  "text/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "text/cache-manifest": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["appcache","manifest"]\n  },\n  "text/calendar": {\n    "source": "iana",\n    "extensions": ["ics","ifb"]\n  },\n  "text/calender": {\n    "compressible": true\n  },\n  "text/cmd": {\n    "compressible": true\n  },\n  "text/coffeescript": {\n    "extensions": ["coffee","litcoffee"]\n  },\n  "text/css": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["css"]\n  },\n  "text/csv": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["csv"]\n  },\n  "text/csv-schema": {\n    "source": "iana"\n  },\n  "text/directory": {\n    "source": "iana"\n  },\n  "text/dns": {\n    "source": "iana"\n  },\n  "text/ecmascript": {\n    "source": "iana"\n  },\n  "text/encaprtp": {\n    "source": "iana"\n  },\n  "text/enriched": {\n    "source": "iana"\n  },\n  "text/flexfec": {\n    "source": "iana"\n  },\n  "text/fwdred": {\n    "source": "iana"\n  },\n  "text/gff3": {\n    "source": "iana"\n  },\n  "text/grammar-ref-list": {\n    "source": "iana"\n  },\n  "text/html": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["html","htm","shtml"]\n  },\n  "text/jade": {\n    "extensions": ["jade"]\n  },\n  "text/javascript": {\n    "source": "iana",\n    "compressible": true\n  },\n  "text/jcr-cnd": {\n    "source": "iana"\n  },\n  "text/jsx": {\n    "compressible": true,\n    "extensions": ["jsx"]\n  },\n  "text/less": {\n    "compressible": true,\n    "extensions": ["less"]\n  },\n  "text/markdown": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["markdown","md"]\n  },\n  "text/mathml": {\n    "source": "nginx",\n    "extensions": ["mml"]\n  },\n  "text/mdx": {\n    "compressible": true,\n    "extensions": ["mdx"]\n  },\n  "text/mizar": {\n    "source": "iana"\n  },\n  "text/n3": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["n3"]\n  },\n  "text/parameters": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/parityfec": {\n    "source": "iana"\n  },\n  "text/plain": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["txt","text","conf","def","list","log","in","ini"]\n  },\n  "text/provenance-notation": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/prs.fallenstein.rst": {\n    "source": "iana"\n  },\n  "text/prs.lines.tag": {\n    "source": "iana",\n    "extensions": ["dsc"]\n  },\n  "text/prs.prop.logic": {\n    "source": "iana"\n  },\n  "text/raptorfec": {\n    "source": "iana"\n  },\n  "text/red": {\n    "source": "iana"\n  },\n  "text/rfc822-headers": {\n    "source": "iana"\n  },\n  "text/richtext": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtx"]\n  },\n  "text/rtf": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["rtf"]\n  },\n  "text/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "text/rtploopback": {\n    "source": "iana"\n  },\n  "text/rtx": {\n    "source": "iana"\n  },\n  "text/sgml": {\n    "source": "iana",\n    "extensions": ["sgml","sgm"]\n  },\n  "text/shaclc": {\n    "source": "iana"\n  },\n  "text/shex": {\n    "extensions": ["shex"]\n  },\n  "text/slim": {\n    "extensions": ["slim","slm"]\n  },\n  "text/spdx": {\n    "source": "iana",\n    "extensions": ["spdx"]\n  },\n  "text/strings": {\n    "source": "iana"\n  },\n  "text/stylus": {\n    "extensions": ["stylus","styl"]\n  },\n  "text/t140": {\n    "source": "iana"\n  },\n  "text/tab-separated-values": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["tsv"]\n  },\n  "text/troff": {\n    "source": "iana",\n    "extensions": ["t","tr","roff","man","me","ms"]\n  },\n  "text/turtle": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["ttl"]\n  },\n  "text/ulpfec": {\n    "source": "iana"\n  },\n  "text/uri-list": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["uri","uris","urls"]\n  },\n  "text/vcard": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["vcard"]\n  },\n  "text/vnd.a": {\n    "source": "iana"\n  },\n  "text/vnd.abc": {\n    "source": "iana"\n  },\n  "text/vnd.ascii-art": {\n    "source": "iana"\n  },\n  "text/vnd.curl": {\n    "source": "iana",\n    "extensions": ["curl"]\n  },\n  "text/vnd.curl.dcurl": {\n    "source": "apache",\n    "extensions": ["dcurl"]\n  },\n  "text/vnd.curl.mcurl": {\n    "source": "apache",\n    "extensions": ["mcurl"]\n  },\n  "text/vnd.curl.scurl": {\n    "source": "apache",\n    "extensions": ["scurl"]\n  },\n  "text/vnd.debian.copyright": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.dmclientscript": {\n    "source": "iana"\n  },\n  "text/vnd.dvb.subtitle": {\n    "source": "iana",\n    "extensions": ["sub"]\n  },\n  "text/vnd.esmertec.theme-descriptor": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.ficlab.flt": {\n    "source": "iana"\n  },\n  "text/vnd.fly": {\n    "source": "iana",\n    "extensions": ["fly"]\n  },\n  "text/vnd.fmi.flexstor": {\n    "source": "iana",\n    "extensions": ["flx"]\n  },\n  "text/vnd.gml": {\n    "source": "iana"\n  },\n  "text/vnd.graphviz": {\n    "source": "iana",\n    "extensions": ["gv"]\n  },\n  "text/vnd.hans": {\n    "source": "iana"\n  },\n  "text/vnd.hgl": {\n    "source": "iana"\n  },\n  "text/vnd.in3d.3dml": {\n    "source": "iana",\n    "extensions": ["3dml"]\n  },\n  "text/vnd.in3d.spot": {\n    "source": "iana",\n    "extensions": ["spot"]\n  },\n  "text/vnd.iptc.newsml": {\n    "source": "iana"\n  },\n  "text/vnd.iptc.nitf": {\n    "source": "iana"\n  },\n  "text/vnd.latex-z": {\n    "source": "iana"\n  },\n  "text/vnd.motorola.reflex": {\n    "source": "iana"\n  },\n  "text/vnd.ms-mediapackage": {\n    "source": "iana"\n  },\n  "text/vnd.net2phone.commcenter.command": {\n    "source": "iana"\n  },\n  "text/vnd.radisys.msml-basic-layout": {\n    "source": "iana"\n  },\n  "text/vnd.senx.warpscript": {\n    "source": "iana"\n  },\n  "text/vnd.si.uricatalogue": {\n    "source": "iana"\n  },\n  "text/vnd.sosi": {\n    "source": "iana"\n  },\n  "text/vnd.sun.j2me.app-descriptor": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "extensions": ["jad"]\n  },\n  "text/vnd.trolltech.linguist": {\n    "source": "iana",\n    "charset": "UTF-8"\n  },\n  "text/vnd.wap.si": {\n    "source": "iana"\n  },\n  "text/vnd.wap.sl": {\n    "source": "iana"\n  },\n  "text/vnd.wap.wml": {\n    "source": "iana",\n    "extensions": ["wml"]\n  },\n  "text/vnd.wap.wmlscript": {\n    "source": "iana",\n    "extensions": ["wmls"]\n  },\n  "text/vtt": {\n    "source": "iana",\n    "charset": "UTF-8",\n    "compressible": true,\n    "extensions": ["vtt"]\n  },\n  "text/x-asm": {\n    "source": "apache",\n    "extensions": ["s","asm"]\n  },\n  "text/x-c": {\n    "source": "apache",\n    "extensions": ["c","cc","cxx","cpp","h","hh","dic"]\n  },\n  "text/x-component": {\n    "source": "nginx",\n    "extensions": ["htc"]\n  },\n  "text/x-fortran": {\n    "source": "apache",\n    "extensions": ["f","for","f77","f90"]\n  },\n  "text/x-gwt-rpc": {\n    "compressible": true\n  },\n  "text/x-handlebars-template": {\n    "extensions": ["hbs"]\n  },\n  "text/x-java-source": {\n    "source": "apache",\n    "extensions": ["java"]\n  },\n  "text/x-jquery-tmpl": {\n    "compressible": true\n  },\n  "text/x-lua": {\n    "extensions": ["lua"]\n  },\n  "text/x-markdown": {\n    "compressible": true,\n    "extensions": ["mkd"]\n  },\n  "text/x-nfo": {\n    "source": "apache",\n    "extensions": ["nfo"]\n  },\n  "text/x-opml": {\n    "source": "apache",\n    "extensions": ["opml"]\n  },\n  "text/x-org": {\n    "compressible": true,\n    "extensions": ["org"]\n  },\n  "text/x-pascal": {\n    "source": "apache",\n    "extensions": ["p","pas"]\n  },\n  "text/x-processing": {\n    "compressible": true,\n    "extensions": ["pde"]\n  },\n  "text/x-sass": {\n    "extensions": ["sass"]\n  },\n  "text/x-scss": {\n    "extensions": ["scss"]\n  },\n  "text/x-setext": {\n    "source": "apache",\n    "extensions": ["etx"]\n  },\n  "text/x-sfv": {\n    "source": "apache",\n    "extensions": ["sfv"]\n  },\n  "text/x-suse-ymp": {\n    "compressible": true,\n    "extensions": ["ymp"]\n  },\n  "text/x-uuencode": {\n    "source": "apache",\n    "extensions": ["uu"]\n  },\n  "text/x-vcalendar": {\n    "source": "apache",\n    "extensions": ["vcs"]\n  },\n  "text/x-vcard": {\n    "source": "apache",\n    "extensions": ["vcf"]\n  },\n  "text/xml": {\n    "source": "iana",\n    "compressible": true,\n    "extensions": ["xml"]\n  },\n  "text/xml-external-parsed-entity": {\n    "source": "iana"\n  },\n  "text/yaml": {\n    "extensions": ["yaml","yml"]\n  },\n  "video/1d-interleaved-parityfec": {\n    "source": "iana"\n  },\n  "video/3gpp": {\n    "source": "iana",\n    "extensions": ["3gp","3gpp"]\n  },\n  "video/3gpp-tt": {\n    "source": "iana"\n  },\n  "video/3gpp2": {\n    "source": "iana",\n    "extensions": ["3g2"]\n  },\n  "video/bmpeg": {\n    "source": "iana"\n  },\n  "video/bt656": {\n    "source": "iana"\n  },\n  "video/celb": {\n    "source": "iana"\n  },\n  "video/dv": {\n    "source": "iana"\n  },\n  "video/encaprtp": {\n    "source": "iana"\n  },\n  "video/flexfec": {\n    "source": "iana"\n  },\n  "video/h261": {\n    "source": "iana",\n    "extensions": ["h261"]\n  },\n  "video/h263": {\n    "source": "iana",\n    "extensions": ["h263"]\n  },\n  "video/h263-1998": {\n    "source": "iana"\n  },\n  "video/h263-2000": {\n    "source": "iana"\n  },\n  "video/h264": {\n    "source": "iana",\n    "extensions": ["h264"]\n  },\n  "video/h264-rcdo": {\n    "source": "iana"\n  },\n  "video/h264-svc": {\n    "source": "iana"\n  },\n  "video/h265": {\n    "source": "iana"\n  },\n  "video/iso.segment": {\n    "source": "iana"\n  },\n  "video/jpeg": {\n    "source": "iana",\n    "extensions": ["jpgv"]\n  },\n  "video/jpeg2000": {\n    "source": "iana"\n  },\n  "video/jpm": {\n    "source": "apache",\n    "extensions": ["jpm","jpgm"]\n  },\n  "video/mj2": {\n    "source": "iana",\n    "extensions": ["mj2","mjp2"]\n  },\n  "video/mp1s": {\n    "source": "iana"\n  },\n  "video/mp2p": {\n    "source": "iana"\n  },\n  "video/mp2t": {\n    "source": "iana",\n    "extensions": ["ts"]\n  },\n  "video/mp4": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mp4","mp4v","mpg4"]\n  },\n  "video/mp4v-es": {\n    "source": "iana"\n  },\n  "video/mpeg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["mpeg","mpg","mpe","m1v","m2v"]\n  },\n  "video/mpeg4-generic": {\n    "source": "iana"\n  },\n  "video/mpv": {\n    "source": "iana"\n  },\n  "video/nv": {\n    "source": "iana"\n  },\n  "video/ogg": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["ogv"]\n  },\n  "video/parityfec": {\n    "source": "iana"\n  },\n  "video/pointer": {\n    "source": "iana"\n  },\n  "video/quicktime": {\n    "source": "iana",\n    "compressible": false,\n    "extensions": ["qt","mov"]\n  },\n  "video/raptorfec": {\n    "source": "iana"\n  },\n  "video/raw": {\n    "source": "iana"\n  },\n  "video/rtp-enc-aescm128": {\n    "source": "iana"\n  },\n  "video/rtploopback": {\n    "source": "iana"\n  },\n  "video/rtx": {\n    "source": "iana"\n  },\n  "video/smpte291": {\n    "source": "iana"\n  },\n  "video/smpte292m": {\n    "source": "iana"\n  },\n  "video/ulpfec": {\n    "source": "iana"\n  },\n  "video/vc1": {\n    "source": "iana"\n  },\n  "video/vc2": {\n    "source": "iana"\n  },\n  "video/vnd.cctv": {\n    "source": "iana"\n  },\n  "video/vnd.dece.hd": {\n    "source": "iana",\n    "extensions": ["uvh","uvvh"]\n  },\n  "video/vnd.dece.mobile": {\n    "source": "iana",\n    "extensions": ["uvm","uvvm"]\n  },\n  "video/vnd.dece.mp4": {\n    "source": "iana"\n  },\n  "video/vnd.dece.pd": {\n    "source": "iana",\n    "extensions": ["uvp","uvvp"]\n  },\n  "video/vnd.dece.sd": {\n    "source": "iana",\n    "extensions": ["uvs","uvvs"]\n  },\n  "video/vnd.dece.video": {\n    "source": "iana",\n    "extensions": ["uvv","uvvv"]\n  },\n  "video/vnd.directv.mpeg": {\n    "source": "iana"\n  },\n  "video/vnd.directv.mpeg-tts": {\n    "source": "iana"\n  },\n  "video/vnd.dlna.mpeg-tts": {\n    "source": "iana"\n  },\n  "video/vnd.dvb.file": {\n    "source": "iana",\n    "extensions": ["dvb"]\n  },\n  "video/vnd.fvt": {\n    "source": "iana",\n    "extensions": ["fvt"]\n  },\n  "video/vnd.hns.video": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.1dparityfec-1010": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.1dparityfec-2005": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.2dparityfec-1010": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.2dparityfec-2005": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.ttsavc": {\n    "source": "iana"\n  },\n  "video/vnd.iptvforum.ttsmpeg2": {\n    "source": "iana"\n  },\n  "video/vnd.motorola.video": {\n    "source": "iana"\n  },\n  "video/vnd.motorola.videop": {\n    "source": "iana"\n  },\n  "video/vnd.mpegurl": {\n    "source": "iana",\n    "extensions": ["mxu","m4u"]\n  },\n  "video/vnd.ms-playready.media.pyv": {\n    "source": "iana",\n    "extensions": ["pyv"]\n  },\n  "video/vnd.nokia.interleaved-multimedia": {\n    "source": "iana"\n  },\n  "video/vnd.nokia.mp4vr": {\n    "source": "iana"\n  },\n  "video/vnd.nokia.videovoip": {\n    "source": "iana"\n  },\n  "video/vnd.objectvideo": {\n    "source": "iana"\n  },\n  "video/vnd.radgamettools.bink": {\n    "source": "iana"\n  },\n  "video/vnd.radgamettools.smacker": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.mpeg1": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.mpeg4": {\n    "source": "iana"\n  },\n  "video/vnd.sealed.swf": {\n    "source": "iana"\n  },\n  "video/vnd.sealedmedia.softseal.mov": {\n    "source": "iana"\n  },\n  "video/vnd.uvvu.mp4": {\n    "source": "iana",\n    "extensions": ["uvu","uvvu"]\n  },\n  "video/vnd.vivo": {\n    "source": "iana",\n    "extensions": ["viv"]\n  },\n  "video/vnd.youtube.yt": {\n    "source": "iana"\n  },\n  "video/vp8": {\n    "source": "iana"\n  },\n  "video/webm": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["webm"]\n  },\n  "video/x-f4v": {\n    "source": "apache",\n    "extensions": ["f4v"]\n  },\n  "video/x-fli": {\n    "source": "apache",\n    "extensions": ["fli"]\n  },\n  "video/x-flv": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["flv"]\n  },\n  "video/x-m4v": {\n    "source": "apache",\n    "extensions": ["m4v"]\n  },\n  "video/x-matroska": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["mkv","mk3d","mks"]\n  },\n  "video/x-mng": {\n    "source": "apache",\n    "extensions": ["mng"]\n  },\n  "video/x-ms-asf": {\n    "source": "apache",\n    "extensions": ["asf","asx"]\n  },\n  "video/x-ms-vob": {\n    "source": "apache",\n    "extensions": ["vob"]\n  },\n  "video/x-ms-wm": {\n    "source": "apache",\n    "extensions": ["wm"]\n  },\n  "video/x-ms-wmv": {\n    "source": "apache",\n    "compressible": false,\n    "extensions": ["wmv"]\n  },\n  "video/x-ms-wmx": {\n    "source": "apache",\n    "extensions": ["wmx"]\n  },\n  "video/x-ms-wvx": {\n    "source": "apache",\n    "extensions": ["wvx"]\n  },\n  "video/x-msvideo": {\n    "source": "apache",\n    "extensions": ["avi"]\n  },\n  "video/x-sgi-movie": {\n    "source": "apache",\n    "extensions": ["movie"]\n  },\n  "video/x-smv": {\n    "source": "apache",\n    "extensions": ["smv"]\n  },\n  "x-conference/x-cooltalk": {\n    "source": "apache",\n    "extensions": ["ice"]\n  },\n  "x-shader/x-fragment": {\n    "compressible": true\n  },\n  "x-shader/x-vertex": {\n    "compressible": true\n  }\n}`);
const EXTRACT_TYPE_REGEXP = /^\s*([^;\s]*)(?:;|\s|$)/;
const TEXT_TYPE_REGEXP = /^text\//i;
const extensions = new Map();
const types1 = new Map();
function populateMaps(extensions1, types1) {
    const preference = [
        "nginx",
        "apache",
        undefined,
        "iana"
    ];
    for (const type of Object.keys(db)){
        const mime = db[type];
        const exts = mime.extensions;
        if (!exts || !exts.length) {
            continue;
        }
        extensions1.set(type, exts);
        for (const ext of exts){
            const current = types1.get(ext);
            if (current) {
                const from = preference.indexOf(db[current].source);
                const to = preference.indexOf(mime.source);
                if (current !== "application/octet-stream" && (from > to || from === to && current.substr(0, 12) === "application/")) {
                    continue;
                }
            }
            types1.set(ext, type);
        }
    }
}
populateMaps(extensions, types1);
function charset(type) {
    const m = EXTRACT_TYPE_REGEXP.exec(type);
    if (!m) {
        return;
    }
    const [match] = m;
    const mime = db[match.toLowerCase()];
    if (mime && mime.charset) {
        return mime.charset;
    }
    if (TEXT_TYPE_REGEXP.test(match)) {
        return "UTF-8";
    }
}
function extension(type) {
    const match = EXTRACT_TYPE_REGEXP.exec(type);
    if (!match) {
        return;
    }
    const exts = extensions.get(match[1].toLowerCase());
    if (!exts || !exts.length) {
        return;
    }
    return exts[0];
}
function lexer(str) {
    const tokens = [];
    let i1 = 0;
    while(i1 < str.length){
        const char = str[i1];
        if (char === "*" || char === "+" || char === "?") {
            tokens.push({
                type: "MODIFIER",
                index: i1,
                value: str[i1++]
            });
            continue;
        }
        if (char === "\\") {
            tokens.push({
                type: "ESCAPED_CHAR",
                index: i1++,
                value: str[i1++]
            });
            continue;
        }
        if (char === "{") {
            tokens.push({
                type: "OPEN",
                index: i1,
                value: str[i1++]
            });
            continue;
        }
        if (char === "}") {
            tokens.push({
                type: "CLOSE",
                index: i1,
                value: str[i1++]
            });
            continue;
        }
        if (char === ":") {
            let name2 = "";
            let j = i1 + 1;
            while(j < str.length){
                const code = str.charCodeAt(j);
                if (code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 95) {
                    name2 += str[j++];
                    continue;
                }
                break;
            }
            if (!name2) throw new TypeError(`Missing parameter name at ${i1}`);
            tokens.push({
                type: "NAME",
                index: i1,
                value: name2
            });
            i1 = j;
            continue;
        }
        if (char === "(") {
            let count = 1;
            let pattern = "";
            let j = i1 + 1;
            if (str[j] === "?") {
                throw new TypeError(`Pattern cannot start with "?" at ${j}`);
            }
            while(j < str.length){
                if (str[j] === "\\") {
                    pattern += str[j++] + str[j++];
                    continue;
                }
                if (str[j] === ")") {
                    count--;
                    if (count === 0) {
                        j++;
                        break;
                    }
                } else if (str[j] === "(") {
                    count++;
                    if (str[j + 1] !== "?") {
                        throw new TypeError(`Capturing groups are not allowed at ${j}`);
                    }
                }
                pattern += str[j++];
            }
            if (count) throw new TypeError(`Unbalanced pattern at ${i1}`);
            if (!pattern) throw new TypeError(`Missing pattern at ${i1}`);
            tokens.push({
                type: "PATTERN",
                index: i1,
                value: pattern
            });
            i1 = j;
            continue;
        }
        tokens.push({
            type: "CHAR",
            index: i1,
            value: str[i1++]
        });
    }
    tokens.push({
        type: "END",
        index: i1,
        value: ""
    });
    return tokens;
}
function regexpToFunction(re, keys1, options2 = {
}) {
    const { decode =(x)=>x
      } = options2;
    return function(pathname) {
        const m = re.exec(pathname);
        if (!m) return false;
        const { 0: path , index  } = m;
        const params = Object.create(null);
        for(let i1 = 1; i1 < m.length; i1++){
            if (m[i1] === undefined) continue;
            const key1 = keys1[i1 - 1];
            if (key1.modifier === "*" || key1.modifier === "+") {
                params[key1.name] = m[i1].split(key1.prefix + key1.suffix).map((value2)=>{
                    return decode(value2, key1);
                });
            } else {
                params[key1.name] = decode(m[i1], key1);
            }
        }
        return {
            path,
            index,
            params
        };
    };
}
function escapeString(str) {
    return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options2) {
    return options2 && options2.sensitive ? "" : "i";
}
function regexpToRegexp(path, keys1) {
    if (!keys1) return path;
    const groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
    let index = 0;
    let execResult = groupsRegex.exec(path.source);
    while(execResult){
        keys1.push({
            name: execResult[1] || index++,
            prefix: "",
            suffix: "",
            modifier: "",
            pattern: ""
        });
        execResult = groupsRegex.exec(path.source);
    }
    return path;
}
function tokensToRegexp(tokens, keys1, options2 = {
}) {
    const { strict =false , start =true , end =true , encode =(x)=>x
      } = options2;
    const endsWith = `[${escapeString(options2.endsWith || "")}]|$`;
    const delimiter = `[${escapeString(options2.delimiter || "/#?")}]`;
    let route = start ? "^" : "";
    for (const token of tokens){
        if (typeof token === "string") {
            route += escapeString(encode(token));
        } else {
            const prefix = escapeString(encode(token.prefix));
            const suffix = escapeString(encode(token.suffix));
            if (token.pattern) {
                if (keys1) keys1.push(token);
                if (prefix || suffix) {
                    if (token.modifier === "+" || token.modifier === "*") {
                        const mod = token.modifier === "*" ? "?" : "";
                        route += `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod}`;
                    } else {
                        route += `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
                    }
                } else {
                    route += `(${token.pattern})${token.modifier}`;
                }
            } else {
                route += `(?:${prefix}${suffix})${token.modifier}`;
            }
        }
    }
    if (end) {
        if (!strict) route += `${delimiter}?`;
        route += !options2.endsWith ? "$" : `(?=${endsWith})`;
    } else {
        const endToken = tokens[tokens.length - 1];
        const isEndDelimited = typeof endToken === "string" ? delimiter.indexOf(endToken[endToken.length - 1]) > -1 : endToken === undefined;
        if (!strict) {
            route += `(?:${delimiter}(?=${endsWith}))?`;
        }
        if (!isEndDelimited) {
            route += `(?=${delimiter}|${endsWith})`;
        }
    }
    return new RegExp(route, flags(options2));
}
const errorStatusMap = {
    "BadRequest": 400,
    "Unauthorized": 401,
    "PaymentRequired": 402,
    "Forbidden": 403,
    "NotFound": 404,
    "MethodNotAllowed": 405,
    "NotAcceptable": 406,
    "ProxyAuthRequired": 407,
    "RequestTimeout": 408,
    "Conflict": 409,
    "Gone": 410,
    "LengthRequired": 411,
    "PreconditionFailed": 412,
    "RequestEntityTooLarge": 413,
    "RequestURITooLong": 414,
    "UnsupportedMediaType": 415,
    "RequestedRangeNotSatisfiable": 416,
    "ExpectationFailed": 417,
    "Teapot": 418,
    "MisdirectedRequest": 421,
    "UnprocessableEntity": 422,
    "Locked": 423,
    "FailedDependency": 424,
    "UpgradeRequired": 426,
    "PreconditionRequired": 428,
    "TooManyRequests": 429,
    "RequestHeaderFieldsTooLarge": 431,
    "UnavailableForLegalReasons": 451,
    "InternalServerError": 500,
    "NotImplemented": 501,
    "BadGateway": 502,
    "ServiceUnavailable": 503,
    "GatewayTimeout": 504,
    "HTTPVersionNotSupported": 505,
    "VariantAlsoNegotiates": 506,
    "InsufficientStorage": 507,
    "LoopDetected": 508,
    "NotExtended": 510,
    "NetworkAuthenticationRequired": 511
};
const httpErrors = {
};
const SUBTYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.-]{0,126}$/;
const TYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126}$/;
const TYPE_REGEXP = /^ *([A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126})\/([A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}) *$/;
class MediaType {
    constructor(type2, subtype, suffix){
        this.type = type2;
        this.subtype = subtype;
        this.suffix = suffix;
    }
}
function format(obj) {
    const { subtype: subtype1 , suffix: suffix1 , type: type1  } = obj;
    if (!TYPE_NAME_REGEXP.test(type1)) {
        throw new TypeError("Invalid type.");
    }
    if (!SUBTYPE_NAME_REGEXP.test(subtype1)) {
        throw new TypeError("Invalid subtype.");
    }
    let str = `${type1}/${subtype1}`;
    if (suffix1) {
        if (!TYPE_NAME_REGEXP.test(suffix1)) {
            throw new TypeError("Invalid suffix.");
        }
        str += `+${suffix1}`;
    }
    return str;
}
function parse(str) {
    const match = TYPE_REGEXP.exec(str.toLowerCase());
    if (!match) {
        throw new TypeError("Invalid media type.");
    }
    let [, type1, subtype1] = match;
    let suffix1;
    const idx = subtype1.lastIndexOf("+");
    if (idx !== -1) {
        suffix1 = subtype1.substr(idx + 1);
        subtype1 = subtype1.substr(0, idx);
    }
    return new MediaType(type1, subtype1, suffix1);
}
function mimeMatch(expected, actual) {
    if (expected === undefined) {
        return false;
    }
    const actualParts = actual.split("/");
    const expectedParts = expected.split("/");
    if (actualParts.length !== 2 || expectedParts.length !== 2) {
        return false;
    }
    const [actualType, actualSubtype] = actualParts;
    const [expectedType, expectedSubtype] = expectedParts;
    if (expectedType !== "*" && expectedType !== actualType) {
        return false;
    }
    if (expectedSubtype.substr(0, 2) === "*+") {
        return expectedSubtype.length <= actualSubtype.length + 1 && expectedSubtype.substr(1) === actualSubtype.substr(1 - expectedSubtype.length);
    }
    if (expectedSubtype !== "*" && expectedSubtype !== actualSubtype) {
        return false;
    }
    return true;
}
function normalizeType(value2) {
    try {
        const val = value2.split(";");
        const type1 = parse(val[0]);
        return format(type1);
    } catch  {
        return;
    }
}
const defaultBodyContentTypes = {
    json: [
        "json",
        "application/*+json",
        "application/csp-report"
    ],
    form: [
        "urlencoded"
    ],
    formData: [
        "multipart"
    ],
    text: [
        "text"
    ]
};
const decoder = new TextDecoder();
const SIMPLE_CHARSET_REGEXP = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseCharset(str, i1) {
    const match = SIMPLE_CHARSET_REGEXP.exec(str);
    if (!match) {
        return;
    }
    const [, charset1] = match;
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const [key1, value2] = param.trim().split("=");
            if (key1 === "q") {
                q = parseFloat(value2);
                break;
            }
        }
    }
    return {
        charset: charset1,
        q,
        i: i1
    };
}
function parseAcceptCharset(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i1 = 0; i1 < accepts.length; i1++){
        const charset1 = parseCharset(accepts[i1].trim(), i1);
        if (charset1) {
            result.push(charset1);
        }
    }
    return result;
}
function specify(charset1, spec, i1) {
    let s = 0;
    if (spec.charset.toLowerCase() === charset1.toLocaleLowerCase()) {
        s |= 1;
    } else if (spec.charset !== "*") {
        return;
    }
    return {
        i: i1,
        o: spec.i,
        q: spec.q,
        s
    };
}
function getCharsetPriority(charset1, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify(charset1, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
const simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseEncoding(str, i1) {
    const match = simpleEncodingRegExp.exec(str);
    if (!match) {
        return undefined;
    }
    const encoding = match[1];
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const p = param.trim().split("=");
            if (p[0] === "q") {
                q = parseFloat(p[1]);
                break;
            }
        }
    }
    return {
        encoding,
        q,
        i: i1
    };
}
function specify1(encoding, spec, i1 = -1) {
    if (!spec.encoding) {
        return;
    }
    let s = 0;
    if (spec.encoding.toLocaleLowerCase() === encoding.toLocaleLowerCase()) {
        s = 1;
    } else if (spec.encoding !== "*") {
        return;
    }
    return {
        i: i1,
        o: spec.i,
        q: spec.q,
        s
    };
}
function parseAcceptEncoding(accept) {
    const accepts = accept.split(",");
    const parsedAccepts = [];
    let hasIdentity = false;
    let minQuality = 1;
    for(let i1 = 0; i1 < accepts.length; i1++){
        const encoding = parseEncoding(accepts[i1].trim(), i1);
        if (encoding) {
            parsedAccepts.push(encoding);
            hasIdentity = hasIdentity || !!specify1("identity", encoding);
            minQuality = Math.min(minQuality, encoding.q || 1);
        }
    }
    if (!hasIdentity) {
        parsedAccepts.push({
            encoding: "identity",
            q: minQuality,
            i: accepts.length - 1
        });
    }
    return parsedAccepts;
}
function getEncodingPriority(encoding, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: 0
    };
    for (const s of accepted){
        const spec = specify1(encoding, s, index);
        if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) {
            priority = spec;
        }
    }
    return priority;
}
const SIMPLE_LANGUAGE_REGEXP = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
function parseLanguage(str, i1) {
    const match = SIMPLE_LANGUAGE_REGEXP.exec(str);
    if (!match) {
        return undefined;
    }
    const [, prefix, suffix1] = match;
    const full = suffix1 ? `${prefix}-${suffix1}` : prefix;
    let q = 1;
    if (match[3]) {
        const params = match[3].split(";");
        for (const param of params){
            const [key1, value2] = param.trim().split("=");
            if (key1 === "q") {
                q = parseFloat(value2);
                break;
            }
        }
    }
    return {
        prefix,
        suffix: suffix1,
        full,
        q,
        i: i1
    };
}
function parseAcceptLanguage(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i1 = 0; i1 < accepts.length; i1++){
        const language = parseLanguage(accepts[i1].trim(), i1);
        if (language) {
            result.push(language);
        }
    }
    return result;
}
function specify2(language, spec, i1) {
    const p = parseLanguage(language, i1);
    if (!p) {
        return undefined;
    }
    let s = 0;
    if (spec.full.toLowerCase() === p.full.toLowerCase()) {
        s |= 4;
    } else if (spec.prefix.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 2;
    } else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 1;
    } else if (spec.full !== "*") {
        return;
    }
    return {
        i: i1,
        o: spec.i,
        q: spec.q,
        s
    };
}
function getLanguagePriority(language, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify2(language, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
const simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
function quoteCount(str) {
    let count = 0;
    let index = 0;
    while((index = str.indexOf(`"`, index)) !== -1){
        count++;
        index++;
    }
    return count;
}
function splitMediaTypes(accept) {
    const accepts = accept.split(",");
    let j = 0;
    for(let i1 = 1; i1 < accepts.length; i1++){
        if (quoteCount(accepts[j]) % 2 === 0) {
            accepts[++j] = accepts[i1];
        } else {
            accepts[j] += `,${accepts[i1]}`;
        }
    }
    accepts.length = j + 1;
    return accepts;
}
function splitParameters(str) {
    const parameters = str.split(";");
    let j = 0;
    for(let i1 = 1; i1 < parameters.length; i1++){
        if (quoteCount(parameters[j]) % 2 === 0) {
            parameters[++j] = parameters[i1];
        } else {
            parameters[j] += `;${parameters[i1]}`;
        }
    }
    parameters.length = j + 1;
    return parameters.map((p)=>p.trim()
    );
}
function splitKeyValuePair(str) {
    const [key1, value2] = str.split("=");
    return [
        key1.toLowerCase(),
        value2
    ];
}
function parseMediaType(str, i1) {
    const match = simpleMediaTypeRegExp.exec(str);
    if (!match) {
        return;
    }
    const params = Object.create(null);
    let q = 1;
    const [, type1, subtype1, parameters] = match;
    if (parameters) {
        const kvps = splitParameters(parameters).map(splitKeyValuePair);
        for (const [key1, val] of kvps){
            const value2 = val && val[0] === `"` && val[val.length - 1] === `"` ? val.substr(1, val.length - 2) : val;
            if (key1 === "q" && value2) {
                q = parseFloat(value2);
                break;
            }
            params[key1] = value2;
        }
    }
    return {
        type: type1,
        subtype: subtype1,
        params,
        q,
        i: i1
    };
}
function parseAccept(accept) {
    const accepts = splitMediaTypes(accept);
    const mediaTypes = [];
    for(let i1 = 0; i1 < accepts.length; i1++){
        const mediaType = parseMediaType(accepts[i1].trim(), i1);
        if (mediaType) {
            mediaTypes.push(mediaType);
        }
    }
    return mediaTypes;
}
function getFullType(spec) {
    return `${spec.type}/${spec.subtype}`;
}
function specify3(type1, spec, index) {
    const p = parseMediaType(type1, index);
    if (!p) {
        return;
    }
    let s = 0;
    if (spec.type.toLowerCase() === p.type.toLowerCase()) {
        s |= 4;
    } else if (spec.type !== "*") {
        return;
    }
    if (spec.subtype.toLowerCase() === p.subtype.toLowerCase()) {
        s |= 2;
    } else if (spec.subtype !== "*") {
        return;
    }
    const keys1 = Object.keys(spec.params);
    if (keys1.length) {
        if (keys1.every((key1)=>(spec.params[key1] || "").toLowerCase() === (p.params[key1] || "").toLowerCase()
        )) {
            s |= 1;
        } else {
            return;
        }
    }
    return {
        i: index,
        o: spec.o,
        q: spec.q,
        s
    };
}
function getMediaTypePriority(type1, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: index
    };
    for (const accepts of accepted){
        const spec = specify3(type1, accepts, index);
        if (spec && ((priority.s || 0) - (spec.s || 0) || (priority.q || 0) - (spec.q || 0) || (priority.o || 0) - (spec.o || 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
const ENCODE_CHARS_REGEXP = /(?:[^\x21\x25\x26-\x3B\x3D\x3F-\x5B\x5D\x5F\x61-\x7A\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
const HTAB = "\t".charCodeAt(0);
const SPACE = " ".charCodeAt(0);
const CR = "\r".charCodeAt(0);
const LF = "\n".charCodeAt(0);
const UNMATCHED_SURROGATE_PAIR_REGEXP = /(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF]([^\uDC00-\uDFFF]|$)/g;
const UNMATCHED_SURROGATE_PAIR_REPLACE = "$1\uFFFD$2";
function decodeComponent(text) {
    try {
        return decodeURIComponent(text);
    } catch  {
        return text;
    }
}
function encodeUrl(url) {
    return String(url).replace(UNMATCHED_SURROGATE_PAIR_REGEXP, UNMATCHED_SURROGATE_PAIR_REPLACE).replace(ENCODE_CHARS_REGEXP, encodeURI);
}
function getRandomFilename(prefix = "", extension1 = "") {
    return `${prefix}${new Sha1().update(crypto.getRandomValues(new Uint8Array(256))).hex()}${extension1 ? `.${extension1}` : ""}`;
}
function isHtml(value2) {
    return /^\s*<(?:!DOCTYPE|html|body)/i.test(value2);
}
function skipLWSPChar(u8) {
    const result = new Uint8Array(u8.length);
    let j = 0;
    for(let i1 = 0; i1 < u8.length; i1++){
        if (u8[i1] === SPACE || u8[i1] === HTAB) continue;
        result[j++] = u8[i1];
    }
    return result.slice(0, j);
}
function stripEol(value2) {
    if (value2[value2.byteLength - 1] == LF) {
        let drop = 1;
        if (value2.byteLength > 1 && value2[value2.byteLength - 2] === CR) {
            drop = 2;
        }
        return value2.subarray(0, value2.byteLength - drop);
    }
    return value2;
}
const UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const REDIRECT_BACK = Symbol("redirect backwards");
const BODY_TYPES = [
    "string",
    "number",
    "bigint",
    "boolean",
    "symbol"
];
const encoder = new TextEncoder();
function isReader(value2) {
    return value2 && typeof value2 === "object" && "read" in value2 && typeof value2.read === "function";
}
async function convertBody(body, type1) {
    let result;
    if (BODY_TYPES.includes(typeof body)) {
        const bodyText = String(body);
        result = encoder.encode(bodyText);
        type1 = type1 ?? (isHtml(bodyText) ? "html" : "text/plain");
    } else if (body instanceof Uint8Array || isReader(body)) {
        result = body;
    } else if (body && typeof body === "object") {
        result = encoder.encode(JSON.stringify(body));
        type1 = type1 ?? "json";
    } else if (typeof body === "function") {
        const result1 = body.call(null);
        return convertBody(await result1, type1);
    } else if (body) {
        throw new TypeError("Response body was set but could not convert.");
    }
    return [
        result,
        type1
    ];
}
function isHidden(path) {
    const pathArr = path.split("/");
    for (const segment of pathArr){
        if (segment[0] === "." && segment !== "." && segment !== "..") {
            return true;
        }
        return false;
    }
}
async function exists(path) {
    try {
        return (await Deno.stat(path)).isFile;
    } catch  {
        return false;
    }
}
const encoder1 = new TextEncoder();
class CloseEvent1 extends Event {
    constructor(eventInit){
        super("close", eventInit);
    }
}
class ServerSentEvent extends Event {
    #data;
    #id;
    #type;
    constructor(type1, data1, { replacer , space , ...eventInit1 } = {
    }){
        super(type1, eventInit1);
        this.#type = type1;
        try {
            this.#data = typeof data1 === "string" ? data1 : JSON.stringify(data1, replacer, space);
        } catch (e) {
            assert(e instanceof Error);
            throw new TypeError(`data could not be coerced into a serialized string.\n  ${e.message}`);
        }
        const { id  } = eventInit1;
        this.#id = id;
    }
    get data() {
        return this.#data;
    }
    get id() {
        return this.#id;
    }
    toString() {
        const data1 = `data: ${this.#data.split("\n").join("\ndata: ")}\n`;
        return `${this.#type === "__message" ? "" : `event: ${this.#type}\n`}${this.#id ? `id: ${String(this.#id)}\n` : ""}${data1}\n`;
    }
}
const response1 = `HTTP/1.1 200 OK\n`;
const responseHeaders = new Headers([
    [
        "Connection",
        "Keep-Alive"
    ],
    [
        "Content-Type",
        "text/event-stream"
    ],
    [
        "Cache-Control",
        "no-cache"
    ],
    [
        "Keep-Alive",
        `timeout=${Number.MAX_SAFE_INTEGER}`
    ], 
]);
class ServerSentEventTarget extends EventTarget {
    #app;
    #closed=false;
    #prev=Promise.resolve();
    #ready;
    #serverRequest;
    #writer;
    #send=async (payload, prev)=>{
        if (this.#closed) {
            return;
        }
        if (this.#ready !== true) {
            await this.#ready;
            this.#ready = true;
        }
        try {
            await prev;
            await this.#writer.write(encoder1.encode(payload));
            await this.#writer.flush();
        } catch (error) {
            this.dispatchEvent(new CloseEvent1({
                cancelable: false
            }));
            const errorEvent = new ErrorEvent("error", {
                error
            });
            this.dispatchEvent(errorEvent);
            this.#app.dispatchEvent(errorEvent);
        }
    };
    #setup=async (overrideHeaders)=>{
        const headers = new Headers(responseHeaders);
        if (overrideHeaders) {
            for (const [key1, value2] of overrideHeaders){
                headers.set(key1, value2);
            }
        }
        let payload = response1;
        for (const [key1, value2] of headers){
            payload += `${key1}: ${value2}\n`;
        }
        payload += `\n`;
        try {
            await this.#writer.write(encoder1.encode(payload));
            await this.#writer.flush();
        } catch (error) {
            this.dispatchEvent(new CloseEvent1({
                cancelable: false
            }));
            const errorEvent = new ErrorEvent("error", {
                error
            });
            this.dispatchEvent(errorEvent);
            this.#app.dispatchEvent(errorEvent);
            throw error;
        }
    };
    get closed() {
        return this.#closed;
    }
    constructor(app, serverRequest, { headers  } = {
    }){
        super();
        this.#app = app;
        this.#serverRequest = serverRequest;
        this.#writer = this.#serverRequest.w;
        this.addEventListener("close", ()=>{
            this.#closed = true;
            try {
                this.#serverRequest.conn.close();
            } catch (error) {
                if (!(error instanceof Deno.errors.BadResource)) {
                    const errorEvent = new ErrorEvent("error", {
                        error
                    });
                    this.dispatchEvent(errorEvent);
                    this.#app.dispatchEvent(errorEvent);
                }
            }
        });
        this.#ready = this.#setup(headers);
    }
    async close() {
        if (this.#ready !== true) {
            await this.#ready;
        }
        await this.#prev;
        this.dispatchEvent(new CloseEvent1({
            cancelable: false
        }));
    }
    dispatchComment(comment) {
        this.#prev = this.#send(`: ${comment.split("\n").join("\n: ")}\n\n`, this.#prev);
        return true;
    }
    dispatchMessage(data) {
        const event = new ServerSentEvent("__message", data);
        return this.dispatchEvent(event);
    }
    dispatchEvent(event) {
        const dispatched = super.dispatchEvent(event);
        if (dispatched && event instanceof ServerSentEvent) {
            this.#prev = this.#send(String(event), this.#prev);
        }
        return dispatched;
    }
}
function compareArrayBuffer(a, b) {
    assert(a.byteLength === b.byteLength, "ArrayBuffer lengths must match.");
    const va = new DataView(a);
    const vb = new DataView(b);
    const length = va.byteLength;
    let out = 0;
    let i1 = -1;
    while((++i1) < length){
        out |= va.getUint8(i1) ^ vb.getUint8(i1);
    }
    return out === 0;
}
function compare(a, b) {
    const key1 = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key1);
    const ah = new HmacSha256(key1).update(a).arrayBuffer();
    const bh = new HmacSha256(key1).update(b).arrayBuffer();
    return compareArrayBuffer(ah, bh);
}
const replacements = {
    "/": "_",
    "+": "-",
    "=": ""
};
class KeyStack {
    #keys;
    constructor(keys1){
        if (!(0 in keys1)) {
            throw new TypeError("keys must contain at least one value");
        }
        this.#keys = keys1;
    }
    #sign=(data2, key1)=>{
        return btoa(String.fromCharCode.apply(undefined, new Uint8Array(new HmacSha256(key1).update(data2).arrayBuffer()))).replace(/\/|\+|=/g, (c)=>replacements[c]
        );
    };
    sign(data) {
        return this.#sign(data, this.#keys[0]);
    }
    verify(data, digest) {
        return this.indexOf(data, digest) > -1;
    }
    indexOf(data, digest) {
        for(let i1 = 0; i1 < this.#keys.length; i1++){
            if (compare(digest, this.#sign(data, this.#keys[i1]))) {
                return i1;
            }
        }
        return -1;
    }
}
function compose(middleware) {
    return function composedMiddleware(context, next) {
        let index = -1;
        async function dispatch(i1) {
            if (i1 <= index) {
                throw new Error("next() called multiple times.");
            }
            index = i1;
            let fn = middleware[i1];
            if (i1 === middleware.length) {
                fn = next;
            }
            if (!fn) {
                return;
            }
            await fn(context, dispatch.bind(null, i1 + 1));
        }
        return dispatch(0);
    };
}
function isOptionsTls(options2) {
    return options2.secure === true;
}
const ADDR_REGEXP = /^\[?([^\]]*)\]?:([0-9]{1,5})$/;
class ApplicationErrorEvent extends ErrorEvent {
    constructor(eventInitDict){
        super("error", eventInitDict);
        this.context = eventInitDict.context;
    }
}
class ApplicationListenEvent extends Event {
    constructor(eventInitDict1){
        super("listen", eventInitDict1);
        this.hostname = eventInitDict1.hostname;
        this.port = eventInitDict1.port;
        this.secure = eventInitDict1.secure;
    }
}
const noColor = globalThis.Deno?.noColor ?? true;
let enabled = !noColor;
function code1(open, close) {
    return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g")
    };
}
function run(str, code1) {
    return enabled ? `${code1.open}${str.replace(code1.regexp, code1.open)}${code1.close}` : str;
}
function bold(str) {
    return run(str, code1([
        1
    ], 22));
}
function red(str) {
    return run(str, code1([
        31
    ], 39));
}
function green(str) {
    return run(str, code1([
        32
    ], 39));
}
function yellow(str) {
    return run(str, code1([
        33
    ], 39));
}
function white(str) {
    return run(str, code1([
        37
    ], 39));
}
function brightBlack(str) {
    return run(str, code1([
        90
    ], 39));
}
function clampAndTruncate(n, max = 255, min = 0) {
    return Math.trunc(Math.max(Math.min(n, max), min));
}
const ANSI_PATTERN = new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))", 
].join("|"), "g");
function stripColor(string) {
    return string.replace(ANSI_PATTERN, "");
}
async function logger(ctx, next) {
    await next();
    const responseTime = ctx.response.headers.get("X-Response-Time");
    console.log(`${ctx.request.method}: ${ctx.request.url}:${responseTime}`);
}
async function timing(ctx, next) {
    const startTime = Date.now();
    await next();
    const endTime = Date.now();
    const difference1 = endTime - startTime;
    ctx.response.headers.set("X-Response-Time", `${difference1}ms`);
}
async function getMovies() {
    return {
        data: [
            {
                title: "Spiderman"
            },
            {
                title: "Batman"
            }
        ]
    };
}
async function getMovie(id1) {
    if (!id1) return {
        data: {
        }
    };
    return {
        data: {
            id: id1,
            title: "Spiderman"
        }
    };
}
console.log(Deno.env.get("API_KEY"));
const CR1 = "\r".charCodeAt(0);
const LF1 = "\n".charCodeAt(0);
class BufferFullError extends Error {
    name = "BufferFullError";
    constructor(partial){
        super("Buffer full");
        this.partial = partial;
    }
}
class BufReader {
    #buffer;
    #reader;
    #posRead=0;
    #posWrite=0;
    #eof=false;
    #fill=async ()=>{
        if (this.#posRead > 0) {
            this.#buffer.copyWithin(0, this.#posRead, this.#posWrite);
            this.#posWrite -= this.#posRead;
            this.#posRead = 0;
        }
        if (this.#posWrite >= this.#buffer.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i1 = 100; i1 > 0; i1--){
            const rr = await this.#reader.read(this.#buffer.subarray(this.#posWrite));
            if (rr === null) {
                this.#eof = true;
                return;
            }
            assert(rr >= 0, "negative read");
            this.#posWrite += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    };
    #reset=(buffer, reader)=>{
        this.#buffer = buffer;
        this.#reader = reader;
        this.#eof = false;
    };
    constructor(rd2, size1 = 4096){
        if (size1 < 16) {
            size1 = 16;
        }
        this.#reset(new Uint8Array(size1), rd2);
    }
    buffered() {
        return this.#posWrite - this.#posRead;
    }
    async readLine(strip = true) {
        let line;
        try {
            line = await this.readSlice(LF1);
        } catch (err) {
            let { partial: partial1  } = err;
            assert(partial1 instanceof Uint8Array, "Caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError)) {
                throw err;
            }
            if (!this.#eof && partial1.byteLength > 0 && partial1[partial1.byteLength - 1] === CR1) {
                assert(this.#posRead > 0, "Tried to rewind past start of buffer");
                this.#posRead--;
                partial1 = partial1.subarray(0, partial1.byteLength - 1);
            }
            return {
                bytes: partial1,
                eol: this.#eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                bytes: line,
                eol: true
            };
        }
        if (strip) {
            line = stripEol(line);
        }
        return {
            bytes: line,
            eol: true
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i1 = this.#buffer.subarray(this.#posRead + s, this.#posWrite).indexOf(delim);
            if (i1 >= 0) {
                i1 += s;
                slice = this.#buffer.subarray(this.#posRead, this.#posRead + i1 + 1);
                this.#posRead += i1 + 1;
                break;
            }
            if (this.#eof) {
                if (this.#posRead === this.#posWrite) {
                    return null;
                }
                slice = this.#buffer.subarray(this.#posRead, this.#posWrite);
                this.#posRead = this.#posWrite;
                break;
            }
            if (this.buffered() >= this.#buffer.byteLength) {
                this.#posRead = this.#posWrite;
                const oldbuf = this.#buffer;
                const newbuf = this.#buffer.slice(0);
                this.#buffer = newbuf;
                throw new BufferFullError(oldbuf);
            }
            s = this.#posWrite - this.#posRead;
            try {
                await this.#fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
}
let needsEncodingFixup = false;
function textDecode(encoding, value2) {
    if (encoding) {
        try {
            const decoder1 = new TextDecoder(encoding, {
                fatal: true
            });
            const bytes = Array.from(value2, (c)=>c.charCodeAt(0)
            );
            if (bytes.every((code1)=>code1 <= 255
            )) {
                value2 = decoder1.decode(new Uint8Array(bytes));
                needsEncodingFixup = false;
            }
        } catch  {
        }
    }
    return value2;
}
const COLON = ":".charCodeAt(0);
const HTAB1 = "\t".charCodeAt(0);
const SPACE1 = " ".charCodeAt(0);
const decoder1 = new TextDecoder();
function toParamRegExp(attributePattern, flags1) {
    return new RegExp(`(?:^|;)\\s*${attributePattern}\\s*=\\s*` + `(` + `[^";\\s][^;\\s]*` + `|` + `"(?:[^"\\\\]|\\\\"?)+"?` + `)`, flags1);
}
async function readHeaders(body) {
    const headers1 = {
    };
    let readResult = await body.readLine();
    while(readResult){
        const { bytes  } = readResult;
        if (!bytes.length) {
            return headers1;
        }
        let i1 = bytes.indexOf(COLON);
        if (i1 === -1) {
            throw new httpErrors.BadRequest(`Malformed header: ${decoder1.decode(bytes)}`);
        }
        const key1 = decoder1.decode(bytes.subarray(0, i1)).trim().toLowerCase();
        if (key1 === "") {
            throw new httpErrors.BadRequest("Invalid header key.");
        }
        i1++;
        while(i1 < bytes.byteLength && (bytes[i1] === SPACE1 || bytes[i1] === HTAB1)){
            i1++;
        }
        const value2 = decoder1.decode(bytes.subarray(i1)).trim();
        headers1[key1] = value2;
        readResult = await body.readLine();
    }
    throw new httpErrors.BadRequest("Unexpected end of body reached.");
}
function unquote(value2) {
    if (value2.startsWith(`"`)) {
        const parts = value2.slice(1).split(`\\"`);
        for(let i1 = 0; i1 < parts.length; ++i1){
            const quoteIndex = parts[i1].indexOf(`"`);
            if (quoteIndex !== -1) {
                parts[i1] = parts[i1].slice(0, quoteIndex);
                parts.length = i1 + 1;
            }
            parts[i1] = parts[i1].replace(/\\(.)/g, "$1");
        }
        value2 = parts.join(`"`);
    }
    return value2;
}
const decoder2 = new TextDecoder();
const encoder2 = new TextEncoder();
const BOUNDARY_PARAM_REGEX = toParamRegExp("boundary", "i");
const NAME_PARAM_REGEX = toParamRegExp("name", "i");
function append(a, b) {
    const ab = new Uint8Array(a.length + b.length);
    ab.set(a, 0);
    ab.set(b, a.length);
    return ab;
}
function isEqual(a, b) {
    return equal(skipLWSPChar(a), b);
}
async function readToStartOrEnd(body, start, end) {
    let lineResult;
    while(lineResult = await body.readLine()){
        if (isEqual(lineResult.bytes, start)) {
            return true;
        }
        if (isEqual(lineResult.bytes, end)) {
            return false;
        }
    }
    throw new httpErrors.BadRequest("Unable to find multi-part boundary.");
}
class Prompt {
    constructor(opts){
        if (!opts.name || opts.name.trim().length === 0) {
            throw new Error('Please provide the name of the prompt.');
        }
        this.name = opts.name;
        this.type = opts.type ?? 'text';
        this.message = opts.message ?? opts.name;
        this.prefix = opts.prefix ?? '\x1b[32m?\x1b[39m';
        this.suffix = opts.suffix ?? (!opts.message && opts.suffix == null ? ':' : '');
        this.default = opts.default;
        this.input = opts.input ?? Deno.stdin;
        this.output = opts.output ?? Deno.stdout;
        this.validate = opts.validate ?? (()=>true
        );
    }
    format(str) {
        return '\x1b[1m' + str + '\x1b[22m' + (this.default ? ` (${this.default})` : '') + this.suffix;
    }
    getPrompt() {
        const components = [];
        if (this.prefix?.length) {
            components.push(this.prefix);
        }
        components.push(this.format(this.message));
        return components.join(' ') + ' ';
    }
}
function findIndex1(source, pat) {
    const s = pat[0];
    for(let i1 = 0; i1 < source.length; i1++){
        if (source[i1] !== s) continue;
        const pin = i1;
        let matched = 1;
        let j = i1;
        while(matched < pat.length){
            j++;
            if (source[j] !== pat[j - i1]) {
                break;
            }
            matched++;
        }
        if (matched === pat.length) {
            return i1;
        }
    }
    return -1;
}
function copyBytes1(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
function assert1(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
const CR2 = "\r".charCodeAt(0);
const LF2 = "\n".charCodeAt(0);
class BufferFullError1 extends Error {
    name = "BufferFullError";
    constructor(partial1){
        super("Buffer full");
        this.partial = partial1;
    }
}
class BufReader1 {
    r = 0;
    w = 0;
    eof = false;
    static create(r, size = 4096) {
        return r instanceof BufReader1 ? r : new BufReader1(r, size);
    }
    constructor(rd1, size2 = 4096){
        if (size2 < 16) {
            size2 = 16;
        }
        this._reset(new Uint8Array(size2), rd1);
    }
    size() {
        return this.buf.byteLength;
    }
    buffered() {
        return this.w - this.r;
    }
    async _fill() {
        if (this.r > 0) {
            this.buf.copyWithin(0, this.r, this.w);
            this.w -= this.r;
            this.r = 0;
        }
        if (this.w >= this.buf.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i1 = 100; i1 > 0; i1--){
            const rr = await this.rd.read(this.buf.subarray(this.w));
            if (rr === null) {
                this.eof = true;
                return;
            }
            assert1(rr >= 0, "negative read");
            this.w += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    reset(r) {
        this._reset(this.buf, r);
    }
    _reset(buf, rd) {
        this.buf = buf;
        this.rd = rd;
        this.eof = false;
    }
    async read(p) {
        let rr = p.byteLength;
        if (p.byteLength === 0) return rr;
        if (this.r === this.w) {
            if (p.byteLength >= this.buf.byteLength) {
                const rr1 = await this.rd.read(p);
                const nread = rr1 ?? 0;
                assert1(nread >= 0, "negative read");
                return rr1;
            }
            this.r = 0;
            this.w = 0;
            rr = await this.rd.read(this.buf);
            if (rr === 0 || rr === null) return rr;
            assert1(rr >= 0, "negative read");
            this.w += rr;
        }
        const copied = copyBytes1(this.buf.subarray(this.r, this.w), p, 0);
        this.r += copied;
        return copied;
    }
    async readFull(p) {
        let bytesRead = 0;
        while(bytesRead < p.length){
            try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                    if (bytesRead === 0) {
                        return null;
                    } else {
                        throw new PartialReadError();
                    }
                }
                bytesRead += rr;
            } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
            }
        }
        return p;
    }
    async readByte() {
        while(this.r === this.w){
            if (this.eof) return null;
            await this._fill();
        }
        const c = this.buf[this.r];
        this.r++;
        return c;
    }
    async readString(delim) {
        if (delim.length !== 1) {
            throw new Error("Delimiter should be a single character");
        }
        const buffer = await this.readSlice(delim.charCodeAt(0));
        if (buffer === null) return null;
        return new TextDecoder().decode(buffer);
    }
    async readLine() {
        let line;
        try {
            line = await this.readSlice(LF2);
        } catch (err) {
            let { partial: partial2  } = err;
            assert1(partial2 instanceof Uint8Array, "bufio: caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError1)) {
                throw err;
            }
            if (!this.eof && partial2.byteLength > 0 && partial2[partial2.byteLength - 1] === CR2) {
                assert1(this.r > 0, "bufio: tried to rewind past start of buffer");
                this.r--;
                partial2 = partial2.subarray(0, partial2.byteLength - 1);
            }
            return {
                line: partial2,
                more: !this.eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                line,
                more: false
            };
        }
        if (line[line.byteLength - 1] == LF2) {
            let drop = 1;
            if (line.byteLength > 1 && line[line.byteLength - 2] === CR2) {
                drop = 2;
            }
            line = line.subarray(0, line.byteLength - drop);
        }
        return {
            line,
            more: false
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i1 = this.buf.subarray(this.r + s, this.w).indexOf(delim);
            if (i1 >= 0) {
                i1 += s;
                slice = this.buf.subarray(this.r, this.r + i1 + 1);
                this.r += i1 + 1;
                break;
            }
            if (this.eof) {
                if (this.r === this.w) {
                    return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
            }
            if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                const oldbuf = this.buf;
                const newbuf = this.buf.slice(0);
                this.buf = newbuf;
                throw new BufferFullError1(oldbuf);
            }
            s = this.w - this.r;
            try {
                await this._fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
    async peek(n) {
        if (n < 0) {
            throw Error("negative count");
        }
        let avail = this.w - this.r;
        while(avail < n && avail < this.buf.byteLength && !this.eof){
            try {
                await this._fill();
            } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
            }
            avail = this.w - this.r;
        }
        if (avail === 0 && this.eof) {
            return null;
        } else if (avail < n && this.eof) {
            return this.buf.subarray(this.r, this.r + avail);
        } else if (avail < n) {
            throw new BufferFullError1(this.buf.subarray(this.r, this.w));
        }
        return this.buf.subarray(this.r, this.r + n);
    }
}
class AbstractBufBase {
    usedBufferBytes = 0;
    err = null;
    size() {
        return this.buf.byteLength;
    }
    available() {
        return this.buf.byteLength - this.usedBufferBytes;
    }
    buffered() {
        return this.usedBufferBytes;
    }
}
class BufWriter extends AbstractBufBase {
    static create(writer, size = 4096) {
        return writer instanceof BufWriter ? writer : new BufWriter(writer, size);
    }
    constructor(writer1, size3 = 4096){
        super();
        this.writer = writer1;
        if (size3 <= 0) {
            size3 = 4096;
        }
        this.buf = new Uint8Array(size3);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    async flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            await Deno.writeAll(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    async write(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = await this.writer.write(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copyBytes1(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copyBytes1(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
class BufWriterSync extends AbstractBufBase {
    static create(writer, size = 4096) {
        return writer instanceof BufWriterSync ? writer : new BufWriterSync(writer, size);
    }
    constructor(writer2, size4 = 4096){
        super();
        this.writer = writer2;
        if (size4 <= 0) {
            size4 = 4096;
        }
        this.buf = new Uint8Array(size4);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            Deno.writeAllSync(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    writeSync(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copyBytes1(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copyBytes1(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
function createLPS(pat) {
    const lps = new Uint8Array(pat.length);
    lps[0] = 0;
    let prefixEnd = 0;
    let i1 = 1;
    while(i1 < lps.length){
        if (pat[i1] == pat[prefixEnd]) {
            prefixEnd++;
            lps[i1] = prefixEnd;
            i1++;
        } else if (prefixEnd === 0) {
            lps[i1] = 0;
            i1++;
        } else {
            prefixEnd = pat[prefixEnd - 1];
        }
    }
    return lps;
}
async function* readDelim(reader, delim) {
    const delimLen = delim.length;
    const delimLPS = createLPS(delim);
    let inputBuffer = new Deno.Buffer();
    const inspectArr = new Uint8Array(Math.max(1024, delimLen + 1));
    let inspectIndex = 0;
    let matchIndex = 0;
    while(true){
        const result = await reader.read(inspectArr);
        if (result === null) {
            yield inputBuffer.bytes();
            return;
        }
        if (result < 0) {
            return;
        }
        const sliceRead = inspectArr.subarray(0, result);
        await Deno.writeAll(inputBuffer, sliceRead);
        let sliceToProcess = inputBuffer.bytes();
        while(inspectIndex < sliceToProcess.length){
            if (sliceToProcess[inspectIndex] === delim[matchIndex]) {
                inspectIndex++;
                matchIndex++;
                if (matchIndex === delimLen) {
                    const matchEnd = inspectIndex - delimLen;
                    const readyBytes = sliceToProcess.subarray(0, matchEnd);
                    const pendingBytes = sliceToProcess.slice(inspectIndex);
                    yield readyBytes;
                    sliceToProcess = pendingBytes;
                    inspectIndex = 0;
                    matchIndex = 0;
                }
            } else {
                if (matchIndex === 0) {
                    inspectIndex++;
                } else {
                    matchIndex = delimLPS[matchIndex - 1];
                }
            }
        }
        inputBuffer = new Deno.Buffer(sliceToProcess);
    }
}
async function* readStringDelim(reader, delim) {
    const encoder3 = new TextEncoder();
    const decoder3 = new TextDecoder();
    for await (const chunk of readDelim(reader, encoder3.encode(delim))){
        yield decoder3.decode(chunk);
    }
}
class Text1 extends Prompt {
    constructor(opts1){
        super(opts1);
    }
    getReader() {
        return new BufReader1(this.input);
    }
    async printError(msg) {
        await this.output.write(new TextEncoder().encode(`\x1b[31m>>\x1b[0m ${msg}\n`));
    }
    async question() {
        const reader = this.getReader();
        const prompt = new TextEncoder().encode(this.getPrompt());
        await this.output.write(prompt);
        try {
            const input = await reader.readLine();
            let result = input?.line && new TextDecoder().decode(input.line);
            let pass = true;
            result = result || this.default || result;
            try {
                pass = await Promise.resolve(this.validate(result));
            } catch (e) {
                pass = false;
                await this.printError(typeof e === 'string' ? e : e.message);
            }
            if (!pass) {
                return this.question();
            }
            return result;
        } catch (err) {
            throw err;
        }
    }
}
function _parseAddrFromStr(addr) {
    let url;
    try {
        const host = addr.startsWith(":") ? `0.0.0.0${addr}` : addr;
        url = new URL(`http://${host}`);
    } catch  {
        throw new TypeError("Invalid address.");
    }
    if (url.username || url.password || url.pathname != "/" || url.search || url.hash) {
        throw new TypeError("Invalid address.");
    }
    return {
        hostname: url.hostname,
        port: url.port === "" ? 80 : Number(url.port)
    };
}
function emptyReader() {
    return {
        read (_) {
            return Promise.resolve(null);
        }
    };
}
function bodyReader(contentLength, r) {
    let totalRead = 0;
    let finished = false;
    async function read(buf) {
        if (finished) return null;
        let result;
        const remaining = contentLength - totalRead;
        if (remaining >= buf.byteLength) {
            result = await r.read(buf);
        } else {
            const readBuf = buf.subarray(0, remaining);
            result = await r.read(readBuf);
        }
        if (result !== null) {
            totalRead += result;
        }
        finished = totalRead === contentLength;
        return result;
    }
    return {
        read
    };
}
function isProhibidedForTrailer(key1) {
    const s = new Set([
        "transfer-encoding",
        "content-length",
        "trailer"
    ]);
    return s.has(key1.toLowerCase());
}
function parseTrailer(field) {
    if (field == null) {
        return undefined;
    }
    const trailerNames = field.split(",").map((v)=>v.trim().toLowerCase()
    );
    if (trailerNames.length === 0) {
        throw new Deno.errors.InvalidData("Empty trailer header.");
    }
    const prohibited = trailerNames.filter((k)=>isProhibidedForTrailer(k)
    );
    if (prohibited.length > 0) {
        throw new Deno.errors.InvalidData(`Prohibited trailer names: ${Deno.inspect(prohibited)}.`);
    }
    return new Headers(trailerNames.map((key1)=>[
            key1,
            ""
        ]
    ));
}
function parseHTTPVersion(vers) {
    switch(vers){
        case "HTTP/1.1":
            return [
                1,
                1
            ];
        case "HTTP/1.0":
            return [
                1,
                0
            ];
        default:
            {
                const Big = 1000000;
                if (!vers.startsWith("HTTP/")) {
                    break;
                }
                const dot = vers.indexOf(".");
                if (dot < 0) {
                    break;
                }
                const majorStr = vers.substring(vers.indexOf("/") + 1, dot);
                const major = Number(majorStr);
                if (!Number.isInteger(major) || major < 0 || major > 1000000) {
                    break;
                }
                const minorStr = vers.substring(dot + 1);
                const minor = Number(minorStr);
                if (!Number.isInteger(minor) || minor < 0 || minor > 1000000) {
                    break;
                }
                return [
                    major,
                    minor
                ];
            }
    }
    throw new Error(`malformed HTTP version ${vers}`);
}
function fixLength(req) {
    const contentLength = req.headers.get("Content-Length");
    if (contentLength) {
        const arrClen = contentLength.split(",");
        if (arrClen.length > 1) {
            const distinct = [
                ...new Set(arrClen.map((e)=>e.trim()
                ))
            ];
            if (distinct.length > 1) {
                throw Error("cannot contain multiple Content-Length headers");
            } else {
                req.headers.set("Content-Length", distinct[0]);
            }
        }
        const c = req.headers.get("Content-Length");
        if (req.method === "HEAD" && c && c !== "0") {
            throw Error("http: method cannot contain a Content-Length");
        }
        if (c && req.headers.has("transfer-encoding")) {
            throw new Error("http: Transfer-Encoding and Content-Length cannot be send together");
        }
    }
}
var Status;
(function(Status1) {
    Status1[Status1["Continue"] = 100] = "Continue";
    Status1[Status1["SwitchingProtocols"] = 101] = "SwitchingProtocols";
    Status1[Status1["Processing"] = 102] = "Processing";
    Status1[Status1["EarlyHints"] = 103] = "EarlyHints";
    Status1[Status1["OK"] = 200] = "OK";
    Status1[Status1["Created"] = 201] = "Created";
    Status1[Status1["Accepted"] = 202] = "Accepted";
    Status1[Status1["NonAuthoritativeInfo"] = 203] = "NonAuthoritativeInfo";
    Status1[Status1["NoContent"] = 204] = "NoContent";
    Status1[Status1["ResetContent"] = 205] = "ResetContent";
    Status1[Status1["PartialContent"] = 206] = "PartialContent";
    Status1[Status1["MultiStatus"] = 207] = "MultiStatus";
    Status1[Status1["AlreadyReported"] = 208] = "AlreadyReported";
    Status1[Status1["IMUsed"] = 226] = "IMUsed";
    Status1[Status1["MultipleChoices"] = 300] = "MultipleChoices";
    Status1[Status1["MovedPermanently"] = 301] = "MovedPermanently";
    Status1[Status1["Found"] = 302] = "Found";
    Status1[Status1["SeeOther"] = 303] = "SeeOther";
    Status1[Status1["NotModified"] = 304] = "NotModified";
    Status1[Status1["UseProxy"] = 305] = "UseProxy";
    Status1[Status1["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    Status1[Status1["PermanentRedirect"] = 308] = "PermanentRedirect";
    Status1[Status1["BadRequest"] = 400] = "BadRequest";
    Status1[Status1["Unauthorized"] = 401] = "Unauthorized";
    Status1[Status1["PaymentRequired"] = 402] = "PaymentRequired";
    Status1[Status1["Forbidden"] = 403] = "Forbidden";
    Status1[Status1["NotFound"] = 404] = "NotFound";
    Status1[Status1["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    Status1[Status1["NotAcceptable"] = 406] = "NotAcceptable";
    Status1[Status1["ProxyAuthRequired"] = 407] = "ProxyAuthRequired";
    Status1[Status1["RequestTimeout"] = 408] = "RequestTimeout";
    Status1[Status1["Conflict"] = 409] = "Conflict";
    Status1[Status1["Gone"] = 410] = "Gone";
    Status1[Status1["LengthRequired"] = 411] = "LengthRequired";
    Status1[Status1["PreconditionFailed"] = 412] = "PreconditionFailed";
    Status1[Status1["RequestEntityTooLarge"] = 413] = "RequestEntityTooLarge";
    Status1[Status1["RequestURITooLong"] = 414] = "RequestURITooLong";
    Status1[Status1["UnsupportedMediaType"] = 415] = "UnsupportedMediaType";
    Status1[Status1["RequestedRangeNotSatisfiable"] = 416] = "RequestedRangeNotSatisfiable";
    Status1[Status1["ExpectationFailed"] = 417] = "ExpectationFailed";
    Status1[Status1["Teapot"] = 418] = "Teapot";
    Status1[Status1["MisdirectedRequest"] = 421] = "MisdirectedRequest";
    Status1[Status1["UnprocessableEntity"] = 422] = "UnprocessableEntity";
    Status1[Status1["Locked"] = 423] = "Locked";
    Status1[Status1["FailedDependency"] = 424] = "FailedDependency";
    Status1[Status1["TooEarly"] = 425] = "TooEarly";
    Status1[Status1["UpgradeRequired"] = 426] = "UpgradeRequired";
    Status1[Status1["PreconditionRequired"] = 428] = "PreconditionRequired";
    Status1[Status1["TooManyRequests"] = 429] = "TooManyRequests";
    Status1[Status1["RequestHeaderFieldsTooLarge"] = 431] = "RequestHeaderFieldsTooLarge";
    Status1[Status1["UnavailableForLegalReasons"] = 451] = "UnavailableForLegalReasons";
    Status1[Status1["InternalServerError"] = 500] = "InternalServerError";
    Status1[Status1["NotImplemented"] = 501] = "NotImplemented";
    Status1[Status1["BadGateway"] = 502] = "BadGateway";
    Status1[Status1["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    Status1[Status1["GatewayTimeout"] = 504] = "GatewayTimeout";
    Status1[Status1["HTTPVersionNotSupported"] = 505] = "HTTPVersionNotSupported";
    Status1[Status1["VariantAlsoNegotiates"] = 506] = "VariantAlsoNegotiates";
    Status1[Status1["InsufficientStorage"] = 507] = "InsufficientStorage";
    Status1[Status1["LoopDetected"] = 508] = "LoopDetected";
    Status1[Status1["NotExtended"] = 510] = "NotExtended";
    Status1[Status1["NetworkAuthenticationRequired"] = 511] = "NetworkAuthenticationRequired";
})(Status || (Status = {
}));
const STATUS_TEXT = new Map([
    [
        Status.Continue,
        "Continue"
    ],
    [
        Status.SwitchingProtocols,
        "Switching Protocols"
    ],
    [
        Status.Processing,
        "Processing"
    ],
    [
        Status.EarlyHints,
        "Early Hints"
    ],
    [
        Status.OK,
        "OK"
    ],
    [
        Status.Created,
        "Created"
    ],
    [
        Status.Accepted,
        "Accepted"
    ],
    [
        Status.NonAuthoritativeInfo,
        "Non-Authoritative Information"
    ],
    [
        Status.NoContent,
        "No Content"
    ],
    [
        Status.ResetContent,
        "Reset Content"
    ],
    [
        Status.PartialContent,
        "Partial Content"
    ],
    [
        Status.MultiStatus,
        "Multi-Status"
    ],
    [
        Status.AlreadyReported,
        "Already Reported"
    ],
    [
        Status.IMUsed,
        "IM Used"
    ],
    [
        Status.MultipleChoices,
        "Multiple Choices"
    ],
    [
        Status.MovedPermanently,
        "Moved Permanently"
    ],
    [
        Status.Found,
        "Found"
    ],
    [
        Status.SeeOther,
        "See Other"
    ],
    [
        Status.NotModified,
        "Not Modified"
    ],
    [
        Status.UseProxy,
        "Use Proxy"
    ],
    [
        Status.TemporaryRedirect,
        "Temporary Redirect"
    ],
    [
        Status.PermanentRedirect,
        "Permanent Redirect"
    ],
    [
        Status.BadRequest,
        "Bad Request"
    ],
    [
        Status.Unauthorized,
        "Unauthorized"
    ],
    [
        Status.PaymentRequired,
        "Payment Required"
    ],
    [
        Status.Forbidden,
        "Forbidden"
    ],
    [
        Status.NotFound,
        "Not Found"
    ],
    [
        Status.MethodNotAllowed,
        "Method Not Allowed"
    ],
    [
        Status.NotAcceptable,
        "Not Acceptable"
    ],
    [
        Status.ProxyAuthRequired,
        "Proxy Authentication Required"
    ],
    [
        Status.RequestTimeout,
        "Request Timeout"
    ],
    [
        Status.Conflict,
        "Conflict"
    ],
    [
        Status.Gone,
        "Gone"
    ],
    [
        Status.LengthRequired,
        "Length Required"
    ],
    [
        Status.PreconditionFailed,
        "Precondition Failed"
    ],
    [
        Status.RequestEntityTooLarge,
        "Request Entity Too Large"
    ],
    [
        Status.RequestURITooLong,
        "Request URI Too Long"
    ],
    [
        Status.UnsupportedMediaType,
        "Unsupported Media Type"
    ],
    [
        Status.RequestedRangeNotSatisfiable,
        "Requested Range Not Satisfiable"
    ],
    [
        Status.ExpectationFailed,
        "Expectation Failed"
    ],
    [
        Status.Teapot,
        "I'm a teapot"
    ],
    [
        Status.MisdirectedRequest,
        "Misdirected Request"
    ],
    [
        Status.UnprocessableEntity,
        "Unprocessable Entity"
    ],
    [
        Status.Locked,
        "Locked"
    ],
    [
        Status.FailedDependency,
        "Failed Dependency"
    ],
    [
        Status.TooEarly,
        "Too Early"
    ],
    [
        Status.UpgradeRequired,
        "Upgrade Required"
    ],
    [
        Status.PreconditionRequired,
        "Precondition Required"
    ],
    [
        Status.TooManyRequests,
        "Too Many Requests"
    ],
    [
        Status.RequestHeaderFieldsTooLarge,
        "Request Header Fields Too Large"
    ],
    [
        Status.UnavailableForLegalReasons,
        "Unavailable For Legal Reasons"
    ],
    [
        Status.InternalServerError,
        "Internal Server Error"
    ],
    [
        Status.NotImplemented,
        "Not Implemented"
    ],
    [
        Status.BadGateway,
        "Bad Gateway"
    ],
    [
        Status.ServiceUnavailable,
        "Service Unavailable"
    ],
    [
        Status.GatewayTimeout,
        "Gateway Timeout"
    ],
    [
        Status.HTTPVersionNotSupported,
        "HTTP Version Not Supported"
    ],
    [
        Status.VariantAlsoNegotiates,
        "Variant Also Negotiates"
    ],
    [
        Status.InsufficientStorage,
        "Insufficient Storage"
    ],
    [
        Status.LoopDetected,
        "Loop Detected"
    ],
    [
        Status.NotExtended,
        "Not Extended"
    ],
    [
        Status.NetworkAuthenticationRequired,
        "Network Authentication Required"
    ], 
]);
const CR3 = "\r".charCodeAt(0);
const LF3 = "\n".charCodeAt(0);
class BufferFullError2 extends Error {
    name = "BufferFullError";
    constructor(partial2){
        super("Buffer full");
        this.partial = partial2;
    }
}
class AbstractBufBase1 {
    usedBufferBytes = 0;
    err = null;
    size() {
        return this.buf.byteLength;
    }
    available() {
        return this.buf.byteLength - this.usedBufferBytes;
    }
    buffered() {
        return this.usedBufferBytes;
    }
}
class BufWriter1 extends AbstractBufBase1 {
    static create(writer, size = 4096) {
        return writer instanceof BufWriter1 ? writer : new BufWriter1(writer, size);
    }
    constructor(writer3, size5 = 4096){
        super();
        this.writer = writer3;
        if (size5 <= 0) {
            size5 = 4096;
        }
        this.buf = new Uint8Array(size5);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    async flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            await Deno.writeAll(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    async write(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = await this.writer.write(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copyBytes(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copyBytes(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
class BufWriterSync1 extends AbstractBufBase1 {
    static create(writer, size = 4096) {
        return writer instanceof BufWriterSync1 ? writer : new BufWriterSync1(writer, size);
    }
    constructor(writer4, size6 = 4096){
        super();
        this.writer = writer4;
        if (size6 <= 0) {
            size6 = 4096;
        }
        this.buf = new Uint8Array(size6);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            Deno.writeAllSync(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    writeSync(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copyBytes(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copyBytes(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
function createLPS1(pat) {
    const lps = new Uint8Array(pat.length);
    lps[0] = 0;
    let prefixEnd = 0;
    let i1 = 1;
    while(i1 < lps.length){
        if (pat[i1] == pat[prefixEnd]) {
            prefixEnd++;
            lps[i1] = prefixEnd;
            i1++;
        } else if (prefixEnd === 0) {
            lps[i1] = 0;
            i1++;
        } else {
            prefixEnd = pat[prefixEnd - 1];
        }
    }
    return lps;
}
async function* readDelim1(reader, delim) {
    const delimLen = delim.length;
    const delimLPS = createLPS1(delim);
    let inputBuffer = new Deno.Buffer();
    const inspectArr = new Uint8Array(Math.max(1024, delimLen + 1));
    let inspectIndex = 0;
    let matchIndex = 0;
    while(true){
        const result = await reader.read(inspectArr);
        if (result === null) {
            yield inputBuffer.bytes();
            return;
        }
        if (result < 0) {
            return;
        }
        const sliceRead = inspectArr.subarray(0, result);
        await Deno.writeAll(inputBuffer, sliceRead);
        let sliceToProcess = inputBuffer.bytes();
        while(inspectIndex < sliceToProcess.length){
            if (sliceToProcess[inspectIndex] === delim[matchIndex]) {
                inspectIndex++;
                matchIndex++;
                if (matchIndex === delimLen) {
                    const matchEnd = inspectIndex - delimLen;
                    const readyBytes = sliceToProcess.subarray(0, matchEnd);
                    const pendingBytes = sliceToProcess.slice(inspectIndex);
                    yield readyBytes;
                    sliceToProcess = pendingBytes;
                    inspectIndex = 0;
                    matchIndex = 0;
                }
            } else {
                if (matchIndex === 0) {
                    inspectIndex++;
                } else {
                    matchIndex = delimLPS[matchIndex - 1];
                }
            }
        }
        inputBuffer = new Deno.Buffer(sliceToProcess);
    }
}
async function* readStringDelim1(reader, delim) {
    const encoder3 = new TextEncoder();
    const decoder3 = new TextDecoder();
    for await (const chunk of readDelim1(reader, encoder3.encode(delim))){
        yield decoder3.decode(chunk);
    }
}
let NATIVE_OS = "linux";
const navigator = globalThis.navigator;
if (globalThis.Deno != null) {
    NATIVE_OS = Deno.build.os;
} else if (navigator?.appVersion?.includes?.("Win") ?? false) {
    NATIVE_OS = "windows";
}
const isWindows = NATIVE_OS == "windows";
function assertPath(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator(code1) {
    return code1 === 47;
}
function isPathSeparator(code1) {
    return isPosixPathSeparator(code1) || code1 === 92;
}
function isWindowsDeviceRoot(code1) {
    return code1 >= 97 && code1 <= 122 || code1 >= 65 && code1 <= 90;
}
function normalizeString(path, allowAboveRoot, separator, isPathSeparator1) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code1;
    for(let i1 = 0, len = path.length; i1 <= len; ++i1){
        if (i1 < len) code1 = path.charCodeAt(i1);
        else if (isPathSeparator1(code1)) break;
        else code1 = 47;
        if (isPathSeparator1(code1)) {
            if (lastSlash === i1 - 1 || dots === 1) {
            } else if (lastSlash !== i1 - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i1;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i1;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i1);
                else res = path.slice(lastSlash + 1, i1);
                lastSegmentLength = i1 - lastSlash - 1;
            }
            lastSlash = i1;
            dots = 0;
        } else if (code1 === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function _format1(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
const mod = function() {
    const sep = "/";
    const delimiter = ":";
    function resolve(...pathSegments) {
        let resolvedPath = "";
        let resolvedAbsolute = false;
        for(let i1 = pathSegments.length - 1; i1 >= -1 && !resolvedAbsolute; i1--){
            let path;
            if (i1 >= 0) path = pathSegments[i1];
            else {
                if (globalThis.Deno == null) {
                    throw new TypeError("Resolved a relative path without a CWD.");
                }
                path = Deno.cwd();
            }
            assertPath(path);
            if (path.length === 0) {
                continue;
            }
            resolvedPath = `${path}/${resolvedPath}`;
            resolvedAbsolute = path.charCodeAt(0) === 47;
        }
        resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator);
        if (resolvedAbsolute) {
            if (resolvedPath.length > 0) return `/${resolvedPath}`;
            else return "/";
        } else if (resolvedPath.length > 0) return resolvedPath;
        else return ".";
    }
    function normalize(path) {
        assertPath(path);
        if (path.length === 0) return ".";
        const isAbsolute = path.charCodeAt(0) === 47;
        const trailingSeparator = path.charCodeAt(path.length - 1) === 47;
        path = normalizeString(path, !isAbsolute, "/", isPosixPathSeparator);
        if (path.length === 0 && !isAbsolute) path = ".";
        if (path.length > 0 && trailingSeparator) path += "/";
        if (isAbsolute) return `/${path}`;
        return path;
    }
    function isAbsolute(path) {
        assertPath(path);
        return path.length > 0 && path.charCodeAt(0) === 47;
    }
    function join(...paths) {
        if (paths.length === 0) return ".";
        let joined;
        for(let i1 = 0, len = paths.length; i1 < len; ++i1){
            const path = paths[i1];
            assertPath(path);
            if (path.length > 0) {
                if (!joined) joined = path;
                else joined += `/${path}`;
            }
        }
        if (!joined) return ".";
        return normalize(joined);
    }
    function relative(from, to) {
        assertPath(from);
        assertPath(to);
        if (from === to) return "";
        from = resolve(from);
        to = resolve(to);
        if (from === to) return "";
        let fromStart = 1;
        const fromEnd = from.length;
        for(; fromStart < fromEnd; ++fromStart){
            if (from.charCodeAt(fromStart) !== 47) break;
        }
        const fromLen = fromEnd - fromStart;
        let toStart = 1;
        const toEnd = to.length;
        for(; toStart < toEnd; ++toStart){
            if (to.charCodeAt(toStart) !== 47) break;
        }
        const toLen = toEnd - toStart;
        const length = fromLen < toLen ? fromLen : toLen;
        let lastCommonSep = -1;
        let i1 = 0;
        for(; i1 <= length; ++i1){
            if (i1 === length) {
                if (toLen > length) {
                    if (to.charCodeAt(toStart + i1) === 47) {
                        return to.slice(toStart + i1 + 1);
                    } else if (i1 === 0) {
                        return to.slice(toStart + i1);
                    }
                } else if (fromLen > length) {
                    if (from.charCodeAt(fromStart + i1) === 47) {
                        lastCommonSep = i1;
                    } else if (i1 === 0) {
                        lastCommonSep = 0;
                    }
                }
                break;
            }
            const fromCode = from.charCodeAt(fromStart + i1);
            const toCode = to.charCodeAt(toStart + i1);
            if (fromCode !== toCode) break;
            else if (fromCode === 47) lastCommonSep = i1;
        }
        let out = "";
        for(i1 = fromStart + lastCommonSep + 1; i1 <= fromEnd; ++i1){
            if (i1 === fromEnd || from.charCodeAt(i1) === 47) {
                if (out.length === 0) out += "..";
                else out += "/..";
            }
        }
        if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
        else {
            toStart += lastCommonSep;
            if (to.charCodeAt(toStart) === 47) ++toStart;
            return to.slice(toStart);
        }
    }
    function toNamespacedPath(path) {
        return path;
    }
    function dirname(path) {
        assertPath(path);
        if (path.length === 0) return ".";
        const hasRoot = path.charCodeAt(0) === 47;
        let end = -1;
        let matchedSlash = true;
        for(let i1 = path.length - 1; i1 >= 1; --i1){
            if (path.charCodeAt(i1) === 47) {
                if (!matchedSlash) {
                    end = i1;
                    break;
                }
            } else {
                matchedSlash = false;
            }
        }
        if (end === -1) return hasRoot ? "/" : ".";
        if (hasRoot && end === 1) return "//";
        return path.slice(0, end);
    }
    function basename(path, ext = "") {
        if (ext !== undefined && typeof ext !== "string") {
            throw new TypeError('"ext" argument must be a string');
        }
        assertPath(path);
        let start = 0;
        let end = -1;
        let matchedSlash = true;
        let i1;
        if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
            if (ext.length === path.length && ext === path) return "";
            let extIdx = ext.length - 1;
            let firstNonSlashEnd = -1;
            for(i1 = path.length - 1; i1 >= 0; --i1){
                const code1 = path.charCodeAt(i1);
                if (code1 === 47) {
                    if (!matchedSlash) {
                        start = i1 + 1;
                        break;
                    }
                } else {
                    if (firstNonSlashEnd === -1) {
                        matchedSlash = false;
                        firstNonSlashEnd = i1 + 1;
                    }
                    if (extIdx >= 0) {
                        if (code1 === ext.charCodeAt(extIdx)) {
                            if ((--extIdx) === -1) {
                                end = i1;
                            }
                        } else {
                            extIdx = -1;
                            end = firstNonSlashEnd;
                        }
                    }
                }
            }
            if (start === end) end = firstNonSlashEnd;
            else if (end === -1) end = path.length;
            return path.slice(start, end);
        } else {
            for(i1 = path.length - 1; i1 >= 0; --i1){
                if (path.charCodeAt(i1) === 47) {
                    if (!matchedSlash) {
                        start = i1 + 1;
                        break;
                    }
                } else if (end === -1) {
                    matchedSlash = false;
                    end = i1 + 1;
                }
            }
            if (end === -1) return "";
            return path.slice(start, end);
        }
    }
    function extname(path) {
        assertPath(path);
        let startDot = -1;
        let startPart = 0;
        let end = -1;
        let matchedSlash = true;
        let preDotState = 0;
        for(let i1 = path.length - 1; i1 >= 0; --i1){
            const code1 = path.charCodeAt(i1);
            if (code1 === 47) {
                if (!matchedSlash) {
                    startPart = i1 + 1;
                    break;
                }
                continue;
            }
            if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
            if (code1 === 46) {
                if (startDot === -1) startDot = i1;
                else if (preDotState !== 1) preDotState = 1;
            } else if (startDot !== -1) {
                preDotState = -1;
            }
        }
        if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
            return "";
        }
        return path.slice(startDot, end);
    }
    function format1(pathObject) {
        if (pathObject === null || typeof pathObject !== "object") {
            throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
        }
        return _format1("/", pathObject);
    }
    function parse1(path) {
        assertPath(path);
        const ret = {
            root: "",
            dir: "",
            base: "",
            ext: "",
            name: ""
        };
        if (path.length === 0) return ret;
        const isAbsolute1 = path.charCodeAt(0) === 47;
        let start;
        if (isAbsolute1) {
            ret.root = "/";
            start = 1;
        } else {
            start = 0;
        }
        let startDot = -1;
        let startPart = 0;
        let end = -1;
        let matchedSlash = true;
        let i1 = path.length - 1;
        let preDotState = 0;
        for(; i1 >= start; --i1){
            const code1 = path.charCodeAt(i1);
            if (code1 === 47) {
                if (!matchedSlash) {
                    startPart = i1 + 1;
                    break;
                }
                continue;
            }
            if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
            if (code1 === 46) {
                if (startDot === -1) startDot = i1;
                else if (preDotState !== 1) preDotState = 1;
            } else if (startDot !== -1) {
                preDotState = -1;
            }
        }
        if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
            if (end !== -1) {
                if (startPart === 0 && isAbsolute1) {
                    ret.base = ret.name = path.slice(1, end);
                } else {
                    ret.base = ret.name = path.slice(startPart, end);
                }
            }
        } else {
            if (startPart === 0 && isAbsolute1) {
                ret.name = path.slice(1, startDot);
                ret.base = path.slice(1, end);
            } else {
                ret.name = path.slice(startPart, startDot);
                ret.base = path.slice(startPart, end);
            }
            ret.ext = path.slice(startDot, end);
        }
        if (startPart > 0) ret.dir = path.slice(0, startPart - 1);
        else if (isAbsolute1) ret.dir = "/";
        return ret;
    }
    function fromFileUrl(url) {
        url = url instanceof URL ? url : new URL(url);
        if (url.protocol != "file:") {
            throw new TypeError("Must be a file URL.");
        }
        return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
    }
    function toFileUrl(path) {
        if (!isAbsolute(path)) {
            throw new TypeError("Must be an absolute path.");
        }
        const url = new URL("file:///");
        url.pathname = path.replace(/%/g, "%25").replace(/\\/g, "%5C");
        return url;
    }
    return {
        sep,
        delimiter,
        resolve,
        normalize,
        isAbsolute,
        join,
        relative,
        toNamespacedPath,
        dirname,
        basename,
        extname,
        format: format1,
        parse: parse1,
        fromFileUrl,
        toFileUrl
    };
}();
const SEP = isWindows ? "\\" : "/";
const SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/;
const regExpEscapeChars = [
    "!",
    "$",
    "(",
    ")",
    "*",
    "+",
    ".",
    "=",
    "?",
    "[",
    "\\",
    "^",
    "{",
    "|"
];
const rangeEscapeChars = [
    "-",
    "\\",
    "]"
];
function compareSpecs(a, b) {
    return b.q - a.q || (b.s ?? 0) - (a.s ?? 0) || (a.o ?? 0) - (b.o ?? 0) || a.i - b.i || 0;
}
function isQuality(spec) {
    return spec.q > 0;
}
const encoder3 = new TextEncoder();
function encode(input) {
    return encoder3.encode(input);
}
const decoder3 = new TextDecoder();
function decode(input) {
    return decoder3.decode(input);
}
function assert2(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
function deferred() {
    let methods;
    const promise = new Promise((resolve, reject)=>{
        methods = {
            resolve,
            reject
        };
    });
    return Object.assign(promise, methods);
}
function parse1(rawDotenv) {
    return rawDotenv.split("\n").reduce((acc, line)=>{
        if (!isVariableStart(line)) return acc;
        let [key1, ...vals] = line.split("=");
        let value2 = trim(vals.join("="));
        if (/^"/.test(value2)) {
            value2 = expandNewlines(value2);
        }
        acc[trim(key1)] = trim(cleanQuotes(value2));
        return acc;
    }, {
    });
}
function parseFile(filepath) {
    try {
        return parse1(new TextDecoder("utf-8").decode(Deno.readFileSync(filepath)));
    } catch (e) {
        if (e instanceof Deno.errors.NotFound) return {
        };
        throw e;
    }
}
function assertSafe(conf, confExample, allowEmptyValues) {
    const currentEnv = Deno.env.toObject();
    const confWithEnv = Object.assign({
    }, currentEnv, conf);
    const missing = difference(Object.keys(confExample), Object.keys(allowEmptyValues ? confWithEnv : compact(confWithEnv)));
    if (missing.length > 0) {
        const errorMessages = [
            `The following variables were defined in the example file but are not present in the environment:\n  ${missing.join(", ")}`,
            `Make sure to add them to your env file.`,
            !allowEmptyValues && `If you expect any of these variables to be empty, you can set the allowEmptyValues option to true.`, 
        ];
        throw new MissingEnvVarsError(errorMessages.filter(Boolean).join("\n\n"));
    }
}
class Input extends Text1 {
    constructor(opts2){
        super(opts2);
    }
    async run() {
        const result = {
        };
        try {
            const answer = await this.question();
            result[this.name] = answer;
            return result;
        } catch (err) {
            throw err;
        }
    }
}
class Number1 extends Text1 {
    constructor(opts3){
        super(opts3);
        this.min = opts3.min === void 1 ? -Infinity : opts3.min;
        this.max = opts3.max === void 1 ? Infinity : opts3.max;
        this.message = this.messageWithRange;
    }
    get messageWithRange() {
        if (this.min === -Infinity && this.max === Infinity) {
            return this.message;
        }
        if (this.min !== -Infinity && this.max === Infinity) {
            return this.message + ` (>= ${this.min})`;
        }
        if (this.min === -Infinity && this.max !== Infinity) {
            return this.message + ` (<= ${this.max})`;
        }
        return this.message + ` (${this.min}-${this.max})`;
    }
    isInputOk(input) {
        if (typeof input !== 'number') {
            return false;
        }
        return input >= this.min && input <= this.max;
    }
    async run() {
        const result = {
        };
        let ok = false;
        let answer;
        try {
            while(!ok){
                const rawAnswer = await this.question();
                answer = rawAnswer && parseInt(rawAnswer, 10);
                ok = this.isInputOk(answer);
            }
            result[this.name] = answer;
            return result;
        } catch (err) {
            throw err;
        }
    }
}
class Confirm extends Text1 {
    constructor(opts4){
        super(opts4);
        this.accept = opts4.accept || 'Y';
        this.deny = opts4.deny || 'n';
        this.message = this.message + ` [${this.accept}/${this.deny}]`;
    }
    async run() {
        const result = {
        };
        try {
            const answer = await this.question();
            if (answer?.length === 0) {
                result[this.name] = true;
                return result;
            }
            result[this.name] = answer?.toLowerCase() === this.accept.toLowerCase();
            return result;
        } catch (err) {
            throw err;
        }
    }
}
function createColor(diffType) {
    switch(diffType){
        case DiffType.added:
            return (s)=>green(bold(s))
            ;
        case DiffType.removed:
            return (s)=>red(bold(s))
            ;
        default:
            return white;
    }
}
function str(buf) {
    if (buf == null) {
        return "";
    } else {
        return decode(buf);
    }
}
class TextProtoReader {
    constructor(r1){
        this.r = r1;
    }
    async readLine() {
        const s = await this.readLineSlice();
        if (s === null) return null;
        return str(s);
    }
    async readMIMEHeader() {
        const m = new Headers();
        let line;
        let buf = await this.r.peek(1);
        if (buf === null) {
            return null;
        } else if (buf[0] == charCode(" ") || buf[0] == charCode("\t")) {
            line = await this.readLineSlice();
        }
        buf = await this.r.peek(1);
        if (buf === null) {
            throw new Deno.errors.UnexpectedEof();
        } else if (buf[0] == charCode(" ") || buf[0] == charCode("\t")) {
            throw new Deno.errors.InvalidData(`malformed MIME header initial line: ${str(line)}`);
        }
        while(true){
            const kv = await this.readLineSlice();
            if (kv === null) throw new Deno.errors.UnexpectedEof();
            if (kv.byteLength === 0) return m;
            let i1 = kv.indexOf(charCode(":"));
            if (i1 < 0) {
                throw new Deno.errors.InvalidData(`malformed MIME header line: ${str(kv)}`);
            }
            const key1 = str(kv.subarray(0, i1));
            if (key1 == "") {
                continue;
            }
            i1++;
            while(i1 < kv.byteLength && (kv[i1] == charCode(" ") || kv[i1] == charCode("\t"))){
                i1++;
            }
            const value2 = str(kv.subarray(i1)).replace(invalidHeaderCharRegex, encodeURI);
            try {
                m.append(key1, value2);
            } catch  {
            }
        }
    }
    async readLineSlice() {
        let line;
        while(true){
            const r1 = await this.r.readLine();
            if (r1 === null) return null;
            const { line: l , more  } = r1;
            if (!line && !more) {
                if (this.skipSpace(l) === 0) {
                    return new Uint8Array(0);
                }
                return l;
            }
            line = line ? concat(line, l) : l;
            if (!more) {
                break;
            }
        }
        return line;
    }
    skipSpace(l) {
        let n = 0;
        for(let i1 = 0; i1 < l.length; i1++){
            if (l[i1] === charCode(" ") || l[i1] === charCode("\t")) {
                continue;
            }
            n++;
        }
        return n;
    }
}
async function writeFrame(frame, writer5) {
    const payloadLength = frame.payload.byteLength;
    let header;
    const hasMask = frame.mask ? 128 : 0;
    if (frame.mask && frame.mask.byteLength !== 4) {
        throw new Error("invalid mask. mask must be 4 bytes: length=" + frame.mask.byteLength);
    }
    if (payloadLength < 126) {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | payloadLength
        ]);
    } else if (payloadLength < 65535) {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | 126,
            payloadLength >>> 8,
            payloadLength & 255, 
        ]);
    } else {
        header = new Uint8Array([
            128 | frame.opcode,
            hasMask | 127,
            ...sliceLongToBytes(payloadLength), 
        ]);
    }
    if (frame.mask) {
        header = concat(header, frame.mask);
    }
    unmask(frame.payload, frame.mask);
    header = concat(header, frame.payload);
    const w = BufWriter1.create(writer5);
    await w.write(header);
    await w.flush();
}
async function readFrame(buf) {
    let b = await buf.readByte();
    assert2(b !== null);
    let isLastFrame = false;
    switch(b >>> 4){
        case 8:
            isLastFrame = true;
            break;
        case 0:
            isLastFrame = false;
            break;
        default:
            throw new Error("invalid signature");
    }
    const opcode = b & 15;
    b = await buf.readByte();
    assert2(b !== null);
    const hasMask = b >>> 7;
    let payloadLength = b & 127;
    if (payloadLength === 126) {
        const l = await readShort(buf);
        assert2(l !== null);
        payloadLength = l;
    } else if (payloadLength === 127) {
        const l = await readLong(buf);
        assert2(l !== null);
        payloadLength = Number(l);
    }
    let mask;
    if (hasMask) {
        mask = new Uint8Array(4);
        assert2(await buf.readFull(mask) !== null);
    }
    const payload = new Uint8Array(payloadLength);
    assert2(await buf.readFull(payload) !== null);
    return {
        isLastFrame,
        opcode,
        mask,
        payload
    };
}
function parse2(str1, options2 = {
}) {
    const tokens = lexer(str1);
    const { prefixes ="./"  } = options2;
    const defaultPattern = `[^${escapeString(options2.delimiter || "/#?")}]+?`;
    const result = [];
    let key1 = 0;
    let i1 = 0;
    let path = "";
    const tryConsume = (type2)=>{
        if (i1 < tokens.length && tokens[i1].type === type2) return tokens[i1++].value;
    };
    const mustConsume = (type2)=>{
        const value2 = tryConsume(type2);
        if (value2 !== undefined) return value2;
        const { type: nextType , index  } = tokens[i1];
        throw new TypeError(`Unexpected ${nextType} at ${index}, expected ${type2}`);
    };
    const consumeText = ()=>{
        let result1 = "";
        let value2;
        while(value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")){
            result1 += value2;
        }
        return result1;
    };
    while(i1 < tokens.length){
        const char = tryConsume("CHAR");
        const name2 = tryConsume("NAME");
        const pattern = tryConsume("PATTERN");
        if (name2 || pattern) {
            let prefix = char || "";
            if (prefixes.indexOf(prefix) === -1) {
                path += prefix;
                prefix = "";
            }
            if (path) {
                result.push(path);
                path = "";
            }
            result.push({
                name: name2 || key1++,
                prefix,
                suffix: "",
                pattern: pattern || defaultPattern,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        const value2 = char || tryConsume("ESCAPED_CHAR");
        if (value2) {
            path += value2;
            continue;
        }
        if (path) {
            result.push(path);
            path = "";
        }
        const open = tryConsume("OPEN");
        if (open) {
            const prefix = consumeText();
            const name3 = tryConsume("NAME") || "";
            const pattern1 = tryConsume("PATTERN") || "";
            const suffix1 = consumeText();
            mustConsume("CLOSE");
            result.push({
                name: name3 || (pattern1 ? key1++ : ""),
                pattern: name3 && !pattern1 ? defaultPattern : pattern1,
                prefix,
                suffix: suffix1,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        mustConsume("END");
    }
    return result;
}
function tokensToFunction(tokens, options2 = {
}) {
    const reFlags = flags(options2);
    const { encode: encode1 = (x)=>x
     , validate =true  } = options2;
    const matches = tokens.map((token)=>{
        if (typeof token === "object") {
            return new RegExp(`^(?:${token.pattern})$`, reFlags);
        }
    });
    return (data2)=>{
        let path = "";
        for(let i1 = 0; i1 < tokens.length; i1++){
            const token = tokens[i1];
            if (typeof token === "string") {
                path += token;
                continue;
            }
            const value2 = data2 ? data2[token.name] : undefined;
            const optional = token.modifier === "?" || token.modifier === "*";
            const repeat = token.modifier === "*" || token.modifier === "+";
            if (Array.isArray(value2)) {
                if (!repeat) {
                    throw new TypeError(`Expected "${token.name}" to not repeat, but got an array`);
                }
                if (value2.length === 0) {
                    if (optional) continue;
                    throw new TypeError(`Expected "${token.name}" to not be empty`);
                }
                for(let j = 0; j < value2.length; j++){
                    const segment = encode1(value2[j], token);
                    if (validate && !matches[i1].test(segment)) {
                        throw new TypeError(`Expected all "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                    }
                    path += token.prefix + segment + token.suffix;
                }
                continue;
            }
            if (typeof value2 === "string" || typeof value2 === "number") {
                const segment = encode1(String(value2), token);
                if (validate && !matches[i1].test(segment)) {
                    throw new TypeError(`Expected "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                }
                path += token.prefix + segment + token.suffix;
                continue;
            }
            if (optional) continue;
            const typeOfMessage = repeat ? "an array" : "a string";
            throw new TypeError(`Expected "${token.name}" to be ${typeOfMessage}`);
        }
        return path;
    };
}
function stringToRegexp(path, keys2, options2) {
    return tokensToRegexp(parse2(path, options2), keys2, options2);
}
class HttpError extends Error {
    expose = false;
    status = Status.InternalServerError;
}
function createHttpErrorConstructor(status) {
    const name2 = `${Status[status]}Error`;
    const Ctor = class extends HttpError {
        constructor(message){
            super();
            this.message = message || STATUS_TEXT.get(status);
            this.status = status;
            this.expose = status >= 400 && status < 500 ? true : false;
            Object.defineProperty(this, "name", {
                configurable: true,
                enumerable: false,
                value: name2,
                writable: true
            });
        }
    };
    return Ctor;
}
for (const [key1, value2] of Object.entries(errorStatusMap)){
    httpErrors[key1] = createHttpErrorConstructor(value2);
}
function createHttpError(status = 500, message) {
    return new httpErrors[Status[status]](message);
}
function preferredCharsets(accept = "*", provided) {
    const accepts = parseAcceptCharset(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.charset
        );
    }
    const priorities = provided.map((type2, index)=>getCharsetPriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
function preferredEncodings(accept, provided) {
    const accepts = parseAcceptEncoding(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.encoding
        );
    }
    const priorities = provided.map((type2, index)=>getEncodingPriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
function preferredLanguages(accept = "*", provided) {
    const accepts = parseAcceptLanguage(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.full
        );
    }
    const priorities = provided.map((type2, index)=>getLanguagePriority(type2, accepts, index)
    );
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
function preferredMediaTypes(accept, provided) {
    const accepts = parseAccept(accept === undefined ? "*/*" : accept || "");
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
    }
    const priorities = provided.map((type2, index)=>{
        return getMediaTypePriority(type2, accepts, index);
    });
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]
    );
}
function isRedirectStatus(value3) {
    return [
        Status.MultipleChoices,
        Status.MovedPermanently,
        Status.Found,
        Status.SeeOther,
        Status.UseProxy,
        Status.TemporaryRedirect,
        Status.PermanentRedirect, 
    ].includes(value3);
}
function gray(str1) {
    return brightBlack(str1);
}
function fixupEncoding(value3) {
    if (needsEncodingFixup && /[\x80-\xff]/.test(value3)) {
        value3 = textDecode("utf-8", value3);
        if (needsEncodingFixup) {
            value3 = textDecode("iso-8859-1", value3);
        }
    }
    return value3;
}
const FILENAME_STAR_REGEX = toParamRegExp("filename\\*", "i");
const FILENAME_START_ITER_REGEX = toParamRegExp("filename\\*((?!0\\d)\\d+)(\\*?)", "ig");
const FILENAME_REGEX = toParamRegExp("filename", "i");
function rfc2047decode(value3) {
    if (!value3.startsWith("=?") || /[\x00-\x19\x80-\xff]/.test(value3)) {
        return value3;
    }
    return value3.replace(/=\?([\w-]*)\?([QqBb])\?((?:[^?]|\?(?!=))*)\?=/g, (_, charset1, encoding, text)=>{
        if (encoding === "q" || encoding === "Q") {
            text = text.replace(/_/g, " ");
            text = text.replace(/=([0-9a-fA-F]{2})/g, (_1, hex)=>String.fromCharCode(parseInt(hex, 16))
            );
            return textDecode(charset1, text);
        }
        try {
            text = atob(text);
        } catch  {
        }
        return textDecode(charset1, text);
    });
}
function rfc5987decode(value3) {
    const encodingEnd = value3.indexOf(`'`);
    if (encodingEnd === -1) {
        return value3;
    }
    const encoding = value3.slice(0, encodingEnd);
    const langValue = value3.slice(encodingEnd + 1);
    return textDecode(encoding, langValue.replace(/^[^']*'/, ""));
}
class MuxAsyncIterator {
    iteratorCount = 0;
    yields = [];
    throws = [];
    signal = deferred();
    add(iterator) {
        ++this.iteratorCount;
        this.callIteratorNext(iterator);
    }
    async callIteratorNext(iterator) {
        try {
            const { value: value3 , done  } = await iterator.next();
            if (done) {
                --this.iteratorCount;
            } else {
                this.yields.push({
                    iterator,
                    value: value3
                });
            }
        } catch (e) {
            this.throws.push(e);
        }
        this.signal.resolve();
    }
    async *iterate() {
        while(this.iteratorCount > 0){
            await this.signal;
            for(let i1 = 0; i1 < this.yields.length; i1++){
                const { iterator , value: value3  } = this.yields[i1];
                yield value3;
                this.callIteratorNext(iterator);
            }
            if (this.throws.length) {
                for (const e of this.throws){
                    throw e;
                }
                this.throws.length = 0;
            }
            this.yields.length = 0;
            this.signal = deferred();
        }
    }
    [Symbol.asyncIterator]() {
        return this.iterate();
    }
}
async function writeChunkedBody(w, r1) {
    const writer5 = BufWriter1.create(w);
    for await (const chunk of Deno.iter(r1)){
        if (chunk.byteLength <= 0) continue;
        const start = encoder3.encode(`${chunk.byteLength.toString(16)}\r\n`);
        const end = encoder3.encode("\r\n");
        await writer5.write(start);
        await writer5.write(chunk);
        await writer5.write(end);
    }
    const endChunk = encoder3.encode("0\r\n\r\n");
    await writer5.write(endChunk);
}
async function writeTrailers(w, headers1, trailers) {
    const trailer = headers1.get("trailer");
    if (trailer === null) {
        throw new TypeError("Missing trailer header.");
    }
    const transferEncoding = headers1.get("transfer-encoding");
    if (transferEncoding === null || !transferEncoding.match(/^chunked/)) {
        throw new TypeError(`Trailers are only allowed for "transfer-encoding: chunked", got "transfer-encoding: ${transferEncoding}".`);
    }
    const writer5 = BufWriter1.create(w);
    const trailerNames = trailer.split(",").map((s)=>s.trim().toLowerCase()
    );
    const prohibitedTrailers = trailerNames.filter((k)=>isProhibidedForTrailer(k)
    );
    if (prohibitedTrailers.length > 0) {
        throw new TypeError(`Prohibited trailer names: ${Deno.inspect(prohibitedTrailers)}.`);
    }
    const undeclared = [
        ...trailers.keys()
    ].filter((k)=>!trailerNames.includes(k)
    );
    if (undeclared.length > 0) {
        throw new TypeError(`Undeclared trailers: ${Deno.inspect(undeclared)}.`);
    }
    for (const [key2, value3] of trailers){
        await writer5.write(encoder3.encode(`${key2}: ${value3}\r\n`));
    }
    await writer5.write(encoder3.encode("\r\n"));
    await writer5.flush();
}
async function writeResponse(w, r1) {
    const protoMajor = 1;
    const protoMinor = 1;
    const statusCode = r1.status || 200;
    const statusText = STATUS_TEXT.get(statusCode);
    const writer5 = BufWriter1.create(w);
    if (!statusText) {
        throw new Deno.errors.InvalidData("Bad status code");
    }
    if (!r1.body) {
        r1.body = new Uint8Array();
    }
    if (typeof r1.body === "string") {
        r1.body = encoder3.encode(r1.body);
    }
    let out = `HTTP/${1}.${1} ${statusCode} ${statusText}\r\n`;
    const headers1 = r1.headers ?? new Headers();
    if (r1.body && !headers1.get("content-length")) {
        if (r1.body instanceof Uint8Array) {
            out += `content-length: ${r1.body.byteLength}\r\n`;
        } else if (!headers1.get("transfer-encoding")) {
            out += "transfer-encoding: chunked\r\n";
        }
    }
    for (const [key2, value3] of headers1){
        out += `${key2}: ${value3}\r\n`;
    }
    out += `\r\n`;
    const header = encoder3.encode(out);
    const n = await writer5.write(header);
    assert2(n === header.byteLength);
    if (r1.body instanceof Uint8Array) {
        const n1 = await writer5.write(r1.body);
        assert2(n1 === r1.body.byteLength);
    } else if (headers1.has("content-length")) {
        const contentLength = headers1.get("content-length");
        assert2(contentLength != null);
        const bodyLength = parseInt(contentLength);
        const n1 = await Deno.copy(r1.body, writer5);
        assert2(n1 === bodyLength);
    } else {
        await writeChunkedBody(writer5, r1.body);
    }
    if (r1.trailers) {
        const t = await r1.trailers();
        await writeTrailers(writer5, headers1, t);
    }
    await writer5.flush();
}
async function readTrailers(headers1, r1) {
    const trailers = parseTrailer(headers1.get("trailer"));
    if (trailers == null) return;
    const trailerNames = [
        ...trailers.keys()
    ];
    const tp = new TextProtoReader(r1);
    const result = await tp.readMIMEHeader();
    if (result == null) {
        throw new Deno.errors.InvalidData("Missing trailer header.");
    }
    const undeclared = [
        ...result.keys()
    ].filter((k)=>!trailerNames.includes(k)
    );
    if (undeclared.length > 0) {
        throw new Deno.errors.InvalidData(`Undeclared trailers: ${Deno.inspect(undeclared)}.`);
    }
    for (const [k, v] of result){
        headers1.append(k, v);
    }
    const missingTrailers = trailerNames.filter((k1)=>!result.has(k1)
    );
    if (missingTrailers.length > 0) {
        throw new Deno.errors.InvalidData(`Missing trailers: ${Deno.inspect(missingTrailers)}.`);
    }
    headers1.delete("trailer");
}
function chunkedBodyReader(h, r1) {
    const tp = new TextProtoReader(r1);
    let finished = false;
    const chunks = [];
    async function read(buf) {
        if (finished) return null;
        const [chunk] = chunks;
        if (chunk) {
            const chunkRemaining = chunk.data.byteLength - chunk.offset;
            const readLength = Math.min(chunkRemaining, buf.byteLength);
            for(let i1 = 0; i1 < readLength; i1++){
                buf[i1] = chunk.data[chunk.offset + i1];
            }
            chunk.offset += readLength;
            if (chunk.offset === chunk.data.byteLength) {
                chunks.shift();
                if (await tp.readLine() === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
            }
            return readLength;
        }
        const line = await tp.readLine();
        if (line === null) throw new Deno.errors.UnexpectedEof();
        const [chunkSizeString] = line.split(";");
        const chunkSize = parseInt(chunkSizeString, 16);
        if (Number.isNaN(chunkSize) || chunkSize < 0) {
            throw new Error("Invalid chunk size");
        }
        if (chunkSize > 0) {
            if (chunkSize > buf.byteLength) {
                let eof = await r1.readFull(buf);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                const restChunk = new Uint8Array(chunkSize - buf.byteLength);
                eof = await r1.readFull(restChunk);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                } else {
                    chunks.push({
                        offset: 0,
                        data: restChunk
                    });
                }
                return buf.byteLength;
            } else {
                const bufToFill = buf.subarray(0, chunkSize);
                const eof = await r1.readFull(bufToFill);
                if (eof === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                if (await tp.readLine() === null) {
                    throw new Deno.errors.UnexpectedEof();
                }
                return chunkSize;
            }
        } else {
            assert2(chunkSize === 0);
            if (await r1.readLine() === null) {
                throw new Deno.errors.UnexpectedEof();
            }
            await readTrailers(h, r1);
            finished = true;
            return null;
        }
    }
    return {
        read
    };
}
class ServerRequest {
    done = deferred();
    _contentLength = undefined;
    get contentLength() {
        if (this._contentLength === undefined) {
            const cl = this.headers.get("content-length");
            if (cl) {
                this._contentLength = parseInt(cl);
                if (Number.isNaN(this._contentLength)) {
                    this._contentLength = null;
                }
            } else {
                this._contentLength = null;
            }
        }
        return this._contentLength;
    }
    _body = null;
    get body() {
        if (!this._body) {
            if (this.contentLength != null) {
                this._body = bodyReader(this.contentLength, this.r);
            } else {
                const transferEncoding = this.headers.get("transfer-encoding");
                if (transferEncoding != null) {
                    const parts = transferEncoding.split(",").map((e)=>e.trim().toLowerCase()
                    );
                    assert2(parts.includes("chunked"), 'transfer-encoding must include "chunked" if content-length is not set');
                    this._body = chunkedBodyReader(this.headers, this.r);
                } else {
                    this._body = emptyReader();
                }
            }
        }
        return this._body;
    }
    async respond(r) {
        let err;
        try {
            await writeResponse(this.w, r);
        } catch (e) {
            try {
                this.conn.close();
            } catch  {
            }
            err = e;
        }
        this.done.resolve(err);
        if (err) {
            throw err;
        }
    }
    finalized = false;
    async finalize() {
        if (this.finalized) return;
        const body = this.body;
        const buf = new Uint8Array(1024);
        while(await body.read(buf) !== null){
        }
        this.finalized = true;
    }
}
async function readRequest(conn, bufr) {
    const tp = new TextProtoReader(bufr);
    const firstLine = await tp.readLine();
    if (firstLine === null) return null;
    const headers1 = await tp.readMIMEHeader();
    if (headers1 === null) throw new Deno.errors.UnexpectedEof();
    const req = new ServerRequest();
    req.conn = conn;
    req.r = bufr;
    [req.method, req.url, req.proto] = firstLine.split(" ", 3);
    [req.protoMinor, req.protoMajor] = parseHTTPVersion(req.proto);
    req.headers = headers1;
    fixLength(req);
    return req;
}
class BufReader2 {
    r = 0;
    w = 0;
    eof = false;
    static create(r, size = 4096) {
        return r instanceof BufReader2 ? r : new BufReader2(r, size);
    }
    constructor(rd3, size7 = 4096){
        if (size7 < 16) {
            size7 = 16;
        }
        this._reset(new Uint8Array(size7), rd3);
    }
    size() {
        return this.buf.byteLength;
    }
    buffered() {
        return this.w - this.r;
    }
    async _fill() {
        if (this.r > 0) {
            this.buf.copyWithin(0, this.r, this.w);
            this.w -= this.r;
            this.r = 0;
        }
        if (this.w >= this.buf.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i1 = 100; i1 > 0; i1--){
            const rr = await this.rd.read(this.buf.subarray(this.w));
            if (rr === null) {
                this.eof = true;
                return;
            }
            assert2(rr >= 0, "negative read");
            this.w += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    reset(r) {
        this._reset(this.buf, r);
    }
    _reset(buf, rd) {
        this.buf = buf;
        this.rd = rd;
        this.eof = false;
    }
    async read(p) {
        let rr = p.byteLength;
        if (p.byteLength === 0) return rr;
        if (this.r === this.w) {
            if (p.byteLength >= this.buf.byteLength) {
                const rr1 = await this.rd.read(p);
                const nread = rr1 ?? 0;
                assert2(nread >= 0, "negative read");
                return rr1;
            }
            this.r = 0;
            this.w = 0;
            rr = await this.rd.read(this.buf);
            if (rr === 0 || rr === null) return rr;
            assert2(rr >= 0, "negative read");
            this.w += rr;
        }
        const copied = copyBytes(this.buf.subarray(this.r, this.w), p, 0);
        this.r += copied;
        return copied;
    }
    async readFull(p) {
        let bytesRead = 0;
        while(bytesRead < p.length){
            try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                    if (bytesRead === 0) {
                        return null;
                    } else {
                        throw new PartialReadError();
                    }
                }
                bytesRead += rr;
            } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
            }
        }
        return p;
    }
    async readByte() {
        while(this.r === this.w){
            if (this.eof) return null;
            await this._fill();
        }
        const c = this.buf[this.r];
        this.r++;
        return c;
    }
    async readString(delim) {
        if (delim.length !== 1) {
            throw new Error("Delimiter should be a single character");
        }
        const buffer = await this.readSlice(delim.charCodeAt(0));
        if (buffer === null) return null;
        return new TextDecoder().decode(buffer);
    }
    async readLine() {
        let line;
        try {
            line = await this.readSlice(LF3);
        } catch (err) {
            let { partial: partial3  } = err;
            assert2(partial3 instanceof Uint8Array, "bufio: caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError2)) {
                throw err;
            }
            if (!this.eof && partial3.byteLength > 0 && partial3[partial3.byteLength - 1] === CR3) {
                assert2(this.r > 0, "bufio: tried to rewind past start of buffer");
                this.r--;
                partial3 = partial3.subarray(0, partial3.byteLength - 1);
            }
            return {
                line: partial3,
                more: !this.eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                line,
                more: false
            };
        }
        if (line[line.byteLength - 1] == LF3) {
            let drop = 1;
            if (line.byteLength > 1 && line[line.byteLength - 2] === CR3) {
                drop = 2;
            }
            line = line.subarray(0, line.byteLength - drop);
        }
        return {
            line,
            more: false
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i1 = this.buf.subarray(this.r + s, this.w).indexOf(delim);
            if (i1 >= 0) {
                i1 += s;
                slice = this.buf.subarray(this.r, this.r + i1 + 1);
                this.r += i1 + 1;
                break;
            }
            if (this.eof) {
                if (this.r === this.w) {
                    return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
            }
            if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                const oldbuf = this.buf;
                const newbuf = this.buf.slice(0);
                this.buf = newbuf;
                throw new BufferFullError2(oldbuf);
            }
            s = this.w - this.r;
            try {
                await this._fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
    async peek(n) {
        if (n < 0) {
            throw Error("negative count");
        }
        let avail = this.w - this.r;
        while(avail < n && avail < this.buf.byteLength && !this.eof){
            try {
                await this._fill();
            } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
            }
            avail = this.w - this.r;
        }
        if (avail === 0 && this.eof) {
            return null;
        } else if (avail < n && this.eof) {
            return this.buf.subarray(this.r, this.r + avail);
        } else if (avail < n) {
            throw new BufferFullError2(this.buf.subarray(this.r, this.w));
        }
        return this.buf.subarray(this.r, this.r + n);
    }
}
const mod1 = function() {
    const sep = "\\";
    const delimiter = ";";
    function resolve(...pathSegments) {
        let resolvedDevice = "";
        let resolvedTail = "";
        let resolvedAbsolute = false;
        for(let i1 = pathSegments.length - 1; i1 >= -1; i1--){
            let path;
            if (i1 >= 0) {
                path = pathSegments[i1];
            } else if (!resolvedDevice) {
                if (globalThis.Deno == null) {
                    throw new TypeError("Resolved a drive-letter-less path without a CWD.");
                }
                path = Deno.cwd();
            } else {
                if (globalThis.Deno == null) {
                    throw new TypeError("Resolved a relative path without a CWD.");
                }
                path = Deno.env.get(`=${resolvedDevice}`) || Deno.cwd();
                if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                    path = `${resolvedDevice}\\`;
                }
            }
            assertPath(path);
            const len = path.length;
            if (len === 0) continue;
            let rootEnd = 0;
            let device = "";
            let isAbsolute = false;
            const code1 = path.charCodeAt(0);
            if (len > 1) {
                if (isPathSeparator(code1)) {
                    isAbsolute = true;
                    if (isPathSeparator(path.charCodeAt(1))) {
                        let j = 2;
                        let last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            const firstPart = path.slice(last, j);
                            last = j;
                            for(; j < len; ++j){
                                if (!isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j < len && j !== last) {
                                last = j;
                                for(; j < len; ++j){
                                    if (isPathSeparator(path.charCodeAt(j))) break;
                                }
                                if (j === len) {
                                    device = `\\\\${firstPart}\\${path.slice(last)}`;
                                    rootEnd = j;
                                } else if (j !== last) {
                                    device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                    rootEnd = j;
                                }
                            }
                        }
                    } else {
                        rootEnd = 1;
                    }
                } else if (isWindowsDeviceRoot(code1)) {
                    if (path.charCodeAt(1) === 58) {
                        device = path.slice(0, 2);
                        rootEnd = 2;
                        if (len > 2) {
                            if (isPathSeparator(path.charCodeAt(2))) {
                                isAbsolute = true;
                                rootEnd = 3;
                            }
                        }
                    }
                }
            } else if (isPathSeparator(code1)) {
                rootEnd = 1;
                isAbsolute = true;
            }
            if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
                continue;
            }
            if (resolvedDevice.length === 0 && device.length > 0) {
                resolvedDevice = device;
            }
            if (!resolvedAbsolute) {
                resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
                resolvedAbsolute = isAbsolute;
            }
            if (resolvedAbsolute && resolvedDevice.length > 0) break;
        }
        resolvedTail = normalizeString(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator);
        return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
    }
    function normalize(path) {
        assertPath(path);
        const len = path.length;
        if (len === 0) return ".";
        let rootEnd = 0;
        let device;
        let isAbsolute = false;
        const code1 = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code1)) {
                isAbsolute = true;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                return `\\\\${firstPart}\\${path.slice(last)}\\`;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot(code1)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator(code1)) {
            return "\\";
        }
        let tail;
        if (rootEnd < len) {
            tail = normalizeString(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator);
        } else {
            tail = "";
        }
        if (tail.length === 0 && !isAbsolute) tail = ".";
        if (tail.length > 0 && isPathSeparator(path.charCodeAt(len - 1))) {
            tail += "\\";
        }
        if (device === undefined) {
            if (isAbsolute) {
                if (tail.length > 0) return `\\${tail}`;
                else return "\\";
            } else if (tail.length > 0) {
                return tail;
            } else {
                return "";
            }
        } else if (isAbsolute) {
            if (tail.length > 0) return `${device}\\${tail}`;
            else return `${device}\\`;
        } else if (tail.length > 0) {
            return device + tail;
        } else {
            return device;
        }
    }
    function isAbsolute(path) {
        assertPath(path);
        const len = path.length;
        if (len === 0) return false;
        const code1 = path.charCodeAt(0);
        if (isPathSeparator(code1)) {
            return true;
        } else if (isWindowsDeviceRoot(code1)) {
            if (len > 2 && path.charCodeAt(1) === 58) {
                if (isPathSeparator(path.charCodeAt(2))) return true;
            }
        }
        return false;
    }
    function join(...paths) {
        const pathsCount = paths.length;
        if (pathsCount === 0) return ".";
        let joined;
        let firstPart = null;
        for(let i1 = 0; i1 < pathsCount; ++i1){
            const path = paths[i1];
            assertPath(path);
            if (path.length > 0) {
                if (joined === undefined) joined = firstPart = path;
                else joined += `\\${path}`;
            }
        }
        if (joined === undefined) return ".";
        let needsReplace = true;
        let slashCount = 0;
        assert2(firstPart != null);
        if (isPathSeparator(firstPart.charCodeAt(0))) {
            ++slashCount;
            const firstLen = firstPart.length;
            if (firstLen > 1) {
                if (isPathSeparator(firstPart.charCodeAt(1))) {
                    ++slashCount;
                    if (firstLen > 2) {
                        if (isPathSeparator(firstPart.charCodeAt(2))) ++slashCount;
                        else {
                            needsReplace = false;
                        }
                    }
                }
            }
        }
        if (needsReplace) {
            for(; slashCount < joined.length; ++slashCount){
                if (!isPathSeparator(joined.charCodeAt(slashCount))) break;
            }
            if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
        }
        return normalize(joined);
    }
    function relative(from, to) {
        assertPath(from);
        assertPath(to);
        if (from === to) return "";
        const fromOrig = resolve(from);
        const toOrig = resolve(to);
        if (fromOrig === toOrig) return "";
        from = fromOrig.toLowerCase();
        to = toOrig.toLowerCase();
        if (from === to) return "";
        let fromStart = 0;
        let fromEnd = from.length;
        for(; fromStart < fromEnd; ++fromStart){
            if (from.charCodeAt(fromStart) !== 92) break;
        }
        for(; fromEnd - 1 > fromStart; --fromEnd){
            if (from.charCodeAt(fromEnd - 1) !== 92) break;
        }
        const fromLen = fromEnd - fromStart;
        let toStart = 0;
        let toEnd = to.length;
        for(; toStart < toEnd; ++toStart){
            if (to.charCodeAt(toStart) !== 92) break;
        }
        for(; toEnd - 1 > toStart; --toEnd){
            if (to.charCodeAt(toEnd - 1) !== 92) break;
        }
        const toLen = toEnd - toStart;
        const length = fromLen < toLen ? fromLen : toLen;
        let lastCommonSep = -1;
        let i1 = 0;
        for(; i1 <= length; ++i1){
            if (i1 === length) {
                if (toLen > length) {
                    if (to.charCodeAt(toStart + i1) === 92) {
                        return toOrig.slice(toStart + i1 + 1);
                    } else if (i1 === 2) {
                        return toOrig.slice(toStart + i1);
                    }
                }
                if (fromLen > length) {
                    if (from.charCodeAt(fromStart + i1) === 92) {
                        lastCommonSep = i1;
                    } else if (i1 === 2) {
                        lastCommonSep = 3;
                    }
                }
                break;
            }
            const fromCode = from.charCodeAt(fromStart + i1);
            const toCode = to.charCodeAt(toStart + i1);
            if (fromCode !== toCode) break;
            else if (fromCode === 92) lastCommonSep = i1;
        }
        if (i1 !== length && lastCommonSep === -1) {
            return toOrig;
        }
        let out = "";
        if (lastCommonSep === -1) lastCommonSep = 0;
        for(i1 = fromStart + lastCommonSep + 1; i1 <= fromEnd; ++i1){
            if (i1 === fromEnd || from.charCodeAt(i1) === 92) {
                if (out.length === 0) out += "..";
                else out += "\\..";
            }
        }
        if (out.length > 0) {
            return out + toOrig.slice(toStart + lastCommonSep, toEnd);
        } else {
            toStart += lastCommonSep;
            if (toOrig.charCodeAt(toStart) === 92) ++toStart;
            return toOrig.slice(toStart, toEnd);
        }
    }
    function toNamespacedPath(path) {
        if (typeof path !== "string") return path;
        if (path.length === 0) return "";
        const resolvedPath = resolve(path);
        if (resolvedPath.length >= 3) {
            if (resolvedPath.charCodeAt(0) === 92) {
                if (resolvedPath.charCodeAt(1) === 92) {
                    const code1 = resolvedPath.charCodeAt(2);
                    if (code1 !== 63 && code1 !== 46) {
                        return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                    }
                }
            } else if (isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
                if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                    return `\\\\?\\${resolvedPath}`;
                }
            }
        }
        return path;
    }
    function dirname(path) {
        assertPath(path);
        const len = path.length;
        if (len === 0) return ".";
        let rootEnd = -1;
        let end = -1;
        let matchedSlash = true;
        let offset = 0;
        const code1 = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code1)) {
                rootEnd = offset = 1;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                return path;
                            }
                            if (j !== last) {
                                rootEnd = offset = j + 1;
                            }
                        }
                    }
                }
            } else if (isWindowsDeviceRoot(code1)) {
                if (path.charCodeAt(1) === 58) {
                    rootEnd = offset = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) rootEnd = offset = 3;
                    }
                }
            }
        } else if (isPathSeparator(code1)) {
            return path;
        }
        for(let i1 = len - 1; i1 >= offset; --i1){
            if (isPathSeparator(path.charCodeAt(i1))) {
                if (!matchedSlash) {
                    end = i1;
                    break;
                }
            } else {
                matchedSlash = false;
            }
        }
        if (end === -1) {
            if (rootEnd === -1) return ".";
            else end = rootEnd;
        }
        return path.slice(0, end);
    }
    function basename(path, ext = "") {
        if (ext !== undefined && typeof ext !== "string") {
            throw new TypeError('"ext" argument must be a string');
        }
        assertPath(path);
        let start = 0;
        let end = -1;
        let matchedSlash = true;
        let i1;
        if (path.length >= 2) {
            const drive = path.charCodeAt(0);
            if (isWindowsDeviceRoot(drive)) {
                if (path.charCodeAt(1) === 58) start = 2;
            }
        }
        if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
            if (ext.length === path.length && ext === path) return "";
            let extIdx = ext.length - 1;
            let firstNonSlashEnd = -1;
            for(i1 = path.length - 1; i1 >= start; --i1){
                const code1 = path.charCodeAt(i1);
                if (isPathSeparator(code1)) {
                    if (!matchedSlash) {
                        start = i1 + 1;
                        break;
                    }
                } else {
                    if (firstNonSlashEnd === -1) {
                        matchedSlash = false;
                        firstNonSlashEnd = i1 + 1;
                    }
                    if (extIdx >= 0) {
                        if (code1 === ext.charCodeAt(extIdx)) {
                            if ((--extIdx) === -1) {
                                end = i1;
                            }
                        } else {
                            extIdx = -1;
                            end = firstNonSlashEnd;
                        }
                    }
                }
            }
            if (start === end) end = firstNonSlashEnd;
            else if (end === -1) end = path.length;
            return path.slice(start, end);
        } else {
            for(i1 = path.length - 1; i1 >= start; --i1){
                if (isPathSeparator(path.charCodeAt(i1))) {
                    if (!matchedSlash) {
                        start = i1 + 1;
                        break;
                    }
                } else if (end === -1) {
                    matchedSlash = false;
                    end = i1 + 1;
                }
            }
            if (end === -1) return "";
            return path.slice(start, end);
        }
    }
    function extname(path) {
        assertPath(path);
        let start = 0;
        let startDot = -1;
        let startPart = 0;
        let end = -1;
        let matchedSlash = true;
        let preDotState = 0;
        if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot(path.charCodeAt(0))) {
            start = startPart = 2;
        }
        for(let i1 = path.length - 1; i1 >= start; --i1){
            const code1 = path.charCodeAt(i1);
            if (isPathSeparator(code1)) {
                if (!matchedSlash) {
                    startPart = i1 + 1;
                    break;
                }
                continue;
            }
            if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
            if (code1 === 46) {
                if (startDot === -1) startDot = i1;
                else if (preDotState !== 1) preDotState = 1;
            } else if (startDot !== -1) {
                preDotState = -1;
            }
        }
        if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
            return "";
        }
        return path.slice(startDot, end);
    }
    function format1(pathObject) {
        if (pathObject === null || typeof pathObject !== "object") {
            throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
        }
        return _format1("\\", pathObject);
    }
    function parse3(path) {
        assertPath(path);
        const ret = {
            root: "",
            dir: "",
            base: "",
            ext: "",
            name: ""
        };
        const len = path.length;
        if (len === 0) return ret;
        let rootEnd = 0;
        let code1 = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code1)) {
                rootEnd = 1;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                rootEnd = j;
                            } else if (j !== last) {
                                rootEnd = j + 1;
                            }
                        }
                    }
                }
            } else if (isWindowsDeviceRoot(code1)) {
                if (path.charCodeAt(1) === 58) {
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) {
                            if (len === 3) {
                                ret.root = ret.dir = path;
                                return ret;
                            }
                            rootEnd = 3;
                        }
                    } else {
                        ret.root = ret.dir = path;
                        return ret;
                    }
                }
            }
        } else if (isPathSeparator(code1)) {
            ret.root = ret.dir = path;
            return ret;
        }
        if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
        let startDot = -1;
        let startPart = rootEnd;
        let end = -1;
        let matchedSlash = true;
        let i1 = path.length - 1;
        let preDotState = 0;
        for(; i1 >= rootEnd; --i1){
            code1 = path.charCodeAt(i1);
            if (isPathSeparator(code1)) {
                if (!matchedSlash) {
                    startPart = i1 + 1;
                    break;
                }
                continue;
            }
            if (end === -1) {
                matchedSlash = false;
                end = i1 + 1;
            }
            if (code1 === 46) {
                if (startDot === -1) startDot = i1;
                else if (preDotState !== 1) preDotState = 1;
            } else if (startDot !== -1) {
                preDotState = -1;
            }
        }
        if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
            if (end !== -1) {
                ret.base = ret.name = path.slice(startPart, end);
            }
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
            ret.ext = path.slice(startDot, end);
        }
        if (startPart > 0 && startPart !== rootEnd) {
            ret.dir = path.slice(0, startPart - 1);
        } else ret.dir = ret.root;
        return ret;
    }
    function fromFileUrl(url) {
        url = url instanceof URL ? url : new URL(url);
        if (url.protocol != "file:") {
            throw new TypeError("Must be a file URL.");
        }
        let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
        if (url.hostname != "") {
            path = `\\\\${url.hostname}${path}`;
        }
        return path;
    }
    function toFileUrl(path) {
        if (!isAbsolute(path)) {
            throw new TypeError("Must be an absolute path.");
        }
        const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\][^/\\]))?(.*)/);
        const url = new URL("file:///");
        url.pathname = pathname.replace(/%/g, "%25");
        if (hostname != null) {
            url.hostname = hostname;
            if (!url.hostname) {
                throw new TypeError("Invalid hostname.");
            }
        }
        return url;
    }
    return {
        sep,
        delimiter,
        resolve,
        normalize,
        isAbsolute,
        join,
        relative,
        toNamespacedPath,
        dirname,
        basename,
        extname,
        format: format1,
        parse: parse3,
        fromFileUrl,
        toFileUrl
    };
}();
const path2 = isWindows ? mod1 : mod;
const { basename , delimiter , dirname , extname , format: format1 , fromFileUrl , isAbsolute , join , normalize , parse: parse3 , relative , resolve , sep , toFileUrl , toNamespacedPath ,  } = path2;
function normalizeGlob(glob, { globstar =false  } = {
}) {
    if (glob.match(/\0/g)) {
        throw new Error(`Glob contains invalid characters: "${glob}"`);
    }
    if (!globstar) {
        return normalize(glob);
    }
    const s = SEP_PATTERN.source;
    const badParentPattern = new RegExp(`(?<=(${s}|^)\\*\\*${s})\\.\\.(?=${s}|$)`, "g");
    return normalize(glob.replace(badParentPattern, "\0")).replace(/\0/g, "..");
}
function config(options2 = {
}) {
    const o = Object.assign({
        path: `.env`,
        export: false,
        safe: false,
        example: `.env.example`,
        allowEmptyValues: false,
        defaults: `.env.defaults`
    }, options2);
    const conf = parseFile(o.path);
    if (o.safe) {
        const confExample = parseFile(o.example);
        assertSafe(conf, confExample, o.allowEmptyValues);
    }
    if (o.defaults) {
        const confDefaults = parseFile(o.defaults);
        for(let key2 in confDefaults){
            if (!(key2 in conf)) {
                conf[key2] = confDefaults[key2];
            }
        }
    }
    if (o.export) {
        for(let key2 in conf){
            if (Deno.env.get(key2) !== undefined) continue;
            Deno.env.set(key2, conf[key2]);
        }
    }
    return conf;
}
config({
    export: true
});
function buildMessage(diffResult) {
    const messages = [];
    messages.push("");
    messages.push("");
    messages.push(`    ${gray(bold("[Diff]"))} ${red(bold("Actual"))} / ${green(bold("Expected"))}`);
    messages.push("");
    messages.push("");
    diffResult.forEach((result)=>{
        const c = createColor(result.type);
        messages.push(c(`${createSign(result.type)}${result.value}`));
    });
    messages.push("");
    return messages;
}
function assertEquals(actual, expected, msg) {
    if (equal1(actual, expected)) {
        return;
    }
    let message = "";
    const actualString = _format(actual);
    const expectedString = _format(expected);
    try {
        const diffResult = diff(actualString.split("\n"), expectedString.split("\n"));
        const diffMsg = buildMessage(diffResult).join("\n");
        message = `Values are not equal:\n${diffMsg}`;
    } catch (e) {
        message = `\n${red(CAN_NOT_DISPLAY)} + \n\n`;
    }
    if (msg) {
        message = msg;
    }
    throw new AssertionError(message);
}
class WebSocketImpl {
    sendQueue = [];
    constructor({ conn: conn1 , bufReader , bufWriter , mask  }){
        this.conn = conn1;
        this.mask = mask;
        this.bufReader = bufReader || new BufReader2(conn1);
        this.bufWriter = bufWriter || new BufWriter1(conn1);
    }
    async *[Symbol.asyncIterator]() {
        let frames = [];
        let payloadsLength = 0;
        while(!this._isClosed){
            let frame;
            try {
                frame = await readFrame(this.bufReader);
            } catch (e) {
                this.ensureSocketClosed();
                break;
            }
            unmask(frame.payload, frame.mask);
            switch(frame.opcode){
                case OpCode.TextFrame:
                case OpCode.BinaryFrame:
                case OpCode.Continue:
                    frames.push(frame);
                    payloadsLength += frame.payload.length;
                    if (frame.isLastFrame) {
                        const concat1 = new Uint8Array(payloadsLength);
                        let offs = 0;
                        for (const frame1 of frames){
                            concat1.set(frame1.payload, offs);
                            offs += frame1.payload.length;
                        }
                        if (frames[0].opcode === OpCode.TextFrame) {
                            yield decode(concat1);
                        } else {
                            yield concat1;
                        }
                        frames = [];
                        payloadsLength = 0;
                    }
                    break;
                case OpCode.Close:
                    {
                        const code1 = frame.payload[0] << 8 | frame.payload[1];
                        const reason = decode(frame.payload.subarray(2, frame.payload.length));
                        await this.close(code1, reason);
                        yield {
                            code: code1,
                            reason
                        };
                        return;
                    }
                case OpCode.Ping:
                    await this.enqueue({
                        opcode: OpCode.Pong,
                        payload: frame.payload,
                        isLastFrame: true
                    });
                    yield [
                        "ping",
                        frame.payload
                    ];
                    break;
                case OpCode.Pong:
                    yield [
                        "pong",
                        frame.payload
                    ];
                    break;
                default:
            }
        }
    }
    dequeue() {
        const [entry] = this.sendQueue;
        if (!entry) return;
        if (this._isClosed) return;
        const { d , frame  } = entry;
        writeFrame(frame, this.bufWriter).then(()=>d.resolve()
        ).catch((e)=>d.reject(e)
        ).finally(()=>{
            this.sendQueue.shift();
            this.dequeue();
        });
    }
    enqueue(frame) {
        if (this._isClosed) {
            throw new Deno.errors.ConnectionReset("Socket has already been closed");
        }
        const d = deferred();
        this.sendQueue.push({
            d,
            frame
        });
        if (this.sendQueue.length === 1) {
            this.dequeue();
        }
        return d;
    }
    send(data) {
        const opcode = typeof data === "string" ? OpCode.TextFrame : OpCode.BinaryFrame;
        const payload = typeof data === "string" ? encode(data) : data;
        const isLastFrame = true;
        const frame = {
            isLastFrame: true,
            opcode,
            payload,
            mask: this.mask
        };
        return this.enqueue(frame);
    }
    ping(data = "") {
        const payload = typeof data === "string" ? encode(data) : data;
        const frame = {
            isLastFrame: true,
            opcode: OpCode.Ping,
            mask: this.mask,
            payload
        };
        return this.enqueue(frame);
    }
    _isClosed = false;
    get isClosed() {
        return this._isClosed;
    }
    async close(code = 1000, reason) {
        try {
            const header = [
                code >>> 8,
                code & 255
            ];
            let payload;
            if (reason) {
                const reasonBytes = encode(reason);
                payload = new Uint8Array(2 + reasonBytes.byteLength);
                payload.set(header);
                payload.set(reasonBytes, 2);
            } else {
                payload = new Uint8Array(header);
            }
            await this.enqueue({
                isLastFrame: true,
                opcode: OpCode.Close,
                mask: this.mask,
                payload
            });
        } catch (e) {
            throw e;
        } finally{
            this.ensureSocketClosed();
        }
    }
    closeForce() {
        this.ensureSocketClosed();
    }
    ensureSocketClosed() {
        if (this.isClosed) return;
        try {
            this.conn.close();
        } catch (e) {
            console.error(e);
        } finally{
            this._isClosed = true;
            const rest = this.sendQueue;
            this.sendQueue = [];
            rest.forEach((e)=>e.d.reject(new Deno.errors.ConnectionReset("Socket has already been closed"))
            );
        }
    }
}
async function acceptWebSocket(req) {
    const { conn: conn1 , headers: headers1 , bufReader: bufReader1 , bufWriter: bufWriter1  } = req;
    if (acceptable(req)) {
        const sock = new WebSocketImpl({
            conn: conn1,
            bufReader: bufReader1,
            bufWriter: bufWriter1
        });
        const secKey = headers1.get("sec-websocket-key");
        if (typeof secKey !== "string") {
            throw new Error("sec-websocket-key is not provided");
        }
        const secAccept = createSecAccept(secKey);
        await writeResponse(bufWriter1, {
            status: 101,
            headers: new Headers({
                Upgrade: "websocket",
                Connection: "Upgrade",
                "Sec-WebSocket-Accept": secAccept
            })
        });
        return sock;
    }
    throw new Error("request is not acceptable");
}
function lookup(path1) {
    const extension1 = extname("x." + path1).toLowerCase().substr(1);
    return types1.get(extension1);
}
function contentType(str1) {
    let mime = str1.includes("/") ? str1 : lookup(str1);
    if (!mime) {
        return;
    }
    if (!mime.includes("charset")) {
        const cs = charset(mime);
        if (cs) {
            mime += `; charset=${cs.toLowerCase()}`;
        }
    }
    return mime;
}
function compile(str1, options2) {
    return tokensToFunction(parse2(str1, options2), options2);
}
function normalize1(type2) {
    if (type2 === "urlencoded") {
        return "application/x-www-form-urlencoded";
    } else if (type2 === "multipart") {
        return "multipart/*";
    } else if (type2[0] === "+") {
        return `*/*${type2}`;
    }
    return type2.includes("/") ? type2 : lookup(type2);
}
function isMediaType(value3, types1) {
    const val = normalizeType(value3);
    if (!val) {
        return false;
    }
    if (!types1.length) {
        return val;
    }
    for (const type2 of types1){
        if (mimeMatch(normalize1(type2), val)) {
            return type2[0] === "+" || type2.includes("*") ? val : type2;
        }
    }
    return false;
}
function resolvePath(rootPath, relativePath) {
    let path1 = relativePath;
    let root = rootPath;
    if (relativePath === undefined) {
        path1 = rootPath;
        root = ".";
    }
    if (path1 == null) {
        throw new TypeError("Argument relativePath is required.");
    }
    if (path1.includes("\0")) {
        throw createHttpError(400, "Malicious Path");
    }
    if (isAbsolute(path1)) {
        throw createHttpError(400, "Malicious Path");
    }
    if (UP_PATH_REGEXP.test(normalize("." + sep + path1))) {
        throw createHttpError(403);
    }
    return normalize(join(root, path1));
}
class Response1 {
    #body;
    #headers=new Headers();
    #request;
    #resources=[];
    #serverResponse;
    #status;
    #type;
    #writable=true;
    #getBody=async ()=>{
        const [body, type2] = await convertBody(this.body, this.type);
        this.type = type2;
        return body;
    };
    #setContentType=()=>{
        if (this.type) {
            const contentTypeString = contentType(this.type);
            if (contentTypeString && !this.headers.has("Content-Type")) {
                this.headers.append("Content-Type", contentTypeString);
            }
        }
    };
    get body() {
        return this.#body;
    }
    set body(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#body = value;
    }
    get headers() {
        return this.#headers;
    }
    set headers(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#headers = value;
    }
    get status() {
        if (this.#status) {
            return this.#status;
        }
        const typeofbody = typeof this.body;
        return this.body && (BODY_TYPES.includes(typeofbody) || typeofbody === "object") ? Status.OK : Status.NotFound;
    }
    set status(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#status = value;
    }
    get type() {
        return this.#type;
    }
    set type(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#type = value;
    }
    get writable() {
        return this.#writable;
    }
    constructor(request1){
        this.#request = request1;
    }
    addResource(rid) {
        this.#resources.push(rid);
    }
    destroy() {
        this.#writable = false;
        this.#body = undefined;
        this.#serverResponse = undefined;
        for (const rid of this.#resources){
            Deno.close(rid);
        }
    }
    redirect(url, alt = "/") {
        if (url === REDIRECT_BACK) {
            url = this.#request.headers.get("Referrer") ?? String(alt);
        } else if (typeof url === "object") {
            url = String(url);
        }
        this.headers.set("Location", encodeUrl(url));
        if (!this.status || !isRedirectStatus(this.status)) {
            this.status = Status.Found;
        }
        if (this.#request.accepts("html")) {
            url = encodeURI(url);
            this.type = "text/html; charset=utf-8";
            this.body = `Redirecting to <a href="${url}">${url}</a>.`;
            return;
        }
        this.type = "text/plain; charset=utf-8";
        this.body = `Redirecting to ${url}.`;
    }
    async toServerResponse() {
        if (this.#serverResponse) {
            return this.#serverResponse;
        }
        const body = await this.#getBody();
        this.#setContentType();
        const { headers: headers1  } = this;
        if (!(body || headers1.has("Content-Type") || headers1.has("Content-Length"))) {
            headers1.append("Content-Length", "0");
        }
        this.#writable = false;
        return this.#serverResponse = {
            status: this.#status ?? (body ? Status.OK : Status.NotFound),
            body,
            headers: headers1
        };
    }
}
async function send({ request: request2 , response: response2  }, path1, options2 = {
    root: ""
}) {
    const { brotli =true , extensions: extensions1 , format: format2 = true , gzip =true , hidden =false , immutable =false , index , maxage =0 , root ,  } = options2;
    const trailingSlash = path1[path1.length - 1] === "/";
    path1 = decodeComponent(path1.substr(parse3(path1).root.length));
    if (index && trailingSlash) {
        path1 += index;
    }
    if (!hidden && isHidden(path1)) {
        throw createHttpError(403);
    }
    path1 = resolvePath(root, path1);
    let encodingExt = "";
    if (brotli && request2.acceptsEncodings("br", "identity") === "br" && await exists(`${path1}.br`)) {
        path1 = `${path1}.br`;
        response2.headers.set("Content-Encoding", "br");
        response2.headers.delete("Content-Length");
        encodingExt = ".br";
    } else if (gzip && request2.acceptsEncodings("gzip", "identity") === "gzip" && await exists(`${path1}.gz`)) {
        path1 = `${path1}.gz`;
        response2.headers.set("Content-Encoding", "gzip");
        response2.headers.delete("Content-Length");
        encodingExt = ".gz";
    }
    if (extensions1 && !/\.[^/]*$/.exec(path1)) {
        for (let ext of extensions1){
            if (!/^\./.exec(ext)) {
                ext = `.${ext}`;
            }
            if (await exists(`${path1}${ext}`)) {
                path1 += ext;
                break;
            }
        }
    }
    let stats;
    try {
        stats = await Deno.stat(path1);
        if (stats.isDirectory) {
            if (format2 && index) {
                path1 += `/${index}`;
                stats = await Deno.stat(path1);
            } else {
                return;
            }
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            throw createHttpError(404, err.message);
        }
        throw createHttpError(500, err.message);
    }
    response2.headers.set("Content-Length", String(stats.size));
    if (!response2.headers.has("Last-Modified") && stats.mtime) {
        response2.headers.set("Last-Modified", stats.mtime.toUTCString());
    }
    if (!response2.headers.has("Cache-Control")) {
        const directives = [
            `max-age=${maxage / 1000 | 0}`
        ];
        if (immutable) {
            directives.push("immutable");
        }
        response2.headers.set("Cache-Control", directives.join(","));
    }
    if (!response2.type) {
        response2.type = encodingExt !== "" ? extname(basename(path1, encodingExt)) : extname(path1);
    }
    const file = await Deno.open(path1, {
        read: true
    });
    response2.addResource(file.rid);
    response2.body = file;
    return path1;
}
async function error(ctx, next) {
    try {
        await next();
    } catch (e) {
        console.error("error middleware", red(e.message), e.status);
        if (e.status === Status.NotFound) {
            await send(ctx, '404.html', {
                root: `${Deno.cwd()}/static`
            });
        } else {
            throw e;
        }
    }
}
async function staticFiles(ctx) {
    await send(ctx, ctx.request.url.pathname, {
        root: `${Deno.cwd()}/static`,
        index: "index.html"
    });
}
function rfc2231getParam(header) {
    const matches = [];
    let match;
    while(match = FILENAME_START_ITER_REGEX.exec(header)){
        const [, ns, quote, part] = match;
        const n = parseInt(ns, 10);
        if (n in matches) {
            if (n === 0) {
                break;
            }
            continue;
        }
        matches[n] = [
            quote,
            part
        ];
    }
    const parts = [];
    for(let n = 0; n < matches.length; ++n){
        if (!(n in matches)) {
            break;
        }
        let [quote, part] = matches[n];
        part = unquote(part);
        if (quote) {
            part = unescape(part);
            if (n === 0) {
                part = rfc5987decode(part);
            }
        }
        parts.push(part);
    }
    return parts.join("");
}
function getFilename(header) {
    needsEncodingFixup = true;
    let matches = FILENAME_STAR_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(rfc5987decode(unescape(unquote(filename)))));
    }
    const filename = rfc2231getParam(header);
    if (filename) {
        return fixupEncoding(rfc2047decode(filename));
    }
    matches = FILENAME_REGEX.exec(header);
    if (matches) {
        const [, filename1] = matches;
        return fixupEncoding(rfc2047decode(unquote(filename1)));
    }
    return "";
}
async function* parts({ body , final , part , maxFileSize , maxSize , outPath , prefix  }) {
    async function getFile(contentType1) {
        const ext = extension(contentType1);
        if (!ext) {
            throw new httpErrors.BadRequest(`Invalid media type for part: ${ext}`);
        }
        if (!outPath) {
            outPath = await Deno.makeTempDir();
        }
        const filename = `${outPath}/${getRandomFilename(prefix, ext)}`;
        const file = await Deno.open(filename, {
            write: true,
            createNew: true
        });
        return [
            filename,
            file
        ];
    }
    while(true){
        const headers1 = await readHeaders(body);
        const contentType1 = headers1["content-type"];
        const contentDisposition = headers1["content-disposition"];
        if (!contentDisposition) {
            throw new httpErrors.BadRequest("Form data part missing content-disposition header");
        }
        if (!contentDisposition.match(/^form-data;/i)) {
            throw new httpErrors.BadRequest(`Unexpected content-disposition header: "${contentDisposition}"`);
        }
        const matches = NAME_PARAM_REGEX.exec(contentDisposition);
        if (!matches) {
            throw new httpErrors.BadRequest(`Unable to determine name of form body part`);
        }
        let [, name2] = matches;
        name2 = unquote(name2);
        if (contentType1) {
            const originalName = getFilename(contentDisposition);
            let byteLength = 0;
            let file;
            let filename;
            let buf;
            if (maxSize) {
                buf = new Uint8Array();
            } else {
                const result = await getFile(contentType1);
                filename = result[0];
                file = result[1];
            }
            while(true){
                const readResult = await body.readLine(false);
                if (!readResult) {
                    throw new httpErrors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                const strippedBytes = stripEol(bytes);
                if (isEqual(strippedBytes, part) || isEqual(strippedBytes, final)) {
                    if (file) {
                        file.close();
                    }
                    yield [
                        name2,
                        {
                            content: buf,
                            contentType: contentType1,
                            name: name2,
                            filename,
                            originalName
                        }, 
                    ];
                    if (isEqual(strippedBytes, final)) {
                        return;
                    }
                    break;
                }
                byteLength += bytes.byteLength;
                if (byteLength > maxFileSize) {
                    if (file) {
                        file.close();
                    }
                    throw new httpErrors.RequestEntityTooLarge(`File size exceeds limit of ${maxFileSize} bytes.`);
                }
                if (buf) {
                    if (byteLength > maxSize) {
                        const result = await getFile(contentType1);
                        filename = result[0];
                        file = result[1];
                        await Deno.writeAll(file, buf);
                        buf = undefined;
                    } else {
                        buf = append(buf, bytes);
                    }
                }
                if (file) {
                    await Deno.writeAll(file, bytes);
                }
            }
        } else {
            const lines = [];
            while(true){
                const readResult = await body.readLine();
                if (!readResult) {
                    throw new httpErrors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                if (isEqual(bytes, part) || isEqual(bytes, final)) {
                    yield [
                        name2,
                        lines.join("\n")
                    ];
                    if (isEqual(bytes, final)) {
                        return;
                    }
                    break;
                }
                lines.push(decoder2.decode(bytes));
            }
        }
    }
}
class FormDataReader {
    #body;
    #boundaryFinal;
    #boundaryPart;
    #reading=false;
    constructor(contentType1, body){
        const matches = contentType1.match(BOUNDARY_PARAM_REGEX);
        if (!matches) {
            throw new httpErrors.BadRequest(`Content type "${contentType1}" does not contain a valid boundary.`);
        }
        let [, boundary] = matches;
        boundary = unquote(boundary);
        this.#boundaryPart = encoder2.encode(`--${boundary}`);
        this.#boundaryFinal = encoder2.encode(`--${boundary}--`);
        this.#body = body;
    }
    async read(options = {
    }) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , maxFileSize =10485760 , maxSize =0 , bufferSize =1048576 ,  } = options;
        const body1 = new BufReader(this.#body, bufferSize);
        const result = {
            fields: {
            }
        };
        if (!await readToStartOrEnd(body1, this.#boundaryPart, this.#boundaryFinal)) {
            return result;
        }
        try {
            for await (const part of parts({
                body: body1,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                const [key2, value3] = part;
                if (typeof value3 === "string") {
                    result.fields[key2] = value3;
                } else {
                    if (!result.files) {
                        result.files = [];
                    }
                    result.files.push(value3);
                }
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
        return result;
    }
    async *stream(options = {
    }) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , maxFileSize =10485760 , maxSize =0 , bufferSize =32000 ,  } = options;
        const body1 = new BufReader(this.#body, bufferSize);
        if (!await readToStartOrEnd(body1, this.#boundaryPart, this.#boundaryFinal)) {
            return;
        }
        try {
            for await (const part of parts({
                body: body1,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                yield part;
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
    }
}
class Server {
    closing = false;
    connections = [];
    constructor(listener1){
        this.listener = listener1;
    }
    close() {
        this.closing = true;
        this.listener.close();
        for (const conn1 of this.connections){
            try {
                conn1.close();
            } catch (e) {
                if (!(e instanceof Deno.errors.BadResource)) {
                    throw e;
                }
            }
        }
    }
    async *iterateHttpRequests(conn) {
        const reader = new BufReader2(conn);
        const writer5 = new BufWriter1(conn);
        while(!this.closing){
            let request2;
            try {
                request2 = await readRequest(conn, reader);
            } catch (error) {
                if (error instanceof Deno.errors.InvalidData || error instanceof Deno.errors.UnexpectedEof) {
                    await writeResponse(writer5, {
                        status: 400,
                        body: encode(`${error.message}\r\n\r\n`)
                    });
                }
                break;
            }
            if (request2 === null) {
                break;
            }
            request2.w = writer5;
            yield request2;
            const responseError = await request2.done;
            if (responseError) {
                this.untrackConnection(request2.conn);
                return;
            }
            await request2.finalize();
        }
        this.untrackConnection(conn);
        try {
            conn.close();
        } catch (e) {
        }
    }
    trackConnection(conn) {
        this.connections.push(conn);
    }
    untrackConnection(conn) {
        const index = this.connections.indexOf(conn);
        if (index !== -1) {
            this.connections.splice(index, 1);
        }
    }
    async *acceptConnAndIterateHttpRequests(mux) {
        if (this.closing) return;
        let conn2;
        try {
            conn2 = await this.listener.accept();
        } catch (error) {
            if (error instanceof Deno.errors.BadResource || error instanceof Deno.errors.InvalidData || error instanceof Deno.errors.UnexpectedEof) {
                return mux.add(this.acceptConnAndIterateHttpRequests(mux));
            }
            throw error;
        }
        this.trackConnection(conn2);
        mux.add(this.acceptConnAndIterateHttpRequests(mux));
        yield* this.iterateHttpRequests(conn2);
    }
    [Symbol.asyncIterator]() {
        const mux = new MuxAsyncIterator();
        mux.add(this.acceptConnAndIterateHttpRequests(mux));
        return mux.iterate();
    }
}
function serve(addr) {
    if (typeof addr === "string") {
        addr = _parseAddrFromStr(addr);
    }
    const listener1 = Deno.listen(addr);
    return new Server(listener1);
}
function serveTLS(options2) {
    const tlsOptions = {
        ...options2,
        transport: "tcp"
    };
    const listener1 = Deno.listenTls(tlsOptions);
    return new Server(listener1);
}
class RequestBody {
    #body;
    #formDataReader;
    #has;
    #headers;
    #readAllBody;
    #type;
    #valuePromise=()=>{
        return this.#readAllBody ?? (this.#readAllBody = Deno.readAll(this.#body));
    };
    constructor(request2){
        const { body: body1 , headers: headers1  } = request2;
        this.#body = body1;
        this.#headers = headers1;
    }
    get({ type , contentTypes  }) {
        if (type === "reader" && this.#type && this.#type !== "reader") {
            throw new TypeError("Body already consumed and cannot be returned as a reader.");
        }
        if (type === "form-data" && this.#type && this.#type !== "form-data") {
            throw new TypeError("Body already consumed and cannot be returned as form data.");
        }
        if (this.#type === "reader" && type !== "reader") {
            throw new TypeError("Body already consumed as a reader and can only be returned as a reader.");
        }
        if (this.#type === "form-data" && type !== "form-data") {
            throw new TypeError("Body already consumed as form data and can only be returned as form data.");
        }
        if (type && contentTypes) {
            throw new TypeError(`"type" and "contentTypes" cannot be specified at the same time`);
        }
        if (type === "reader") {
            this.#type = "reader";
            return {
                type,
                value: this.#body
            };
        }
        if (!this.has()) {
            this.#type = "undefined";
        } else if (!this.#type) {
            const encoding = this.#headers.get("content-encoding") ?? "identity";
            if (encoding !== "identity") {
                throw new httpErrors.UnsupportedMediaType(`Unsupported content-encoding: ${encoding}`);
            }
        }
        if (this.#type === "undefined") {
            if (type) {
                throw new TypeError(`Body is undefined and cannot be returned as "${type}".`);
            }
            return {
                type: "undefined",
                value: undefined
            };
        }
        if (!type) {
            const contentType2 = this.#headers.get("content-type");
            assert(contentType2);
            contentTypes = contentTypes ?? {
            };
            const contentTypesJson = [
                ...defaultBodyContentTypes.json,
                ...contentTypes.json ?? [], 
            ];
            const contentTypesForm = [
                ...defaultBodyContentTypes.form,
                ...contentTypes.form ?? [], 
            ];
            const contentTypesFormData = [
                ...defaultBodyContentTypes.formData,
                ...contentTypes.formData ?? [], 
            ];
            const contentTypesText = [
                ...defaultBodyContentTypes.text,
                ...contentTypes.text ?? [], 
            ];
            if (contentTypes.raw && isMediaType(contentType2, contentTypes.raw)) {
                type = "raw";
            } else if (isMediaType(contentType2, contentTypesJson)) {
                type = "json";
            } else if (isMediaType(contentType2, contentTypesForm)) {
                type = "form";
            } else if (isMediaType(contentType2, contentTypesFormData)) {
                type = "form-data";
            } else if (isMediaType(contentType2, contentTypesText)) {
                type = "text";
            } else {
                type = "raw";
            }
        }
        assert(type);
        let value3;
        switch(type){
            case "form":
                this.#type = "raw";
                value3 = async ()=>new URLSearchParams(decoder.decode(await this.#valuePromise()).replace(/\+/g, " "))
                ;
                break;
            case "form-data":
                this.#type = "form-data";
                value3 = ()=>{
                    const contentType2 = this.#headers.get("content-type");
                    assert(contentType2);
                    return this.#formDataReader ?? (this.#formDataReader = new FormDataReader(contentType2, this.#body));
                };
                break;
            case "json":
                this.#type = "raw";
                value3 = async ()=>JSON.parse(decoder.decode(await this.#valuePromise()))
                ;
                break;
            case "raw":
                this.#type = "raw";
                value3 = ()=>this.#valuePromise()
                ;
                break;
            case "text":
                this.#type = "raw";
                value3 = async ()=>decoder.decode(await this.#valuePromise())
                ;
                break;
            default:
                throw new TypeError(`Invalid body type: "${type}"`);
        }
        return {
            type,
            get value () {
                return value3();
            }
        };
    }
    has() {
        return this.#has !== undefined ? this.#has : this.#has = this.#headers.get("transfer-encoding") !== null || !!parseInt(this.#headers.get("content-length") ?? "", 10);
    }
}
class Request1 {
    #body;
    #proxy;
    #secure;
    #serverRequest;
    #url;
    get hasBody() {
        return this.#body.has();
    }
    get headers() {
        return this.#serverRequest.headers;
    }
    get ip() {
        return this.#proxy ? this.ips[0] : this.#serverRequest.conn.remoteAddr.hostname;
    }
    get ips() {
        return this.#proxy ? (this.#serverRequest.headers.get("x-forwarded-for") ?? this.#serverRequest.conn.remoteAddr.hostname).split(/\s*,\s*/) : [];
    }
    get method() {
        return this.#serverRequest.method;
    }
    get secure() {
        return this.#secure;
    }
    get serverRequest() {
        return this.#serverRequest;
    }
    get url() {
        if (!this.#url) {
            const serverRequest1 = this.#serverRequest;
            let proto;
            let host;
            if (this.#proxy) {
                proto = serverRequest1.headers.get("x-forwarded-proto")?.split(/\s*,\s*/, 1)[0] ?? "http";
                host = serverRequest1.headers.get("x-forwarded-host") ?? serverRequest1.headers.get("host") ?? "";
            } else {
                proto = this.#secure ? "https" : "http";
                host = serverRequest1.headers.get("host") ?? "";
            }
            this.#url = new URL(`${proto}://${host}${serverRequest1.url}`);
        }
        return this.#url;
    }
    constructor(serverRequest1, proxy = false, secure1 = false){
        this.#proxy = proxy;
        this.#secure = secure1;
        this.#serverRequest = serverRequest1;
        this.#body = new RequestBody(serverRequest1);
    }
    accepts(...types) {
        const acceptValue = this.#serverRequest.headers.get("Accept");
        if (!acceptValue) {
            return;
        }
        if (types.length) {
            return preferredMediaTypes(acceptValue, types)[0];
        }
        return preferredMediaTypes(acceptValue);
    }
    acceptsCharsets(...charsets) {
        const acceptCharsetValue = this.#serverRequest.headers.get("Accept-Charset");
        if (!acceptCharsetValue) {
            return;
        }
        if (charsets.length) {
            return preferredCharsets(acceptCharsetValue, charsets)[0];
        }
        return preferredCharsets(acceptCharsetValue);
    }
    acceptsEncodings(...encodings) {
        const acceptEncodingValue = this.#serverRequest.headers.get("Accept-Encoding");
        if (!acceptEncodingValue) {
            return;
        }
        if (encodings.length) {
            return preferredEncodings(acceptEncodingValue, encodings)[0];
        }
        return preferredEncodings(acceptEncodingValue);
    }
    acceptsLanguages(...langs) {
        const acceptLanguageValue = this.#serverRequest.headers.get("Accept-Language");
        if (!acceptLanguageValue) {
            return;
        }
        if (langs.length) {
            return preferredLanguages(acceptLanguageValue, langs)[0];
        }
        return preferredLanguages(acceptLanguageValue);
    }
    body(options = {
    }) {
        return this.#body.get(options);
    }
}
class Context {
    #socket;
    #sse;
    get isUpgradable() {
        return acceptable(this.request);
    }
    get socket() {
        return this.#socket;
    }
    constructor(app1, serverRequest2, secure2 = false){
        this.app = app1;
        this.state = app1.state;
        this.request = new Request1(serverRequest2, app1.proxy, secure2);
        this.respond = true;
        this.response = new Response1(this.request);
        this.cookies = new Cookies(this.request, this.response, {
            keys: this.app.keys,
            secure: this.request.secure
        });
    }
    assert(condition, errorStatus = 500, message, props) {
        if (condition) {
            return;
        }
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    send(options) {
        const { path: path1 = this.request.url.pathname , ...sendOptions } = options;
        return send(this, path1, sendOptions);
    }
    sendEvents(options) {
        if (this.#sse) {
            return this.#sse;
        }
        this.respond = false;
        return this.#sse = new ServerSentEventTarget(this.app, this.request.serverRequest, options);
    }
    throw(errorStatus, message, props) {
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    async upgrade() {
        if (this.#socket) {
            return this.#socket;
        }
        const { conn: conn2 , r: bufReader1 , w: bufWriter1 , headers: headers2  } = this.request.serverRequest;
        this.#socket = await acceptWebSocket({
            conn: conn2,
            bufReader: bufReader1,
            bufWriter: bufWriter1,
            headers: headers2
        });
        this.respond = false;
        return this.#socket;
    }
}
class Application extends EventTarget {
    #composedMiddleware;
    #keys;
    #middleware=[];
    #serve;
    #serveTls;
    get keys() {
        return this.#keys;
    }
    set keys(keys) {
        if (!keys) {
            this.#keys = undefined;
            return;
        } else if (Array.isArray(keys)) {
            this.#keys = new KeyStack(keys);
        } else {
            this.#keys = keys;
        }
    }
    constructor(options2 = {
    }){
        super();
        const { state , keys: keys3 , proxy: proxy1 , serve: serve1 = serve , serveTls =serveTLS ,  } = options2;
        this.proxy = proxy1 ?? false;
        this.keys = keys3;
        this.state = state ?? {
        };
        this.#serve = serve1;
        this.#serveTls = serveTls;
    }
    #getComposed=()=>{
        if (!this.#composedMiddleware) {
            this.#composedMiddleware = compose(this.#middleware);
        }
        return this.#composedMiddleware;
    };
    #handleError=(context, error1)=>{
        if (!(error1 instanceof Error)) {
            error1 = new Error(`non-error thrown: ${JSON.stringify(error1)}`);
        }
        const { message  } = error1;
        this.dispatchEvent(new ApplicationErrorEvent({
            context,
            message,
            error: error1
        }));
        if (!context.response.writable) {
            return;
        }
        for (const key2 of context.response.headers.keys()){
            context.response.headers.delete(key2);
        }
        if (error1.headers && error1.headers instanceof Headers) {
            for (const [key3, value3] of error1.headers){
                context.response.headers.set(key3, value3);
            }
        }
        context.response.type = "text";
        const status = context.response.status = error1 instanceof Deno.errors.NotFound ? 404 : error1.status && typeof error1.status === "number" ? error1.status : 500;
        context.response.body = error1.expose ? error1.message : STATUS_TEXT.get(status);
    };
    #handleRequest=async (request3, secure3, state1)=>{
        const context = new Context(this, request3, secure3);
        let resolve1;
        const handlingPromise = new Promise((res)=>resolve1 = res
        );
        state1.handling.add(handlingPromise);
        if (!state1.closing && !state1.closed) {
            try {
                await this.#getComposed()(context);
            } catch (err) {
                this.#handleError(context, err);
            }
        }
        if (context.respond === false) {
            context.response.destroy();
            resolve1();
            state1.handling.delete(handlingPromise);
            return;
        }
        try {
            await request3.respond(await context.response.toServerResponse());
            if (state1.closing) {
                state1.server.close();
                state1.closed = true;
            }
        } catch (err) {
            this.#handleError(context, err);
        } finally{
            context.response.destroy();
            resolve1();
            state1.handling.delete(handlingPromise);
        }
    };
    addEventListener(type, listener, options) {
        super.addEventListener(type, listener, options);
    }
    handle = async (request3, secure3 = false)=>{
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        const context = new Context(this, request3, secure3);
        try {
            await this.#getComposed()(context);
        } catch (err) {
            this.#handleError(context, err);
        }
        if (context.respond === false) {
            context.response.destroy();
            return;
        }
        try {
            const response2 = await context.response.toServerResponse();
            context.response.destroy();
            return response2;
        } catch (err) {
            this.#handleError(context, err);
            throw err;
        }
    };
    async listen(options) {
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        if (typeof options === "string") {
            const match = ADDR_REGEXP.exec(options);
            if (!match) {
                throw TypeError(`Invalid address passed: "${options}"`);
            }
            const [, hostname, portStr] = match;
            options = {
                hostname,
                port: parseInt(portStr, 10)
            };
        }
        const server = isOptionsTls(options) ? this.#serveTls(options) : this.#serve(options);
        const { signal  } = options;
        const state1 = {
            closed: false,
            closing: false,
            handling: new Set(),
            server
        };
        if (signal) {
            signal.addEventListener("abort", ()=>{
                if (!state1.handling.size) {
                    server.close();
                    state1.closed = true;
                }
                state1.closing = true;
            });
        }
        const { hostname , port , secure: secure3 = false  } = options;
        this.dispatchEvent(new ApplicationListenEvent({
            hostname,
            port,
            secure: secure3
        }));
        try {
            for await (const request3 of server){
                this.#handleRequest(request3, secure3, state1);
            }
            await Promise.all(state1.handling);
        } catch (error) {
            const message = error instanceof Error ? error.message : "Application Error";
            this.dispatchEvent(new ApplicationErrorEvent({
                message,
                error
            }));
        }
    }
    use(...middleware) {
        this.#middleware.push(...middleware);
        this.#composedMiddleware = undefined;
        return this;
    }
}
const app2 = new Application();
app2.use(logger);
app2.use(timing);
app2.use(error);
app2.use(staticFiles);
app2.addEventListener("listen", ({ hostname , port  })=>{
    console.log(bold("Start listening on ") + yellow(`${hostname}:${port}`));
});
await app2.listen({
    hostname: "127.0.01",
    port: 8000
});
function arrayToRegexp(paths, keys4, options3) {
    const parts1 = paths.map((path1)=>pathToRegexp(path1, keys4, options3).source
    );
    return new RegExp(`(?:${parts1.join("|")})`, flags(options3));
}
function pathToRegexp(path1, keys4, options3) {
    if (path1 instanceof RegExp) return regexpToRegexp(path1, keys4);
    if (Array.isArray(path1)) return arrayToRegexp(path1, keys4, options3);
    return stringToRegexp(path1, keys4, options3);
}
function toUrl(url, params = {
}, options3) {
    const tokens = parse2(url);
    let replace = {
    };
    if (tokens.some((token)=>typeof token === "object"
    )) {
        replace = params;
    } else {
        options3 = params;
    }
    const toPath = compile(url, options3);
    const replaced = toPath(replace);
    if (options3 && options3.query) {
        const url1 = new URL(replaced, "http://oak");
        if (typeof options3.query === "string") {
            url1.search = options3.query;
        } else {
            url1.search = String(options3.query instanceof URLSearchParams ? options3.query : new URLSearchParams(options3.query));
        }
        return `${url1.pathname}${url1.search}${url1.hash}`;
    }
    return replaced;
}
class Layer {
    #opts;
    #paramNames=[];
    #regexp;
    constructor(path1, methods, middleware1, { name: name2 , ...opts5 } = {
    }){
        this.#opts = opts5;
        this.name = name2;
        this.methods = [
            ...methods
        ];
        if (this.methods.includes("GET")) {
            this.methods.unshift("HEAD");
        }
        this.stack = Array.isArray(middleware1) ? middleware1 : [
            middleware1
        ];
        this.path = path1;
        this.#regexp = pathToRegexp(path1, this.#paramNames, this.#opts);
    }
    match(path) {
        return this.#regexp.test(path);
    }
    params(captures, existingParams = {
    }) {
        const params = existingParams;
        for(let i1 = 0; i1 < captures.length; i1++){
            if (this.#paramNames[i1]) {
                const c = captures[i1];
                existingParams[this.#paramNames[i1].name] = c ? decodeComponent(c) : c;
            }
        }
        return existingParams;
    }
    captures(path) {
        if (this.#opts.ignoreCaptures) {
            return [];
        }
        return path.match(this.#regexp)?.slice(1) ?? [];
    }
    url(params = {
    }, options) {
        const url = this.path.replace(/\(\.\*\)/g, "");
        return toUrl(url, params, options);
    }
    param(param, fn) {
        const stack = this.stack;
        const params = this.#paramNames;
        const middleware1 = function(ctx, next) {
            const p = ctx.params[param];
            assert(p);
            return fn.call(this, p, ctx, next);
        };
        middleware1.param = param;
        const names = params.map((p)=>p.name
        );
        const x = names.indexOf(param);
        if (x >= 0) {
            for(let i1 = 0; i1 < stack.length; i1++){
                const fn = stack[i1];
                if (!fn.param || names.indexOf(fn.param) > x) {
                    stack.splice(i1, 0, middleware1);
                    break;
                }
            }
        }
        return this;
    }
    setPrefix(prefix) {
        if (this.path) {
            this.path = this.path !== "/" || this.#opts.strict === true ? `${prefix}${this.path}` : prefix;
            this.#paramNames = [];
            this.#regexp = pathToRegexp(this.path, this.#paramNames, this.#opts);
        }
        return this;
    }
    toJSON() {
        return {
            methods: [
                ...this.methods
            ],
            middleware: [
                ...this.stack
            ],
            paramNames: this.#paramNames.map((key2)=>key2.name
            ),
            path: this.path,
            regexp: this.#regexp,
            options: {
                ...this.#opts
            }
        };
    }
}
class Router {
    #opts;
    #methods;
    #params={
    };
    #stack=[];
    #match=(path3, method)=>{
        const matches1 = {
            path: [],
            pathAndMethod: [],
            route: false
        };
        for (const route of this.#stack){
            if (route.match(path3)) {
                matches1.path.push(route);
                if (route.methods.length === 0 || route.methods.includes(method)) {
                    matches1.pathAndMethod.push(route);
                    if (route.methods.length) {
                        matches1.route = true;
                    }
                }
            }
        }
        return matches1;
    };
    #register=(path3, middleware1, methods1, options3 = {
    })=>{
        if (Array.isArray(path3)) {
            for (const p of path3){
                this.#register(p, middleware1, methods1, options3);
            }
            return;
        }
        const { end , name: name3 , sensitive , strict , ignoreCaptures  } = options3;
        const route = new Layer(path3, methods1, middleware1, {
            end: end === false ? end : true,
            name: name3,
            sensitive: sensitive ?? this.#opts.sensitive ?? false,
            strict: strict ?? this.#opts.strict ?? false,
            ignoreCaptures
        });
        if (this.#opts.prefix) {
            route.setPrefix(this.#opts.prefix);
        }
        for (const [param, mw] of Object.entries(this.#params)){
            route.param(param, mw);
        }
        this.#stack.push(route);
    };
    #route=(name3)=>{
        for (const route of this.#stack){
            if (route.name === name3) {
                return route;
            }
        }
    };
    #useVerb=(nameOrPath, pathOrMiddleware, middleware1, methods1)=>{
        let name3 = undefined;
        let path3;
        if (typeof pathOrMiddleware === "string") {
            name3 = nameOrPath;
            path3 = pathOrMiddleware;
        } else {
            path3 = nameOrPath;
            middleware1.unshift(pathOrMiddleware);
        }
        this.#register(path3, middleware1, methods1, {
            name: name3
        });
    };
    constructor(opts6 = {
    }){
        this.#opts = opts6;
        this.#methods = opts6.methods ?? [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT", 
        ];
    }
    all(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE",
            "GET",
            "POST",
            "PUT"
        ]);
        return this;
    }
    allowedMethods(options = {
    }) {
        const implemented = this.#methods;
        const allowedMethods = async (context, next)=>{
            const ctx = context;
            await next();
            if (!context.response.status || context.response.status === Status.NotFound) {
                assert(context.matched);
                const allowed = new Set();
                for (const route of context.matched){
                    for (const method of route.methods){
                        allowed.add(method);
                    }
                }
                const allowedStr = [
                    ...allowed
                ].join(", ");
                if (!implemented.includes(context.request.method)) {
                    if (options.throw) {
                        throw options.notImplemented ? options.notImplemented() : new httpErrors.NotImplemented();
                    } else {
                        context.response.status = Status.NotImplemented;
                        context.response.headers.set("Allowed", allowedStr);
                    }
                } else if (allowed.size) {
                    if (context.request.method === "OPTIONS") {
                        context.response.status = Status.OK;
                        context.response.headers.set("Allowed", allowedStr);
                    } else if (!allowed.has(context.request.method)) {
                        if (options.throw) {
                            throw options.methodNotAllowed ? options.methodNotAllowed() : new httpErrors.MethodNotAllowed();
                        } else {
                            context.response.status = Status.MethodNotAllowed;
                            context.response.headers.set("Allowed", allowedStr);
                        }
                    }
                }
            }
        };
        return allowedMethods;
    }
    delete(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE"
        ]);
        return this;
    }
    *entries() {
        for (const route of this.#stack){
            const value3 = route.toJSON();
            yield [
                value3,
                value3
            ];
        }
    }
    forEach(callback, thisArg = null) {
        for (const route of this.#stack){
            const value3 = route.toJSON();
            callback.call(thisArg, value3, value3, this);
        }
    }
    get(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "GET"
        ]);
        return this;
    }
    head(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "HEAD"
        ]);
        return this;
    }
    *keys() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    options(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "OPTIONS"
        ]);
        return this;
    }
    param(param, middleware) {
        this.#params[param] = middleware;
        for (const route of this.#stack){
            route.param(param, middleware);
        }
        return this;
    }
    patch(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PATCH"
        ]);
        return this;
    }
    post(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "POST"
        ]);
        return this;
    }
    prefix(prefix) {
        prefix = prefix.replace(/\/$/, "");
        this.#opts.prefix = prefix;
        for (const route of this.#stack){
            route.setPrefix(prefix);
        }
        return this;
    }
    put(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PUT"
        ]);
        return this;
    }
    redirect(source, destination, status = Status.Found) {
        if (source[0] !== "/") {
            const s = this.url(source);
            if (!s) {
                throw new RangeError(`Could not resolve named route: "${source}"`);
            }
            source = s;
        }
        if (destination[0] !== "/") {
            const d = this.url(destination);
            if (!d) {
                throw new RangeError(`Could not resolve named route: "${source}"`);
            }
            destination = d;
        }
        this.all(source, (ctx)=>{
            ctx.response.redirect(destination);
            ctx.response.status = status;
        });
        return this;
    }
    routes() {
        const dispatch = (context, next)=>{
            const ctx = context;
            const { url: { pathname  } , method  } = context.request;
            const path3 = this.#opts.routerPath ?? context.routerPath ?? decodeURIComponent(pathname);
            const matches1 = this.#match(path3, method);
            if (context.matched) {
                context.matched.push(...matches1.path);
            } else {
                context.matched = [
                    ...matches1.path
                ];
            }
            context.router = this;
            if (!matches1.route) return next();
            const { pathAndMethod: matchedRoutes  } = matches1;
            const chain = matchedRoutes.reduce((prev, route)=>[
                    ...prev,
                    (ctx1, next1)=>{
                        ctx1.captures = route.captures(path3);
                        ctx1.params = route.params(ctx1.captures, ctx1.params);
                        ctx1.routeName = route.name;
                        return next1();
                    },
                    ...route.stack, 
                ]
            , []);
            return compose(chain)(context, next);
        };
        dispatch.router = this;
        return dispatch;
    }
    url(name, params, options) {
        const route = this.#route(name);
        if (route) {
            return route.url(params, options);
        }
    }
    use(pathOrMiddleware, ...middleware) {
        let path3;
        if (typeof pathOrMiddleware === "string" || Array.isArray(pathOrMiddleware)) {
            path3 = pathOrMiddleware;
        } else {
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path3 ?? "(.*)", middleware, [], {
            end: false,
            ignoreCaptures: !path3
        });
        return this;
    }
    *values() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    *[Symbol.iterator]() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    static url(path, params, options) {
        return toUrl(path, params, options);
    }
}
const router = new Router();
router.get('/hi', (ctx)=>{
    ctx.response.body = {
        hello: {
            from: {
                the: {
                    router: "hi"
                }
            }
        }
    };
}).get('/api/movies', async (ctx)=>{
    console.log('movies route');
    const movies = await getMovies();
    ctx.response.body = movies;
}).get('/api/movie/:id', async (ctx)=>{
    const movies = await getMovie(ctx.params.id);
    ctx.response.body = movies;
});
app2.use(router.routes());
