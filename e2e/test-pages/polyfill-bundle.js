//#region \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJSMin = (cb, mod) => () => (mod || cb((mod = { exports: {} }).exports, mod), mod.exports);
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
//#endregion
//#region ../node_modules/.pnpm/@noble+ed25519@3.0.1/node_modules/@noble/ed25519/index.js
/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
/**
* 5KB JS implementation of ed25519 EdDSA signatures.
* Compliant with RFC8032, FIPS 186-5 & ZIP215.
* @module
* @example
* ```js
import * as ed from '@noble/ed25519';
(async () => {
const secretKey = ed.utils.randomSecretKey();
const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
const pubKey = await ed.getPublicKeyAsync(secretKey); // Sync methods are also present
const signature = await ed.signAsync(message, secretKey);
const isValid = await ed.verifyAsync(signature, message, pubKey);
})();
```
*/
/**
* Curve params. ed25519 is twisted edwards curve. Equation is −x² + y² = -a + dx²y².
* * P = `2n**255n - 19n` // field over which calculations are done
* * N = `2n**252n + 27742317777372353535851937790883648493n` // group order, amount of curve points
* * h = 8 // cofactor
* * a = `Fp.create(BigInt(-1))` // equation param
* * d = -121665/121666 a.k.a. `Fp.neg(121665 * Fp.inv(121666))` // equation param
* * Gx, Gy are coordinates of Generator / base point
*/
var ed25519_CURVE = {
	p: 57896044618658097711785492504343953926634992332820282019728792003956564819949n,
	n: 7237005577332262213973186563042994240857116359379907606001950938285454250989n,
	h: 8n,
	a: 57896044618658097711785492504343953926634992332820282019728792003956564819948n,
	d: 37095705934669439343138083508754565189542113879843219016388785533085940283555n,
	Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
	Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n
};
var { p: P$1, n: N, Gx, Gy, a: _a, d: _d, h } = ed25519_CURVE;
var L = 32;
var captureTrace = (...args) => {
	if ("captureStackTrace" in Error && typeof Error.captureStackTrace === "function") Error.captureStackTrace(...args);
};
var err = (message = "") => {
	const e = new Error(message);
	captureTrace(e, err);
	throw e;
};
var isBig = (n) => typeof n === "bigint";
var isStr = (s) => typeof s === "string";
var isBytes$1 = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
/** Asserts something is Uint8Array. */
var abytes$1 = (value, length, title = "") => {
	const bytes = isBytes$1(value);
	const len = value?.length;
	const needsLen = length !== void 0;
	if (!bytes || needsLen && len !== length) {
		const prefix = title && `"${title}" `;
		const ofLen = needsLen ? ` of length ${length}` : "";
		const got = bytes ? `length=${len}` : `type=${typeof value}`;
		err(prefix + "expected Uint8Array" + ofLen + ", got " + got);
	}
	return value;
};
/** create Uint8Array */
var u8n = (len) => new Uint8Array(len);
var u8fr = (buf) => Uint8Array.from(buf);
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex$1 = (b) => Array.from(abytes$1(b)).map((e) => padh(e, 2)).join("");
var C = {
	_0: 48,
	_9: 57,
	A: 65,
	F: 70,
	a: 97,
	f: 102
};
var _ch = (ch) => {
	if (ch >= C._0 && ch <= C._9) return ch - C._0;
	if (ch >= C.A && ch <= C.F) return ch - (C.A - 10);
	if (ch >= C.a && ch <= C.f) return ch - (C.a - 10);
};
var hexToBytes$1 = (hex) => {
	const e = "hex invalid";
	if (!isStr(hex)) return err(e);
	const hl = hex.length;
	const al = hl / 2;
	if (hl % 2) return err(e);
	const array = u8n(al);
	for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
		const n1 = _ch(hex.charCodeAt(hi));
		const n2 = _ch(hex.charCodeAt(hi + 1));
		if (n1 === void 0 || n2 === void 0) return err(e);
		array[ai] = n1 * 16 + n2;
	}
	return array;
};
var cr = () => globalThis?.crypto;
var subtle$1 = () => cr()?.subtle ?? err("crypto.subtle must be defined, consider polyfill");
var concatBytes = (...arrs) => {
	const r = u8n(arrs.reduce((sum, a) => sum + abytes$1(a).length, 0));
	let pad = 0;
	arrs.forEach((a) => {
		r.set(a, pad);
		pad += a.length;
	});
	return r;
};
/** WebCrypto OS-level CSPRNG (random number generator). Will throw when not available. */
var randomBytes$1 = (len = L) => {
	return cr().getRandomValues(u8n(len));
};
var big = BigInt;
var assertRange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
/** modular division */
var M = (a, b = P$1) => {
	const r = a % b;
	return r >= 0n ? r : b + r;
};
var P_MASK = (1n << 255n) - 1n;
var modP = (num) => {
	if (num < 0n) err("negative coordinate");
	let r = (num >> 255n) * 19n + (num & P_MASK);
	r = (r >> 255n) * 19n + (r & P_MASK);
	return r % P$1;
};
var modN = (a) => M(a, N);
/** Modular inversion using euclidean GCD (non-CT). No negative exponent for now. */
var invert = (num, md) => {
	if (num === 0n || md <= 0n) err("no inverse n=" + num + " mod=" + md);
	let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
	while (a !== 0n) {
		const q = b / a, r = b % a;
		const m = x - u * q, n = y - v * q;
		b = a, a = r, x = u, y = v, u = m, v = n;
	}
	return b === 1n ? M(x, md) : err("no inverse");
};
var callHash = (name) => {
	const fn = hashes[name];
	if (typeof fn !== "function") err("hashes." + name + " not set");
	return fn;
};
var apoint = (p) => p instanceof Point ? p : err("Point expected");
var B256 = 2n ** 256n;
/** Point in XYZT extended coordinates. */
var Point = class Point {
	static BASE;
	static ZERO;
	X;
	Y;
	Z;
	T;
	constructor(X, Y, Z, T) {
		const max = B256;
		this.X = assertRange(X, 0n, max);
		this.Y = assertRange(Y, 0n, max);
		this.Z = assertRange(Z, 1n, max);
		this.T = assertRange(T, 0n, max);
		Object.freeze(this);
	}
	static CURVE() {
		return ed25519_CURVE;
	}
	static fromAffine(p) {
		return new Point(p.x, p.y, 1n, modP(p.x * p.y));
	}
	/** RFC8032 5.1.3: Uint8Array to Point. */
	static fromBytes(hex, zip215 = false) {
		const d = _d;
		const normed = u8fr(abytes$1(hex, L));
		const lastByte = hex[31];
		normed[31] = lastByte & -129;
		const y = bytesToNumberLE(normed);
		assertRange(y, 0n, zip215 ? B256 : P$1);
		const y2 = modP(y * y);
		let { isValid, value: x } = uvRatio(M(y2 - 1n), modP(d * y2 + 1n));
		if (!isValid) err("bad point: y not sqrt");
		const isXOdd = (x & 1n) === 1n;
		const isLastByteOdd = (lastByte & 128) !== 0;
		if (!zip215 && x === 0n && isLastByteOdd) err("bad point: x==0, isLastByteOdd");
		if (isLastByteOdd !== isXOdd) x = M(-x);
		return new Point(x, y, 1n, modP(x * y));
	}
	static fromHex(hex, zip215) {
		return Point.fromBytes(hexToBytes$1(hex), zip215);
	}
	get x() {
		return this.toAffine().x;
	}
	get y() {
		return this.toAffine().y;
	}
	/** Checks if the point is valid and on-curve. */
	assertValidity() {
		const a = _a;
		const d = _d;
		const p = this;
		if (p.is0()) return err("bad point: ZERO");
		const { X, Y, Z, T } = p;
		const X2 = modP(X * X);
		const Y2 = modP(Y * Y);
		const Z2 = modP(Z * Z);
		const Z4 = modP(Z2 * Z2);
		if (modP(Z2 * (modP(X2 * a) + Y2)) !== M(Z4 + modP(d * modP(X2 * Y2)))) return err("bad point: equation left != right (1)");
		if (modP(X * Y) !== modP(Z * T)) return err("bad point: equation left != right (2)");
		return this;
	}
	/** Equality check: compare points P&Q. */
	equals(other) {
		const { X: X1, Y: Y1, Z: Z1 } = this;
		const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
		const X1Z2 = modP(X1 * Z2);
		const X2Z1 = modP(X2 * Z1);
		const Y1Z2 = modP(Y1 * Z2);
		const Y2Z1 = modP(Y2 * Z1);
		return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
	}
	is0() {
		return this.equals(I);
	}
	/** Flip point over y coordinate. */
	negate() {
		return new Point(M(-this.X), this.Y, this.Z, M(-this.T));
	}
	/** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
	double() {
		const { X: X1, Y: Y1, Z: Z1 } = this;
		const a = _a;
		const A = modP(X1 * X1);
		const B = modP(Y1 * Y1);
		const C = modP(2n * Z1 * Z1);
		const D = modP(a * A);
		const x1y1 = M(X1 + Y1);
		const E = M(modP(x1y1 * x1y1) - A - B);
		const G = M(D + B);
		const F = M(G - C);
		const H = M(D - B);
		const X3 = modP(E * F);
		const Y3 = modP(G * H);
		const T3 = modP(E * H);
		return new Point(X3, Y3, modP(F * G), T3);
	}
	/** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
	add(other) {
		const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
		const { X: X2, Y: Y2, Z: Z2, T: T2 } = apoint(other);
		const a = _a;
		const d = _d;
		const A = modP(X1 * X2);
		const B = modP(Y1 * Y2);
		const C = modP(modP(T1 * d) * T2);
		const D = modP(Z1 * Z2);
		const E = M(modP(M(X1 + Y1) * M(X2 + Y2)) - A - B);
		const F = M(D - C);
		const G = M(D + C);
		const H = M(B - modP(a * A));
		const X3 = modP(E * F);
		const Y3 = modP(G * H);
		const T3 = modP(E * H);
		return new Point(X3, Y3, modP(F * G), T3);
	}
	subtract(other) {
		return this.add(apoint(other).negate());
	}
	/**
	* Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
	* Uses {@link wNAF} for base point.
	* Uses fake point to mitigate side-channel leakage.
	* @param n scalar by which point is multiplied
	* @param safe safe mode guards against timing attacks; unsafe mode is faster
	*/
	multiply(n, safe = true) {
		if (!safe && (n === 0n || this.is0())) return I;
		assertRange(n, 1n, N);
		if (n === 1n) return this;
		if (this.equals(G$1)) return wNAF(n).p;
		let p = I;
		let f = G$1;
		for (let d = this; n > 0n; d = d.double(), n >>= 1n) if (n & 1n) p = p.add(d);
		else if (safe) f = f.add(d);
		return p;
	}
	multiplyUnsafe(scalar) {
		return this.multiply(scalar, false);
	}
	/** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
	toAffine() {
		const { X, Y, Z } = this;
		if (this.equals(I)) return {
			x: 0n,
			y: 1n
		};
		const iz = invert(Z, P$1);
		if (modP(Z * iz) !== 1n) err("invalid inverse");
		return {
			x: modP(X * iz),
			y: modP(Y * iz)
		};
	}
	toBytes() {
		const { x, y } = this.toAffine();
		const b = numTo32bLE(y);
		b[31] |= x & 1n ? 128 : 0;
		return b;
	}
	toHex() {
		return bytesToHex$1(this.toBytes());
	}
	clearCofactor() {
		return this.multiply(big(h), false);
	}
	isSmallOrder() {
		return this.clearCofactor().is0();
	}
	isTorsionFree() {
		let p = this.multiply(N / 2n, false).double();
		if (N % 2n) p = p.add(this);
		return p.is0();
	}
};
/** Generator / base point */
var G$1 = new Point(Gx, Gy, 1n, M(Gx * Gy));
/** Identity / zero point */
var I = new Point(0n, 1n, 1n, 0n);
Point.BASE = G$1;
Point.ZERO = I;
var numTo32bLE = (num) => hexToBytes$1(padh(assertRange(num, 0n, B256), 64)).reverse();
var bytesToNumberLE = (b) => big("0x" + bytesToHex$1(u8fr(abytes$1(b)).reverse()));
var pow2 = (x, power) => {
	let r = x;
	while (power-- > 0n) r = modP(r * r);
	return r;
};
var pow_2_252_3 = (x) => {
	const b2 = modP(modP(x * x) * x);
	const b5 = modP(pow2(modP(pow2(b2, 2n) * b2), 1n) * x);
	const b10 = modP(pow2(b5, 5n) * b5);
	const b20 = modP(pow2(b10, 10n) * b10);
	const b40 = modP(pow2(b20, 20n) * b20);
	const b80 = modP(pow2(b40, 40n) * b40);
	return {
		pow_p_5_8: modP(pow2(modP(pow2(modP(pow2(modP(pow2(b80, 80n) * b80), 80n) * b80), 10n) * b10), 2n) * x),
		b2
	};
};
var RM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
var uvRatio = (u, v) => {
	const v3 = modP(v * modP(v * v));
	const pow = pow_2_252_3(modP(u * modP(modP(v3 * v3) * v))).pow_p_5_8;
	let x = modP(u * modP(v3 * pow));
	const vx2 = modP(v * modP(x * x));
	const root1 = x;
	const root2 = modP(x * RM1);
	const useRoot1 = vx2 === u;
	const useRoot2 = vx2 === M(-u);
	const noRoot = vx2 === M(-u * RM1);
	if (useRoot1) x = root1;
	if (useRoot2 || noRoot) x = root2;
	if ((M(x) & 1n) === 1n) x = M(-x);
	return {
		isValid: useRoot1 || useRoot2,
		value: x
	};
};
var modL_LE = (hash) => modN(bytesToNumberLE(hash));
/** hashes.sha512 should conform to the interface. */
var sha512a = (...m) => hashes.sha512Async(concatBytes(...m));
var sha512s = (...m) => callHash("sha512")(concatBytes(...m));
var hash2extK = (hashed) => {
	const head = hashed.slice(0, 32);
	head[0] &= 248;
	head[31] &= 127;
	head[31] |= 64;
	const prefix = hashed.slice(32, 64);
	const scalar = modL_LE(head);
	const point = G$1.multiply(scalar);
	return {
		head,
		prefix,
		scalar,
		point,
		pointBytes: point.toBytes()
	};
};
var getExtendedPublicKeyAsync = (secretKey) => sha512a(abytes$1(secretKey, L)).then(hash2extK);
var getExtendedPublicKey = (secretKey) => hash2extK(sha512s(abytes$1(secretKey, L)));
/** Creates 32-byte ed25519 public key from 32-byte secret key. Async. */
var getPublicKeyAsync = (secretKey) => getExtendedPublicKeyAsync(secretKey).then((p) => p.pointBytes);
var hashFinishA = (res) => sha512a(res.hashable).then(res.finish);
var _sign = (e, rBytes, msg) => {
	const { pointBytes: P, scalar: s } = e;
	const r = modL_LE(rBytes);
	const R = G$1.multiply(r).toBytes();
	const hashable = concatBytes(R, P, msg);
	const finish = (hashed) => {
		return abytes$1(concatBytes(R, numTo32bLE(modN(r + modL_LE(hashed) * s))), 64);
	};
	return {
		hashable,
		finish
	};
};
/**
* Signs message using secret key. Async.
* Follows RFC8032 5.1.6.
*/
var signAsync = async (message, secretKey) => {
	const m = abytes$1(message);
	const e = await getExtendedPublicKeyAsync(secretKey);
	return hashFinishA(_sign(e, await sha512a(e.prefix, m), m));
};
var defaultVerifyOpts = { zip215: true };
var _verify = (sig, msg, publicKey, options = defaultVerifyOpts) => {
	sig = abytes$1(sig, 64);
	msg = abytes$1(msg);
	publicKey = abytes$1(publicKey, L);
	const { zip215 } = options;
	const r = sig.subarray(0, L);
	const s = bytesToNumberLE(sig.subarray(L, L * 2));
	let A, R, SB;
	let hashable = Uint8Array.of();
	let finished = false;
	try {
		A = Point.fromBytes(publicKey, zip215);
		R = Point.fromBytes(r, zip215);
		SB = G$1.multiply(s, false);
		hashable = concatBytes(R.toBytes(), A.toBytes(), msg);
		finished = true;
	} catch (error) {}
	const finish = (hashed) => {
		if (!finished) return false;
		if (!zip215 && A.isSmallOrder()) return false;
		const k = modL_LE(hashed);
		return R.add(A.multiply(k, false)).subtract(SB).clearCofactor().is0();
	};
	return {
		hashable,
		finish
	};
};
/** Verifies signature on message and public key. Async. Follows RFC8032 5.1.7. */
var verifyAsync = async (signature, message, publicKey, opts = defaultVerifyOpts) => hashFinishA(_verify(signature, message, publicKey, opts));
/** Math, hex, byte helpers. Not in `utils` because utils share API with noble-curves. */
var etc = {
	bytesToHex: bytesToHex$1,
	hexToBytes: hexToBytes$1,
	concatBytes,
	mod: M,
	invert,
	randomBytes: randomBytes$1
};
var hashes = {
	sha512Async: async (message) => {
		const s = subtle$1();
		const m = concatBytes(message);
		return u8n(await s.digest("SHA-512", m.buffer));
	},
	sha512: void 0
};
var randomSecretKey = (seed = randomBytes$1(L)) => seed;
/** ed25519-specific key utilities. */
var utils = {
	getExtendedPublicKeyAsync,
	getExtendedPublicKey,
	randomSecretKey
};
var W = 8;
var pwindows = Math.ceil(256 / W) + 1;
var pwindowSize = 2 ** (W - 1);
var precompute = () => {
	const points = [];
	let p = G$1;
	let b = p;
	for (let w = 0; w < pwindows; w++) {
		b = p;
		points.push(b);
		for (let i = 1; i < pwindowSize; i++) {
			b = b.add(p);
			points.push(b);
		}
		p = b.double();
	}
	return points;
};
var Gpows = void 0;
var ctneg = (cnd, p) => {
	const n = p.negate();
	return cnd ? n : p;
};
/**
* Precomputes give 12x faster getPublicKey(), 10x sign(), 2x verify() by
* caching multiples of G (base point). Cache is stored in 32MB of RAM.
* Any time `G.multiply` is done, precomputes are used.
* Not used for getSharedSecret, which instead multiplies random pubkey `P.multiply`.
*
* w-ary non-adjacent form (wNAF) precomputation method is 10% slower than windowed method,
* but takes 2x less RAM. RAM reduction is possible by utilizing `.subtract`.
*
* !! Precomputes can be disabled by commenting-out call of the wNAF() inside Point#multiply().
*/
var wNAF = (n) => {
	const comp = Gpows || (Gpows = precompute());
	let p = I;
	let f = G$1;
	const pow_2_w = 2 ** W;
	const maxNum = pow_2_w;
	const mask = big(pow_2_w - 1);
	const shiftBy = big(W);
	for (let w = 0; w < pwindows; w++) {
		let wbits = Number(n & mask);
		n >>= shiftBy;
		if (wbits > pwindowSize) {
			wbits -= maxNum;
			n += 1n;
		}
		const off = w * pwindowSize;
		const offF = off;
		const offP = off + Math.abs(wbits) - 1;
		const isEven = w % 2 !== 0;
		const isNeg = wbits < 0;
		if (wbits === 0) f = f.add(ctneg(isEven, comp[offF]));
		else p = p.add(ctneg(isNeg, comp[offP]));
	}
	if (n !== 0n) err("invalid wnaf");
	return {
		p,
		f
	};
};
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/utils.js
/**
* Utilities for hex, bytes, CSPRNG.
* @module
*/
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
	return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
/** Asserts something is positive integer. */
function anumber(n, title = "") {
	if (!Number.isSafeInteger(n) || n < 0) {
		const prefix = title && `"${title}" `;
		throw new Error(`${prefix}expected integer >= 0, got ${n}`);
	}
}
/** Asserts something is Uint8Array. */
function abytes(value, length, title = "") {
	const bytes = isBytes(value);
	const len = value?.length;
	const needsLen = length !== void 0;
	if (!bytes || needsLen && len !== length) {
		const prefix = title && `"${title}" `;
		const ofLen = needsLen ? ` of length ${length}` : "";
		const got = bytes ? `length=${len}` : `type=${typeof value}`;
		throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
	}
	return value;
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
	if (instance.destroyed) throw new Error("Hash instance has been destroyed");
	if (checkFinished && instance.finished) throw new Error("Hash#digest() has already been called");
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
	abytes(out, void 0, "digestInto() output");
	const min = instance.outputLen;
	if (out.length < min) throw new Error("\"digestInto() output\" expected to be of length >=" + min);
}
/** Cast u8 / u16 / u32 to u8. */
function u8(arr) {
	return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** Cast u8 / u16 / u32 to u32. */
function u32(arr) {
	return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
	for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
}
/** Create DataView of an array for easy byte-level manipulation. */
function createView(arr) {
	return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** The rotate right (circular right shift) operation for uint32 */
function rotr(word, shift) {
	return word << 32 - shift | word >>> shift;
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
/** The byte swap operation for uint32 */
function byteSwap(word) {
	return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
/** Conditionally byte swap if on a big-endian platform */
var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n);
/** In place byte swap for Uint32Array */
function byteSwap32(arr) {
	for (let i = 0; i < arr.length; i++) arr[i] = byteSwap(arr[i]);
	return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
var hasHexBuiltin = typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function";
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
/**
* Convert byte array to hex string. Uses built-in function, when available.
* @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
*/
function bytesToHex(bytes) {
	abytes(bytes);
	if (hasHexBuiltin) return bytes.toHex();
	let hex = "";
	for (let i = 0; i < bytes.length; i++) hex += hexes[bytes[i]];
	return hex;
}
var asciis = {
	_0: 48,
	_9: 57,
	A: 65,
	F: 70,
	a: 97,
	f: 102
};
function asciiToBase16(ch) {
	if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0;
	if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10);
	if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10);
}
/**
* Convert hex string to byte array. Uses built-in function, when available.
* @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
*/
function hexToBytes(hex) {
	if (typeof hex !== "string") throw new Error("hex string expected, got " + typeof hex);
	if (hasHexBuiltin) return Uint8Array.fromHex(hex);
	const hl = hex.length;
	const al = hl / 2;
	if (hl % 2) throw new Error("hex string expected, got unpadded hex of length " + hl);
	const array = new Uint8Array(al);
	for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
		const n1 = asciiToBase16(hex.charCodeAt(hi));
		const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
		if (n1 === void 0 || n2 === void 0) {
			const char = hex[hi] + hex[hi + 1];
			throw new Error("hex string expected, got non-hex character \"" + char + "\" at index " + hi);
		}
		array[ai] = n1 * 16 + n2;
	}
	return array;
}
/**
* Converts string to bytes using UTF8 encoding.
* Built-in doesn't validate input to be string: we do the check.
* @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
*/
function utf8ToBytes(str) {
	if (typeof str !== "string") throw new Error("string expected");
	return new Uint8Array(new TextEncoder().encode(str));
}
/**
* Helper for KDFs: consumes uint8array or string.
* When string is passed, does utf8 decoding, using TextDecoder.
*/
function kdfInputToBytes(data, errorTitle = "") {
	if (typeof data === "string") return utf8ToBytes(data);
	return abytes(data, void 0, errorTitle);
}
/** Creates function with outputLen, blockLen, create properties from a class constructor. */
function createHasher(hashCons, info = {}) {
	const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
	const tmp = hashCons(void 0);
	hashC.outputLen = tmp.outputLen;
	hashC.blockLen = tmp.blockLen;
	hashC.create = (opts) => hashCons(opts);
	Object.assign(hashC, info);
	return Object.freeze(hashC);
}
/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
function randomBytes(bytesLength = 32) {
	const cr = typeof globalThis === "object" ? globalThis.crypto : null;
	if (typeof cr?.getRandomValues !== "function") throw new Error("crypto.getRandomValues must be defined");
	return cr.getRandomValues(new Uint8Array(bytesLength));
}
/** Creates OID opts for NIST hashes, with prefix 06 09 60 86 48 01 65 03 04 02. */
var oidNist = (suffix) => ({ oid: Uint8Array.from([
	6,
	9,
	96,
	134,
	72,
	1,
	101,
	3,
	4,
	2,
	suffix
]) });
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/_md.js
/**
* Internal Merkle-Damgard hash utils.
* @module
*/
/** Choice: a ? b : c */
function Chi(a, b, c) {
	return a & b ^ ~a & c;
}
/** Majority function, true if any two inputs is true. */
function Maj(a, b, c) {
	return a & b ^ a & c ^ b & c;
}
/**
* Merkle-Damgard hash construction base class.
* Could be used to create MD5, RIPEMD, SHA1, SHA2.
*/
var HashMD = class {
	blockLen;
	outputLen;
	padOffset;
	isLE;
	buffer;
	view;
	finished = false;
	length = 0;
	pos = 0;
	destroyed = false;
	constructor(blockLen, outputLen, padOffset, isLE) {
		this.blockLen = blockLen;
		this.outputLen = outputLen;
		this.padOffset = padOffset;
		this.isLE = isLE;
		this.buffer = new Uint8Array(blockLen);
		this.view = createView(this.buffer);
	}
	update(data) {
		aexists(this);
		abytes(data);
		const { view, buffer, blockLen } = this;
		const len = data.length;
		for (let pos = 0; pos < len;) {
			const take = Math.min(blockLen - this.pos, len - pos);
			if (take === blockLen) {
				const dataView = createView(data);
				for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
				continue;
			}
			buffer.set(data.subarray(pos, pos + take), this.pos);
			this.pos += take;
			pos += take;
			if (this.pos === blockLen) {
				this.process(view, 0);
				this.pos = 0;
			}
		}
		this.length += data.length;
		this.roundClean();
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		this.finished = true;
		const { buffer, view, blockLen, isLE } = this;
		let { pos } = this;
		buffer[pos++] = 128;
		clean(this.buffer.subarray(pos));
		if (this.padOffset > blockLen - pos) {
			this.process(view, 0);
			pos = 0;
		}
		for (let i = pos; i < blockLen; i++) buffer[i] = 0;
		view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE);
		this.process(view, 0);
		const oview = createView(out);
		const len = this.outputLen;
		if (len % 4) throw new Error("_sha2: outputLen must be aligned to 32bit");
		const outLen = len / 4;
		const state = this.get();
		if (outLen > state.length) throw new Error("_sha2: outputLen bigger than state");
		for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
	}
	digest() {
		const { buffer, outputLen } = this;
		this.digestInto(buffer);
		const res = buffer.slice(0, outputLen);
		this.destroy();
		return res;
	}
	_cloneInto(to) {
		to ||= new this.constructor();
		to.set(...this.get());
		const { blockLen, buffer, length, finished, destroyed, pos } = this;
		to.destroyed = destroyed;
		to.finished = finished;
		to.length = length;
		to.pos = pos;
		if (length % blockLen) to.buffer.set(buffer);
		return to;
	}
	clone() {
		return this._cloneInto();
	}
};
/**
* Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
* Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
*/
/** Initial SHA256 state. Bits 0..32 of frac part of sqrt of primes 2..19 */
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
	1779033703,
	3144134277,
	1013904242,
	2773480762,
	1359893119,
	2600822924,
	528734635,
	1541459225
]);
/** Initial SHA512 state. Bits 0..64 of frac part of sqrt of primes 2..19 */
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
	1779033703,
	4089235720,
	3144134277,
	2227873595,
	1013904242,
	4271175723,
	2773480762,
	1595750129,
	1359893119,
	2917565137,
	2600822924,
	725511199,
	528734635,
	4215389547,
	1541459225,
	327033209
]);
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/_u64.js
/**
* Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
* @todo re-check https://issues.chromium.org/issues/42212588
* @module
*/
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
	if (le) return {
		h: Number(n & U32_MASK64),
		l: Number(n >> _32n & U32_MASK64)
	};
	return {
		h: Number(n >> _32n & U32_MASK64) | 0,
		l: Number(n & U32_MASK64) | 0
	};
}
function split(lst, le = false) {
	const len = lst.length;
	let Ah = new Uint32Array(len);
	let Al = new Uint32Array(len);
	for (let i = 0; i < len; i++) {
		const { h, l } = fromBig(lst[i], le);
		[Ah[i], Al[i]] = [h, l];
	}
	return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
var rotr32H = (_h, l) => l;
var rotr32L = (h, _l) => h;
function add(Ah, Al, Bh, Bl) {
	const l = (Al >>> 0) + (Bl >>> 0);
	return {
		h: Ah + Bh + (l / 2 ** 32 | 0) | 0,
		l: l | 0
	};
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/sha2.js
/**
* SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
* SHA256 is the fastest hash implementable in JS, even faster than Blake3.
* Check out [RFC 4634](https://www.rfc-editor.org/rfc/rfc4634) and
* [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
* @module
*/
/**
* Round constants:
* First 32 bits of fractional parts of the cube roots of the first 64 primes 2..311)
*/
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
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
	3329325298
]);
/** Reusable temporary buffer. "W" comes straight from spec. */
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
/** Internal 32-byte base SHA2 hash class. */
var SHA2_32B = class extends HashMD {
	constructor(outputLen) {
		super(64, outputLen, 8, false);
	}
	get() {
		const { A, B, C, D, E, F, G, H } = this;
		return [
			A,
			B,
			C,
			D,
			E,
			F,
			G,
			H
		];
	}
	set(A, B, C, D, E, F, G, H) {
		this.A = A | 0;
		this.B = B | 0;
		this.C = C | 0;
		this.D = D | 0;
		this.E = E | 0;
		this.F = F | 0;
		this.G = G | 0;
		this.H = H | 0;
	}
	process(view, offset) {
		for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
		for (let i = 16; i < 64; i++) {
			const W15 = SHA256_W[i - 15];
			const W2 = SHA256_W[i - 2];
			const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
			SHA256_W[i] = (rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10) + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
		}
		let { A, B, C, D, E, F, G, H } = this;
		for (let i = 0; i < 64; i++) {
			const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
			const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
			const T2 = (rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + Maj(A, B, C) | 0;
			H = G;
			G = F;
			F = E;
			E = D + T1 | 0;
			D = C;
			C = B;
			B = A;
			A = T1 + T2 | 0;
		}
		A = A + this.A | 0;
		B = B + this.B | 0;
		C = C + this.C | 0;
		D = D + this.D | 0;
		E = E + this.E | 0;
		F = F + this.F | 0;
		G = G + this.G | 0;
		H = H + this.H | 0;
		this.set(A, B, C, D, E, F, G, H);
	}
	roundClean() {
		clean(SHA256_W);
	}
	destroy() {
		this.set(0, 0, 0, 0, 0, 0, 0, 0);
		clean(this.buffer);
	}
};
/** Internal SHA2-256 hash class. */
var _SHA256 = class extends SHA2_32B {
	A = SHA256_IV[0] | 0;
	B = SHA256_IV[1] | 0;
	C = SHA256_IV[2] | 0;
	D = SHA256_IV[3] | 0;
	E = SHA256_IV[4] | 0;
	F = SHA256_IV[5] | 0;
	G = SHA256_IV[6] | 0;
	H = SHA256_IV[7] | 0;
	constructor() {
		super(32);
	}
};
var K512 = split([
	"0x428a2f98d728ae22",
	"0x7137449123ef65cd",
	"0xb5c0fbcfec4d3b2f",
	"0xe9b5dba58189dbbc",
	"0x3956c25bf348b538",
	"0x59f111f1b605d019",
	"0x923f82a4af194f9b",
	"0xab1c5ed5da6d8118",
	"0xd807aa98a3030242",
	"0x12835b0145706fbe",
	"0x243185be4ee4b28c",
	"0x550c7dc3d5ffb4e2",
	"0x72be5d74f27b896f",
	"0x80deb1fe3b1696b1",
	"0x9bdc06a725c71235",
	"0xc19bf174cf692694",
	"0xe49b69c19ef14ad2",
	"0xefbe4786384f25e3",
	"0x0fc19dc68b8cd5b5",
	"0x240ca1cc77ac9c65",
	"0x2de92c6f592b0275",
	"0x4a7484aa6ea6e483",
	"0x5cb0a9dcbd41fbd4",
	"0x76f988da831153b5",
	"0x983e5152ee66dfab",
	"0xa831c66d2db43210",
	"0xb00327c898fb213f",
	"0xbf597fc7beef0ee4",
	"0xc6e00bf33da88fc2",
	"0xd5a79147930aa725",
	"0x06ca6351e003826f",
	"0x142929670a0e6e70",
	"0x27b70a8546d22ffc",
	"0x2e1b21385c26c926",
	"0x4d2c6dfc5ac42aed",
	"0x53380d139d95b3df",
	"0x650a73548baf63de",
	"0x766a0abb3c77b2a8",
	"0x81c2c92e47edaee6",
	"0x92722c851482353b",
	"0xa2bfe8a14cf10364",
	"0xa81a664bbc423001",
	"0xc24b8b70d0f89791",
	"0xc76c51a30654be30",
	"0xd192e819d6ef5218",
	"0xd69906245565a910",
	"0xf40e35855771202a",
	"0x106aa07032bbd1b8",
	"0x19a4c116b8d2d0c8",
	"0x1e376c085141ab53",
	"0x2748774cdf8eeb99",
	"0x34b0bcb5e19b48a8",
	"0x391c0cb3c5c95a63",
	"0x4ed8aa4ae3418acb",
	"0x5b9cca4f7763e373",
	"0x682e6ff3d6b2b8a3",
	"0x748f82ee5defb2fc",
	"0x78a5636f43172f60",
	"0x84c87814a1f0ab72",
	"0x8cc702081a6439ec",
	"0x90befffa23631e28",
	"0xa4506cebde82bde9",
	"0xbef9a3f7b2c67915",
	"0xc67178f2e372532b",
	"0xca273eceea26619c",
	"0xd186b8c721c0c207",
	"0xeada7dd6cde0eb1e",
	"0xf57d4f7fee6ed178",
	"0x06f067aa72176fba",
	"0x0a637dc5a2c898a6",
	"0x113f9804bef90dae",
	"0x1b710b35131c471b",
	"0x28db77f523047d84",
	"0x32caab7b40c72493",
	"0x3c9ebe0a15c9bebc",
	"0x431d67c49c100d4c",
	"0x4cc5d4becb3e42b6",
	"0x597f299cfc657e2a",
	"0x5fcb6fab3ad6faec",
	"0x6c44198c4a475817"
].map((n) => BigInt(n)));
var SHA512_Kh = K512[0];
var SHA512_Kl = K512[1];
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
/** Internal 64-byte base SHA2 hash class. */
var SHA2_64B = class extends HashMD {
	constructor(outputLen) {
		super(128, outputLen, 16, false);
	}
	get() {
		const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
		return [
			Ah,
			Al,
			Bh,
			Bl,
			Ch,
			Cl,
			Dh,
			Dl,
			Eh,
			El,
			Fh,
			Fl,
			Gh,
			Gl,
			Hh,
			Hl
		];
	}
	set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
		this.Ah = Ah | 0;
		this.Al = Al | 0;
		this.Bh = Bh | 0;
		this.Bl = Bl | 0;
		this.Ch = Ch | 0;
		this.Cl = Cl | 0;
		this.Dh = Dh | 0;
		this.Dl = Dl | 0;
		this.Eh = Eh | 0;
		this.El = El | 0;
		this.Fh = Fh | 0;
		this.Fl = Fl | 0;
		this.Gh = Gh | 0;
		this.Gl = Gl | 0;
		this.Hh = Hh | 0;
		this.Hl = Hl | 0;
	}
	process(view, offset) {
		for (let i = 0; i < 16; i++, offset += 4) {
			SHA512_W_H[i] = view.getUint32(offset);
			SHA512_W_L[i] = view.getUint32(offset += 4);
		}
		for (let i = 16; i < 80; i++) {
			const W15h = SHA512_W_H[i - 15] | 0;
			const W15l = SHA512_W_L[i - 15] | 0;
			const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
			const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
			const W2h = SHA512_W_H[i - 2] | 0;
			const W2l = SHA512_W_L[i - 2] | 0;
			const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
			const SUMl = add4L(s0l, rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6), SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
			SHA512_W_H[i] = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]) | 0;
			SHA512_W_L[i] = SUMl | 0;
		}
		let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
		for (let i = 0; i < 80; i++) {
			const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
			const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
			const CHIh = Eh & Fh ^ ~Eh & Gh;
			const CHIl = El & Fl ^ ~El & Gl;
			const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
			const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
			const T1l = T1ll | 0;
			const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
			const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
			const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
			const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
			Hh = Gh | 0;
			Hl = Gl | 0;
			Gh = Fh | 0;
			Gl = Fl | 0;
			Fh = Eh | 0;
			Fl = El | 0;
			({h: Eh, l: El} = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
			Dh = Ch | 0;
			Dl = Cl | 0;
			Ch = Bh | 0;
			Cl = Bl | 0;
			Bh = Ah | 0;
			Bl = Al | 0;
			const All = add3L(T1l, sigma0l, MAJl);
			Ah = add3H(All, T1h, sigma0h, MAJh);
			Al = All | 0;
		}
		({h: Ah, l: Al} = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
		({h: Bh, l: Bl} = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
		({h: Ch, l: Cl} = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
		({h: Dh, l: Dl} = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
		({h: Eh, l: El} = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
		({h: Fh, l: Fl} = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
		({h: Gh, l: Gl} = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
		({h: Hh, l: Hl} = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
		this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
	}
	roundClean() {
		clean(SHA512_W_H, SHA512_W_L);
	}
	destroy() {
		clean(this.buffer);
		this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
};
/** Internal SHA2-512 hash class. */
var _SHA512 = class extends SHA2_64B {
	Ah = SHA512_IV[0] | 0;
	Al = SHA512_IV[1] | 0;
	Bh = SHA512_IV[2] | 0;
	Bl = SHA512_IV[3] | 0;
	Ch = SHA512_IV[4] | 0;
	Cl = SHA512_IV[5] | 0;
	Dh = SHA512_IV[6] | 0;
	Dl = SHA512_IV[7] | 0;
	Eh = SHA512_IV[8] | 0;
	El = SHA512_IV[9] | 0;
	Fh = SHA512_IV[10] | 0;
	Fl = SHA512_IV[11] | 0;
	Gh = SHA512_IV[12] | 0;
	Gl = SHA512_IV[13] | 0;
	Hh = SHA512_IV[14] | 0;
	Hl = SHA512_IV[15] | 0;
	constructor() {
		super(64);
	}
};
/**
* SHA2-256 hash function from RFC 4634. In JS it's the fastest: even faster than Blake3. Some info:
*
* - Trying 2^128 hashes would get 50% chance of collision, using birthday attack.
* - BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
* - Each sha256 hash is executing 2^18 bit operations.
* - Good 2024 ASICs can do 200Th/sec with 3500 watts of power, corresponding to 2^36 hashes/joule.
*/
var sha256 = /* @__PURE__ */ createHasher(() => new _SHA256(), /* @__PURE__ */ oidNist(1));
/** SHA2-512 hash function from RFC 4634. */
var sha512 = /* @__PURE__ */ createHasher(() => new _SHA512(), /* @__PURE__ */ oidNist(3));
//#endregion
//#region ../node_modules/.pnpm/canonicalize@2.1.0/node_modules/canonicalize/lib/canonicalize.js
var require_canonicalize = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = function serialize(object) {
		if (typeof object === "number" && isNaN(object)) throw new Error("NaN is not allowed");
		if (typeof object === "number" && !isFinite(object)) throw new Error("Infinity is not allowed");
		if (object === null || typeof object !== "object") return JSON.stringify(object);
		if (object.toJSON instanceof Function) return serialize(object.toJSON());
		if (Array.isArray(object)) return `[${object.reduce((t, cv, ci) => {
			return `${t}${ci === 0 ? "" : ","}${serialize(cv === void 0 || typeof cv === "symbol" ? null : cv)}`;
		}, "")}]`;
		return `{${Object.keys(object).sort().reduce((t, cv) => {
			if (object[cv] === void 0 || typeof object[cv] === "symbol") return t;
			return `${t}${t.length === 0 ? "" : ","}${serialize(cv)}:${serialize(object[cv])}`;
		}, "")}}`;
	};
}));
//#endregion
//#region ../node_modules/.pnpm/uuid@13.0.0/node_modules/uuid/dist/stringify.js
var byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));
function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
//#endregion
//#region ../node_modules/.pnpm/uuid@13.0.0/node_modules/uuid/dist/rng.js
var getRandomValues$1;
var rnds8 = new Uint8Array(16);
function rng() {
	if (!getRandomValues$1) {
		if (typeof crypto === "undefined" || !crypto.getRandomValues) throw new Error("crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported");
		getRandomValues$1 = crypto.getRandomValues.bind(crypto);
	}
	return getRandomValues$1(rnds8);
}
var native_default = { randomUUID: typeof crypto !== "undefined" && crypto.randomUUID && crypto.randomUUID.bind(crypto) };
//#endregion
//#region ../node_modules/.pnpm/uuid@13.0.0/node_modules/uuid/dist/v4.js
function _v4(options, buf, offset) {
	options = options || {};
	const rnds = options.random ?? options.rng?.() ?? rng();
	if (rnds.length < 16) throw new Error("Random bytes length must be >= 16");
	rnds[6] = rnds[6] & 15 | 64;
	rnds[8] = rnds[8] & 63 | 128;
	if (buf) {
		offset = offset || 0;
		if (offset < 0 || offset + 16 > buf.length) throw new RangeError(`UUID byte range ${offset}:${offset + 15} is out of buffer bounds`);
		for (let i = 0; i < 16; ++i) buf[offset + i] = rnds[i];
		return buf;
	}
	return unsafeStringify(rnds);
}
function v4(options, buf, offset) {
	if (native_default.randomUUID && !buf && !options) return native_default.randomUUID();
	return _v4(options, buf, offset);
}
//#endregion
//#region ../polyfills/personal-graph/dist/chunk-HC6TLNCU.js
var import_canonicalize = /* @__PURE__ */ __toESM(require_canonicalize(), 1);
var etc2$1 = etc;
if (etc2$1 && !etc2$1.sha512Sync) {
	etc2$1.sha512Sync = (...msgs) => {
		const merged = new Uint8Array(msgs.reduce((acc, m) => acc + m.length, 0));
		let offset = 0;
		for (const m of msgs) {
			merged.set(m, offset);
			offset += m.length;
		}
		return sha512(merged);
	};
	etc2$1.sha512Async = async (...msgs) => {
		return etc2$1.sha512Sync(...msgs);
	};
}
var EphemeralIdentity = class {
	privateKey;
	publicKey;
	did;
	ready;
	constructor() {
		this.privateKey = (utils.randomPrivateKey || utils.randomSecretKey)();
		this.publicKey = new Uint8Array(0);
		this.did = "";
		this.ready = this.init();
	}
	async init() {
		this.publicKey = await getPublicKeyAsync(this.privateKey);
		this.did = `did:key:z6Mk${bytesToHex(this.publicKey).slice(0, 32)}`;
	}
	async ensureReady() {
		await this.ready;
	}
	getDID() {
		return this.did;
	}
	getKeyURI() {
		return `${this.did}#key-1`;
	}
	async sign(data) {
		await this.ready;
		return signAsync(data, this.privateKey);
	}
	getPublicKey() {
		return this.publicKey;
	}
};
function computeSignaturePayload(triple, timestamp) {
	const message = (0, import_canonicalize.default)({
		source: triple.source,
		target: triple.target,
		predicate: triple.predicate
	}) + timestamp;
	return sha256(new TextEncoder().encode(message));
}
async function signTriple(triple, identity) {
	const timestamp = (/* @__PURE__ */ new Date()).toISOString();
	const payload = computeSignaturePayload(triple, timestamp);
	const signature = await identity.sign(payload);
	const proof = {
		key: identity.getKeyURI(),
		signature: bytesToHex(signature)
	};
	return {
		data: triple,
		author: identity.getDID(),
		timestamp,
		proof
	};
}
var TripleEvent = class extends Event {
	triple;
	constructor(type, triple) {
		super(type);
		this.triple = triple;
	}
};
var DEFAULT_QUOTA_BYTES = 50 * 1024 * 1024;
var PersonalGraph = class extends EventTarget {
	uuid;
	name;
	state = "private";
	triples = [];
	identity;
	storage;
	_ontripleadded = null;
	_ontripleremoved = null;
	_quotaBytes = DEFAULT_QUOTA_BYTES;
	_usedBytes = 0;
	_channel = null;
	_instanceId;
	constructor(uuid, name, identity, storage) {
		super();
		this.uuid = uuid;
		this.name = name;
		this.identity = identity;
		this.storage = storage;
		this._instanceId = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : v4();
		if (typeof BroadcastChannel !== "undefined") {
			this._channel = new BroadcastChannel(`living-web-graph-${this.uuid}`);
			this._channel.onmessage = (event) => {
				if (event.data.origin === this._instanceId) return;
				if (event.data.type === "triple-added") this._addTripleFromRemote(event.data.triple);
				else if (event.data.type === "triple-removed") this._removeTripleFromRemote(event.data.triple);
			};
		}
	}
	/** Add a triple received from another tab (no re-broadcast) */
	_addTripleFromRemote(triple) {
		if (this.triples.some((t) => t.data.source === triple.data.source && t.data.target === triple.data.target && t.data.predicate === triple.data.predicate && t.author === triple.author && t.timestamp === triple.timestamp)) return;
		this.triples.push(triple);
		this.storage.saveTriple(this.uuid, triple);
		this.dispatchEvent(new TripleEvent("tripleadded", triple));
	}
	/** Remove a triple received from another tab (no re-broadcast) */
	_removeTripleFromRemote(triple) {
		const idx = this.triples.findIndex((t) => t.data.source === triple.data.source && t.data.target === triple.data.target && t.data.predicate === triple.data.predicate && t.author === triple.author && t.timestamp === triple.timestamp);
		if (idx === -1) return;
		const removed = this.triples.splice(idx, 1)[0];
		this.storage.removeTriple(this.uuid, triple);
		this.dispatchEvent(new TripleEvent("tripleremoved", removed));
	}
	async _loadFromStorage() {
		this.triples = await this.storage.loadTriples(this.uuid);
		this._usedBytes = this.triples.reduce((sum, t) => sum + this._estimateTripleSize(t), 0);
	}
	get ontripleadded() {
		return this._ontripleadded;
	}
	set ontripleadded(handler) {
		if (this._ontripleadded) this.removeEventListener("tripleadded", this._ontripleadded);
		this._ontripleadded = handler;
		if (handler) this.addEventListener("tripleadded", handler);
	}
	get ontripleremoved() {
		return this._ontripleremoved;
	}
	set ontripleremoved(handler) {
		if (this._ontripleremoved) this.removeEventListener("tripleremoved", this._ontripleremoved);
		this._ontripleremoved = handler;
		if (handler) this.addEventListener("tripleremoved", handler);
	}
	/** §7.4 Get/set storage quota in bytes */
	get quotaBytes() {
		return this._quotaBytes;
	}
	set quotaBytes(value) {
		this._quotaBytes = value;
	}
	get usedBytes() {
		return this._usedBytes;
	}
	_estimateTripleSize(signed) {
		return JSON.stringify(signed).length * 2;
	}
	_checkQuota(additionalBytes) {
		if (this._usedBytes + additionalBytes > this._quotaBytes) throw new DOMException("Storage quota exceeded", "QuotaExceededError");
	}
	async addTriple(triple) {
		if (!this.identity.getDID()) throw new DOMException("No active identity", "InvalidStateError");
		const signed = await signTriple(triple, this.identity);
		const size = this._estimateTripleSize(signed);
		this._checkQuota(size);
		this.triples.push(signed);
		this._usedBytes += size;
		await this.storage.saveTriple(this.uuid, signed);
		this.dispatchEvent(new TripleEvent("tripleadded", signed));
		this._broadcast("triple-added", signed);
		return signed;
	}
	async addTriples(triples) {
		if (!this.identity.getDID()) throw new DOMException("No active identity", "InvalidStateError");
		const signed = [];
		let totalSize = 0;
		for (const triple of triples) {
			const s = await signTriple(triple, this.identity);
			signed.push(s);
			totalSize += this._estimateTripleSize(s);
		}
		this._checkQuota(totalSize);
		this.triples.push(...signed);
		this._usedBytes += totalSize;
		await this.storage.saveTriples(this.uuid, signed);
		for (const s of signed) {
			this.dispatchEvent(new TripleEvent("tripleadded", s));
			this._broadcast("triple-added", s);
		}
		return signed;
	}
	async removeTriple(triple) {
		const idx = this.triples.findIndex((t) => t.data.source === triple.data.source && t.data.target === triple.data.target && t.data.predicate === triple.data.predicate && t.author === triple.author && t.timestamp === triple.timestamp);
		if (idx === -1) return false;
		const removed = this.triples.splice(idx, 1)[0];
		await this.storage.removeTriple(this.uuid, triple);
		this.dispatchEvent(new TripleEvent("tripleremoved", removed));
		this._broadcast("triple-removed", removed);
		return true;
	}
	/** Broadcast a triple event to other tabs */
	_broadcast(type, triple) {
		this._channel?.postMessage({
			type,
			triple,
			origin: this._instanceId
		});
	}
	async queryTriples(query) {
		let results = this.triples.filter((t) => {
			if (query.source != null && t.data.source !== query.source) return false;
			if (query.target != null && t.data.target !== query.target) return false;
			if (query.predicate != null && t.data.predicate !== query.predicate) return false;
			if (query.fromDate != null && t.timestamp < query.fromDate) return false;
			if (query.untilDate != null && t.timestamp >= query.untilDate) return false;
			return true;
		});
		results.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
		if (query.limit != null) results = results.slice(0, query.limit);
		return results;
	}
	async querySparql(sparql) {
		const selectMatch = sparql.match(/SELECT\s+([\s\S]*?)\s+WHERE\s*\{([\s\S]*?)\}/i);
		if (!selectMatch) throw new DOMException("Only basic SELECT queries are supported in this polyfill", "NotSupportedError");
		const varsStr = selectMatch[1].trim();
		const bodyStr = selectMatch[2].trim();
		const limitMatch = sparql.match(/LIMIT\s+(\d+)/i);
		const limit = limitMatch ? parseInt(limitMatch[1]) : void 0;
		const vars = varsStr.split(/\s+/).filter((v) => v.startsWith("?")).map((v) => v.slice(1));
		const patterns = this.parseBGPs(bodyStr);
		if (patterns.length === 0) return {
			type: "bindings",
			bindings: []
		};
		let bindings = [{}];
		for (const pattern of patterns) bindings = this.matchPattern(bindings, pattern);
		let projected = bindings.map((b) => {
			const result = {};
			for (const v of vars) if (b[v] !== void 0) result[v] = b[v];
			return result;
		});
		if (limit !== void 0) projected = projected.slice(0, limit);
		return {
			type: "bindings",
			bindings: projected
		};
	}
	parseBGPs(body) {
		const patterns = [];
		const normalized = body.replace(/\s+/g, " ").trim();
		const statements = [];
		let current = "";
		let inBracket = false;
		for (let i = 0; i < normalized.length; i++) {
			const ch = normalized[i];
			if (ch === "<") inBracket = true;
			if (ch === ">") inBracket = false;
			if (ch === "." && !inBracket) {
				const trimmed2 = current.trim();
				if (trimmed2) statements.push(trimmed2);
				current = "";
			} else current += ch;
		}
		const trimmed = current.trim();
		if (trimmed) statements.push(trimmed);
		for (const stmt of statements) {
			const parts = stmt.match(/^(\S+)\s+((?:<[^>]+>)|\S+)\s+((?:<[^>]+>)|\S+|"[^"]*")$/);
			if (parts) patterns.push({
				s: parts[1],
				p: parts[2],
				o: parts[3]
			});
		}
		return patterns;
	}
	matchPattern(bindings, pattern) {
		const results = [];
		for (const binding of bindings) for (const triple of this.triples) {
			const newBinding = { ...binding };
			if (!this.matchTerm(pattern.s, triple.data.source, newBinding)) continue;
			if (!this.matchTerm(pattern.p, triple.data.predicate ?? "", newBinding)) continue;
			if (!this.matchTerm(pattern.o, triple.data.target, newBinding)) continue;
			results.push(newBinding);
		}
		return results;
	}
	matchTerm(pattern, value, binding) {
		if (pattern.startsWith("?")) {
			const varName = pattern.slice(1);
			if (binding[varName] !== void 0) return binding[varName] === value;
			binding[varName] = value;
			return true;
		}
		return pattern.replace(/^<|>$/g, "") === value;
	}
	async snapshot() {
		return [...this.triples].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
	}
};
var DB_VERSION$1 = 1;
var GRAPHS_STORE = "graphs";
var TRIPLES_STORE = "triples";
function openDB$1(dbName) {
	return new Promise((resolve, reject) => {
		const request = indexedDB.open(dbName, DB_VERSION$1);
		request.onupgradeneeded = () => {
			const db = request.result;
			if (!db.objectStoreNames.contains(GRAPHS_STORE)) db.createObjectStore(GRAPHS_STORE, { keyPath: "uuid" });
			if (!db.objectStoreNames.contains(TRIPLES_STORE)) db.createObjectStore(TRIPLES_STORE, { autoIncrement: true }).createIndex("graphUuid", "graphUuid", { unique: false });
		};
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}
function tx(db, stores, mode, fn) {
	return new Promise((resolve, reject) => {
		const req = fn(db.transaction(stores, mode));
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
function txAll(db, stores, mode, fn) {
	return new Promise((resolve, reject) => {
		const req = fn(db.transaction(stores, mode));
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
var GraphStorage = class {
	db = null;
	dbName;
	constructor(dbName = "living-web-personal-graph") {
		this.dbName = dbName;
	}
	async getDB() {
		if (!this.db) this.db = await openDB$1(this.dbName);
		return this.db;
	}
	close() {
		if (this.db) {
			this.db.close();
			this.db = null;
		}
	}
	async saveGraph(uuid, name) {
		const db = await this.getDB();
		const record = {
			uuid,
			name,
			createdAt: (/* @__PURE__ */ new Date()).toISOString()
		};
		await tx(db, [GRAPHS_STORE], "readwrite", (t) => t.objectStore(GRAPHS_STORE).put(record));
	}
	async listGraphs() {
		return txAll(await this.getDB(), [GRAPHS_STORE], "readonly", (t) => t.objectStore(GRAPHS_STORE).getAll());
	}
	async getGraph(uuid) {
		return tx(await this.getDB(), [GRAPHS_STORE], "readonly", (t) => t.objectStore(GRAPHS_STORE).get(uuid));
	}
	async removeGraph(uuid) {
		const db = await this.getDB();
		if (!await this.getGraph(uuid)) return false;
		await tx(db, [GRAPHS_STORE], "readwrite", (t) => t.objectStore(GRAPHS_STORE).delete(uuid));
		await this.removeAllTriples(uuid);
		return true;
	}
	async saveTriple(graphUuid, triple) {
		await tx(await this.getDB(), [TRIPLES_STORE], "readwrite", (t) => t.objectStore(TRIPLES_STORE).add({
			graphUuid,
			...this.serializeTriple(triple)
		}));
	}
	async saveTriples(graphUuid, triples) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const transaction = db.transaction([TRIPLES_STORE], "readwrite");
			const store = transaction.objectStore(TRIPLES_STORE);
			for (const triple of triples) store.add({
				graphUuid,
				...this.serializeTriple(triple)
			});
			transaction.oncomplete = () => resolve();
			transaction.onerror = () => reject(transaction.error);
		});
	}
	async removeTriple(graphUuid, triple) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const request = db.transaction([TRIPLES_STORE], "readwrite").objectStore(TRIPLES_STORE).index("graphUuid").openCursor(IDBKeyRange.only(graphUuid));
			let found = false;
			request.onsuccess = () => {
				const cursor = request.result;
				if (cursor) {
					const record = cursor.value;
					if (this.tripleMatches(record, triple)) {
						cursor.delete();
						found = true;
					}
					cursor.continue();
				} else resolve(found);
			};
			request.onerror = () => reject(request.error);
		});
	}
	async loadTriples(graphUuid) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const request = db.transaction([TRIPLES_STORE], "readonly").objectStore(TRIPLES_STORE).index("graphUuid").getAll(IDBKeyRange.only(graphUuid));
			request.onsuccess = () => {
				const records = request.result;
				resolve(records.map((r) => this.deserializeTriple(r)));
			};
			request.onerror = () => reject(request.error);
		});
	}
	async removeAllTriples(graphUuid) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const request = db.transaction([TRIPLES_STORE], "readwrite").objectStore(TRIPLES_STORE).index("graphUuid").openCursor(IDBKeyRange.only(graphUuid));
			request.onsuccess = () => {
				const cursor = request.result;
				if (cursor) {
					cursor.delete();
					cursor.continue();
				} else resolve();
			};
			request.onerror = () => reject(request.error);
		});
	}
	serializeTriple(triple) {
		return {
			source: triple.data.source,
			target: triple.data.target,
			predicate: triple.data.predicate,
			author: triple.author,
			timestamp: triple.timestamp,
			proofKey: triple.proof.key,
			proofSignature: triple.proof.signature
		};
	}
	deserializeTriple(record) {
		const { SemanticTriple: _unused, ...rest } = record;
		return {
			data: {
				source: record.source,
				target: record.target,
				predicate: record.predicate
			},
			author: record.author,
			timestamp: record.timestamp,
			proof: {
				key: record.proofKey,
				signature: record.proofSignature
			}
		};
	}
	tripleMatches(record, triple) {
		return record.source === triple.data.source && record.target === triple.data.target && record.predicate === triple.data.predicate && record.author === triple.author && record.timestamp === triple.timestamp;
	}
};
var PersonalGraphManager = class {
	graphs = /* @__PURE__ */ new Map();
	identity;
	storage;
	initialized = false;
	constructor(identity, dbName) {
		this.identity = identity ?? new EphemeralIdentity();
		this.storage = new GraphStorage(dbName);
	}
	async ensureInit() {
		if (this.initialized) return;
		if (this.identity instanceof EphemeralIdentity) await this.identity.ensureReady();
		const records = await this.storage.listGraphs();
		for (const record of records) {
			const graph = new PersonalGraph(record.uuid, record.name, this.identity, this.storage);
			await graph._loadFromStorage();
			this.graphs.set(record.uuid, graph);
		}
		this.initialized = true;
	}
	async create(name) {
		await this.ensureInit();
		const uuid = v4();
		const graphName = name ?? null;
		await this.storage.saveGraph(uuid, graphName);
		const graph = new PersonalGraph(uuid, graphName, this.identity, this.storage);
		this.graphs.set(uuid, graph);
		return graph;
	}
	async list() {
		await this.ensureInit();
		return Array.from(this.graphs.values());
	}
	async get(uuid) {
		await this.ensureInit();
		return this.graphs.get(uuid) ?? null;
	}
	async remove(uuid) {
		await this.ensureInit();
		if (!this.graphs.has(uuid)) return false;
		const success = await this.storage.removeGraph(uuid);
		if (success) this.graphs.delete(uuid);
		return success;
	}
};
//#endregion
//#region ../polyfills/personal-graph/dist/index.js
var dist_exports = /* @__PURE__ */ __exportAll({
	SemanticTriple: () => SemanticTriple,
	signTriple: () => signTriple
});
var SemanticTriple = class {
	source;
	target;
	predicate;
	constructor(source, target, predicate) {
		if (!isValidURI(source)) throw new TypeError(`Invalid source URI: ${source}`);
		if (predicate != null && !isValidURI(predicate)) throw new TypeError(`Invalid predicate URI: ${predicate}`);
		if (typeof target !== "string" || target.length === 0) throw new TypeError("Target must be a non-empty string");
		this.source = source;
		this.target = target;
		this.predicate = predicate ?? null;
	}
};
function isValidURI(value) {
	return /^[a-zA-Z][a-zA-Z0-9+\-.]*:.+$/.test(value);
}
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/_blake.js
/**
* Internal blake variable.
* For BLAKE2b, the two extra permutations for rounds 10 and 11 are SIGMA[10..11] = SIGMA[0..1].
*/
var BSIGMA = /* @__PURE__ */ Uint8Array.from([
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	14,
	10,
	4,
	8,
	9,
	15,
	13,
	6,
	1,
	12,
	0,
	2,
	11,
	7,
	5,
	3,
	11,
	8,
	12,
	0,
	5,
	2,
	15,
	13,
	10,
	14,
	3,
	6,
	7,
	1,
	9,
	4,
	7,
	9,
	3,
	1,
	13,
	12,
	11,
	14,
	2,
	6,
	5,
	10,
	4,
	0,
	15,
	8,
	9,
	0,
	5,
	7,
	2,
	4,
	10,
	15,
	14,
	1,
	11,
	12,
	6,
	8,
	3,
	13,
	2,
	12,
	6,
	10,
	0,
	11,
	8,
	3,
	4,
	13,
	7,
	5,
	15,
	14,
	1,
	9,
	12,
	5,
	1,
	15,
	14,
	13,
	4,
	10,
	0,
	7,
	6,
	3,
	9,
	2,
	8,
	11,
	13,
	11,
	7,
	14,
	12,
	1,
	3,
	9,
	5,
	0,
	15,
	4,
	8,
	6,
	2,
	10,
	6,
	15,
	14,
	9,
	11,
	3,
	0,
	8,
	12,
	2,
	13,
	7,
	1,
	4,
	10,
	5,
	10,
	2,
	8,
	4,
	7,
	6,
	1,
	5,
	15,
	11,
	9,
	14,
	3,
	12,
	13,
	0,
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	14,
	10,
	4,
	8,
	9,
	15,
	13,
	6,
	1,
	12,
	0,
	2,
	11,
	7,
	5,
	3,
	11,
	8,
	12,
	0,
	5,
	2,
	15,
	13,
	10,
	14,
	3,
	6,
	7,
	1,
	9,
	4,
	7,
	9,
	3,
	1,
	13,
	12,
	11,
	14,
	2,
	6,
	5,
	10,
	4,
	0,
	15,
	8,
	9,
	0,
	5,
	7,
	2,
	4,
	10,
	15,
	14,
	1,
	11,
	12,
	6,
	8,
	3,
	13,
	2,
	12,
	6,
	10,
	0,
	11,
	8,
	3,
	4,
	13,
	7,
	5,
	15,
	14,
	1,
	9
]);
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/blake2.js
/**
* blake2b (64-bit) & blake2s (8 to 32-bit) hash functions.
* b could have been faster, but there is no fast u64 in js, so s is 1.5x faster.
* @module
*/
var B2B_IV = /* @__PURE__ */ Uint32Array.from([
	4089235720,
	1779033703,
	2227873595,
	3144134277,
	4271175723,
	1013904242,
	1595750129,
	2773480762,
	2917565137,
	1359893119,
	725511199,
	2600822924,
	4215389547,
	528734635,
	327033209,
	1541459225
]);
var BBUF = /* @__PURE__ */ new Uint32Array(32);
function G1b(a, b, c, d, msg, x) {
	const Xl = msg[x], Xh = msg[x + 1];
	let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
	let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
	let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
	let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
	let ll = add3L(Al, Bl, Xl);
	Ah = add3H(ll, Ah, Bh, Xh);
	Al = ll | 0;
	({Dh, Dl} = {
		Dh: Dh ^ Ah,
		Dl: Dl ^ Al
	});
	({Dh, Dl} = {
		Dh: rotr32H(Dh, Dl),
		Dl: rotr32L(Dh, Dl)
	});
	({h: Ch, l: Cl} = add(Ch, Cl, Dh, Dl));
	({Bh, Bl} = {
		Bh: Bh ^ Ch,
		Bl: Bl ^ Cl
	});
	({Bh, Bl} = {
		Bh: rotrSH(Bh, Bl, 24),
		Bl: rotrSL(Bh, Bl, 24)
	});
	BBUF[2 * a] = Al, BBUF[2 * a + 1] = Ah;
	BBUF[2 * b] = Bl, BBUF[2 * b + 1] = Bh;
	BBUF[2 * c] = Cl, BBUF[2 * c + 1] = Ch;
	BBUF[2 * d] = Dl, BBUF[2 * d + 1] = Dh;
}
function G2b(a, b, c, d, msg, x) {
	const Xl = msg[x], Xh = msg[x + 1];
	let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
	let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
	let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
	let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
	let ll = add3L(Al, Bl, Xl);
	Ah = add3H(ll, Ah, Bh, Xh);
	Al = ll | 0;
	({Dh, Dl} = {
		Dh: Dh ^ Ah,
		Dl: Dl ^ Al
	});
	({Dh, Dl} = {
		Dh: rotrSH(Dh, Dl, 16),
		Dl: rotrSL(Dh, Dl, 16)
	});
	({h: Ch, l: Cl} = add(Ch, Cl, Dh, Dl));
	({Bh, Bl} = {
		Bh: Bh ^ Ch,
		Bl: Bl ^ Cl
	});
	({Bh, Bl} = {
		Bh: rotrBH(Bh, Bl, 63),
		Bl: rotrBL(Bh, Bl, 63)
	});
	BBUF[2 * a] = Al, BBUF[2 * a + 1] = Ah;
	BBUF[2 * b] = Bl, BBUF[2 * b + 1] = Bh;
	BBUF[2 * c] = Cl, BBUF[2 * c + 1] = Ch;
	BBUF[2 * d] = Dl, BBUF[2 * d + 1] = Dh;
}
function checkBlake2Opts(outputLen, opts = {}, keyLen, saltLen, persLen) {
	anumber(keyLen);
	if (outputLen < 0 || outputLen > keyLen) throw new Error("outputLen bigger than keyLen");
	const { key, salt, personalization } = opts;
	if (key !== void 0 && (key.length < 1 || key.length > keyLen)) throw new Error("\"key\" expected to be undefined or of length=1.." + keyLen);
	if (salt !== void 0) abytes(salt, saltLen, "salt");
	if (personalization !== void 0) abytes(personalization, persLen, "personalization");
}
/** Internal base class for BLAKE2. */
var _BLAKE2 = class {
	buffer;
	buffer32;
	finished = false;
	destroyed = false;
	length = 0;
	pos = 0;
	blockLen;
	outputLen;
	constructor(blockLen, outputLen) {
		anumber(blockLen);
		anumber(outputLen);
		this.blockLen = blockLen;
		this.outputLen = outputLen;
		this.buffer = new Uint8Array(blockLen);
		this.buffer32 = u32(this.buffer);
	}
	update(data) {
		aexists(this);
		abytes(data);
		const { blockLen, buffer, buffer32 } = this;
		const len = data.length;
		const offset = data.byteOffset;
		const buf = data.buffer;
		for (let pos = 0; pos < len;) {
			if (this.pos === blockLen) {
				swap32IfBE(buffer32);
				this.compress(buffer32, 0, false);
				swap32IfBE(buffer32);
				this.pos = 0;
			}
			const take = Math.min(blockLen - this.pos, len - pos);
			const dataOffset = offset + pos;
			if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
				const data32 = new Uint32Array(buf, dataOffset, Math.floor((len - pos) / 4));
				swap32IfBE(data32);
				for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
					this.length += blockLen;
					this.compress(data32, pos32, false);
				}
				swap32IfBE(data32);
				continue;
			}
			buffer.set(data.subarray(pos, pos + take), this.pos);
			this.pos += take;
			this.length += take;
			pos += take;
		}
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		const { pos, buffer32 } = this;
		this.finished = true;
		clean(this.buffer.subarray(pos));
		swap32IfBE(buffer32);
		this.compress(buffer32, 0, true);
		swap32IfBE(buffer32);
		const out32 = u32(out);
		this.get().forEach((v, i) => out32[i] = swap8IfBE(v));
	}
	digest() {
		const { buffer, outputLen } = this;
		this.digestInto(buffer);
		const res = buffer.slice(0, outputLen);
		this.destroy();
		return res;
	}
	_cloneInto(to) {
		const { buffer, length, finished, destroyed, outputLen, pos } = this;
		to ||= new this.constructor({ dkLen: outputLen });
		to.set(...this.get());
		to.buffer.set(buffer);
		to.destroyed = destroyed;
		to.finished = finished;
		to.length = length;
		to.pos = pos;
		to.outputLen = outputLen;
		return to;
	}
	clone() {
		return this._cloneInto();
	}
};
/** Internal blake2b hash class. */
var _BLAKE2b = class extends _BLAKE2 {
	v0l = B2B_IV[0] | 0;
	v0h = B2B_IV[1] | 0;
	v1l = B2B_IV[2] | 0;
	v1h = B2B_IV[3] | 0;
	v2l = B2B_IV[4] | 0;
	v2h = B2B_IV[5] | 0;
	v3l = B2B_IV[6] | 0;
	v3h = B2B_IV[7] | 0;
	v4l = B2B_IV[8] | 0;
	v4h = B2B_IV[9] | 0;
	v5l = B2B_IV[10] | 0;
	v5h = B2B_IV[11] | 0;
	v6l = B2B_IV[12] | 0;
	v6h = B2B_IV[13] | 0;
	v7l = B2B_IV[14] | 0;
	v7h = B2B_IV[15] | 0;
	constructor(opts = {}) {
		const olen = opts.dkLen === void 0 ? 64 : opts.dkLen;
		super(128, olen);
		checkBlake2Opts(olen, opts, 64, 16, 16);
		let { key, personalization, salt } = opts;
		let keyLength = 0;
		if (key !== void 0) {
			abytes(key, void 0, "key");
			keyLength = key.length;
		}
		this.v0l ^= this.outputLen | keyLength << 8 | 16842752;
		if (salt !== void 0) {
			abytes(salt, void 0, "salt");
			const slt = u32(salt);
			this.v4l ^= swap8IfBE(slt[0]);
			this.v4h ^= swap8IfBE(slt[1]);
			this.v5l ^= swap8IfBE(slt[2]);
			this.v5h ^= swap8IfBE(slt[3]);
		}
		if (personalization !== void 0) {
			abytes(personalization, void 0, "personalization");
			const pers = u32(personalization);
			this.v6l ^= swap8IfBE(pers[0]);
			this.v6h ^= swap8IfBE(pers[1]);
			this.v7l ^= swap8IfBE(pers[2]);
			this.v7h ^= swap8IfBE(pers[3]);
		}
		if (key !== void 0) {
			const tmp = new Uint8Array(this.blockLen);
			tmp.set(key);
			this.update(tmp);
		}
	}
	get() {
		let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
		return [
			v0l,
			v0h,
			v1l,
			v1h,
			v2l,
			v2h,
			v3l,
			v3h,
			v4l,
			v4h,
			v5l,
			v5h,
			v6l,
			v6h,
			v7l,
			v7h
		];
	}
	set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
		this.v0l = v0l | 0;
		this.v0h = v0h | 0;
		this.v1l = v1l | 0;
		this.v1h = v1h | 0;
		this.v2l = v2l | 0;
		this.v2h = v2h | 0;
		this.v3l = v3l | 0;
		this.v3h = v3h | 0;
		this.v4l = v4l | 0;
		this.v4h = v4h | 0;
		this.v5l = v5l | 0;
		this.v5h = v5h | 0;
		this.v6l = v6l | 0;
		this.v6h = v6h | 0;
		this.v7l = v7l | 0;
		this.v7h = v7h | 0;
	}
	compress(msg, offset, isLast) {
		this.get().forEach((v, i) => BBUF[i] = v);
		BBUF.set(B2B_IV, 16);
		let { h, l } = fromBig(BigInt(this.length));
		BBUF[24] = B2B_IV[8] ^ l;
		BBUF[25] = B2B_IV[9] ^ h;
		if (isLast) {
			BBUF[28] = ~BBUF[28];
			BBUF[29] = ~BBUF[29];
		}
		let j = 0;
		const s = BSIGMA;
		for (let i = 0; i < 12; i++) {
			G1b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
			G2b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
			G1b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
			G2b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
			G1b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
			G2b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
			G1b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
			G2b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
			G1b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
			G2b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
			G1b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
			G2b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
			G1b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
			G2b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
			G1b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
			G2b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
		}
		this.v0l ^= BBUF[0] ^ BBUF[16];
		this.v0h ^= BBUF[1] ^ BBUF[17];
		this.v1l ^= BBUF[2] ^ BBUF[18];
		this.v1h ^= BBUF[3] ^ BBUF[19];
		this.v2l ^= BBUF[4] ^ BBUF[20];
		this.v2h ^= BBUF[5] ^ BBUF[21];
		this.v3l ^= BBUF[6] ^ BBUF[22];
		this.v3h ^= BBUF[7] ^ BBUF[23];
		this.v4l ^= BBUF[8] ^ BBUF[24];
		this.v4h ^= BBUF[9] ^ BBUF[25];
		this.v5l ^= BBUF[10] ^ BBUF[26];
		this.v5h ^= BBUF[11] ^ BBUF[27];
		this.v6l ^= BBUF[12] ^ BBUF[28];
		this.v6h ^= BBUF[13] ^ BBUF[29];
		this.v7l ^= BBUF[14] ^ BBUF[30];
		this.v7h ^= BBUF[15] ^ BBUF[31];
		clean(BBUF);
	}
	destroy() {
		this.destroyed = true;
		clean(this.buffer32);
		this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
};
/**
* Blake2b hash function. 64-bit. 1.5x slower than blake2s in JS.
* @param msg - message that would be hashed
* @param opts - dkLen output length, key for MAC mode, salt, personalization
*/
var blake2b = /* @__PURE__ */ createHasher((opts) => new _BLAKE2b(opts));
//#endregion
//#region ../node_modules/.pnpm/@noble+hashes@2.0.1/node_modules/@noble/hashes/argon2.js
/**
* Argon2 KDF from RFC 9106. Can be used to create a key from password and salt.
* We suggest to use Scrypt. JS Argon is 2-10x slower than native code because of 64-bitness:
* * argon uses uint64, but JS doesn't have fast uint64array
* * uint64 multiplication is 1/3 of time
* * `P` function would be very nice with u64, because most of value will be in registers,
*   hovewer with u32 it will require 32 registers, which is too much.
* * JS arrays do slow bound checks, so reading from `A2_BUF` slows it down
* @module
*/
var AT = {
	Argond2d: 0,
	Argon2i: 1,
	Argon2id: 2
};
var ARGON2_SYNC_POINTS = 4;
var abytesOrZero = (buf, errorTitle = "") => {
	if (buf === void 0) return Uint8Array.of();
	return kdfInputToBytes(buf, errorTitle);
};
function mul(a, b) {
	const aL = a & 65535;
	const aH = a >>> 16;
	const bL = b & 65535;
	const bH = b >>> 16;
	const ll = Math.imul(aL, bL);
	const hl = Math.imul(aH, bL);
	const lh = Math.imul(aL, bH);
	const hh = Math.imul(aH, bH);
	const carry = (ll >>> 16) + (hl & 65535) + lh;
	return {
		h: hh + (hl >>> 16) + (carry >>> 16) | 0,
		l: carry << 16 | ll & 65535
	};
}
function mul2(a, b) {
	const { h, l } = mul(a, b);
	return {
		h: (h << 1 | l >>> 31) & 4294967295,
		l: l << 1 & 4294967295
	};
}
function blamka(Ah, Al, Bh, Bl) {
	const { h: Ch, l: Cl } = mul2(Al, Bl);
	const Rll = add3L(Al, Bl, Cl);
	return {
		h: add3H(Rll, Ah, Bh, Ch),
		l: Rll | 0
	};
}
var A2_BUF = new Uint32Array(256);
function G(a, b, c, d) {
	let Al = A2_BUF[2 * a], Ah = A2_BUF[2 * a + 1];
	let Bl = A2_BUF[2 * b], Bh = A2_BUF[2 * b + 1];
	let Cl = A2_BUF[2 * c], Ch = A2_BUF[2 * c + 1];
	let Dl = A2_BUF[2 * d], Dh = A2_BUF[2 * d + 1];
	({h: Ah, l: Al} = blamka(Ah, Al, Bh, Bl));
	({Dh, Dl} = {
		Dh: Dh ^ Ah,
		Dl: Dl ^ Al
	});
	({Dh, Dl} = {
		Dh: rotr32H(Dh, Dl),
		Dl: rotr32L(Dh, Dl)
	});
	({h: Ch, l: Cl} = blamka(Ch, Cl, Dh, Dl));
	({Bh, Bl} = {
		Bh: Bh ^ Ch,
		Bl: Bl ^ Cl
	});
	({Bh, Bl} = {
		Bh: rotrSH(Bh, Bl, 24),
		Bl: rotrSL(Bh, Bl, 24)
	});
	({h: Ah, l: Al} = blamka(Ah, Al, Bh, Bl));
	({Dh, Dl} = {
		Dh: Dh ^ Ah,
		Dl: Dl ^ Al
	});
	({Dh, Dl} = {
		Dh: rotrSH(Dh, Dl, 16),
		Dl: rotrSL(Dh, Dl, 16)
	});
	({h: Ch, l: Cl} = blamka(Ch, Cl, Dh, Dl));
	({Bh, Bl} = {
		Bh: Bh ^ Ch,
		Bl: Bl ^ Cl
	});
	({Bh, Bl} = {
		Bh: rotrBH(Bh, Bl, 63),
		Bl: rotrBL(Bh, Bl, 63)
	});
	A2_BUF[2 * a] = Al, A2_BUF[2 * a + 1] = Ah;
	A2_BUF[2 * b] = Bl, A2_BUF[2 * b + 1] = Bh;
	A2_BUF[2 * c] = Cl, A2_BUF[2 * c + 1] = Ch;
	A2_BUF[2 * d] = Dl, A2_BUF[2 * d + 1] = Dh;
}
function P(v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15) {
	G(v00, v04, v08, v12);
	G(v01, v05, v09, v13);
	G(v02, v06, v10, v14);
	G(v03, v07, v11, v15);
	G(v00, v05, v10, v15);
	G(v01, v06, v11, v12);
	G(v02, v07, v08, v13);
	G(v03, v04, v09, v14);
}
function block(x, xPos, yPos, outPos, needXor) {
	for (let i = 0; i < 256; i++) A2_BUF[i] = x[xPos + i] ^ x[yPos + i];
	for (let i = 0; i < 128; i += 16) P(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
	for (let i = 0; i < 16; i += 2) P(i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49, i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
	if (needXor) for (let i = 0; i < 256; i++) x[outPos + i] ^= A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
	else for (let i = 0; i < 256; i++) x[outPos + i] = A2_BUF[i] ^ x[xPos + i] ^ x[yPos + i];
	clean(A2_BUF);
}
function Hp(A, dkLen) {
	const A8 = u8(A);
	const T = new Uint32Array(1);
	const T8 = u8(T);
	T[0] = dkLen;
	if (dkLen <= 64) return blake2b.create({ dkLen }).update(T8).update(A8).digest();
	const out = new Uint8Array(dkLen);
	let V = blake2b.create({}).update(T8).update(A8).digest();
	let pos = 0;
	out.set(V.subarray(0, 32));
	pos += 32;
	for (; dkLen - pos > 64; pos += 32) {
		const Vh = blake2b.create({}).update(V);
		Vh.digestInto(V);
		Vh.destroy();
		out.set(V.subarray(0, 32), pos);
	}
	out.set(blake2b(V, { dkLen: dkLen - pos }), pos);
	clean(V, T);
	return u32(out);
}
function indexAlpha(r, s, laneLen, segmentLen, index, randL, sameLane = false) {
	let area;
	if (r === 0) if (s === 0) area = index - 1;
	else if (sameLane) area = s * segmentLen + index - 1;
	else area = s * segmentLen + (index == 0 ? -1 : 0);
	else if (sameLane) area = laneLen - segmentLen + index - 1;
	else area = laneLen - segmentLen + (index == 0 ? -1 : 0);
	return ((r !== 0 && s !== ARGON2_SYNC_POINTS - 1 ? (s + 1) * segmentLen : 0) + (area - 1 - mul(area, mul(randL, randL).h).h)) % laneLen;
}
var maxUint32 = Math.pow(2, 32);
function isU32(num) {
	return Number.isSafeInteger(num) && num >= 0 && num < maxUint32;
}
function argon2Opts(opts) {
	const merged = {
		version: 19,
		dkLen: 32,
		maxmem: maxUint32 - 1,
		asyncTick: 10
	};
	for (let [k, v] of Object.entries(opts)) if (v !== void 0) merged[k] = v;
	const { dkLen, p, m, t, version, onProgress, asyncTick } = merged;
	if (!isU32(dkLen) || dkLen < 4) throw new Error("\"dkLen\" must be 4..");
	if (!isU32(p) || p < 1 || p >= Math.pow(2, 24)) throw new Error("\"p\" must be 1..2^24");
	if (!isU32(m)) throw new Error("\"m\" must be 0..2^32");
	if (!isU32(t) || t < 1) throw new Error("\"t\" (iterations) must be 1..2^32");
	if (onProgress !== void 0 && typeof onProgress !== "function") throw new Error("\"progressCb\" must be a function");
	anumber(asyncTick, "asyncTick");
	if (!isU32(m) || m < 8 * p) throw new Error("\"m\" (memory) must be at least 8*p bytes");
	if (version !== 16 && version !== 19) throw new Error("\"version\" must be 0x10 or 0x13, got " + version);
	return merged;
}
function argon2Init(password, salt, type, opts) {
	password = kdfInputToBytes(password, "password");
	salt = kdfInputToBytes(salt, "salt");
	if (!isU32(password.length)) throw new Error("\"password\" must be less of length 1..4Gb");
	if (!isU32(salt.length) || salt.length < 8) throw new Error("\"salt\" must be of length 8..4Gb");
	if (!Object.values(AT).includes(type)) throw new Error("\"type\" was invalid");
	let { p, dkLen, m, t, version, key, personalization, maxmem, onProgress, asyncTick } = argon2Opts(opts);
	key = abytesOrZero(key, "key");
	personalization = abytesOrZero(personalization, "personalization");
	const h = blake2b.create();
	const BUF = new Uint32Array(1);
	const BUF8 = u8(BUF);
	for (let item of [
		p,
		dkLen,
		m,
		t,
		version,
		type
	]) {
		BUF[0] = item;
		h.update(BUF8);
	}
	for (let i of [
		password,
		salt,
		key,
		personalization
	]) {
		BUF[0] = i.length;
		h.update(BUF8).update(i);
	}
	const H0 = new Uint32Array(18);
	const H0_8 = u8(H0);
	h.digestInto(H0_8);
	const lanes = p;
	const mP = 4 * p * Math.floor(m / (ARGON2_SYNC_POINTS * p));
	const laneLen = Math.floor(mP / p);
	const segmentLen = Math.floor(laneLen / ARGON2_SYNC_POINTS);
	const memUsed = mP * 256;
	if (!isU32(maxmem) || memUsed > maxmem) throw new Error("\"maxmem\" expected <2**32, got: maxmem=" + maxmem + ", memused=" + memUsed);
	const B = new Uint32Array(memUsed);
	for (let l = 0; l < p; l++) {
		const i = 256 * laneLen * l;
		H0[17] = l;
		H0[16] = 0;
		B.set(Hp(H0, 1024), i);
		H0[16] = 1;
		B.set(Hp(H0, 1024), i + 256);
	}
	let perBlock = () => {};
	if (onProgress) {
		const totalBlock = t * ARGON2_SYNC_POINTS * p * segmentLen;
		const callbackPer = Math.max(Math.floor(totalBlock / 1e4), 1);
		let blockCnt = 0;
		perBlock = () => {
			blockCnt++;
			if (onProgress && (!(blockCnt % callbackPer) || blockCnt === totalBlock)) onProgress(blockCnt / totalBlock);
		};
	}
	clean(BUF, H0);
	return {
		type,
		mP,
		p,
		t,
		version,
		B,
		laneLen,
		lanes,
		segmentLen,
		dkLen,
		perBlock,
		asyncTick
	};
}
function argon2Output(B, p, laneLen, dkLen) {
	const B_final = new Uint32Array(256);
	for (let l = 0; l < p; l++) for (let j = 0; j < 256; j++) B_final[j] ^= B[256 * (laneLen * l + laneLen - 1) + j];
	const res = u8(Hp(B_final, dkLen));
	clean(B_final);
	return res;
}
function processBlock(B, address, l, r, s, index, laneLen, segmentLen, lanes, offset, prev, dataIndependent, needXor) {
	if (offset % laneLen) prev = offset - 1;
	let randL, randH;
	if (dataIndependent) {
		let i128 = index % 128;
		if (i128 === 0) {
			address[268]++;
			block(address, 256, 2 * 256, 0, false);
			block(address, 0, 2 * 256, 0, false);
		}
		randL = address[2 * i128];
		randH = address[2 * i128 + 1];
	} else {
		const T = 256 * prev;
		randL = B[T];
		randH = B[T + 1];
	}
	const refLane = r === 0 && s === 0 ? l : randH % lanes;
	const refPos = indexAlpha(r, s, laneLen, segmentLen, index, randL, refLane == l);
	const refBlock = laneLen * refLane + refPos;
	block(B, 256 * prev, 256 * refBlock, offset * 256, needXor);
}
function argon2(type, password, salt, opts) {
	const { mP, p, t, version, B, laneLen, lanes, segmentLen, dkLen, perBlock } = argon2Init(password, salt, type, opts);
	const address = new Uint32Array(3 * 256);
	address[262] = mP;
	address[264] = t;
	address[266] = type;
	for (let r = 0; r < t; r++) {
		const needXor = r !== 0 && version === 19;
		address[256] = r;
		for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
			address[260] = s;
			const dataIndependent = type == AT.Argon2i || type == AT.Argon2id && r === 0 && s < 2;
			for (let l = 0; l < p; l++) {
				address[258] = l;
				address[268] = 0;
				let startPos = 0;
				if (r === 0 && s === 0) {
					startPos = 2;
					if (dataIndependent) {
						address[268]++;
						block(address, 256, 2 * 256, 0, false);
						block(address, 0, 2 * 256, 0, false);
					}
				}
				let offset = l * laneLen + s * segmentLen + startPos;
				let prev = offset % laneLen ? offset - 1 : offset + laneLen - 1;
				for (let index = startPos; index < segmentLen; index++, offset++, prev++) {
					perBlock();
					processBlock(B, address, l, r, s, index, laneLen, segmentLen, lanes, offset, prev, dataIndependent, needXor);
				}
			}
		}
	}
	clean(address);
	return argon2Output(B, p, laneLen, dkLen);
}
/** argon2id, combining i+d, the most popular version from RFC 9106 */
var argon2id = (password, salt, opts) => argon2(AT.Argon2id, password, salt, opts);
//#endregion
//#region ../polyfills/identity/dist/chunk-2ZQ5GRHO.js
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(bytes) {
	let zeroes = 0;
	for (let i = 0; i < bytes.length && bytes[i] === 0; i++) zeroes++;
	const size = Math.ceil(bytes.length * 138 / 100) + 1;
	const b58 = new Uint8Array(size);
	let length = 0;
	for (let i = zeroes; i < bytes.length; i++) {
		let carry = bytes[i];
		let j = 0;
		for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
			carry += 256 * b58[k];
			b58[k] = carry % 58;
			carry = Math.floor(carry / 58);
		}
		length = j;
	}
	let str = "1".repeat(zeroes);
	let started = false;
	for (let i = 0; i < size; i++) {
		if (!started && b58[i] === 0) continue;
		started = true;
		str += BASE58_ALPHABET[b58[i]];
	}
	return str || "1";
}
function base58btcDecode(str) {
	let zeroes = 0;
	for (let i = 0; i < str.length && str[i] === "1"; i++) zeroes++;
	const size = Math.ceil(str.length * 733 / 1e3) + 1;
	const b256 = new Uint8Array(size);
	let length = 0;
	for (let i = zeroes; i < str.length; i++) {
		const idx = BASE58_ALPHABET.indexOf(str[i]);
		if (idx === -1) throw new Error(`Invalid base58 character: ${str[i]}`);
		let carry = idx;
		let j = 0;
		for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
			carry += 58 * b256[k];
			b256[k] = carry % 256;
			carry = Math.floor(carry / 256);
		}
		length = j;
	}
	let start = 0;
	while (start < size && b256[start] === 0) start++;
	const result = new Uint8Array(zeroes + (size - start));
	for (let i = 0; i < zeroes; i++) result[i] = 0;
	for (let i = start; i < size; i++) result[zeroes + (i - start)] = b256[i];
	return result;
}
var ED25519_MULTICODEC = new Uint8Array([237, 1]);
function publicKeyToDID(publicKey) {
	if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
	const multicodecKey = new Uint8Array(34);
	multicodecKey.set(ED25519_MULTICODEC, 0);
	multicodecKey.set(publicKey, 2);
	return `did:key:z${base58btcEncode(multicodecKey)}`;
}
function didToPublicKey(did) {
	if (!did.startsWith("did:key:z")) throw new Error("Invalid did:key URI");
	const decoded = base58btcDecode(did.slice(9));
	if (decoded[0] !== 237 || decoded[1] !== 1) throw new Error("Unsupported multicodec prefix (expected Ed25519 0xed01)");
	return decoded.slice(2);
}
function resolveDIDKey(did) {
	if (!did.startsWith("did:key:z")) throw new Error("Invalid did:key URI");
	const multibaseKey = did.slice(8);
	didToPublicKey(did);
	const keyId = `${did}#${multibaseKey}`;
	return {
		"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
		id: did,
		verificationMethod: [{
			id: keyId,
			type: "Ed25519VerificationKey2020",
			controller: did,
			publicKeyMultibase: multibaseKey
		}],
		authentication: [keyId],
		assertionMethod: [keyId]
	};
}
var etc2 = etc;
if (etc2 && !etc2.sha512Sync) {
	etc2.sha512Sync = (...msgs) => {
		const merged = new Uint8Array(msgs.reduce((acc, m) => acc + m.length, 0));
		let offset = 0;
		for (const m of msgs) {
			merged.set(m, offset);
			offset += m.length;
		}
		return sha512(merged);
	};
	etc2.sha512Async = async (...msgs) => {
		return etc2.sha512Sync(...msgs);
	};
}
function computeSigningPayload(data, timestamp) {
	const canonical = (0, import_canonicalize.default)(data);
	if (canonical === void 0) throw new DOMException("Data cannot be canonicalised (circular or non-JSON)", "DataCloneError");
	const message = canonical + timestamp;
	return sha256(new TextEncoder().encode(message));
}
async function signData(data, privateKey, did, keyURI) {
	const timestamp = (/* @__PURE__ */ new Date()).toISOString();
	return {
		data,
		author: did,
		timestamp,
		proof: {
			key: keyURI,
			signature: bytesToHex(await signAsync(computeSigningPayload(data, timestamp), privateKey))
		}
	};
}
async function verifySignedContent(signed) {
	try {
		const publicKey = didToPublicKey(signed.author);
		const payload = computeSigningPayload(signed.data, signed.timestamp);
		return await verifyAsync(hexToBytes(signed.proof.signature), payload, publicKey);
	} catch {
		return false;
	}
}
var DB_NAME = "living-web-identity";
var STORE_NAME = "credentials";
var DB_VERSION = 1;
function openDB() {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME, { keyPath: "did" });
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
function idbRequest(req) {
	return new Promise((resolve, reject) => {
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
function hexEncode(bytes) {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexDecode(hex) {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
	return bytes;
}
async function deriveKey(passphrase, salt) {
	const keyBytes = argon2id(passphrase, salt, {
		t: 3,
		m: 4096,
		p: 1,
		dkLen: 32
	});
	return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encryptPrivateKey(privateKey, passphrase) {
	const salt = randomBytes(16);
	const iv = randomBytes(12);
	const aesKey = await deriveKey(passphrase, salt);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
		name: "AES-GCM",
		iv
	}, aesKey, privateKey));
	const packed = new Uint8Array(28 + ciphertext.length);
	packed.set(salt, 0);
	packed.set(iv, 16);
	packed.set(ciphertext, 28);
	return packed;
}
async function decryptPrivateKey(packed, passphrase) {
	const salt = packed.slice(0, 16);
	const iv = packed.slice(16, 28);
	const ciphertext = packed.slice(28);
	const aesKey = await deriveKey(passphrase, salt);
	try {
		return new Uint8Array(await crypto.subtle.decrypt({
			name: "AES-GCM",
			iv
		}, aesKey, ciphertext));
	} catch {
		throw new DOMException("Incorrect passphrase", "InvalidAccessError");
	}
}
async function storeCredential(did, algorithm, displayName, createdAt, publicKey, privateKey, passphrase) {
	const encrypted = await encryptPrivateKey(privateKey, passphrase);
	const record = {
		did,
		algorithm,
		displayName,
		createdAt,
		publicKey: hexEncode(publicKey),
		encryptedPrivateKey: hexEncode(encrypted)
	};
	const db = await openDB();
	await idbRequest(db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(record));
	db.close();
}
async function loadCredential(did) {
	const db = await openDB();
	const record = await idbRequest(db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(did));
	db.close();
	return record || void 0;
}
async function loadAllCredentials() {
	const db = await openDB();
	const records = await idbRequest(db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).getAll());
	db.close();
	return records || [];
}
async function deleteCredential(did) {
	const db = await openDB();
	await idbRequest(db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).delete(did));
	db.close();
}
async function unlockPrivateKey(stored, passphrase) {
	return decryptPrivateKey(hexDecode(stored.encryptedPrivateKey), passphrase);
}
async function exportEncrypted(privateKey, exportPassphrase) {
	return encryptPrivateKey(privateKey, exportPassphrase);
}
async function importEncrypted(encrypted, exportPassphrase) {
	return decryptPrivateKey(encrypted, exportPassphrase);
}
var DIDCredential = class _DIDCredential {
	id;
	type = "did";
	did;
	algorithm;
	displayName;
	createdAt;
	_publicKey;
	_privateKey = null;
	_isLocked = true;
	get isLocked() {
		return this._isLocked;
	}
	constructor(did, algorithm, displayName, createdAt, publicKey, privateKey) {
		this.id = did;
		this.did = did;
		this.algorithm = algorithm;
		this.displayName = displayName;
		this.createdAt = createdAt;
		this._publicKey = publicKey;
		if (privateKey) {
			this._privateKey = privateKey;
			this._isLocked = false;
		}
	}
	get publicKey() {
		return this._publicKey;
	}
	get keyURI() {
		const multibaseKey = this.did.slice(8);
		return `${this.did}#${multibaseKey}`;
	}
	/** Raw Ed25519 signing — for IdentityProvider integration */
	async signRaw(data) {
		if (this._isLocked || !this._privateKey) throw new DOMException("Credential is locked", "InvalidStateError");
		return signAsync(data, this._privateKey);
	}
	async sign(data) {
		if (this._isLocked || !this._privateKey) throw new DOMException("Credential is locked", "InvalidStateError");
		return signData(data, this._privateKey, this.did, this.keyURI);
	}
	async verify(signed) {
		return verifySignedContent(signed);
	}
	resolve() {
		return resolveDIDKey(this.did);
	}
	async lock() {
		if (this._privateKey) {
			this._privateKey.fill(0);
			this._privateKey = null;
		}
		this._isLocked = true;
	}
	async unlock(passphrase) {
		const stored = await loadCredential(this.did);
		if (!stored) throw new DOMException("Credential not found in storage", "NotFoundError");
		this._privateKey = await unlockPrivateKey(stored, passphrase);
		this._isLocked = false;
	}
	async delete() {
		await this.lock();
		await deleteCredential(this.did);
	}
	async exportKey(exportPassphrase) {
		if (this._isLocked || !this._privateKey) throw new DOMException("Credential is locked", "InvalidStateError");
		return exportEncrypted(this._privateKey, exportPassphrase);
	}
	static async importKey(encrypted, exportPassphrase, displayName, storePassphrase) {
		const privateKey = await importEncrypted(encrypted, exportPassphrase);
		const publicKey = await getPublicKeyAsync(privateKey);
		const did = publicKeyToDID(publicKey);
		const createdAt = (/* @__PURE__ */ new Date()).toISOString();
		await storeCredential(did, "Ed25519", displayName, createdAt, publicKey, privateKey, storePassphrase);
		return new _DIDCredential(did, "Ed25519", displayName, createdAt, publicKey, privateKey);
	}
	/** Create a new DID credential from scratch */
	static async create(displayName, passphrase, algorithm = "Ed25519") {
		if (algorithm !== "Ed25519") throw new DOMException(`Unsupported algorithm: ${algorithm}`, "NotSupportedError");
		const privateKey = (utils.randomPrivateKey || utils.randomSecretKey)();
		const publicKey = await getPublicKeyAsync(privateKey);
		const did = publicKeyToDID(publicKey);
		const createdAt = (/* @__PURE__ */ new Date()).toISOString();
		await storeCredential(did, algorithm, displayName, createdAt, publicKey, privateKey, passphrase);
		return new _DIDCredential(did, algorithm, displayName, createdAt, publicKey, privateKey);
	}
	/** Load from stored record (locked state) */
	static fromStored(stored) {
		return new _DIDCredential(stored.did, stored.algorithm, stored.displayName, stored.createdAt, hexDecode(stored.publicKey));
	}
};
var IdentityManager = class {
	_credentials = /* @__PURE__ */ new Map();
	_activeDID = null;
	get active() {
		if (!this._activeDID) return null;
		return this._credentials.get(this._activeDID) ?? null;
	}
	get credentials() {
		return Array.from(this._credentials.values());
	}
	async loadAll() {
		const stored = await loadAllCredentials();
		for (const record of stored) if (!this._credentials.has(record.did)) this._credentials.set(record.did, DIDCredential.fromStored(record));
	}
	async create(displayName, passphrase, algorithm) {
		const cred = await DIDCredential.create(displayName, passphrase, algorithm);
		this._credentials.set(cred.did, cred);
		if (!this._activeDID) this._activeDID = cred.did;
		return cred;
	}
	setActive(did) {
		if (!this._credentials.has(did)) throw new Error(`Unknown credential: ${did}`);
		this._activeDID = did;
	}
	get(did) {
		return this._credentials.get(did);
	}
	async delete(did) {
		const cred = this._credentials.get(did);
		if (cred) {
			await cred.delete();
			this._credentials.delete(did);
			if (this._activeDID === did) {
				const remaining = this._credentials.keys().next();
				this._activeDID = remaining.done ? null : remaining.value;
			}
		}
	}
};
var manager = new IdentityManager();
var POLYFILL_PASSPHRASE = "__living-web-polyfill__";
function install$1() {
	if (typeof globalThis.navigator === "undefined") return;
	if (!globalThis.navigator.credentials) return;
	if (globalThis.navigator.credentials.__livingWebNativeDID) {
		console.info("[living-web] Native DID credential support detected — polyfill skipped");
		return;
	}
	console.info("[living-web] DID identity polyfill installed (no native support detected)");
	const originalCreate = globalThis.navigator.credentials.create?.bind(globalThis.navigator.credentials);
	const originalGet = globalThis.navigator.credentials.get?.bind(globalThis.navigator.credentials);
	globalThis.navigator.credentials.create = async function(options) {
		if (options?.did) {
			const { displayName, algorithm } = options.did;
			return await manager.create(displayName || "Unnamed", POLYFILL_PASSPHRASE, algorithm);
		}
		return originalCreate?.(options);
	};
	globalThis.navigator.credentials.get = async function(options) {
		if (options?.did !== void 0) {
			await manager.loadAll();
			const active = manager.active;
			if (!active) return null;
			if (active.isLocked) await active.unlock(POLYFILL_PASSPHRASE);
			if (options.did?.challenge) {
				const challenge = options.did.challenge;
				const challengeBytes = challenge instanceof Uint8Array ? challenge : new Uint8Array(challenge);
				active._signedChallenge = await active.sign({ challenge: Array.from(challengeBytes) });
			}
			return active;
		}
		return originalGet?.(options);
	};
}
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/map.js
/**
* Utility module to work with key-value stores.
*
* @module map
*/
/**
* @template K
* @template V
* @typedef {Map<K,V>} GlobalMap
*/
/**
* Creates a new Map instance.
*
* @function
* @return {Map<any, any>}
*
* @function
*/
var create$5 = () => /* @__PURE__ */ new Map();
/**
* Copy a Map object into a fresh Map object.
*
* @function
* @template K,V
* @param {Map<K,V>} m
* @return {Map<K,V>}
*/
var copy = (m) => {
	const r = create$5();
	m.forEach((v, k) => {
		r.set(k, v);
	});
	return r;
};
/**
* Get map property. Create T if property is undefined and set T on map.
*
* ```js
* const listeners = map.setIfUndefined(events, 'eventName', set.create)
* listeners.add(listener)
* ```
*
* @function
* @template {Map<any, any>} MAP
* @template {MAP extends Map<any,infer V> ? function():V : unknown} CF
* @param {MAP} map
* @param {MAP extends Map<infer K,any> ? K : unknown} key
* @param {CF} createT
* @return {ReturnType<CF>}
*/
var setIfUndefined = (map, key, createT) => {
	let set = map.get(key);
	if (set === void 0) map.set(key, set = createT());
	return set;
};
/**
* Creates an Array and populates it with the content of all key-value pairs using the `f(value, key)` function.
*
* @function
* @template K
* @template V
* @template R
* @param {Map<K,V>} m
* @param {function(V,K):R} f
* @return {Array<R>}
*/
var map = (m, f) => {
	const res = [];
	for (const [key, value] of m) res.push(f(value, key));
	return res;
};
/**
* Tests whether any key-value pairs pass the test implemented by `f(value, key)`.
*
* @todo should rename to some - similarly to Array.some
*
* @function
* @template K
* @template V
* @param {Map<K,V>} m
* @param {function(V,K):boolean} f
* @return {boolean}
*/
var any = (m, f) => {
	for (const [key, value] of m) if (f(value, key)) return true;
	return false;
};
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/set.js
/**
* Utility module to work with sets.
*
* @module set
*/
var create$4 = () => /* @__PURE__ */ new Set();
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/array.js
/**
* Return the last element of an array. The element must exist
*
* @template L
* @param {ArrayLike<L>} arr
* @return {L}
*/
var last = (arr) => arr[arr.length - 1];
/**
* Append elements from src to dest
*
* @template M
* @param {Array<M>} dest
* @param {Array<M>} src
*/
var appendTo = (dest, src) => {
	for (let i = 0; i < src.length; i++) dest.push(src[i]);
};
/**
* Transforms something array-like to an actual Array.
*
* @function
* @template T
* @param {ArrayLike<T>|Iterable<T>} arraylike
* @return {T}
*/
var from = Array.from;
/**
* True iff condition holds on every element in the Array.
*
* @function
* @template {ArrayLike<any>} ARR
*
* @param {ARR} arr
* @param {ARR extends ArrayLike<infer S> ? ((value:S, index:number, arr:ARR) => boolean) : any} f
* @return {boolean}
*/
var every$1 = (arr, f) => {
	for (let i = 0; i < arr.length; i++) if (!f(arr[i], i, arr)) return false;
	return true;
};
/**
* True iff condition holds on some element in the Array.
*
* @function
* @template {ArrayLike<any>} ARR
*
* @param {ARR} arr
* @param {ARR extends ArrayLike<infer S> ? ((value:S, index:number, arr:ARR) => boolean) : never} f
* @return {boolean}
*/
var some = (arr, f) => {
	for (let i = 0; i < arr.length; i++) if (f(arr[i], i, arr)) return true;
	return false;
};
/**
* @template T
* @param {number} len
* @param {function(number, Array<T>):T} f
* @return {Array<T>}
*/
var unfold = (len, f) => {
	const array = new Array(len);
	for (let i = 0; i < len; i++) array[i] = f(i, array);
	return array;
};
var isArray$1 = Array.isArray;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/observable.js
/**
* Observable class prototype.
*
* @module observable
*/
/**
* Handles named events.
* @experimental
*
* This is basically a (better typed) duplicate of Observable, which will replace Observable in the
* next release.
*
* @template {{[key in keyof EVENTS]: function(...any):void}} EVENTS
*/
var ObservableV2 = class {
	constructor() {
		/**
		* Some desc.
		* @type {Map<string, Set<any>>}
		*/
		this._observers = create$5();
	}
	/**
	* @template {keyof EVENTS & string} NAME
	* @param {NAME} name
	* @param {EVENTS[NAME]} f
	*/
	on(name, f) {
		setIfUndefined(this._observers, name, create$4).add(f);
		return f;
	}
	/**
	* @template {keyof EVENTS & string} NAME
	* @param {NAME} name
	* @param {EVENTS[NAME]} f
	*/
	once(name, f) {
		/**
		* @param  {...any} args
		*/
		const _f = (...args) => {
			this.off(name, _f);
			f(...args);
		};
		this.on(name, _f);
	}
	/**
	* @template {keyof EVENTS & string} NAME
	* @param {NAME} name
	* @param {EVENTS[NAME]} f
	*/
	off(name, f) {
		const observers = this._observers.get(name);
		if (observers !== void 0) {
			observers.delete(f);
			if (observers.size === 0) this._observers.delete(name);
		}
	}
	/**
	* Emit a named event. All registered event listeners that listen to the
	* specified name will receive the event.
	*
	* @todo This should catch exceptions
	*
	* @template {keyof EVENTS & string} NAME
	* @param {NAME} name The event name.
	* @param {Parameters<EVENTS[NAME]>} args The arguments that are applied to the event listener.
	*/
	emit(name, args) {
		return from((this._observers.get(name) || create$5()).values()).forEach((f) => f(...args));
	}
	destroy() {
		this._observers = create$5();
	}
};
/* c8 ignore end */
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/math.js
/**
* Common Math expressions.
*
* @module math
*/
var floor = Math.floor;
var abs = Math.abs;
/**
* @function
* @param {number} a
* @param {number} b
* @return {number} The smaller element of a and b
*/
var min = (a, b) => a < b ? a : b;
/**
* @function
* @param {number} a
* @param {number} b
* @return {number} The bigger element of a and b
*/
var max = (a, b) => a > b ? a : b;
Number.isNaN;
/**
* Check whether n is negative, while considering the -0 edge case. While `-0 < 0` is false, this
* function returns true for -0,-1,,.. and returns false for 0,1,2,...
* @param {number} n
* @return {boolean} Wether n is negative. This function also distinguishes between -0 and +0
*/
var isNegativeZero = (n) => n !== 0 ? n < 0 : 1 / n < 0;
var BIT18 = 1 << 17;
var BIT19 = 1 << 18;
var BIT20 = 1 << 19;
var BIT21 = 1 << 20;
var BIT22 = 1 << 21;
var BIT23 = 1 << 22;
var BIT24 = 1 << 23;
var BIT25 = 1 << 24;
var BIT26 = 1 << 25;
var BIT27 = 1 << 26;
var BIT28 = 1 << 27;
var BIT29 = 1 << 28;
var BIT30 = 1 << 29;
var BIT31 = 1 << 30;
BIT18 - 1;
BIT19 - 1;
BIT20 - 1;
BIT21 - 1;
BIT22 - 1;
BIT23 - 1;
BIT24 - 1;
BIT25 - 1;
BIT26 - 1;
BIT27 - 1;
BIT28 - 1;
BIT29 - 1;
BIT30 - 1;
BIT31 - 1;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/number.js
/**
* Utility helpers for working with numbers.
*
* @module number
*/
var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
var MIN_SAFE_INTEGER = Number.MIN_SAFE_INTEGER;
/* c8 ignore next */
var isInteger = Number.isInteger || ((num) => typeof num === "number" && isFinite(num) && floor(num) === num);
Number.isNaN;
Number.parseInt;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/string.js
/**
* Utility module to work with strings.
*
* @module string
*/
var fromCharCode = String.fromCharCode;
String.fromCodePoint;
fromCharCode(65535);
/**
* @param {string} s
* @return {string}
*/
var toLowerCase = (s) => s.toLowerCase();
var trimLeftRegex = /^\s*/g;
/**
* @param {string} s
* @return {string}
*/
var trimLeft = (s) => s.replace(trimLeftRegex, "");
var fromCamelCaseRegex = /([A-Z])/g;
/**
* @param {string} s
* @param {string} separator
* @return {string}
*/
var fromCamelCase = (s, separator) => trimLeft(s.replace(fromCamelCaseRegex, (match) => `${separator}${toLowerCase(match)}`));
/**
* @param {string} str
* @return {Uint8Array<ArrayBuffer>}
*/
var _encodeUtf8Polyfill = (str) => {
	const encodedString = unescape(encodeURIComponent(str));
	const len = encodedString.length;
	const buf = new Uint8Array(len);
	for (let i = 0; i < len; i++) buf[i] = encodedString.codePointAt(i);
	return buf;
};
/* c8 ignore next */
var utf8TextEncoder = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
/**
* @param {string} str
* @return {Uint8Array<ArrayBuffer>}
*/
var _encodeUtf8Native = (str) => utf8TextEncoder.encode(str);
/**
* @param {string} str
* @return {Uint8Array}
*/
/* c8 ignore next */
var encodeUtf8 = utf8TextEncoder ? _encodeUtf8Native : _encodeUtf8Polyfill;
/* c8 ignore next */
var utf8TextDecoder = typeof TextDecoder === "undefined" ? null : new TextDecoder("utf-8", {
	fatal: true,
	ignoreBOM: true
});
/* c8 ignore start */
if (utf8TextDecoder && utf8TextDecoder.decode(new Uint8Array()).length === 1)
 /* c8 ignore next */
utf8TextDecoder = null;
/**
* @param {string} source
* @param {number} n
*/
var repeat = (source, n) => unfold(n, () => source).join("");
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/encoding.js
/**
* Efficient schema-less binary encoding with support for variable length encoding.
*
* Use [lib0/encoding] with [lib0/decoding]. Every encoding function has a corresponding decoding function.
*
* Encodes numbers in little-endian order (least to most significant byte order)
* and is compatible with Golang's binary encoding (https://golang.org/pkg/encoding/binary/)
* which is also used in Protocol Buffers.
*
* ```js
* // encoding step
* const encoder = encoding.createEncoder()
* encoding.writeVarUint(encoder, 256)
* encoding.writeVarString(encoder, 'Hello world!')
* const buf = encoding.toUint8Array(encoder)
* ```
*
* ```js
* // decoding step
* const decoder = decoding.createDecoder(buf)
* decoding.readVarUint(decoder) // => 256
* decoding.readVarString(decoder) // => 'Hello world!'
* decoding.hasContent(decoder) // => false - all data is read
* ```
*
* @module encoding
*/
/**
* A BinaryEncoder handles the encoding to an Uint8Array.
*/
var Encoder = class {
	constructor() {
		this.cpos = 0;
		this.cbuf = new Uint8Array(100);
		/**
		* @type {Array<Uint8Array>}
		*/
		this.bufs = [];
	}
};
/**
* @function
* @return {Encoder}
*/
var createEncoder = () => new Encoder();
/**
* The current length of the encoded data.
*
* @function
* @param {Encoder} encoder
* @return {number}
*/
var length = (encoder) => {
	let len = encoder.cpos;
	for (let i = 0; i < encoder.bufs.length; i++) len += encoder.bufs[i].length;
	return len;
};
/**
* Transform to Uint8Array.
*
* @function
* @param {Encoder} encoder
* @return {Uint8Array<ArrayBuffer>} The created ArrayBuffer.
*/
var toUint8Array = (encoder) => {
	const uint8arr = new Uint8Array(length(encoder));
	let curPos = 0;
	for (let i = 0; i < encoder.bufs.length; i++) {
		const d = encoder.bufs[i];
		uint8arr.set(d, curPos);
		curPos += d.length;
	}
	uint8arr.set(new Uint8Array(encoder.cbuf.buffer, 0, encoder.cpos), curPos);
	return uint8arr;
};
/**
* Verify that it is possible to write `len` bytes wtihout checking. If
* necessary, a new Buffer with the required length is attached.
*
* @param {Encoder} encoder
* @param {number} len
*/
var verifyLen = (encoder, len) => {
	const bufferLen = encoder.cbuf.length;
	if (bufferLen - encoder.cpos < len) {
		encoder.bufs.push(new Uint8Array(encoder.cbuf.buffer, 0, encoder.cpos));
		encoder.cbuf = new Uint8Array(max(bufferLen, len) * 2);
		encoder.cpos = 0;
	}
};
/**
* Write one byte to the encoder.
*
* @function
* @param {Encoder} encoder
* @param {number} num The byte that is to be encoded.
*/
var write = (encoder, num) => {
	const bufferLen = encoder.cbuf.length;
	if (encoder.cpos === bufferLen) {
		encoder.bufs.push(encoder.cbuf);
		encoder.cbuf = new Uint8Array(bufferLen * 2);
		encoder.cpos = 0;
	}
	encoder.cbuf[encoder.cpos++] = num;
};
/**
* Write one byte as an unsigned integer.
*
* @function
* @param {Encoder} encoder
* @param {number} num The number that is to be encoded.
*/
var writeUint8 = write;
/**
* Write a variable length unsigned integer. Max encodable integer is 2^53.
*
* @function
* @param {Encoder} encoder
* @param {number} num The number that is to be encoded.
*/
var writeVarUint = (encoder, num) => {
	while (num > 127) {
		write(encoder, 128 | 127 & num);
		num = floor(num / 128);
	}
	write(encoder, 127 & num);
};
/**
* Write a variable length integer.
*
* We use the 7th bit instead for signaling that this is a negative number.
*
* @function
* @param {Encoder} encoder
* @param {number} num The number that is to be encoded.
*/
var writeVarInt = (encoder, num) => {
	const isNegative = isNegativeZero(num);
	if (isNegative) num = -num;
	write(encoder, (num > 63 ? 128 : 0) | (isNegative ? 64 : 0) | 63 & num);
	num = floor(num / 64);
	while (num > 0) {
		write(encoder, (num > 127 ? 128 : 0) | 127 & num);
		num = floor(num / 128);
	}
};
/**
* A cache to store strings temporarily
*/
var _strBuffer = new Uint8Array(3e4);
var _maxStrBSize = _strBuffer.length / 3;
/**
* Write a variable length string.
*
* @function
* @param {Encoder} encoder
* @param {String} str The string that is to be encoded.
*/
var _writeVarStringNative = (encoder, str) => {
	if (str.length < _maxStrBSize) {
		/* c8 ignore next */
		const written = utf8TextEncoder.encodeInto(str, _strBuffer).written || 0;
		writeVarUint(encoder, written);
		for (let i = 0; i < written; i++) write(encoder, _strBuffer[i]);
	} else writeVarUint8Array(encoder, encodeUtf8(str));
};
/**
* Write a variable length string.
*
* @function
* @param {Encoder} encoder
* @param {String} str The string that is to be encoded.
*/
var _writeVarStringPolyfill = (encoder, str) => {
	const encodedString = unescape(encodeURIComponent(str));
	const len = encodedString.length;
	writeVarUint(encoder, len);
	for (let i = 0; i < len; i++) write(encoder, encodedString.codePointAt(i));
};
/**
* Write a variable length string.
*
* @function
* @param {Encoder} encoder
* @param {String} str The string that is to be encoded.
*/
/* c8 ignore next */
var writeVarString = utf8TextEncoder && utf8TextEncoder.encodeInto ? _writeVarStringNative : _writeVarStringPolyfill;
/**
* Append fixed-length Uint8Array to the encoder.
*
* @function
* @param {Encoder} encoder
* @param {Uint8Array} uint8Array
*/
var writeUint8Array = (encoder, uint8Array) => {
	const bufferLen = encoder.cbuf.length;
	const cpos = encoder.cpos;
	const leftCopyLen = min(bufferLen - cpos, uint8Array.length);
	const rightCopyLen = uint8Array.length - leftCopyLen;
	encoder.cbuf.set(uint8Array.subarray(0, leftCopyLen), cpos);
	encoder.cpos += leftCopyLen;
	if (rightCopyLen > 0) {
		encoder.bufs.push(encoder.cbuf);
		encoder.cbuf = new Uint8Array(max(bufferLen * 2, rightCopyLen));
		encoder.cbuf.set(uint8Array.subarray(leftCopyLen));
		encoder.cpos = rightCopyLen;
	}
};
/**
* Append an Uint8Array to Encoder.
*
* @function
* @param {Encoder} encoder
* @param {Uint8Array} uint8Array
*/
var writeVarUint8Array = (encoder, uint8Array) => {
	writeVarUint(encoder, uint8Array.byteLength);
	writeUint8Array(encoder, uint8Array);
};
/**
* Create an DataView of the next `len` bytes. Use it to write data after
* calling this function.
*
* ```js
* // write float32 using DataView
* const dv = writeOnDataView(encoder, 4)
* dv.setFloat32(0, 1.1)
* // read float32 using DataView
* const dv = readFromDataView(encoder, 4)
* dv.getFloat32(0) // => 1.100000023841858 (leaving it to the reader to find out why this is the correct result)
* ```
*
* @param {Encoder} encoder
* @param {number} len
* @return {DataView}
*/
var writeOnDataView = (encoder, len) => {
	verifyLen(encoder, len);
	const dview = new DataView(encoder.cbuf.buffer, encoder.cpos, len);
	encoder.cpos += len;
	return dview;
};
/**
* @param {Encoder} encoder
* @param {number} num
*/
var writeFloat32 = (encoder, num) => writeOnDataView(encoder, 4).setFloat32(0, num, false);
/**
* @param {Encoder} encoder
* @param {number} num
*/
var writeFloat64 = (encoder, num) => writeOnDataView(encoder, 8).setFloat64(0, num, false);
/**
* @param {Encoder} encoder
* @param {bigint} num
*/
var writeBigInt64 = (encoder, num) => writeOnDataView(encoder, 8).setBigInt64(0, num, false);
var floatTestBed = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(4));
/**
* Check if a number can be encoded as a 32 bit float.
*
* @param {number} num
* @return {boolean}
*/
var isFloat32 = (num) => {
	floatTestBed.setFloat32(0, num);
	return floatTestBed.getFloat32(0) === num;
};
/**
* @typedef {Array<AnyEncodable>} AnyEncodableArray
*/
/**
* @typedef {undefined|null|number|bigint|boolean|string|{[k:string]:AnyEncodable}|AnyEncodableArray|Uint8Array} AnyEncodable
*/
/**
* Encode data with efficient binary format.
*
* Differences to JSON:
* • Transforms data to a binary format (not to a string)
* • Encodes undefined, NaN, and ArrayBuffer (these can't be represented in JSON)
* • Numbers are efficiently encoded either as a variable length integer, as a
*   32 bit float, as a 64 bit float, or as a 64 bit bigint.
*
* Encoding table:
*
* | Data Type           | Prefix   | Encoding Method    | Comment |
* | ------------------- | -------- | ------------------ | ------- |
* | undefined           | 127      |                    | Functions, symbol, and everything that cannot be identified is encoded as undefined |
* | null                | 126      |                    | |
* | integer             | 125      | writeVarInt        | Only encodes 32 bit signed integers |
* | float32             | 124      | writeFloat32       | |
* | float64             | 123      | writeFloat64       | |
* | bigint              | 122      | writeBigInt64      | |
* | boolean (false)     | 121      |                    | True and false are different data types so we save the following byte |
* | boolean (true)      | 120      |                    | - 0b01111000 so the last bit determines whether true or false |
* | string              | 119      | writeVarString     | |
* | object<string,any>  | 118      | custom             | Writes {length} then {length} key-value pairs |
* | array<any>          | 117      | custom             | Writes {length} then {length} json values |
* | Uint8Array          | 116      | writeVarUint8Array | We use Uint8Array for any kind of binary data |
*
* Reasons for the decreasing prefix:
* We need the first bit for extendability (later we may want to encode the
* prefix with writeVarUint). The remaining 7 bits are divided as follows:
* [0-30]   the beginning of the data range is used for custom purposes
*          (defined by the function that uses this library)
* [31-127] the end of the data range is used for data encoding by
*          lib0/encoding.js
*
* @param {Encoder} encoder
* @param {AnyEncodable} data
*/
var writeAny = (encoder, data) => {
	switch (typeof data) {
		case "string":
			write(encoder, 119);
			writeVarString(encoder, data);
			break;
		case "number":
			if (isInteger(data) && abs(data) <= 2147483647) {
				write(encoder, 125);
				writeVarInt(encoder, data);
			} else if (isFloat32(data)) {
				write(encoder, 124);
				writeFloat32(encoder, data);
			} else {
				write(encoder, 123);
				writeFloat64(encoder, data);
			}
			break;
		case "bigint":
			write(encoder, 122);
			writeBigInt64(encoder, data);
			break;
		case "object":
			if (data === null) write(encoder, 126);
			else if (isArray$1(data)) {
				write(encoder, 117);
				writeVarUint(encoder, data.length);
				for (let i = 0; i < data.length; i++) writeAny(encoder, data[i]);
			} else if (data instanceof Uint8Array) {
				write(encoder, 116);
				writeVarUint8Array(encoder, data);
			} else {
				write(encoder, 118);
				const keys = Object.keys(data);
				writeVarUint(encoder, keys.length);
				for (let i = 0; i < keys.length; i++) {
					const key = keys[i];
					writeVarString(encoder, key);
					writeAny(encoder, data[key]);
				}
			}
			break;
		case "boolean":
			write(encoder, data ? 120 : 121);
			break;
		default: write(encoder, 127);
	}
};
/**
* Now come a few stateful encoder that have their own classes.
*/
/**
* Basic Run Length Encoder - a basic compression implementation.
*
* Encodes [1,1,1,7] to [1,3,7,1] (3 times 1, 1 time 7). This encoder might do more harm than good if there are a lot of values that are not repeated.
*
* It was originally used for image compression. Cool .. article http://csbruce.com/cbm/transactor/pdfs/trans_v7_i06.pdf
*
* @note T must not be null!
*
* @template T
*/
var RleEncoder = class extends Encoder {
	/**
	* @param {function(Encoder, T):void} writer
	*/
	constructor(writer) {
		super();
		/**
		* The writer
		*/
		this.w = writer;
		/**
		* Current state
		* @type {T|null}
		*/
		this.s = null;
		this.count = 0;
	}
	/**
	* @param {T} v
	*/
	write(v) {
		if (this.s === v) this.count++;
		else {
			if (this.count > 0) writeVarUint(this, this.count - 1);
			this.count = 1;
			this.w(this, v);
			this.s = v;
		}
	}
};
/**
* @param {UintOptRleEncoder} encoder
*/
var flushUintOptRleEncoder = (encoder) => {
	if (encoder.count > 0) {
		writeVarInt(encoder.encoder, encoder.count === 1 ? encoder.s : -encoder.s);
		if (encoder.count > 1) writeVarUint(encoder.encoder, encoder.count - 2);
	}
};
/**
* Optimized Rle encoder that does not suffer from the mentioned problem of the basic Rle encoder.
*
* Internally uses VarInt encoder to write unsigned integers. If the input occurs multiple times, we write
* write it as a negative number. The UintOptRleDecoder then understands that it needs to read a count.
*
* Encodes [1,2,3,3,3] as [1,2,-3,3] (once 1, once 2, three times 3)
*/
var UintOptRleEncoder = class {
	constructor() {
		this.encoder = new Encoder();
		/**
		* @type {number}
		*/
		this.s = 0;
		this.count = 0;
	}
	/**
	* @param {number} v
	*/
	write(v) {
		if (this.s === v) this.count++;
		else {
			flushUintOptRleEncoder(this);
			this.count = 1;
			this.s = v;
		}
	}
	/**
	* Flush the encoded state and transform this to a Uint8Array.
	*
	* Note that this should only be called once.
	*/
	toUint8Array() {
		flushUintOptRleEncoder(this);
		return toUint8Array(this.encoder);
	}
};
/**
* @param {IntDiffOptRleEncoder} encoder
*/
var flushIntDiffOptRleEncoder = (encoder) => {
	if (encoder.count > 0) {
		const encodedDiff = encoder.diff * 2 + (encoder.count === 1 ? 0 : 1);
		writeVarInt(encoder.encoder, encodedDiff);
		if (encoder.count > 1) writeVarUint(encoder.encoder, encoder.count - 2);
	}
};
/**
* A combination of the IntDiffEncoder and the UintOptRleEncoder.
*
* The count approach is similar to the UintDiffOptRleEncoder, but instead of using the negative bitflag, it encodes
* in the LSB whether a count is to be read. Therefore this Encoder only supports 31 bit integers!
*
* Encodes [1, 2, 3, 2] as [3, 1, 6, -1] (more specifically [(1 << 1) | 1, (3 << 0) | 0, -1])
*
* Internally uses variable length encoding. Contrary to normal UintVar encoding, the first byte contains:
* * 1 bit that denotes whether the next value is a count (LSB)
* * 1 bit that denotes whether this value is negative (MSB - 1)
* * 1 bit that denotes whether to continue reading the variable length integer (MSB)
*
* Therefore, only five bits remain to encode diff ranges.
*
* Use this Encoder only when appropriate. In most cases, this is probably a bad idea.
*/
var IntDiffOptRleEncoder = class {
	constructor() {
		this.encoder = new Encoder();
		/**
		* @type {number}
		*/
		this.s = 0;
		this.count = 0;
		this.diff = 0;
	}
	/**
	* @param {number} v
	*/
	write(v) {
		if (this.diff === v - this.s) {
			this.s = v;
			this.count++;
		} else {
			flushIntDiffOptRleEncoder(this);
			this.count = 1;
			this.diff = v - this.s;
			this.s = v;
		}
	}
	/**
	* Flush the encoded state and transform this to a Uint8Array.
	*
	* Note that this should only be called once.
	*/
	toUint8Array() {
		flushIntDiffOptRleEncoder(this);
		return toUint8Array(this.encoder);
	}
};
/**
* Optimized String Encoder.
*
* Encoding many small strings in a simple Encoder is not very efficient. The function call to decode a string takes some time and creates references that must be eventually deleted.
* In practice, when decoding several million small strings, the GC will kick in more and more often to collect orphaned string objects (or maybe there is another reason?).
*
* This string encoder solves the above problem. All strings are concatenated and written as a single string using a single encoding call.
*
* The lengths are encoded using a UintOptRleEncoder.
*/
var StringEncoder = class {
	constructor() {
		/**
		* @type {Array<string>}
		*/
		this.sarr = [];
		this.s = "";
		this.lensE = new UintOptRleEncoder();
	}
	/**
	* @param {string} string
	*/
	write(string) {
		this.s += string;
		if (this.s.length > 19) {
			this.sarr.push(this.s);
			this.s = "";
		}
		this.lensE.write(string.length);
	}
	toUint8Array() {
		const encoder = new Encoder();
		this.sarr.push(this.s);
		this.s = "";
		writeVarString(encoder, this.sarr.join(""));
		writeUint8Array(encoder, this.lensE.toUint8Array());
		return toUint8Array(encoder);
	}
};
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/error.js
/**
* Error helpers.
*
* @module error
*/
/**
* @param {string} s
* @return {Error}
*/
/* c8 ignore next */
var create$3 = (s) => new Error(s);
/**
* @throws {Error}
* @return {never}
*/
/* c8 ignore next 3 */
var methodUnimplemented = () => {
	throw create$3("Method unimplemented");
};
/**
* @throws {Error}
* @return {never}
*/
/* c8 ignore next 3 */
var unexpectedCase = () => {
	throw create$3("Unexpected case");
};
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/decoding.js
/**
* Efficient schema-less binary decoding with support for variable length encoding.
*
* Use [lib0/decoding] with [lib0/encoding]. Every encoding function has a corresponding decoding function.
*
* Encodes numbers in little-endian order (least to most significant byte order)
* and is compatible with Golang's binary encoding (https://golang.org/pkg/encoding/binary/)
* which is also used in Protocol Buffers.
*
* ```js
* // encoding step
* const encoder = encoding.createEncoder()
* encoding.writeVarUint(encoder, 256)
* encoding.writeVarString(encoder, 'Hello world!')
* const buf = encoding.toUint8Array(encoder)
* ```
*
* ```js
* // decoding step
* const decoder = decoding.createDecoder(buf)
* decoding.readVarUint(decoder) // => 256
* decoding.readVarString(decoder) // => 'Hello world!'
* decoding.hasContent(decoder) // => false - all data is read
* ```
*
* @module decoding
*/
var errorUnexpectedEndOfArray = create$3("Unexpected end of array");
var errorIntegerOutOfRange = create$3("Integer out of Range");
/**
* A Decoder handles the decoding of an Uint8Array.
* @template {ArrayBufferLike} [Buf=ArrayBufferLike]
*/
var Decoder = class {
	/**
	* @param {Uint8Array<Buf>} uint8Array Binary data to decode
	*/
	constructor(uint8Array) {
		/**
		* Decoding target.
		*
		* @type {Uint8Array<Buf>}
		*/
		this.arr = uint8Array;
		/**
		* Current decoding position.
		*
		* @type {number}
		*/
		this.pos = 0;
	}
};
/**
* @function
* @template {ArrayBufferLike} Buf
* @param {Uint8Array<Buf>} uint8Array
* @return {Decoder<Buf>}
*/
var createDecoder = (uint8Array) => new Decoder(uint8Array);
/**
* @function
* @param {Decoder} decoder
* @return {boolean}
*/
var hasContent = (decoder) => decoder.pos !== decoder.arr.length;
/**
* Create an Uint8Array view of the next `len` bytes and advance the position by `len`.
*
* Important: The Uint8Array still points to the underlying ArrayBuffer. Make sure to discard the result as soon as possible to prevent any memory leaks.
*            Use `buffer.copyUint8Array` to copy the result into a new Uint8Array.
*
* @function
* @template {ArrayBufferLike} Buf
* @param {Decoder<Buf>} decoder The decoder instance
* @param {number} len The length of bytes to read
* @return {Uint8Array<Buf>}
*/
var readUint8Array = (decoder, len) => {
	const view = new Uint8Array(decoder.arr.buffer, decoder.pos + decoder.arr.byteOffset, len);
	decoder.pos += len;
	return view;
};
/**
* Read variable length Uint8Array.
*
* Important: The Uint8Array still points to the underlying ArrayBuffer. Make sure to discard the result as soon as possible to prevent any memory leaks.
*            Use `buffer.copyUint8Array` to copy the result into a new Uint8Array.
*
* @function
* @template {ArrayBufferLike} Buf
* @param {Decoder<Buf>} decoder
* @return {Uint8Array<Buf>}
*/
var readVarUint8Array = (decoder) => readUint8Array(decoder, readVarUint(decoder));
/**
* Read one byte as unsigned integer.
* @function
* @param {Decoder} decoder The decoder instance
* @return {number} Unsigned 8-bit integer
*/
var readUint8 = (decoder) => decoder.arr[decoder.pos++];
/**
* Read unsigned integer (32bit) with variable length.
* 1/8th of the storage is used as encoding overhead.
*  * numbers < 2^7 is stored in one bytlength
*  * numbers < 2^14 is stored in two bylength
*
* @function
* @param {Decoder} decoder
* @return {number} An unsigned integer.length
*/
var readVarUint = (decoder) => {
	let num = 0;
	let mult = 1;
	const len = decoder.arr.length;
	while (decoder.pos < len) {
		const r = decoder.arr[decoder.pos++];
		num = num + (r & 127) * mult;
		mult *= 128;
		if (r < 128) return num;
		/* c8 ignore start */
		if (num > MAX_SAFE_INTEGER) throw errorIntegerOutOfRange;
	}
	throw errorUnexpectedEndOfArray;
};
/**
* Read signed integer (32bit) with variable length.
* 1/8th of the storage is used as encoding overhead.
*  * numbers < 2^7 is stored in one bytlength
*  * numbers < 2^14 is stored in two bylength
* @todo This should probably create the inverse ~num if number is negative - but this would be a breaking change.
*
* @function
* @param {Decoder} decoder
* @return {number} An unsigned integer.length
*/
var readVarInt = (decoder) => {
	let r = decoder.arr[decoder.pos++];
	let num = r & 63;
	let mult = 64;
	const sign = (r & 64) > 0 ? -1 : 1;
	if ((r & 128) === 0) return sign * num;
	const len = decoder.arr.length;
	while (decoder.pos < len) {
		r = decoder.arr[decoder.pos++];
		num = num + (r & 127) * mult;
		mult *= 128;
		if (r < 128) return sign * num;
		/* c8 ignore start */
		if (num > MAX_SAFE_INTEGER) throw errorIntegerOutOfRange;
	}
	throw errorUnexpectedEndOfArray;
};
/**
* We don't test this function anymore as we use native decoding/encoding by default now.
* Better not modify this anymore..
*
* Transforming utf8 to a string is pretty expensive. The code performs 10x better
* when String.fromCodePoint is fed with all characters as arguments.
* But most environments have a maximum number of arguments per functions.
* For effiency reasons we apply a maximum of 10000 characters at once.
*
* @function
* @param {Decoder} decoder
* @return {String} The read String.
*/
/* c8 ignore start */
var _readVarStringPolyfill = (decoder) => {
	let remainingLen = readVarUint(decoder);
	if (remainingLen === 0) return "";
	else {
		let encodedString = String.fromCodePoint(readUint8(decoder));
		if (--remainingLen < 100) while (remainingLen--) encodedString += String.fromCodePoint(readUint8(decoder));
		else while (remainingLen > 0) {
			const nextLen = remainingLen < 1e4 ? remainingLen : 1e4;
			const bytes = decoder.arr.subarray(decoder.pos, decoder.pos + nextLen);
			decoder.pos += nextLen;
			encodedString += String.fromCodePoint.apply(null, bytes);
			remainingLen -= nextLen;
		}
		return decodeURIComponent(escape(encodedString));
	}
};
/* c8 ignore stop */
/**
* @function
* @param {Decoder} decoder
* @return {String} The read String
*/
var _readVarStringNative = (decoder) => utf8TextDecoder.decode(readVarUint8Array(decoder));
/**
* Read string of variable length
* * varUint is used to store the length of the string
*
* @function
* @param {Decoder} decoder
* @return {String} The read String
*
*/
/* c8 ignore next */
var readVarString = utf8TextDecoder ? _readVarStringNative : _readVarStringPolyfill;
/**
* @param {Decoder} decoder
* @param {number} len
* @return {DataView}
*/
var readFromDataView = (decoder, len) => {
	const dv = new DataView(decoder.arr.buffer, decoder.arr.byteOffset + decoder.pos, len);
	decoder.pos += len;
	return dv;
};
/**
* @param {Decoder} decoder
*/
var readFloat32 = (decoder) => readFromDataView(decoder, 4).getFloat32(0, false);
/**
* @param {Decoder} decoder
*/
var readFloat64 = (decoder) => readFromDataView(decoder, 8).getFloat64(0, false);
/**
* @param {Decoder} decoder
*/
var readBigInt64 = (decoder) => readFromDataView(decoder, 8).getBigInt64(0, false);
/**
* @type {Array<function(Decoder):any>}
*/
var readAnyLookupTable = [
	(decoder) => void 0,
	(decoder) => null,
	readVarInt,
	readFloat32,
	readFloat64,
	readBigInt64,
	(decoder) => false,
	(decoder) => true,
	readVarString,
	(decoder) => {
		const len = readVarUint(decoder);
		/**
		* @type {Object<string,any>}
		*/
		const obj = {};
		for (let i = 0; i < len; i++) {
			const key = readVarString(decoder);
			obj[key] = readAny(decoder);
		}
		return obj;
	},
	(decoder) => {
		const len = readVarUint(decoder);
		const arr = [];
		for (let i = 0; i < len; i++) arr.push(readAny(decoder));
		return arr;
	},
	readVarUint8Array
];
/**
* @param {Decoder} decoder
*/
var readAny = (decoder) => readAnyLookupTable[127 - readUint8(decoder)](decoder);
/**
* T must not be null.
*
* @template T
*/
var RleDecoder = class extends Decoder {
	/**
	* @param {Uint8Array} uint8Array
	* @param {function(Decoder):T} reader
	*/
	constructor(uint8Array, reader) {
		super(uint8Array);
		/**
		* The reader
		*/
		this.reader = reader;
		/**
		* Current state
		* @type {T|null}
		*/
		this.s = null;
		this.count = 0;
	}
	read() {
		if (this.count === 0) {
			this.s = this.reader(this);
			if (hasContent(this)) this.count = readVarUint(this) + 1;
			else this.count = -1;
		}
		this.count--;
		return this.s;
	}
};
var UintOptRleDecoder = class extends Decoder {
	/**
	* @param {Uint8Array} uint8Array
	*/
	constructor(uint8Array) {
		super(uint8Array);
		/**
		* @type {number}
		*/
		this.s = 0;
		this.count = 0;
	}
	read() {
		if (this.count === 0) {
			this.s = readVarInt(this);
			const isNegative = isNegativeZero(this.s);
			this.count = 1;
			if (isNegative) {
				this.s = -this.s;
				this.count = readVarUint(this) + 2;
			}
		}
		this.count--;
		return this.s;
	}
};
var IntDiffOptRleDecoder = class extends Decoder {
	/**
	* @param {Uint8Array} uint8Array
	*/
	constructor(uint8Array) {
		super(uint8Array);
		/**
		* @type {number}
		*/
		this.s = 0;
		this.count = 0;
		this.diff = 0;
	}
	/**
	* @return {number}
	*/
	read() {
		if (this.count === 0) {
			const diff = readVarInt(this);
			const hasCount = diff & 1;
			this.diff = floor(diff / 2);
			this.count = 1;
			if (hasCount) this.count = readVarUint(this) + 2;
		}
		this.s += this.diff;
		this.count--;
		return this.s;
	}
};
var StringDecoder = class {
	/**
	* @param {Uint8Array} uint8Array
	*/
	constructor(uint8Array) {
		this.decoder = new UintOptRleDecoder(uint8Array);
		this.str = readVarString(this.decoder);
		/**
		* @type {number}
		*/
		this.spos = 0;
	}
	/**
	* @return {string}
	*/
	read() {
		const end = this.spos + this.decoder.read();
		const res = this.str.slice(this.spos, end);
		this.spos = end;
		return res;
	}
};
crypto.subtle;
var getRandomValues = crypto.getRandomValues.bind(crypto);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/random.js
var uint32 = () => getRandomValues(new Uint32Array(1))[0];
var uuidv4Template = "10000000-1000-4000-8000-100000000000";
/**
* @return {string}
*/
var uuidv4 = () => uuidv4Template.replace(
	/[018]/g,
	/** @param {number} c */
	(c) => (c ^ uint32() & 15 >> c / 4).toString(16)
);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/time.js
/**
* Return current unix time.
*
* @return {number}
*/
var getUnixTime = Date.now;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/promise.js
/**
* @template T
* @callback PromiseResolve
* @param {T|PromiseLike<T>} [result]
*/
/**
* @template T
* @param {function(PromiseResolve<T>,function(Error):void):any} f
* @return {Promise<T>}
*/
var create$2 = (f) => new Promise(f);
Promise.all.bind(Promise);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/conditions.js
/**
* Often used conditions.
*
* @module conditions
*/
/**
* @template T
* @param {T|null|undefined} v
* @return {T|null}
*/
/* c8 ignore next */
var undefinedToNull = (v) => v === void 0 ? null : v;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/storage.js
/**
* Isomorphic variable storage.
*
* Uses LocalStorage in the browser and falls back to in-memory storage.
*
* @module storage
*/
/* c8 ignore start */
var VarStoragePolyfill = class {
	constructor() {
		this.map = /* @__PURE__ */ new Map();
	}
	/**
	* @param {string} key
	* @param {any} newValue
	*/
	setItem(key, newValue) {
		this.map.set(key, newValue);
	}
	/**
	* @param {string} key
	*/
	getItem(key) {
		return this.map.get(key);
	}
};
/* c8 ignore stop */
/**
* @type {any}
*/
var _localStorage = new VarStoragePolyfill();
/* c8 ignore start */
try {
	if (typeof localStorage !== "undefined" && localStorage) _localStorage = localStorage;
} catch (e) {}
/* c8 ignore stop */
/**
* This is basically localStorage in browser, or a polyfill in nodejs
*/
/* c8 ignore next */
var varStorage = _localStorage;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/trait/equality.js
var EqualityTraitSymbol = Symbol("Equality");
/**
* @typedef {{ [EqualityTraitSymbol]:(other:EqualityTrait)=>boolean }} EqualityTrait
*/
/**
*
* Utility function to compare any two objects.
*
* Note that it is expected that the first parameter is more specific than the latter one.
*
* @example js
*     class X { [traits.EqualityTraitSymbol] (other) { return other === this }  }
*     class X2 { [traits.EqualityTraitSymbol] (other) { return other === this }, x2 () { return 2 }  }
*     // this is fine
*     traits.equals(new X2(), new X())
*     // this is not, because the left type is less specific than the right one
*     traits.equals(new X(), new X2())
*
* @template {EqualityTrait} T
* @param {NoInfer<T>} a
* @param {T} b
* @return {boolean}
*/
var equals = (a, b) => a === b || !!a?.[EqualityTraitSymbol]?.(b) || false;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/object.js
/**
* @param {any} o
* @return {o is { [k:string]:any }}
*/
var isObject = (o) => typeof o === "object";
/**
* Object.assign
*/
var assign = Object.assign;
/**
* @param {Object<string,any>} obj
*/
var keys = Object.keys;
/**
* @template V
* @param {{[k:string]:V}} obj
* @param {function(V,string):any} f
*/
var forEach = (obj, f) => {
	for (const key in obj) f(obj[key], key);
};
/**
* @param {Object<string,any>} obj
* @return {number}
*/
var size = (obj) => keys(obj).length;
/**
* @param {Object|null|undefined} obj
*/
var isEmpty = (obj) => {
	for (const _k in obj) return false;
	return true;
};
/**
* @template {{ [key:string|number|symbol]: any }} T
* @param {T} obj
* @param {(v:T[keyof T],k:keyof T)=>boolean} f
* @return {boolean}
*/
var every = (obj, f) => {
	for (const key in obj) if (!f(obj[key], key)) return false;
	return true;
};
/**
* Calls `Object.prototype.hasOwnProperty`.
*
* @param {any} obj
* @param {string|number|symbol} key
* @return {boolean}
*/
var hasProperty = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
/**
* @param {Object<string,any>} a
* @param {Object<string,any>} b
* @return {boolean}
*/
var equalFlat = (a, b) => a === b || size(a) === size(b) && every(a, (val, key) => (val !== void 0 || hasProperty(b, key)) && equals(b[key], val));
/**
* Make an object immutable. This hurts performance and is usually not needed if you perform good
* coding practices.
*/
var freeze = Object.freeze;
/**
* Make an object and all its children immutable.
* This *really* hurts performance and is usually not needed if you perform good coding practices.
*
* @template {any} T
* @param {T} o
* @return {Readonly<T>}
*/
var deepFreeze = (o) => {
	for (const key in o) {
		const c = o[key];
		if (typeof c === "object" || typeof c === "function") deepFreeze(o[key]);
	}
	return freeze(o);
};
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/function.js
/**
* Common functions and function call helpers.
*
* @module function
*/
/**
* Calls all functions in `fs` with args. Only throws after all functions were called.
*
* @param {Array<function>} fs
* @param {Array<any>} args
*/
var callAll = (fs, args, i = 0) => {
	try {
		for (; i < fs.length; i++) fs[i](...args);
	} finally {
		if (i < fs.length) callAll(fs, args, i + 1);
	}
};
/**
* @template A
*
* @param {A} a
* @return {A}
*/
var id = (a) => a;
/* c8 ignore start */
/**
* @param {any} a
* @param {any} b
* @return {boolean}
*/
var equalityDeep = (a, b) => {
	if (a === b) return true;
	if (a == null || b == null || a.constructor !== b.constructor && (a.constructor || Object) !== (b.constructor || Object)) return false;
	if (a[EqualityTraitSymbol] != null) return a[EqualityTraitSymbol](b);
	switch (a.constructor) {
		case ArrayBuffer:
			a = new Uint8Array(a);
			b = new Uint8Array(b);
		case Uint8Array:
			if (a.byteLength !== b.byteLength) return false;
			for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
			break;
		case Set:
			if (a.size !== b.size) return false;
			for (const value of a) if (!b.has(value)) return false;
			break;
		case Map:
			if (a.size !== b.size) return false;
			for (const key of a.keys()) if (!b.has(key) || !equalityDeep(a.get(key), b.get(key))) return false;
			break;
		case void 0:
		case Object:
			if (size(a) !== size(b)) return false;
			for (const key in a) if (!hasProperty(a, key) || !equalityDeep(a[key], b[key])) return false;
			break;
		case Array:
			if (a.length !== b.length) return false;
			for (let i = 0; i < a.length; i++) if (!equalityDeep(a[i], b[i])) return false;
			break;
		default: return false;
	}
	return true;
};
/**
* @template V
* @template {V} OPTS
*
* @param {V} value
* @param {Array<OPTS>} options
*/
var isOneOf = (value, options) => options.includes(value);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/environment.js
/**
* Isomorphic module to work access the environment (query params, env variables).
*
* @module environment
*/
/* c8 ignore next 2 */
var isNode = typeof process !== "undefined" && process.release && /node|io\.js/.test(process.release.name) && Object.prototype.toString.call(typeof process !== "undefined" ? process : 0) === "[object process]";
typeof navigator !== "undefined" && /Mac/.test(navigator.platform);
/**
* @type {Map<string,string>}
*/
var params;
var args = [];
/* c8 ignore start */
var computeParams = () => {
	if (params === void 0) if (isNode) {
		params = create$5();
		const pargs = process.argv;
		let currParamName = null;
		for (let i = 0; i < pargs.length; i++) {
			const parg = pargs[i];
			if (parg[0] === "-") {
				if (currParamName !== null) params.set(currParamName, "");
				currParamName = parg;
			} else if (currParamName !== null) {
				params.set(currParamName, parg);
				currParamName = null;
			} else args.push(parg);
		}
		if (currParamName !== null) params.set(currParamName, "");
	} else if (typeof location === "object") {
		params = create$5();
		(location.search || "?").slice(1).split("&").forEach((kv) => {
			if (kv.length !== 0) {
				const [key, value] = kv.split("=");
				params.set(`--${fromCamelCase(key, "-")}`, value);
				params.set(`-${fromCamelCase(key, "-")}`, value);
			}
		});
	} else params = create$5();
	return params;
};
/* c8 ignore stop */
/**
* @param {string} name
* @return {boolean}
*/
/* c8 ignore next */
var hasParam = (name) => computeParams().has(name);
/**
* @param {string} name
* @return {string|null}
*/
/* c8 ignore next 4 */
var getVariable = (name) => isNode ? undefinedToNull({}[name.toUpperCase().replaceAll("-", "_")]) : undefinedToNull(varStorage.getItem(name));
/**
* @param {string} name
* @return {boolean}
*/
/* c8 ignore next 2 */
var hasConf = (name) => hasParam("--" + name) || getVariable(name) !== null;
/* c8 ignore next */
var production = hasConf("production");
/* c8 ignore start */
/**
* Color is enabled by default if the terminal supports it.
*
* Explicitly enable color using `--color` parameter
* Disable color using `--no-color` parameter or using `NO_COLOR=1` environment variable.
* `FORCE_COLOR=1` enables color and takes precedence over all.
*/
var supportsColor = isNode && isOneOf({}.FORCE_COLOR, [
	"true",
	"1",
	"2"
]) || !hasParam("--no-colors") && !hasConf("no-color") && (!isNode || process.stdout.isTTY) && (!isNode || hasParam("--color") || getVariable("COLORTERM") !== null || (getVariable("TERM") || "").includes("color"));
/* c8 ignore stop */
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/buffer.js
/**
* Utility functions to work with buffers (Uint8Array).
*
* @module buffer
*/
/**
* @param {number} len
*/
var createUint8ArrayFromLen = (len) => new Uint8Array(len);
/**
* Copy the content of an Uint8Array view to a new ArrayBuffer.
*
* @param {Uint8Array} uint8Array
* @return {Uint8Array}
*/
var copyUint8Array = (uint8Array) => {
	const newBuf = createUint8ArrayFromLen(uint8Array.byteLength);
	newBuf.set(uint8Array);
	return newBuf;
};
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/pair.js
/**
* Working with value pairs.
*
* @module pair
*/
/**
* @template L,R
*/
var Pair = class {
	/**
	* @param {L} left
	* @param {R} right
	*/
	constructor(left, right) {
		this.left = left;
		this.right = right;
	}
};
/**
* @template L,R
* @param {L} left
* @param {R} right
* @return {Pair<L,R>}
*/
var create$1 = (left, right) => new Pair(left, right);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/prng.js
/**
* Generates a single random bool.
*
* @param {PRNG} gen A random number generator.
* @return {Boolean} A random boolean
*/
var bool = (gen) => gen.next() >= .5;
/**
* Generates a random integer with 53 bit resolution.
*
* @param {PRNG} gen A random number generator.
* @param {Number} min The lower bound of the allowed return values (inclusive).
* @param {Number} max The upper bound of the allowed return values (inclusive).
* @return {Number} A random integer on [min, max]
*/
var int53 = (gen, min, max) => floor(gen.next() * (max + 1 - min) + min);
/**
* Generates a random integer with 32 bit resolution.
*
* @param {PRNG} gen A random number generator.
* @param {Number} min The lower bound of the allowed return values (inclusive).
* @param {Number} max The upper bound of the allowed return values (inclusive).
* @return {Number} A random integer on [min, max]
*/
var int32 = (gen, min, max) => floor(gen.next() * (max + 1 - min) + min);
/**
* @deprecated
* Optimized version of prng.int32. It has the same precision as prng.int32, but should be preferred when
* openaring on smaller ranges.
*
* @param {PRNG} gen A random number generator.
* @param {Number} min The lower bound of the allowed return values (inclusive).
* @param {Number} max The upper bound of the allowed return values (inclusive). The max inclusive number is `binary.BITS31-1`
* @return {Number} A random integer on [min, max]
*/
var int31 = (gen, min, max) => int32(gen, min, max);
/**
* @param {PRNG} gen
* @return {string} A single letter (a-z)
*/
var letter = (gen) => fromCharCode(int31(gen, 97, 122));
/**
* @param {PRNG} gen
* @param {number} [minLen=0]
* @param {number} [maxLen=20]
* @return {string} A random word (0-20 characters) without spaces consisting of letters (a-z)
*/
var word = (gen, minLen = 0, maxLen = 20) => {
	const len = int31(gen, minLen, maxLen);
	let str = "";
	for (let i = 0; i < len; i++) str += letter(gen);
	return str;
};
/**
* Returns one element of a given array.
*
* @param {PRNG} gen A random number generator.
* @param {Array<T>} array Non empty Array of possible values.
* @return {T} One of the values of the supplied Array.
* @template T
*/
var oneOf = (gen, array) => array[int31(gen, 0, array.length - 1)];
/* c8 ignore stop */
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/schema.js
/**
* @experimental WIP
*
* Simple & efficient schemas for your data.
*/
/**
* @typedef {string|number|bigint|boolean|null|undefined|symbol} Primitive
*/
/**
* @typedef {{ [k:string|number|symbol]: any }} AnyObject
*/
/**
* @template T
* @typedef {T extends Schema<infer X> ? X : T} Unwrap
*/
/**
* @template T
* @typedef {T extends Schema<infer X> ? X : T} TypeOf
*/
/**
* @template {readonly unknown[]} T
* @typedef {T extends readonly [Schema<infer First>, ...infer Rest] ? [First, ...UnwrapArray<Rest>] : [] } UnwrapArray
*/
/**
* @template T
* @typedef {T extends Schema<infer S> ? Schema<S> : never} CastToSchema
*/
/**
* @template {unknown[]} Arr
* @typedef {Arr extends [...unknown[], infer L] ? L : never} TupleLast
*/
/**
* @template {unknown[]} Arr
* @typedef {Arr extends [...infer Fs, unknown] ? Fs : never} TuplePop
*/
/**
* @template {readonly unknown[]} T
* @typedef {T extends []
*   ? {}
*   : T extends [infer First]
*   ? First
*   : T extends [infer First, ...infer Rest]
*   ? First & Intersect<Rest>
*   : never
* } Intersect
*/
var schemaSymbol = Symbol("0schema");
var ValidationError = class {
	constructor() {
		/**
		* Reverse errors
		* @type {Array<{ path: string?, expected: string, has: string, message: string? }>}
		*/
		this._rerrs = [];
	}
	/**
	* @param {string?} path
	* @param {string} expected
	* @param {string} has
	* @param {string?} message
	*/
	extend(path, expected, has, message = null) {
		this._rerrs.push({
			path,
			expected,
			has,
			message
		});
	}
	toString() {
		const s = [];
		for (let i = this._rerrs.length - 1; i > 0; i--) {
			const r = this._rerrs[i];
			/* c8 ignore next */
			s.push(repeat(" ", (this._rerrs.length - i) * 2) + `${r.path != null ? `[${r.path}] ` : ""}${r.has} doesn't match ${r.expected}. ${r.message}`);
		}
		return s.join("\n");
	}
};
/**
* @param {any} a
* @param {any} b
* @return {boolean}
*/
var shapeExtends = (a, b) => {
	if (a === b) return true;
	if (a == null || b == null || a.constructor !== b.constructor) return false;
	if (a[EqualityTraitSymbol]) return equals(a, b);
	if (isArray$1(a)) return every$1(a, (aitem) => some(b, (bitem) => shapeExtends(aitem, bitem)));
	else if (isObject(a)) return every(a, (aitem, akey) => shapeExtends(aitem, b[akey]));
	/* c8 ignore next */
	return false;
};
/**
* @template T
* @implements {equalityTraits.EqualityTrait}
*/
var Schema = class {
	/**
	* If true, the more things are added to the shape the more objects this schema will accept (e.g.
	* union). By default, the more objects are added, the the fewer objects this schema will accept.
	* @protected
	*/
	static _dilutes = false;
	/**
	* @param {Schema<any>} other
	*/
	extends(other) {
		let [a, b] = [this.shape, other.shape];
		if (this.constructor._dilutes) [b, a] = [a, b];
		return shapeExtends(a, b);
	}
	/**
	* Overwrite this when necessary. By default, we only check the `shape` property which every shape
	* should have.
	* @param {Schema<any>} other
	*/
	equals(other) {
		return this.constructor === other.constructor && equalityDeep(this.shape, other.shape);
	}
	[schemaSymbol]() {
		return true;
	}
	/**
	* @param {object} other
	*/
	[EqualityTraitSymbol](other) {
		return this.equals(other);
	}
	/**
	* Use `schema.validate(obj)` with a typed parameter that is already of typed to be an instance of
	* Schema. Validate will check the structure of the parameter and return true iff the instance
	* really is an instance of Schema.
	*
	* @param {T} o
	* @return {boolean}
	*/
	validate(o) {
		return this.check(o);
	}
	/* c8 ignore start */
	/**
	* Similar to validate, but this method accepts untyped parameters.
	*
	* @param {any} _o
	* @param {ValidationError} [_err]
	* @return {_o is T}
	*/
	check(_o, _err) {
		methodUnimplemented();
	}
	/* c8 ignore stop */
	/**
	* @type {Schema<T?>}
	*/
	get nullable() {
		return $union(this, $null);
	}
	/**
	* @type {$Optional<Schema<T>>}
	*/
	get optional() {
		return new $Optional(this);
	}
	/**
	* Cast a variable to a specific type. Returns the casted value, or throws an exception otherwise.
	* Use this if you know that the type is of a specific type and you just want to convince the type
	* system.
	*
	* **Do not rely on these error messages!**
	* Performs an assertion check only if not in a production environment.
	*
	* @template OO
	* @param {OO} o
	* @return {Extract<OO, T> extends never ? T : (OO extends Array<never> ? T : Extract<OO,T>)}
	*/
	cast(o) {
		assert(o, this);
		return o;
	}
	/**
	* EXPECTO PATRONUM!! 🪄
	* This function protects against type errors. Though it may not work in the real world.
	*
	* "After all this time?"
	* "Always." - Snape, talking about type safety
	*
	* Ensures that a variable is a a specific type. Returns the value, or throws an exception if the assertion check failed.
	* Use this if you know that the type is of a specific type and you just want to convince the type
	* system.
	*
	* Can be useful when defining lambdas: `s.lambda(s.$number, s.$void).expect((n) => n + 1)`
	*
	* **Do not rely on these error messages!**
	* Performs an assertion check if not in a production environment.
	*
	* @param {T} o
	* @return {o extends T ? T : never}
	*/
	expect(o) {
		assert(o, this);
		return o;
	}
};
/**
* @template {(new (...args:any[]) => any) | ((...args:any[]) => any)} Constr
* @typedef {Constr extends ((...args:any[]) => infer T) ? T : (Constr extends (new (...args:any[]) => any) ? InstanceType<Constr> : never)} Instance
*/
/**
* @template {(new (...args:any[]) => any) | ((...args:any[]) => any)} C
* @extends {Schema<Instance<C>>}
*/
var $ConstructedBy = class extends Schema {
	/**
	* @param {C} c
	* @param {((o:Instance<C>)=>boolean)|null} check
	*/
	constructor(c, check) {
		super();
		this.shape = c;
		this._c = check;
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is C extends ((...args:any[]) => infer T) ? T : (C extends (new (...args:any[]) => any) ? InstanceType<C> : never)} o
	*/
	check(o, err = void 0) {
		const c = o?.constructor === this.shape && (this._c == null || this._c(o));
		/* c8 ignore next */
		!c && err?.extend(null, this.shape.name, o?.constructor.name, o?.constructor !== this.shape ? "Constructor match failed" : "Check failed");
		return c;
	}
};
/**
* @template {(new (...args:any[]) => any) | ((...args:any[]) => any)} C
* @param {C} c
* @param {((o:Instance<C>) => boolean)|null} check
* @return {CastToSchema<$ConstructedBy<C>>}
*/
var $constructedBy = (c, check = null) => new $ConstructedBy(c, check);
$constructedBy($ConstructedBy);
/**
* Check custom properties on any object. You may want to overwrite the generated Schema<any>.
*
* @extends {Schema<any>}
*/
var $Custom = class extends Schema {
	/**
	* @param {(o:any) => boolean} check
	*/
	constructor(check) {
		super();
		/**
		* @type {(o:any) => boolean}
		*/
		this.shape = check;
	}
	/**
	* @param {any} o
	* @param {ValidationError} err
	* @return {o is any}
	*/
	check(o, err) {
		const c = this.shape(o);
		/* c8 ignore next */
		!c && err?.extend(null, "custom prop", o?.constructor.name, "failed to check custom prop");
		return c;
	}
};
/**
* @param {(o:any) => boolean} check
* @return {Schema<any>}
*/
var $custom = (check) => new $Custom(check);
$constructedBy($Custom);
/**
* @template {Primitive} T
* @extends {Schema<T>}
*/
var $Literal = class extends Schema {
	/**
	* @param {Array<T>} literals
	*/
	constructor(literals) {
		super();
		this.shape = literals;
	}
	/**
	*
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is T}
	*/
	check(o, err) {
		const c = this.shape.some((a) => a === o);
		/* c8 ignore next */
		!c && err?.extend(null, this.shape.join(" | "), o.toString());
		return c;
	}
};
/**
* @template {Primitive[]} T
* @param {T} literals
* @return {CastToSchema<$Literal<T[number]>>}
*/
var $literal = (...literals) => new $Literal(literals);
var $$literal = $constructedBy($Literal);
/**
* @template {Array<string|Schema<string|number>>} Ts
* @typedef {Ts extends [] ? `` : (Ts extends [infer T] ? (Unwrap<T> extends (string|number) ? Unwrap<T> : never) : (Ts extends [infer T1, ...infer Rest] ? `${Unwrap<T1> extends (string|number) ? Unwrap<T1> : never}${Rest extends Array<string|Schema<string|number>> ? CastStringTemplateArgsToTemplate<Rest> : never}` : never))} CastStringTemplateArgsToTemplate
*/
/**
* @param {string} str
* @return {string}
*/
var _regexEscape = RegExp.escape || ((str) => str.replace(/[().|&,$^[\]]/g, (s) => "\\" + s));
/**
* @param {string|Schema<any>} s
* @return {string[]}
*/
var _schemaStringTemplateToRegex = (s) => {
	if ($string.check(s)) return [_regexEscape(s)];
	if ($$literal.check(s)) return s.shape.map((v) => v + "");
	if ($$number.check(s)) return ["[+-]?\\d+.?\\d*"];
	if ($$string.check(s)) return [".*"];
	if ($$union.check(s)) return s.shape.map(_schemaStringTemplateToRegex).flat(1);
	/* c8 ignore next 2 */
	unexpectedCase();
};
/**
* @template {Array<string|Schema<string|number>>} T
* @extends {Schema<CastStringTemplateArgsToTemplate<T>>}
*/
var $StringTemplate = class extends Schema {
	/**
	* @param {T} shape
	*/
	constructor(shape) {
		super();
		this.shape = shape;
		this._r = new RegExp("^" + shape.map(_schemaStringTemplateToRegex).map((opts) => `(${opts.join("|")})`).join("") + "$");
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is CastStringTemplateArgsToTemplate<T>}
	*/
	check(o, err) {
		const c = this._r.exec(o) != null;
		/* c8 ignore next */
		!c && err?.extend(null, this._r.toString(), o.toString(), "String doesn't match string template.");
		return c;
	}
};
$constructedBy($StringTemplate);
var isOptionalSymbol = Symbol("optional");
/**
* @template {Schema<any>} S
* @extends Schema<Unwrap<S>|undefined>
*/
var $Optional = class extends Schema {
	/**
	* @param {S} shape
	*/
	constructor(shape) {
		super();
		this.shape = shape;
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is (Unwrap<S>|undefined)}
	*/
	check(o, err) {
		const c = o === void 0 || this.shape.check(o);
		/* c8 ignore next */
		!c && err?.extend(null, "undefined (optional)", "()");
		return c;
	}
	get [isOptionalSymbol]() {
		return true;
	}
};
var $$optional = $constructedBy($Optional);
/**
* @extends Schema<never>
*/
var $Never = class extends Schema {
	/**
	* @param {any} _o
	* @param {ValidationError} [err]
	* @return {_o is never}
	*/
	check(_o, err) {
		/* c8 ignore next */
		err?.extend(null, "never", typeof _o);
		return false;
	}
};
new $Never();
$constructedBy($Never);
/**
* @template {{ [key: string|symbol|number]: Schema<any> }} S
* @typedef {{ [Key in keyof S as S[Key] extends $Optional<Schema<any>> ? Key : never]?: S[Key] extends $Optional<Schema<infer Type>> ? Type : never } & { [Key in keyof S as S[Key] extends $Optional<Schema<any>> ? never : Key]: S[Key] extends Schema<infer Type> ? Type : never }} $ObjectToType
*/
/**
* @template {{[key:string|symbol|number]: Schema<any>}} S
* @extends {Schema<$ObjectToType<S>>}
*/
var $Object = class $Object extends Schema {
	/**
	* @param {S} shape
	* @param {boolean} partial
	*/
	constructor(shape, partial = false) {
		super();
		/**
		* @type {S}
		*/
		this.shape = shape;
		this._isPartial = partial;
	}
	static _dilutes = true;
	/**
	* @type {Schema<Partial<$ObjectToType<S>>>}
	*/
	get partial() {
		return new $Object(this.shape, true);
	}
	/**
	* @param {any} o
	* @param {ValidationError} err
	* @return {o is $ObjectToType<S>}
	*/
	check(o, err) {
		if (o == null) {
			/* c8 ignore next */
			err?.extend(null, "object", "null");
			return false;
		}
		return every(this.shape, (vv, vk) => {
			const c = this._isPartial && !hasProperty(o, vk) || vv.check(o[vk], err);
			!c && err?.extend(vk.toString(), vv.toString(), typeof o[vk], "Object property does not match");
			return c;
		});
	}
};
/**
* @template S
* @typedef {Schema<{ [Key in keyof S as S[Key] extends $Optional<Schema<any>> ? Key : never]?: S[Key] extends $Optional<Schema<infer Type>> ? Type : never } & { [Key in keyof S as S[Key] extends $Optional<Schema<any>> ? never : Key]: S[Key] extends Schema<infer Type> ? Type : never }>} _ObjectDefToSchema
*/
/**
* @template {{ [key:string|symbol|number]: Schema<any> }} S
* @param {S} def
* @return {_ObjectDefToSchema<S> extends Schema<infer S> ? Schema<{ [K in keyof S]: S[K] }> : never}
*/
var $object = (def) => new $Object(def);
var $$object = $constructedBy($Object);
/**
* @type {Schema<{[key:string]: any}>}
*/
var $objectAny = $custom((o) => o != null && (o.constructor === Object || o.constructor == null));
/**
* @template {Schema<string|number|symbol>} Keys
* @template {Schema<any>} Values
* @extends {Schema<{ [key in Unwrap<Keys>]: Unwrap<Values> }>}
*/
var $Record = class extends Schema {
	/**
	* @param {Keys} keys
	* @param {Values} values
	*/
	constructor(keys, values) {
		super();
		this.shape = {
			keys,
			values
		};
	}
	/**
	* @param {any} o
	* @param {ValidationError} err
	* @return {o is { [key in Unwrap<Keys>]: Unwrap<Values> }}
	*/
	check(o, err) {
		return o != null && every(o, (vv, vk) => {
			const ck = this.shape.keys.check(vk, err);
			/* c8 ignore next */
			!ck && err?.extend(vk + "", "Record", typeof o, ck ? "Key doesn't match schema" : "Value doesn't match value");
			return ck && this.shape.values.check(vv, err);
		});
	}
};
/**
* @template {Schema<string|number|symbol>} Keys
* @template {Schema<any>} Values
* @param {Keys} keys
* @param {Values} values
* @return {CastToSchema<$Record<Keys,Values>>}
*/
var $record = (keys, values) => new $Record(keys, values);
var $$record = $constructedBy($Record);
/**
* @template {Schema<any>[]} S
* @extends {Schema<{ [Key in keyof S]: S[Key] extends Schema<infer Type> ? Type : never }>}
*/
var $Tuple = class extends Schema {
	/**
	* @param {S} shape
	*/
	constructor(shape) {
		super();
		this.shape = shape;
	}
	/**
	* @param {any} o
	* @param {ValidationError} err
	* @return {o is { [K in keyof S]: S[K] extends Schema<infer Type> ? Type : never }}
	*/
	check(o, err) {
		return o != null && every(this.shape, (vv, vk) => {
			const c = vv.check(o[vk], err);
			/* c8 ignore next */
			!c && err?.extend(vk.toString(), "Tuple", typeof vv);
			return c;
		});
	}
};
/**
* @template {Array<Schema<any>>} T
* @param {T} def
* @return {CastToSchema<$Tuple<T>>}
*/
var $tuple = (...def) => new $Tuple(def);
$constructedBy($Tuple);
/**
* @template {Schema<any>} S
* @extends {Schema<Array<S extends Schema<infer T> ? T : never>>}
*/
var $Array = class extends Schema {
	/**
	* @param {Array<S>} v
	*/
	constructor(v) {
		super();
		/**
		* @type {Schema<S extends Schema<infer T> ? T : never>}
		*/
		this.shape = v.length === 1 ? v[0] : new $Union(v);
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is Array<S extends Schema<infer T> ? T : never>} o
	*/
	check(o, err) {
		const c = isArray$1(o) && every$1(o, (oi) => this.shape.check(oi));
		/* c8 ignore next */
		!c && err?.extend(null, "Array", "");
		return c;
	}
};
/**
* @template {Array<Schema<any>>} T
* @param {T} def
* @return {Schema<Array<T extends Array<Schema<infer S>> ? S : never>>}
*/
var $array = (...def) => new $Array(def);
var $$array = $constructedBy($Array);
/**
* @type {Schema<Array<any>>}
*/
var $arrayAny = $custom((o) => isArray$1(o));
/**
* @template T
* @extends {Schema<T>}
*/
var $InstanceOf = class extends Schema {
	/**
	* @param {new (...args:any) => T} constructor
	* @param {((o:T) => boolean)|null} check
	*/
	constructor(constructor, check) {
		super();
		this.shape = constructor;
		this._c = check;
	}
	/**
	* @param {any} o
	* @param {ValidationError} err
	* @return {o is T}
	*/
	check(o, err) {
		const c = o instanceof this.shape && (this._c == null || this._c(o));
		/* c8 ignore next */
		!c && err?.extend(null, this.shape.name, o?.constructor.name);
		return c;
	}
};
/**
* @template T
* @param {new (...args:any) => T} c
* @param {((o:T) => boolean)|null} check
* @return {Schema<T>}
*/
var $instanceOf = (c, check = null) => new $InstanceOf(c, check);
$constructedBy($InstanceOf);
var $$schema = $instanceOf(Schema);
/**
* @template {Schema<any>[]} Args
* @typedef {(...args:UnwrapArray<TuplePop<Args>>)=>Unwrap<TupleLast<Args>>} _LArgsToLambdaDef
*/
/**
* @template {Array<Schema<any>>} Args
* @extends {Schema<_LArgsToLambdaDef<Args>>}
*/
var $Lambda = class extends Schema {
	/**
	* @param {Args} args
	*/
	constructor(args) {
		super();
		this.len = args.length - 1;
		this.args = $tuple(...args.slice(-1));
		this.res = args[this.len];
	}
	/**
	* @param {any} f
	* @param {ValidationError} err
	* @return {f is _LArgsToLambdaDef<Args>}
	*/
	check(f, err) {
		const c = f.constructor === Function && f.length <= this.len;
		/* c8 ignore next */
		!c && err?.extend(null, "function", typeof f);
		return c;
	}
};
var $$lambda = $constructedBy($Lambda);
/**
* @type {Schema<Function>}
*/
var $function = $custom((o) => typeof o === "function");
/**
* @template {Array<Schema<any>>} T
* @extends {Schema<Intersect<UnwrapArray<T>>>}
*/
var $Intersection = class extends Schema {
	/**
	* @param {T} v
	*/
	constructor(v) {
		super();
		/**
		* @type {T}
		*/
		this.shape = v;
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is Intersect<UnwrapArray<T>>}
	*/
	check(o, err) {
		const c = every$1(this.shape, (check) => check.check(o, err));
		/* c8 ignore next */
		!c && err?.extend(null, "Intersectinon", typeof o);
		return c;
	}
};
$constructedBy($Intersection, (o) => o.shape.length > 0);
/**
* @template S
* @extends {Schema<S>}
*/
var $Union = class extends Schema {
	static _dilutes = true;
	/**
	* @param {Array<Schema<S>>} v
	*/
	constructor(v) {
		super();
		this.shape = v;
	}
	/**
	* @param {any} o
	* @param {ValidationError} [err]
	* @return {o is S}
	*/
	check(o, err) {
		const c = some(this.shape, (vv) => vv.check(o, err));
		err?.extend(null, "Union", typeof o);
		return c;
	}
};
/**
* @template {Array<any>} T
* @param {T} schemas
* @return {CastToSchema<$Union<Unwrap<ReadSchema<T>>>>}
*/
var $union = (...schemas) => schemas.findIndex(($s) => $$union.check($s)) >= 0 ? $union(...schemas.map(($s) => $($s)).map(($s) => $$union.check($s) ? $s.shape : [$s]).flat(1)) : schemas.length === 1 ? schemas[0] : new $Union(schemas);
var $$union = $constructedBy($Union);
var _t = () => true;
/**
* @type {Schema<any>}
*/
var $any = $custom(_t);
var $$any = $constructedBy($Custom, (o) => o.shape === _t);
/**
* @type {Schema<bigint>}
*/
var $bigint = $custom((o) => typeof o === "bigint");
var $$bigint = $custom((o) => o === $bigint);
/**
* @type {Schema<symbol>}
*/
var $symbol = $custom((o) => typeof o === "symbol");
$custom((o) => o === $symbol);
/**
* @type {Schema<number>}
*/
var $number = $custom((o) => typeof o === "number");
var $$number = $custom((o) => o === $number);
/**
* @type {Schema<string>}
*/
var $string = $custom((o) => typeof o === "string");
var $$string = $custom((o) => o === $string);
/**
* @type {Schema<boolean>}
*/
var $boolean = $custom((o) => typeof o === "boolean");
var $$boolean = $custom((o) => o === $boolean);
/**
* @type {Schema<undefined>}
*/
var $undefined = $literal(void 0);
$constructedBy($Literal, (o) => o.shape.length === 1 && o.shape[0] === void 0);
$literal(void 0);
var $null = $literal(null);
var $$null = $constructedBy($Literal, (o) => o.shape.length === 1 && o.shape[0] === null);
$constructedBy(Uint8Array);
$constructedBy($ConstructedBy, (o) => o.shape === Uint8Array);
/**
* @type {Schema<Primitive>}
*/
var $primitive = $union($number, $string, $null, $undefined, $bigint, $boolean, $symbol);
(() => {
	const $jsonArr = $array($any);
	const $jsonRecord = $record($string, $any);
	const $json = $union($number, $string, $null, $boolean, $jsonArr, $jsonRecord);
	$jsonArr.shape = $json;
	$jsonRecord.shape.values = $json;
	return $json;
})();
/**
* @template {any} IN
* @typedef {IN extends Schema<any> ? IN
*   : (IN extends string|number|boolean|null ? Schema<IN>
*     : (IN extends new (...args:any[])=>any ? Schema<InstanceType<IN>>
*       : (IN extends any[] ? Schema<{ [K in keyof IN]: Unwrap<ReadSchema<IN[K]>> }[number]>
*       : (IN extends object ? (_ObjectDefToSchema<{[K in keyof IN]:ReadSchema<IN[K]>}> extends Schema<infer S> ? Schema<{ [K in keyof S]: S[K] }> : never)
*         : never)
*         )
*       )
*     )
* } ReadSchemaOld
*/
/**
* @template {any} IN
* @typedef {[Extract<IN,Schema<any>>,Extract<IN,string|number|boolean|null>,Extract<IN,new (...args:any[])=>any>,Extract<IN,any[]>,Extract<Exclude<IN,Schema<any>|string|number|boolean|null|(new (...args:any[])=>any)|any[]>,object>] extends [infer Schemas, infer Primitives, infer Constructors, infer Arrs, infer Obj]
*   ? Schema<
*       (Schemas extends Schema<infer S> ? S : never)
*     | Primitives
*     | (Constructors extends new (...args:any[])=>any ? InstanceType<Constructors> : never)
*     | (Arrs extends any[] ? { [K in keyof Arrs]: Unwrap<ReadSchema<Arrs[K]>> }[number] : never)
*     | (Obj extends object ? Unwrap<(_ObjectDefToSchema<{[K in keyof Obj]:ReadSchema<Obj[K]>}> extends Schema<infer S> ? Schema<{ [K in keyof S]: S[K] }> : never)> : never)>
*   : never
* } ReadSchema
*/
/**
* @typedef {ReadSchema<{x:42}|{y:99}|Schema<string>|[1,2,{}]>} Q
*/
/**
* @template IN
* @param {IN} o
* @return {ReadSchema<IN>}
*/
var $ = (o) => {
	if ($$schema.check(o)) return o;
	else if ($objectAny.check(o)) {
		/**
		* @type {any}
		*/
		const o2 = {};
		for (const k in o) o2[k] = $(o[k]);
		return $object(o2);
	} else if ($arrayAny.check(o)) return $union(...o.map($));
	else if ($primitive.check(o)) return $literal(o);
	else if ($function.check(o)) return $constructedBy(o);
	/* c8 ignore next */
	unexpectedCase();
};
/* c8 ignore start */
/**
* Assert that a variable is of this specific type.
* The assertion check is only performed in non-production environments.
*
* @type {<T>(o:any,schema:Schema<T>) => asserts o is T}
*/
var assert = production ? () => {} : (o, schema) => {
	const err = new ValidationError();
	if (!schema.check(o, err)) throw create$3(`Expected value to be of type ${schema.constructor.name}.\n${err.toString()}`);
};
/* c8 ignore end */
/**
* @template In
* @template Out
* @typedef {{ if: Schema<In>, h: (o:In,state?:any)=>Out }} Pattern
*/
/**
* @template {Pattern<any,any>} P
* @template In
* @typedef {ReturnType<Extract<P,Pattern<In extends number ? number : (In extends string ? string : In),any>>['h']>} PatternMatchResult
*/
/**
* @todo move this to separate library
* @template {any} [State=undefined]
* @template {Pattern<any,any>} [Patterns=never]
*/
var PatternMatcher = class {
	/**
	* @param {Schema<State>} [$state]
	*/
	constructor($state) {
		/**
		* @type {Array<Patterns>}
		*/
		this.patterns = [];
		this.$state = $state;
	}
	/**
	* @template P
	* @template R
	* @param {P} pattern
	* @param {(o:NoInfer<Unwrap<ReadSchema<P>>>,s:State)=>R} handler
	* @return {PatternMatcher<State,Patterns|Pattern<Unwrap<ReadSchema<P>>,R>>}
	*/
	if(pattern, handler) {
		this.patterns.push({
			if: $(pattern),
			h: handler
		});
		return this;
	}
	/**
	* @template R
	* @param {(o:any,s:State)=>R} h
	*/
	else(h) {
		return this.if($any, h);
	}
	/**
	* @return {State extends undefined
	*   ? <In extends Unwrap<Patterns['if']>>(o:In,state?:undefined)=>PatternMatchResult<Patterns,In>
	*   : <In extends Unwrap<Patterns['if']>>(o:In,state:State)=>PatternMatchResult<Patterns,In>}
	*/
	done() {
		return (o, s) => {
			for (let i = 0; i < this.patterns.length; i++) {
				const p = this.patterns[i];
				if (p.if.check(o)) return p.h(o, s);
			}
			throw create$3("Unhandled pattern");
		};
	}
};
/**
* @template [State=undefined]
* @param {State} [state]
* @return {PatternMatcher<State extends undefined ? undefined : Unwrap<ReadSchema<State>>>}
*/
var match = (state) => new PatternMatcher(state);
/**
* Helper function to generate a (non-exhaustive) sample set from a gives schema.
*
* @type {<T>(o:T,gen:prng.PRNG)=>T}
*/
var _random = match($any).if($$number, (_o, gen) => int53(gen, MIN_SAFE_INTEGER, MAX_SAFE_INTEGER)).if($$string, (_o, gen) => word(gen)).if($$boolean, (_o, gen) => bool(gen)).if($$bigint, (_o, gen) => BigInt(int53(gen, MIN_SAFE_INTEGER, MAX_SAFE_INTEGER))).if($$union, (o, gen) => random(gen, oneOf(gen, o.shape))).if($$object, (o, gen) => {
	/**
	* @type {any}
	*/
	const res = {};
	for (const k in o.shape) {
		let prop = o.shape[k];
		if ($$optional.check(prop)) {
			if (bool(gen)) continue;
			prop = prop.shape;
		}
		res[k] = _random(prop, gen);
	}
	return res;
}).if($$array, (o, gen) => {
	const arr = [];
	const n = int32(gen, 0, 42);
	for (let i = 0; i < n; i++) arr.push(random(gen, o.shape));
	return arr;
}).if($$literal, (o, gen) => {
	return oneOf(gen, o.shape);
}).if($$null, (o, gen) => {
	return null;
}).if($$lambda, (o, gen) => {
	const res = random(gen, o.res);
	return () => res;
}).if($$any, (o, gen) => random(gen, oneOf(gen, [
	$number,
	$string,
	$null,
	$undefined,
	$bigint,
	$boolean,
	$array($number),
	$record($union("a", "b", "c"), $number)
]))).if($$record, (o, gen) => {
	/**
	* @type {any}
	*/
	const res = {};
	const keysN = int53(gen, 0, 3);
	for (let i = 0; i < keysN; i++) {
		const key = random(gen, o.shape.keys);
		res[key] = random(gen, o.shape.values);
	}
	return res;
}).done();
/**
* @template S
* @param {prng.PRNG} gen
* @param {S} schema
* @return {Unwrap<ReadSchema<S>>}
*/
var random = (gen, schema) => _random($(schema), gen);
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/dom.js
/* c8 ignore start */
/**
* @type {Document}
*/
var doc = typeof document !== "undefined" ? document : {};
$custom((el) => el.nodeType === DOCUMENT_FRAGMENT_NODE);
typeof DOMParser !== "undefined" && new DOMParser();
$custom((el) => el.nodeType === ELEMENT_NODE);
$custom((el) => el.nodeType === TEXT_NODE);
/**
* @param {Map<string,string>} m
* @return {string}
*/
var mapToStyleString = (m) => map(m, (value, key) => `${key}:${value};`).join("");
var ELEMENT_NODE = doc.ELEMENT_NODE;
var TEXT_NODE = doc.TEXT_NODE;
doc.CDATA_SECTION_NODE;
doc.COMMENT_NODE;
var DOCUMENT_NODE = doc.DOCUMENT_NODE;
doc.DOCUMENT_TYPE_NODE;
var DOCUMENT_FRAGMENT_NODE = doc.DOCUMENT_FRAGMENT_NODE;
$custom((el) => el.nodeType === DOCUMENT_NODE);
/* c8 ignore stop */
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/symbol.js
/**
* Utility module to work with EcmaScript Symbols.
*
* @module symbol
*/
/**
* Return fresh symbol.
*/
var create = Symbol;
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/logging.common.js
var BOLD = create();
var UNBOLD = create();
var BLUE = create();
var GREY = create();
var GREEN = create();
var RED = create();
var PURPLE = create();
var ORANGE = create();
var UNCOLOR = create();
/* c8 ignore start */
/**
* @param {Array<undefined|string|Symbol|Object|number|function():any>} args
* @return {Array<string|object|number|undefined>}
*/
var computeNoColorLoggingArgs = (args) => {
	if (args.length === 1 && args[0]?.constructor === Function) args = args[0]();
	const strBuilder = [];
	const logArgs = [];
	let i = 0;
	for (; i < args.length; i++) {
		const arg = args[i];
		if (arg === void 0) break;
		else if (arg.constructor === String || arg.constructor === Number) strBuilder.push(arg);
		else if (arg.constructor === Object) break;
	}
	if (i > 0) logArgs.push(strBuilder.join(""));
	for (; i < args.length; i++) {
		const arg = args[i];
		if (!(arg instanceof Symbol)) logArgs.push(arg);
	}
	return logArgs;
};
getUnixTime();
/* c8 ignore stop */
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/logging.js
/**
* Isomorphic logging module with support for colors!
*
* @module logging
*/
/**
* @type {Object<Symbol,pair.Pair<string,string>>}
*/
var _browserStyleMap = {
	[BOLD]: create$1("font-weight", "bold"),
	[UNBOLD]: create$1("font-weight", "normal"),
	[BLUE]: create$1("color", "blue"),
	[GREEN]: create$1("color", "green"),
	[GREY]: create$1("color", "grey"),
	[RED]: create$1("color", "red"),
	[PURPLE]: create$1("color", "purple"),
	[ORANGE]: create$1("color", "orange"),
	[UNCOLOR]: create$1("color", "black")
};
/**
* @param {Array<string|Symbol|Object|number|function():any>} args
* @return {Array<string|object|number>}
*/
/* c8 ignore start */
var computeBrowserLoggingArgs = (args) => {
	if (args.length === 1 && args[0]?.constructor === Function) args = args[0]();
	const strBuilder = [];
	const styles = [];
	const currentStyle = create$5();
	/**
	* @type {Array<string|Object|number>}
	*/
	let logArgs = [];
	let i = 0;
	for (; i < args.length; i++) {
		const arg = args[i];
		const style = _browserStyleMap[arg];
		if (style !== void 0) currentStyle.set(style.left, style.right);
		else {
			if (arg === void 0) break;
			if (arg.constructor === String || arg.constructor === Number) {
				const style = mapToStyleString(currentStyle);
				if (i > 0 || style.length > 0) {
					strBuilder.push("%c" + arg);
					styles.push(style);
				} else strBuilder.push(arg);
			} else break;
		}
	}
	if (i > 0) {
		logArgs = styles;
		logArgs.unshift(strBuilder.join(""));
	}
	for (; i < args.length; i++) {
		const arg = args[i];
		if (!(arg instanceof Symbol)) logArgs.push(arg);
	}
	return logArgs;
};
/* c8 ignore stop */
/* c8 ignore start */
var computeLoggingArgs = supportsColor ? computeBrowserLoggingArgs : computeNoColorLoggingArgs;
/* c8 ignore stop */
/**
* @param {Array<string|Symbol|Object|number>} args
*/
var print = (...args) => {
	console.log(...computeLoggingArgs(args));
	/* c8 ignore next */
	vconsoles.forEach((vc) => vc.print(args));
};
/* c8 ignore start */
/**
* @param {Array<string|Symbol|Object|number>} args
*/
var warn = (...args) => {
	console.warn(...computeLoggingArgs(args));
	args.unshift(ORANGE);
	vconsoles.forEach((vc) => vc.print(args));
};
var vconsoles = create$4();
//#endregion
//#region ../node_modules/.pnpm/lib0@0.2.117/node_modules/lib0/iterator.js
/**
* @template T
* @param {function():IteratorResult<T>} next
* @return {IterableIterator<T>}
*/
var createIterator = (next) => ({
	[Symbol.iterator]() {
		return this;
	},
	next
});
/**
* @template T
* @param {Iterator<T>} iterator
* @param {function(T):boolean} filter
*/
var iteratorFilter = (iterator, filter) => createIterator(() => {
	let res;
	do
		res = iterator.next();
	while (!res.done && !filter(res.value));
	return res;
});
/**
* @template T,M
* @param {Iterator<T>} iterator
* @param {function(T):M} fmap
*/
var iteratorMap = (iterator, fmap) => createIterator(() => {
	const { done, value } = iterator.next();
	return {
		done,
		value: done ? void 0 : fmap(value)
	};
});
//#endregion
//#region ../node_modules/.pnpm/yjs@13.6.30/node_modules/yjs/dist/yjs.mjs
var DeleteItem = class {
	/**
	* @param {number} clock
	* @param {number} len
	*/
	constructor(clock, len) {
		/**
		* @type {number}
		*/
		this.clock = clock;
		/**
		* @type {number}
		*/
		this.len = len;
	}
};
/**
* We no longer maintain a DeleteStore. DeleteSet is a temporary object that is created when needed.
* - When created in a transaction, it must only be accessed after sorting, and merging
*   - This DeleteSet is send to other clients
* - We do not create a DeleteSet when we send a sync message. The DeleteSet message is created directly from StructStore
* - We read a DeleteSet as part of a sync/update message. In this case the DeleteSet is already sorted and merged.
*/
var DeleteSet = class {
	constructor() {
		/**
		* @type {Map<number,Array<DeleteItem>>}
		*/
		this.clients = /* @__PURE__ */ new Map();
	}
};
/**
* Iterate over all structs that the DeleteSet gc's.
*
* @param {Transaction} transaction
* @param {DeleteSet} ds
* @param {function(GC|Item):void} f
*
* @function
*/
var iterateDeletedStructs = (transaction, ds, f) => ds.clients.forEach((deletes, clientid) => {
	const structs = transaction.doc.store.clients.get(clientid);
	if (structs != null) {
		const lastStruct = structs[structs.length - 1];
		const clockState = lastStruct.id.clock + lastStruct.length;
		for (let i = 0, del = deletes[i]; i < deletes.length && del.clock < clockState; del = deletes[++i]) iterateStructs(transaction, structs, del.clock, del.len, f);
	}
});
/**
* @param {Array<DeleteItem>} dis
* @param {number} clock
* @return {number|null}
*
* @private
* @function
*/
var findIndexDS = (dis, clock) => {
	let left = 0;
	let right = dis.length - 1;
	while (left <= right) {
		const midindex = floor((left + right) / 2);
		const mid = dis[midindex];
		const midclock = mid.clock;
		if (midclock <= clock) {
			if (clock < midclock + mid.len) return midindex;
			left = midindex + 1;
		} else right = midindex - 1;
	}
	return null;
};
/**
* @param {DeleteSet} ds
* @param {ID} id
* @return {boolean}
*
* @private
* @function
*/
var isDeleted = (ds, id) => {
	const dis = ds.clients.get(id.client);
	return dis !== void 0 && findIndexDS(dis, id.clock) !== null;
};
/**
* @param {DeleteSet} ds
*
* @private
* @function
*/
var sortAndMergeDeleteSet = (ds) => {
	ds.clients.forEach((dels) => {
		dels.sort((a, b) => a.clock - b.clock);
		let i, j;
		for (i = 1, j = 1; i < dels.length; i++) {
			const left = dels[j - 1];
			const right = dels[i];
			if (left.clock + left.len >= right.clock) dels[j - 1] = new DeleteItem(left.clock, max(left.len, right.clock + right.len - left.clock));
			else {
				if (j < i) dels[j] = right;
				j++;
			}
		}
		dels.length = j;
	});
};
/**
* @param {Array<DeleteSet>} dss
* @return {DeleteSet} A fresh DeleteSet
*/
var mergeDeleteSets = (dss) => {
	const merged = new DeleteSet();
	for (let dssI = 0; dssI < dss.length; dssI++) dss[dssI].clients.forEach((delsLeft, client) => {
		if (!merged.clients.has(client)) {
			/**
			* @type {Array<DeleteItem>}
			*/
			const dels = delsLeft.slice();
			for (let i = dssI + 1; i < dss.length; i++) appendTo(dels, dss[i].clients.get(client) || []);
			merged.clients.set(client, dels);
		}
	});
	sortAndMergeDeleteSet(merged);
	return merged;
};
/**
* @param {DeleteSet} ds
* @param {number} client
* @param {number} clock
* @param {number} length
*
* @private
* @function
*/
var addToDeleteSet = (ds, client, clock, length) => {
	setIfUndefined(ds.clients, client, () => []).push(new DeleteItem(clock, length));
};
var createDeleteSet = () => new DeleteSet();
/**
* @param {StructStore} ss
* @return {DeleteSet} Merged and sorted DeleteSet
*
* @private
* @function
*/
var createDeleteSetFromStructStore = (ss) => {
	const ds = createDeleteSet();
	ss.clients.forEach((structs, client) => {
		/**
		* @type {Array<DeleteItem>}
		*/
		const dsitems = [];
		for (let i = 0; i < structs.length; i++) {
			const struct = structs[i];
			if (struct.deleted) {
				const clock = struct.id.clock;
				let len = struct.length;
				if (i + 1 < structs.length) for (let next = structs[i + 1]; i + 1 < structs.length && next.deleted; next = structs[++i + 1]) len += next.length;
				dsitems.push(new DeleteItem(clock, len));
			}
		}
		if (dsitems.length > 0) ds.clients.set(client, dsitems);
	});
	return ds;
};
/**
* @param {DSEncoderV1 | DSEncoderV2} encoder
* @param {DeleteSet} ds
*
* @private
* @function
*/
var writeDeleteSet = (encoder, ds) => {
	writeVarUint(encoder.restEncoder, ds.clients.size);
	from(ds.clients.entries()).sort((a, b) => b[0] - a[0]).forEach(([client, dsitems]) => {
		encoder.resetDsCurVal();
		writeVarUint(encoder.restEncoder, client);
		const len = dsitems.length;
		writeVarUint(encoder.restEncoder, len);
		for (let i = 0; i < len; i++) {
			const item = dsitems[i];
			encoder.writeDsClock(item.clock);
			encoder.writeDsLen(item.len);
		}
	});
};
/**
* @param {DSDecoderV1 | DSDecoderV2} decoder
* @return {DeleteSet}
*
* @private
* @function
*/
var readDeleteSet = (decoder) => {
	const ds = new DeleteSet();
	const numClients = readVarUint(decoder.restDecoder);
	for (let i = 0; i < numClients; i++) {
		decoder.resetDsCurVal();
		const client = readVarUint(decoder.restDecoder);
		const numberOfDeletes = readVarUint(decoder.restDecoder);
		if (numberOfDeletes > 0) {
			const dsField = setIfUndefined(ds.clients, client, () => []);
			for (let i = 0; i < numberOfDeletes; i++) dsField.push(new DeleteItem(decoder.readDsClock(), decoder.readDsLen()));
		}
	}
	return ds;
};
/**
* @todo YDecoder also contains references to String and other Decoders. Would make sense to exchange YDecoder.toUint8Array for YDecoder.DsToUint8Array()..
*/
/**
* @param {DSDecoderV1 | DSDecoderV2} decoder
* @param {Transaction} transaction
* @param {StructStore} store
* @return {Uint8Array|null} Returns a v2 update containing all deletes that couldn't be applied yet; or null if all deletes were applied successfully.
*
* @private
* @function
*/
var readAndApplyDeleteSet = (decoder, transaction, store) => {
	const unappliedDS = new DeleteSet();
	const numClients = readVarUint(decoder.restDecoder);
	for (let i = 0; i < numClients; i++) {
		decoder.resetDsCurVal();
		const client = readVarUint(decoder.restDecoder);
		const numberOfDeletes = readVarUint(decoder.restDecoder);
		const structs = store.clients.get(client) || [];
		const state = getState(store, client);
		for (let i = 0; i < numberOfDeletes; i++) {
			const clock = decoder.readDsClock();
			const clockEnd = clock + decoder.readDsLen();
			if (clock < state) {
				if (state < clockEnd) addToDeleteSet(unappliedDS, client, state, clockEnd - state);
				let index = findIndexSS(structs, clock);
				/**
				* We can ignore the case of GC and Delete structs, because we are going to skip them
				* @type {Item}
				*/
				let struct = structs[index];
				if (!struct.deleted && struct.id.clock < clock) {
					structs.splice(index + 1, 0, splitItem(transaction, struct, clock - struct.id.clock));
					index++;
				}
				while (index < structs.length) {
					struct = structs[index++];
					if (struct.id.clock < clockEnd) {
						if (!struct.deleted) {
							if (clockEnd < struct.id.clock + struct.length) structs.splice(index, 0, splitItem(transaction, struct, clockEnd - struct.id.clock));
							struct.delete(transaction);
						}
					} else break;
				}
			} else addToDeleteSet(unappliedDS, client, clock, clockEnd - clock);
		}
	}
	if (unappliedDS.clients.size > 0) {
		const ds = new UpdateEncoderV2();
		writeVarUint(ds.restEncoder, 0);
		writeDeleteSet(ds, unappliedDS);
		return ds.toUint8Array();
	}
	return null;
};
/**
* @module Y
*/
var generateNewClientId = uint32;
/**
* @typedef {Object} DocOpts
* @property {boolean} [DocOpts.gc=true] Disable garbage collection (default: gc=true)
* @property {function(Item):boolean} [DocOpts.gcFilter] Will be called before an Item is garbage collected. Return false to keep the Item.
* @property {string} [DocOpts.guid] Define a globally unique identifier for this document
* @property {string | null} [DocOpts.collectionid] Associate this document with a collection. This only plays a role if your provider has a concept of collection.
* @property {any} [DocOpts.meta] Any kind of meta information you want to associate with this document. If this is a subdocument, remote peers will store the meta information as well.
* @property {boolean} [DocOpts.autoLoad] If a subdocument, automatically load document. If this is a subdocument, remote peers will load the document as well automatically.
* @property {boolean} [DocOpts.shouldLoad] Whether the document should be synced by the provider now. This is toggled to true when you call ydoc.load()
*/
/**
* @typedef {Object} DocEvents
* @property {function(Doc):void} DocEvents.destroy
* @property {function(Doc):void} DocEvents.load
* @property {function(boolean, Doc):void} DocEvents.sync
* @property {function(Uint8Array, any, Doc, Transaction):void} DocEvents.update
* @property {function(Uint8Array, any, Doc, Transaction):void} DocEvents.updateV2
* @property {function(Doc):void} DocEvents.beforeAllTransactions
* @property {function(Transaction, Doc):void} DocEvents.beforeTransaction
* @property {function(Transaction, Doc):void} DocEvents.beforeObserverCalls
* @property {function(Transaction, Doc):void} DocEvents.afterTransaction
* @property {function(Transaction, Doc):void} DocEvents.afterTransactionCleanup
* @property {function(Doc, Array<Transaction>):void} DocEvents.afterAllTransactions
* @property {function({ loaded: Set<Doc>, added: Set<Doc>, removed: Set<Doc> }, Doc, Transaction):void} DocEvents.subdocs
*/
/**
* A Yjs instance handles the state of shared data.
* @extends ObservableV2<DocEvents>
*/
var Doc = class Doc extends ObservableV2 {
	/**
	* @param {DocOpts} opts configuration
	*/
	constructor({ guid = uuidv4(), collectionid = null, gc = true, gcFilter = () => true, meta = null, autoLoad = false, shouldLoad = true } = {}) {
		super();
		this.gc = gc;
		this.gcFilter = gcFilter;
		this.clientID = generateNewClientId();
		this.guid = guid;
		this.collectionid = collectionid;
		/**
		* @type {Map<string, AbstractType<YEvent<any>>>}
		*/
		this.share = /* @__PURE__ */ new Map();
		this.store = new StructStore();
		/**
		* @type {Transaction | null}
		*/
		this._transaction = null;
		/**
		* @type {Array<Transaction>}
		*/
		this._transactionCleanups = [];
		/**
		* @type {Set<Doc>}
		*/
		this.subdocs = /* @__PURE__ */ new Set();
		/**
		* If this document is a subdocument - a document integrated into another document - then _item is defined.
		* @type {Item?}
		*/
		this._item = null;
		this.shouldLoad = shouldLoad;
		this.autoLoad = autoLoad;
		this.meta = meta;
		/**
		* This is set to true when the persistence provider loaded the document from the database or when the `sync` event fires.
		* Note that not all providers implement this feature. Provider authors are encouraged to fire the `load` event when the doc content is loaded from the database.
		*
		* @type {boolean}
		*/
		this.isLoaded = false;
		/**
		* This is set to true when the connection provider has successfully synced with a backend.
		* Note that when using peer-to-peer providers this event may not provide very useful.
		* Also note that not all providers implement this feature. Provider authors are encouraged to fire
		* the `sync` event when the doc has been synced (with `true` as a parameter) or if connection is
		* lost (with false as a parameter).
		*/
		this.isSynced = false;
		this.isDestroyed = false;
		/**
		* Promise that resolves once the document has been loaded from a persistence provider.
		*/
		this.whenLoaded = create$2((resolve) => {
			this.on("load", () => {
				this.isLoaded = true;
				resolve(this);
			});
		});
		const provideSyncedPromise = () => create$2((resolve) => {
			/**
			* @param {boolean} isSynced
			*/
			const eventHandler = (isSynced) => {
				if (isSynced === void 0 || isSynced === true) {
					this.off("sync", eventHandler);
					resolve();
				}
			};
			this.on("sync", eventHandler);
		});
		this.on("sync", (isSynced) => {
			if (isSynced === false && this.isSynced) this.whenSynced = provideSyncedPromise();
			this.isSynced = isSynced === void 0 || isSynced === true;
			if (this.isSynced && !this.isLoaded) this.emit("load", [this]);
		});
		/**
		* Promise that resolves once the document has been synced with a backend.
		* This promise is recreated when the connection is lost.
		* Note the documentation about the `isSynced` property.
		*/
		this.whenSynced = provideSyncedPromise();
	}
	/**
	* Notify the parent document that you request to load data into this subdocument (if it is a subdocument).
	*
	* `load()` might be used in the future to request any provider to load the most current data.
	*
	* It is safe to call `load()` multiple times.
	*/
	load() {
		const item = this._item;
		if (item !== null && !this.shouldLoad) transact(
			/** @type {any} */
			item.parent.doc,
			(transaction) => {
				transaction.subdocsLoaded.add(this);
			},
			null,
			true
		);
		this.shouldLoad = true;
	}
	getSubdocs() {
		return this.subdocs;
	}
	getSubdocGuids() {
		return new Set(from(this.subdocs).map((doc) => doc.guid));
	}
	/**
	* Changes that happen inside of a transaction are bundled. This means that
	* the observer fires _after_ the transaction is finished and that all changes
	* that happened inside of the transaction are sent as one message to the
	* other peers.
	*
	* @template T
	* @param {function(Transaction):T} f The function that should be executed as a transaction
	* @param {any} [origin] Origin of who started the transaction. Will be stored on transaction.origin
	* @return T
	*
	* @public
	*/
	transact(f, origin = null) {
		return transact(this, f, origin);
	}
	/**
	* Define a shared data type.
	*
	* Multiple calls of `ydoc.get(name, TypeConstructor)` yield the same result
	* and do not overwrite each other. I.e.
	* `ydoc.get(name, Y.Array) === ydoc.get(name, Y.Array)`
	*
	* After this method is called, the type is also available on `ydoc.share.get(name)`.
	*
	* *Best Practices:*
	* Define all types right after the Y.Doc instance is created and store them in a separate object.
	* Also use the typed methods `getText(name)`, `getArray(name)`, ..
	*
	* @template {typeof AbstractType<any>} Type
	* @example
	*   const ydoc = new Y.Doc(..)
	*   const appState = {
	*     document: ydoc.getText('document')
	*     comments: ydoc.getArray('comments')
	*   }
	*
	* @param {string} name
	* @param {Type} TypeConstructor The constructor of the type definition. E.g. Y.Text, Y.Array, Y.Map, ...
	* @return {InstanceType<Type>} The created type. Constructed with TypeConstructor
	*
	* @public
	*/
	get(name, TypeConstructor = AbstractType) {
		const type = setIfUndefined(this.share, name, () => {
			const t = new TypeConstructor();
			t._integrate(this, null);
			return t;
		});
		const Constr = type.constructor;
		if (TypeConstructor !== AbstractType && Constr !== TypeConstructor) if (Constr === AbstractType) {
			const t = new TypeConstructor();
			t._map = type._map;
			type._map.forEach(
				/** @param {Item?} n */
				(n) => {
					for (; n !== null; n = n.left) n.parent = t;
				}
			);
			t._start = type._start;
			for (let n = t._start; n !== null; n = n.right) n.parent = t;
			t._length = type._length;
			this.share.set(name, t);
			t._integrate(this, null);
			return t;
		} else throw new Error(`Type with the name ${name} has already been defined with a different constructor`);
		return type;
	}
	/**
	* @template T
	* @param {string} [name]
	* @return {YArray<T>}
	*
	* @public
	*/
	getArray(name = "") {
		return this.get(name, YArray);
	}
	/**
	* @param {string} [name]
	* @return {YText}
	*
	* @public
	*/
	getText(name = "") {
		return this.get(name, YText);
	}
	/**
	* @template T
	* @param {string} [name]
	* @return {YMap<T>}
	*
	* @public
	*/
	getMap(name = "") {
		return this.get(name, YMap);
	}
	/**
	* @param {string} [name]
	* @return {YXmlElement}
	*
	* @public
	*/
	getXmlElement(name = "") {
		return this.get(name, YXmlElement);
	}
	/**
	* @param {string} [name]
	* @return {YXmlFragment}
	*
	* @public
	*/
	getXmlFragment(name = "") {
		return this.get(name, YXmlFragment);
	}
	/**
	* Converts the entire document into a js object, recursively traversing each yjs type
	* Doesn't log types that have not been defined (using ydoc.getType(..)).
	*
	* @deprecated Do not use this method and rather call toJSON directly on the shared types.
	*
	* @return {Object<string, any>}
	*/
	toJSON() {
		/**
		* @type {Object<string, any>}
		*/
		const doc = {};
		this.share.forEach((value, key) => {
			doc[key] = value.toJSON();
		});
		return doc;
	}
	/**
	* Emit `destroy` event and unregister all event handlers.
	*/
	destroy() {
		this.isDestroyed = true;
		from(this.subdocs).forEach((subdoc) => subdoc.destroy());
		const item = this._item;
		if (item !== null) {
			this._item = null;
			const content = item.content;
			content.doc = new Doc({
				guid: this.guid,
				...content.opts,
				shouldLoad: false
			});
			content.doc._item = item;
			transact(
				/** @type {any} */
				item.parent.doc,
				(transaction) => {
					const doc = content.doc;
					if (!item.deleted) transaction.subdocsAdded.add(doc);
					transaction.subdocsRemoved.add(this);
				},
				null,
				true
			);
		}
		this.emit("destroyed", [true]);
		this.emit("destroy", [this]);
		super.destroy();
	}
};
var DSDecoderV1 = class {
	/**
	* @param {decoding.Decoder} decoder
	*/
	constructor(decoder) {
		this.restDecoder = decoder;
	}
	resetDsCurVal() {}
	/**
	* @return {number}
	*/
	readDsClock() {
		return readVarUint(this.restDecoder);
	}
	/**
	* @return {number}
	*/
	readDsLen() {
		return readVarUint(this.restDecoder);
	}
};
var UpdateDecoderV1 = class extends DSDecoderV1 {
	/**
	* @return {ID}
	*/
	readLeftID() {
		return createID(readVarUint(this.restDecoder), readVarUint(this.restDecoder));
	}
	/**
	* @return {ID}
	*/
	readRightID() {
		return createID(readVarUint(this.restDecoder), readVarUint(this.restDecoder));
	}
	/**
	* Read the next client id.
	* Use this in favor of readID whenever possible to reduce the number of objects created.
	*/
	readClient() {
		return readVarUint(this.restDecoder);
	}
	/**
	* @return {number} info An unsigned 8-bit integer
	*/
	readInfo() {
		return readUint8(this.restDecoder);
	}
	/**
	* @return {string}
	*/
	readString() {
		return readVarString(this.restDecoder);
	}
	/**
	* @return {boolean} isKey
	*/
	readParentInfo() {
		return readVarUint(this.restDecoder) === 1;
	}
	/**
	* @return {number} info An unsigned 8-bit integer
	*/
	readTypeRef() {
		return readVarUint(this.restDecoder);
	}
	/**
	* Write len of a struct - well suited for Opt RLE encoder.
	*
	* @return {number} len
	*/
	readLen() {
		return readVarUint(this.restDecoder);
	}
	/**
	* @return {any}
	*/
	readAny() {
		return readAny(this.restDecoder);
	}
	/**
	* @return {Uint8Array}
	*/
	readBuf() {
		return copyUint8Array(readVarUint8Array(this.restDecoder));
	}
	/**
	* Legacy implementation uses JSON parse. We use any-decoding in v2.
	*
	* @return {any}
	*/
	readJSON() {
		return JSON.parse(readVarString(this.restDecoder));
	}
	/**
	* @return {string}
	*/
	readKey() {
		return readVarString(this.restDecoder);
	}
};
var DSDecoderV2 = class {
	/**
	* @param {decoding.Decoder} decoder
	*/
	constructor(decoder) {
		/**
		* @private
		*/
		this.dsCurrVal = 0;
		this.restDecoder = decoder;
	}
	resetDsCurVal() {
		this.dsCurrVal = 0;
	}
	/**
	* @return {number}
	*/
	readDsClock() {
		this.dsCurrVal += readVarUint(this.restDecoder);
		return this.dsCurrVal;
	}
	/**
	* @return {number}
	*/
	readDsLen() {
		const diff = readVarUint(this.restDecoder) + 1;
		this.dsCurrVal += diff;
		return diff;
	}
};
var UpdateDecoderV2 = class extends DSDecoderV2 {
	/**
	* @param {decoding.Decoder} decoder
	*/
	constructor(decoder) {
		super(decoder);
		/**
		* List of cached keys. If the keys[id] does not exist, we read a new key
		* from stringEncoder and push it to keys.
		*
		* @type {Array<string>}
		*/
		this.keys = [];
		readVarUint(decoder);
		this.keyClockDecoder = new IntDiffOptRleDecoder(readVarUint8Array(decoder));
		this.clientDecoder = new UintOptRleDecoder(readVarUint8Array(decoder));
		this.leftClockDecoder = new IntDiffOptRleDecoder(readVarUint8Array(decoder));
		this.rightClockDecoder = new IntDiffOptRleDecoder(readVarUint8Array(decoder));
		this.infoDecoder = new RleDecoder(readVarUint8Array(decoder), readUint8);
		this.stringDecoder = new StringDecoder(readVarUint8Array(decoder));
		this.parentInfoDecoder = new RleDecoder(readVarUint8Array(decoder), readUint8);
		this.typeRefDecoder = new UintOptRleDecoder(readVarUint8Array(decoder));
		this.lenDecoder = new UintOptRleDecoder(readVarUint8Array(decoder));
	}
	/**
	* @return {ID}
	*/
	readLeftID() {
		return new ID(this.clientDecoder.read(), this.leftClockDecoder.read());
	}
	/**
	* @return {ID}
	*/
	readRightID() {
		return new ID(this.clientDecoder.read(), this.rightClockDecoder.read());
	}
	/**
	* Read the next client id.
	* Use this in favor of readID whenever possible to reduce the number of objects created.
	*/
	readClient() {
		return this.clientDecoder.read();
	}
	/**
	* @return {number} info An unsigned 8-bit integer
	*/
	readInfo() {
		return this.infoDecoder.read();
	}
	/**
	* @return {string}
	*/
	readString() {
		return this.stringDecoder.read();
	}
	/**
	* @return {boolean}
	*/
	readParentInfo() {
		return this.parentInfoDecoder.read() === 1;
	}
	/**
	* @return {number} An unsigned 8-bit integer
	*/
	readTypeRef() {
		return this.typeRefDecoder.read();
	}
	/**
	* Write len of a struct - well suited for Opt RLE encoder.
	*
	* @return {number}
	*/
	readLen() {
		return this.lenDecoder.read();
	}
	/**
	* @return {any}
	*/
	readAny() {
		return readAny(this.restDecoder);
	}
	/**
	* @return {Uint8Array}
	*/
	readBuf() {
		return readVarUint8Array(this.restDecoder);
	}
	/**
	* This is mainly here for legacy purposes.
	*
	* Initial we incoded objects using JSON. Now we use the much faster lib0/any-encoder. This method mainly exists for legacy purposes for the v1 encoder.
	*
	* @return {any}
	*/
	readJSON() {
		return readAny(this.restDecoder);
	}
	/**
	* @return {string}
	*/
	readKey() {
		const keyClock = this.keyClockDecoder.read();
		if (keyClock < this.keys.length) return this.keys[keyClock];
		else {
			const key = this.stringDecoder.read();
			this.keys.push(key);
			return key;
		}
	}
};
var DSEncoderV1 = class {
	constructor() {
		this.restEncoder = createEncoder();
	}
	toUint8Array() {
		return toUint8Array(this.restEncoder);
	}
	resetDsCurVal() {}
	/**
	* @param {number} clock
	*/
	writeDsClock(clock) {
		writeVarUint(this.restEncoder, clock);
	}
	/**
	* @param {number} len
	*/
	writeDsLen(len) {
		writeVarUint(this.restEncoder, len);
	}
};
var UpdateEncoderV1 = class extends DSEncoderV1 {
	/**
	* @param {ID} id
	*/
	writeLeftID(id) {
		writeVarUint(this.restEncoder, id.client);
		writeVarUint(this.restEncoder, id.clock);
	}
	/**
	* @param {ID} id
	*/
	writeRightID(id) {
		writeVarUint(this.restEncoder, id.client);
		writeVarUint(this.restEncoder, id.clock);
	}
	/**
	* Use writeClient and writeClock instead of writeID if possible.
	* @param {number} client
	*/
	writeClient(client) {
		writeVarUint(this.restEncoder, client);
	}
	/**
	* @param {number} info An unsigned 8-bit integer
	*/
	writeInfo(info) {
		writeUint8(this.restEncoder, info);
	}
	/**
	* @param {string} s
	*/
	writeString(s) {
		writeVarString(this.restEncoder, s);
	}
	/**
	* @param {boolean} isYKey
	*/
	writeParentInfo(isYKey) {
		writeVarUint(this.restEncoder, isYKey ? 1 : 0);
	}
	/**
	* @param {number} info An unsigned 8-bit integer
	*/
	writeTypeRef(info) {
		writeVarUint(this.restEncoder, info);
	}
	/**
	* Write len of a struct - well suited for Opt RLE encoder.
	*
	* @param {number} len
	*/
	writeLen(len) {
		writeVarUint(this.restEncoder, len);
	}
	/**
	* @param {any} any
	*/
	writeAny(any) {
		writeAny(this.restEncoder, any);
	}
	/**
	* @param {Uint8Array} buf
	*/
	writeBuf(buf) {
		writeVarUint8Array(this.restEncoder, buf);
	}
	/**
	* @param {any} embed
	*/
	writeJSON(embed) {
		writeVarString(this.restEncoder, JSON.stringify(embed));
	}
	/**
	* @param {string} key
	*/
	writeKey(key) {
		writeVarString(this.restEncoder, key);
	}
};
var DSEncoderV2 = class {
	constructor() {
		this.restEncoder = createEncoder();
		this.dsCurrVal = 0;
	}
	toUint8Array() {
		return toUint8Array(this.restEncoder);
	}
	resetDsCurVal() {
		this.dsCurrVal = 0;
	}
	/**
	* @param {number} clock
	*/
	writeDsClock(clock) {
		const diff = clock - this.dsCurrVal;
		this.dsCurrVal = clock;
		writeVarUint(this.restEncoder, diff);
	}
	/**
	* @param {number} len
	*/
	writeDsLen(len) {
		if (len === 0) unexpectedCase();
		writeVarUint(this.restEncoder, len - 1);
		this.dsCurrVal += len;
	}
};
var UpdateEncoderV2 = class extends DSEncoderV2 {
	constructor() {
		super();
		/**
		* @type {Map<string,number>}
		*/
		this.keyMap = /* @__PURE__ */ new Map();
		/**
		* Refers to the next unique key-identifier to me used.
		* See writeKey method for more information.
		*
		* @type {number}
		*/
		this.keyClock = 0;
		this.keyClockEncoder = new IntDiffOptRleEncoder();
		this.clientEncoder = new UintOptRleEncoder();
		this.leftClockEncoder = new IntDiffOptRleEncoder();
		this.rightClockEncoder = new IntDiffOptRleEncoder();
		this.infoEncoder = new RleEncoder(writeUint8);
		this.stringEncoder = new StringEncoder();
		this.parentInfoEncoder = new RleEncoder(writeUint8);
		this.typeRefEncoder = new UintOptRleEncoder();
		this.lenEncoder = new UintOptRleEncoder();
	}
	toUint8Array() {
		const encoder = createEncoder();
		writeVarUint(encoder, 0);
		writeVarUint8Array(encoder, this.keyClockEncoder.toUint8Array());
		writeVarUint8Array(encoder, this.clientEncoder.toUint8Array());
		writeVarUint8Array(encoder, this.leftClockEncoder.toUint8Array());
		writeVarUint8Array(encoder, this.rightClockEncoder.toUint8Array());
		writeVarUint8Array(encoder, toUint8Array(this.infoEncoder));
		writeVarUint8Array(encoder, this.stringEncoder.toUint8Array());
		writeVarUint8Array(encoder, toUint8Array(this.parentInfoEncoder));
		writeVarUint8Array(encoder, this.typeRefEncoder.toUint8Array());
		writeVarUint8Array(encoder, this.lenEncoder.toUint8Array());
		writeUint8Array(encoder, toUint8Array(this.restEncoder));
		return toUint8Array(encoder);
	}
	/**
	* @param {ID} id
	*/
	writeLeftID(id) {
		this.clientEncoder.write(id.client);
		this.leftClockEncoder.write(id.clock);
	}
	/**
	* @param {ID} id
	*/
	writeRightID(id) {
		this.clientEncoder.write(id.client);
		this.rightClockEncoder.write(id.clock);
	}
	/**
	* @param {number} client
	*/
	writeClient(client) {
		this.clientEncoder.write(client);
	}
	/**
	* @param {number} info An unsigned 8-bit integer
	*/
	writeInfo(info) {
		this.infoEncoder.write(info);
	}
	/**
	* @param {string} s
	*/
	writeString(s) {
		this.stringEncoder.write(s);
	}
	/**
	* @param {boolean} isYKey
	*/
	writeParentInfo(isYKey) {
		this.parentInfoEncoder.write(isYKey ? 1 : 0);
	}
	/**
	* @param {number} info An unsigned 8-bit integer
	*/
	writeTypeRef(info) {
		this.typeRefEncoder.write(info);
	}
	/**
	* Write len of a struct - well suited for Opt RLE encoder.
	*
	* @param {number} len
	*/
	writeLen(len) {
		this.lenEncoder.write(len);
	}
	/**
	* @param {any} any
	*/
	writeAny(any) {
		writeAny(this.restEncoder, any);
	}
	/**
	* @param {Uint8Array} buf
	*/
	writeBuf(buf) {
		writeVarUint8Array(this.restEncoder, buf);
	}
	/**
	* This is mainly here for legacy purposes.
	*
	* Initial we incoded objects using JSON. Now we use the much faster lib0/any-encoder. This method mainly exists for legacy purposes for the v1 encoder.
	*
	* @param {any} embed
	*/
	writeJSON(embed) {
		writeAny(this.restEncoder, embed);
	}
	/**
	* Property keys are often reused. For example, in y-prosemirror the key `bold` might
	* occur very often. For a 3d application, the key `position` might occur very often.
	*
	* We cache these keys in a Map and refer to them via a unique number.
	*
	* @param {string} key
	*/
	writeKey(key) {
		const clock = this.keyMap.get(key);
		if (clock === void 0) {
			/**
			* @todo uncomment to introduce this feature finally
			*
			* Background. The ContentFormat object was always encoded using writeKey, but the decoder used to use readString.
			* Furthermore, I forgot to set the keyclock. So everything was working fine.
			*
			* However, this feature here is basically useless as it is not being used (it actually only consumes extra memory).
			*
			* I don't know yet how to reintroduce this feature..
			*
			* Older clients won't be able to read updates when we reintroduce this feature. So this should probably be done using a flag.
			*
			*/
			this.keyClockEncoder.write(this.keyClock++);
			this.stringEncoder.write(key);
		} else this.keyClockEncoder.write(clock);
	}
};
/**
* @module encoding
*/
/**
* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
* @param {Array<GC|Item>} structs All structs by `client`
* @param {number} client
* @param {number} clock write structs starting with `ID(client,clock)`
*
* @function
*/
var writeStructs = (encoder, structs, client, clock) => {
	clock = max(clock, structs[0].id.clock);
	const startNewStructs = findIndexSS(structs, clock);
	writeVarUint(encoder.restEncoder, structs.length - startNewStructs);
	encoder.writeClient(client);
	writeVarUint(encoder.restEncoder, clock);
	const firstStruct = structs[startNewStructs];
	firstStruct.write(encoder, clock - firstStruct.id.clock);
	for (let i = startNewStructs + 1; i < structs.length; i++) structs[i].write(encoder, 0);
};
/**
* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
* @param {StructStore} store
* @param {Map<number,number>} _sm
*
* @private
* @function
*/
var writeClientsStructs = (encoder, store, _sm) => {
	const sm = /* @__PURE__ */ new Map();
	_sm.forEach((clock, client) => {
		if (getState(store, client) > clock) sm.set(client, clock);
	});
	getStateVector(store).forEach((_clock, client) => {
		if (!_sm.has(client)) sm.set(client, 0);
	});
	writeVarUint(encoder.restEncoder, sm.size);
	from(sm.entries()).sort((a, b) => b[0] - a[0]).forEach(([client, clock]) => {
		writeStructs(encoder, store.clients.get(client), client, clock);
	});
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder The decoder object to read data from.
* @param {Doc} doc
* @return {Map<number, { i: number, refs: Array<Item | GC> }>}
*
* @private
* @function
*/
var readClientsStructRefs = (decoder, doc) => {
	/**
	* @type {Map<number, { i: number, refs: Array<Item | GC> }>}
	*/
	const clientRefs = create$5();
	const numOfStateUpdates = readVarUint(decoder.restDecoder);
	for (let i = 0; i < numOfStateUpdates; i++) {
		const numberOfStructs = readVarUint(decoder.restDecoder);
		/**
		* @type {Array<GC|Item>}
		*/
		const refs = new Array(numberOfStructs);
		const client = decoder.readClient();
		let clock = readVarUint(decoder.restDecoder);
		clientRefs.set(client, {
			i: 0,
			refs
		});
		for (let i = 0; i < numberOfStructs; i++) {
			const info = decoder.readInfo();
			switch (31 & info) {
				case 0: {
					const len = decoder.readLen();
					refs[i] = new GC(createID(client, clock), len);
					clock += len;
					break;
				}
				case 10: {
					const len = readVarUint(decoder.restDecoder);
					refs[i] = new Skip(createID(client, clock), len);
					clock += len;
					break;
				}
				default: {
					/**
					* The optimized implementation doesn't use any variables because inlining variables is faster.
					* Below a non-optimized version is shown that implements the basic algorithm with
					* a few comments
					*/
					const cantCopyParentInfo = (info & 192) === 0;
					const struct = new Item(createID(client, clock), null, (info & 128) === 128 ? decoder.readLeftID() : null, null, (info & 64) === 64 ? decoder.readRightID() : null, cantCopyParentInfo ? decoder.readParentInfo() ? doc.get(decoder.readString()) : decoder.readLeftID() : null, cantCopyParentInfo && (info & 32) === 32 ? decoder.readString() : null, readItemContent(decoder, info));
					refs[i] = struct;
					clock += struct.length;
				}
			}
		}
	}
	return clientRefs;
};
/**
* Resume computing structs generated by struct readers.
*
* While there is something to do, we integrate structs in this order
* 1. top element on stack, if stack is not empty
* 2. next element from current struct reader (if empty, use next struct reader)
*
* If struct causally depends on another struct (ref.missing), we put next reader of
* `ref.id.client` on top of stack.
*
* At some point we find a struct that has no causal dependencies,
* then we start emptying the stack.
*
* It is not possible to have circles: i.e. struct1 (from client1) depends on struct2 (from client2)
* depends on struct3 (from client1). Therefore the max stack size is equal to `structReaders.length`.
*
* This method is implemented in a way so that we can resume computation if this update
* causally depends on another update.
*
* @param {Transaction} transaction
* @param {StructStore} store
* @param {Map<number, { i: number, refs: (GC | Item)[] }>} clientsStructRefs
* @return { null | { update: Uint8Array, missing: Map<number,number> } }
*
* @private
* @function
*/
var integrateStructs = (transaction, store, clientsStructRefs) => {
	/**
	* @type {Array<Item | GC>}
	*/
	const stack = [];
	let clientsStructRefsIds = from(clientsStructRefs.keys()).sort((a, b) => a - b);
	if (clientsStructRefsIds.length === 0) return null;
	const getNextStructTarget = () => {
		if (clientsStructRefsIds.length === 0) return null;
		let nextStructsTarget = clientsStructRefs.get(clientsStructRefsIds[clientsStructRefsIds.length - 1]);
		while (nextStructsTarget.refs.length === nextStructsTarget.i) {
			clientsStructRefsIds.pop();
			if (clientsStructRefsIds.length > 0) nextStructsTarget = clientsStructRefs.get(clientsStructRefsIds[clientsStructRefsIds.length - 1]);
			else return null;
		}
		return nextStructsTarget;
	};
	let curStructsTarget = getNextStructTarget();
	if (curStructsTarget === null) return null;
	/**
	* @type {StructStore}
	*/
	const restStructs = new StructStore();
	const missingSV = /* @__PURE__ */ new Map();
	/**
	* @param {number} client
	* @param {number} clock
	*/
	const updateMissingSv = (client, clock) => {
		const mclock = missingSV.get(client);
		if (mclock == null || mclock > clock) missingSV.set(client, clock);
	};
	/**
	* @type {GC|Item}
	*/
	let stackHead = curStructsTarget.refs[curStructsTarget.i++];
	const state = /* @__PURE__ */ new Map();
	const addStackToRestSS = () => {
		for (const item of stack) {
			const client = item.id.client;
			const inapplicableItems = clientsStructRefs.get(client);
			if (inapplicableItems) {
				inapplicableItems.i--;
				restStructs.clients.set(client, inapplicableItems.refs.slice(inapplicableItems.i));
				clientsStructRefs.delete(client);
				inapplicableItems.i = 0;
				inapplicableItems.refs = [];
			} else restStructs.clients.set(client, [item]);
			clientsStructRefsIds = clientsStructRefsIds.filter((c) => c !== client);
		}
		stack.length = 0;
	};
	while (true) {
		if (stackHead.constructor !== Skip) {
			const offset = setIfUndefined(state, stackHead.id.client, () => getState(store, stackHead.id.client)) - stackHead.id.clock;
			if (offset < 0) {
				stack.push(stackHead);
				updateMissingSv(stackHead.id.client, stackHead.id.clock - 1);
				addStackToRestSS();
			} else {
				const missing = stackHead.getMissing(transaction, store);
				if (missing !== null) {
					stack.push(stackHead);
					/**
					* @type {{ refs: Array<GC|Item>, i: number }}
					*/
					const structRefs = clientsStructRefs.get(missing) || {
						refs: [],
						i: 0
					};
					if (structRefs.refs.length === structRefs.i) {
						updateMissingSv(missing, getState(store, missing));
						addStackToRestSS();
					} else {
						stackHead = structRefs.refs[structRefs.i++];
						continue;
					}
				} else if (offset === 0 || offset < stackHead.length) {
					stackHead.integrate(transaction, offset);
					state.set(stackHead.id.client, stackHead.id.clock + stackHead.length);
				}
			}
		}
		if (stack.length > 0) stackHead = stack.pop();
		else if (curStructsTarget !== null && curStructsTarget.i < curStructsTarget.refs.length) stackHead = curStructsTarget.refs[curStructsTarget.i++];
		else {
			curStructsTarget = getNextStructTarget();
			if (curStructsTarget === null) break;
			else stackHead = curStructsTarget.refs[curStructsTarget.i++];
		}
	}
	if (restStructs.clients.size > 0) {
		const encoder = new UpdateEncoderV2();
		writeClientsStructs(encoder, restStructs, /* @__PURE__ */ new Map());
		writeVarUint(encoder.restEncoder, 0);
		return {
			missing: missingSV,
			update: encoder.toUint8Array()
		};
	}
	return null;
};
/**
* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
* @param {Transaction} transaction
*
* @private
* @function
*/
var writeStructsFromTransaction = (encoder, transaction) => writeClientsStructs(encoder, transaction.doc.store, transaction.beforeState);
/**
* Read and apply a document update.
*
* This function has the same effect as `applyUpdate` but accepts a decoder.
*
* @param {decoding.Decoder} decoder
* @param {Doc} ydoc
* @param {any} [transactionOrigin] This will be stored on `transaction.origin` and `.on('update', (update, origin))`
* @param {UpdateDecoderV1 | UpdateDecoderV2} [structDecoder]
*
* @function
*/
var readUpdateV2 = (decoder, ydoc, transactionOrigin, structDecoder = new UpdateDecoderV2(decoder)) => transact(ydoc, (transaction) => {
	transaction.local = false;
	let retry = false;
	const doc = transaction.doc;
	const store = doc.store;
	const restStructs = integrateStructs(transaction, store, readClientsStructRefs(structDecoder, doc));
	const pending = store.pendingStructs;
	if (pending) {
		for (const [client, clock] of pending.missing) if (clock < getState(store, client)) {
			retry = true;
			break;
		}
		if (restStructs) {
			for (const [client, clock] of restStructs.missing) {
				const mclock = pending.missing.get(client);
				if (mclock == null || mclock > clock) pending.missing.set(client, clock);
			}
			pending.update = mergeUpdatesV2([pending.update, restStructs.update]);
		}
	} else store.pendingStructs = restStructs;
	const dsRest = readAndApplyDeleteSet(structDecoder, transaction, store);
	if (store.pendingDs) {
		const pendingDSUpdate = new UpdateDecoderV2(createDecoder(store.pendingDs));
		readVarUint(pendingDSUpdate.restDecoder);
		const dsRest2 = readAndApplyDeleteSet(pendingDSUpdate, transaction, store);
		if (dsRest && dsRest2) store.pendingDs = mergeUpdatesV2([dsRest, dsRest2]);
		else store.pendingDs = dsRest || dsRest2;
	} else store.pendingDs = dsRest;
	if (retry) {
		const update = store.pendingStructs.update;
		store.pendingStructs = null;
		applyUpdateV2(transaction.doc, update);
	}
}, transactionOrigin, false);
/**
* Apply a document update created by, for example, `y.on('update', update => ..)` or `update = encodeStateAsUpdate()`.
*
* This function has the same effect as `readUpdate` but accepts an Uint8Array instead of a Decoder.
*
* @param {Doc} ydoc
* @param {Uint8Array} update
* @param {any} [transactionOrigin] This will be stored on `transaction.origin` and `.on('update', (update, origin))`
* @param {typeof UpdateDecoderV1 | typeof UpdateDecoderV2} [YDecoder]
*
* @function
*/
var applyUpdateV2 = (ydoc, update, transactionOrigin, YDecoder = UpdateDecoderV2) => {
	const decoder = createDecoder(update);
	readUpdateV2(decoder, ydoc, transactionOrigin, new YDecoder(decoder));
};
/**
* Apply a document update created by, for example, `y.on('update', update => ..)` or `update = encodeStateAsUpdate()`.
*
* This function has the same effect as `readUpdate` but accepts an Uint8Array instead of a Decoder.
*
* @param {Doc} ydoc
* @param {Uint8Array} update
* @param {any} [transactionOrigin] This will be stored on `transaction.origin` and `.on('update', (update, origin))`
*
* @function
*/
var applyUpdate = (ydoc, update, transactionOrigin) => applyUpdateV2(ydoc, update, transactionOrigin, UpdateDecoderV1);
/**
* Write all the document as a single update message. If you specify the state of the remote client (`targetStateVector`) it will
* only write the operations that are missing.
*
* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
* @param {Doc} doc
* @param {Map<number,number>} [targetStateVector] The state of the target that receives the update. Leave empty to write all known structs
*
* @function
*/
var writeStateAsUpdate = (encoder, doc, targetStateVector = /* @__PURE__ */ new Map()) => {
	writeClientsStructs(encoder, doc.store, targetStateVector);
	writeDeleteSet(encoder, createDeleteSetFromStructStore(doc.store));
};
/**
* Write all the document as a single update message that can be applied on the remote document. If you specify the state of the remote client (`targetState`) it will
* only write the operations that are missing.
*
* Use `writeStateAsUpdate` instead if you are working with lib0/encoding.js#Encoder
*
* @param {Doc} doc
* @param {Uint8Array} [encodedTargetStateVector] The state of the target that receives the update. Leave empty to write all known structs
* @param {UpdateEncoderV1 | UpdateEncoderV2} [encoder]
* @return {Uint8Array}
*
* @function
*/
var encodeStateAsUpdateV2 = (doc, encodedTargetStateVector = new Uint8Array([0]), encoder = new UpdateEncoderV2()) => {
	writeStateAsUpdate(encoder, doc, decodeStateVector(encodedTargetStateVector));
	const updates = [encoder.toUint8Array()];
	if (doc.store.pendingDs) updates.push(doc.store.pendingDs);
	if (doc.store.pendingStructs) updates.push(diffUpdateV2(doc.store.pendingStructs.update, encodedTargetStateVector));
	if (updates.length > 1) {
		if (encoder.constructor === UpdateEncoderV1) return mergeUpdates(updates.map((update, i) => i === 0 ? update : convertUpdateFormatV2ToV1(update)));
		else if (encoder.constructor === UpdateEncoderV2) return mergeUpdatesV2(updates);
	}
	return updates[0];
};
/**
* Write all the document as a single update message that can be applied on the remote document. If you specify the state of the remote client (`targetState`) it will
* only write the operations that are missing.
*
* Use `writeStateAsUpdate` instead if you are working with lib0/encoding.js#Encoder
*
* @param {Doc} doc
* @param {Uint8Array} [encodedTargetStateVector] The state of the target that receives the update. Leave empty to write all known structs
* @return {Uint8Array}
*
* @function
*/
var encodeStateAsUpdate = (doc, encodedTargetStateVector) => encodeStateAsUpdateV2(doc, encodedTargetStateVector, new UpdateEncoderV1());
/**
* Read state vector from Decoder and return as Map
*
* @param {DSDecoderV1 | DSDecoderV2} decoder
* @return {Map<number,number>} Maps `client` to the number next expected `clock` from that client.
*
* @function
*/
var readStateVector = (decoder) => {
	const ss = /* @__PURE__ */ new Map();
	const ssLength = readVarUint(decoder.restDecoder);
	for (let i = 0; i < ssLength; i++) {
		const client = readVarUint(decoder.restDecoder);
		const clock = readVarUint(decoder.restDecoder);
		ss.set(client, clock);
	}
	return ss;
};
/**
* Read decodedState and return State as Map.
*
* @param {Uint8Array} decodedState
* @return {Map<number,number>} Maps `client` to the number next expected `clock` from that client.
*
* @function
*/
/**
* Read decodedState and return State as Map.
*
* @param {Uint8Array} decodedState
* @return {Map<number,number>} Maps `client` to the number next expected `clock` from that client.
*
* @function
*/
var decodeStateVector = (decodedState) => readStateVector(new DSDecoderV1(createDecoder(decodedState)));
/**
* General event handler implementation.
*
* @template ARG0, ARG1
*
* @private
*/
var EventHandler = class {
	constructor() {
		/**
		* @type {Array<function(ARG0, ARG1):void>}
		*/
		this.l = [];
	}
};
/**
* @template ARG0,ARG1
* @returns {EventHandler<ARG0,ARG1>}
*
* @private
* @function
*/
var createEventHandler = () => new EventHandler();
/**
* Adds an event listener that is called when
* {@link EventHandler#callEventListeners} is called.
*
* @template ARG0,ARG1
* @param {EventHandler<ARG0,ARG1>} eventHandler
* @param {function(ARG0,ARG1):void} f The event handler.
*
* @private
* @function
*/
var addEventHandlerListener = (eventHandler, f) => eventHandler.l.push(f);
/**
* Removes an event listener.
*
* @template ARG0,ARG1
* @param {EventHandler<ARG0,ARG1>} eventHandler
* @param {function(ARG0,ARG1):void} f The event handler that was added with
*                     {@link EventHandler#addEventListener}
*
* @private
* @function
*/
var removeEventHandlerListener = (eventHandler, f) => {
	const l = eventHandler.l;
	const len = l.length;
	eventHandler.l = l.filter((g) => f !== g);
	if (len === eventHandler.l.length) console.error("[yjs] Tried to remove event handler that doesn't exist.");
};
/**
* Call all event listeners that were added via
* {@link EventHandler#addEventListener}.
*
* @template ARG0,ARG1
* @param {EventHandler<ARG0,ARG1>} eventHandler
* @param {ARG0} arg0
* @param {ARG1} arg1
*
* @private
* @function
*/
var callEventHandlerListeners = (eventHandler, arg0, arg1) => callAll(eventHandler.l, [arg0, arg1]);
var ID = class {
	/**
	* @param {number} client client id
	* @param {number} clock unique per client id, continuous number
	*/
	constructor(client, clock) {
		/**
		* Client id
		* @type {number}
		*/
		this.client = client;
		/**
		* unique per client id, continuous number
		* @type {number}
		*/
		this.clock = clock;
	}
};
/**
* @param {ID | null} a
* @param {ID | null} b
* @return {boolean}
*
* @function
*/
var compareIDs = (a, b) => a === b || a !== null && b !== null && a.client === b.client && a.clock === b.clock;
/**
* @param {number} client
* @param {number} clock
*
* @private
* @function
*/
var createID = (client, clock) => new ID(client, clock);
/**
* The top types are mapped from y.share.get(keyname) => type.
* `type` does not store any information about the `keyname`.
* This function finds the correct `keyname` for `type` and throws otherwise.
*
* @param {AbstractType<any>} type
* @return {string}
*
* @private
* @function
*/
var findRootTypeKey = (type) => {
	for (const [key, value] of type.doc.share.entries()) if (value === type) return key;
	throw unexpectedCase();
};
var Snapshot = class {
	/**
	* @param {DeleteSet} ds
	* @param {Map<number,number>} sv state map
	*/
	constructor(ds, sv) {
		/**
		* @type {DeleteSet}
		*/
		this.ds = ds;
		/**
		* State Map
		* @type {Map<number,number>}
		*/
		this.sv = sv;
	}
};
/**
* @param {DeleteSet} ds
* @param {Map<number,number>} sm
* @return {Snapshot}
*/
var createSnapshot = (ds, sm) => new Snapshot(ds, sm);
createSnapshot(createDeleteSet(), /* @__PURE__ */ new Map());
/**
* @param {Item} item
* @param {Snapshot|undefined} snapshot
*
* @protected
* @function
*/
var isVisible = (item, snapshot) => snapshot === void 0 ? !item.deleted : snapshot.sv.has(item.id.client) && (snapshot.sv.get(item.id.client) || 0) > item.id.clock && !isDeleted(snapshot.ds, item.id);
/**
* @param {Transaction} transaction
* @param {Snapshot} snapshot
*/
var splitSnapshotAffectedStructs = (transaction, snapshot) => {
	const meta = setIfUndefined(transaction.meta, splitSnapshotAffectedStructs, create$4);
	const store = transaction.doc.store;
	if (!meta.has(snapshot)) {
		snapshot.sv.forEach((clock, client) => {
			if (clock < getState(store, client)) getItemCleanStart(transaction, createID(client, clock));
		});
		iterateDeletedStructs(transaction, snapshot.ds, (_item) => {});
		meta.add(snapshot);
	}
};
var StructStore = class {
	constructor() {
		/**
		* @type {Map<number,Array<GC|Item>>}
		*/
		this.clients = /* @__PURE__ */ new Map();
		/**
		* @type {null | { missing: Map<number, number>, update: Uint8Array }}
		*/
		this.pendingStructs = null;
		/**
		* @type {null | Uint8Array}
		*/
		this.pendingDs = null;
	}
};
/**
* Return the states as a Map<client,clock>.
* Note that clock refers to the next expected clock id.
*
* @param {StructStore} store
* @return {Map<number,number>}
*
* @public
* @function
*/
var getStateVector = (store) => {
	const sm = /* @__PURE__ */ new Map();
	store.clients.forEach((structs, client) => {
		const struct = structs[structs.length - 1];
		sm.set(client, struct.id.clock + struct.length);
	});
	return sm;
};
/**
* @param {StructStore} store
* @param {number} client
* @return {number}
*
* @public
* @function
*/
var getState = (store, client) => {
	const structs = store.clients.get(client);
	if (structs === void 0) return 0;
	const lastStruct = structs[structs.length - 1];
	return lastStruct.id.clock + lastStruct.length;
};
/**
* @param {StructStore} store
* @param {GC|Item} struct
*
* @private
* @function
*/
var addStruct = (store, struct) => {
	let structs = store.clients.get(struct.id.client);
	if (structs === void 0) {
		structs = [];
		store.clients.set(struct.id.client, structs);
	} else {
		const lastStruct = structs[structs.length - 1];
		if (lastStruct.id.clock + lastStruct.length !== struct.id.clock) throw unexpectedCase();
	}
	structs.push(struct);
};
/**
* Perform a binary search on a sorted array
* @param {Array<Item|GC>} structs
* @param {number} clock
* @return {number}
*
* @private
* @function
*/
var findIndexSS = (structs, clock) => {
	let left = 0;
	let right = structs.length - 1;
	let mid = structs[right];
	let midclock = mid.id.clock;
	if (midclock === clock) return right;
	let midindex = floor(clock / (midclock + mid.length - 1) * right);
	while (left <= right) {
		mid = structs[midindex];
		midclock = mid.id.clock;
		if (midclock <= clock) {
			if (clock < midclock + mid.length) return midindex;
			left = midindex + 1;
		} else right = midindex - 1;
		midindex = floor((left + right) / 2);
	}
	throw unexpectedCase();
};
/**
* Expects that id is actually in store. This function throws or is an infinite loop otherwise.
*
* @param {StructStore} store
* @param {ID} id
* @return {GC|Item}
*
* @private
* @function
*/
var find = (store, id) => {
	/**
	* @type {Array<GC|Item>}
	*/
	const structs = store.clients.get(id.client);
	return structs[findIndexSS(structs, id.clock)];
};
/**
* Expects that id is actually in store. This function throws or is an infinite loop otherwise.
* @private
* @function
*/
var getItem = find;
/**
* @param {Transaction} transaction
* @param {Array<Item|GC>} structs
* @param {number} clock
*/
var findIndexCleanStart = (transaction, structs, clock) => {
	const index = findIndexSS(structs, clock);
	const struct = structs[index];
	if (struct.id.clock < clock && struct instanceof Item) {
		structs.splice(index + 1, 0, splitItem(transaction, struct, clock - struct.id.clock));
		return index + 1;
	}
	return index;
};
/**
* Expects that id is actually in store. This function throws or is an infinite loop otherwise.
*
* @param {Transaction} transaction
* @param {ID} id
* @return {Item}
*
* @private
* @function
*/
var getItemCleanStart = (transaction, id) => {
	const structs = transaction.doc.store.clients.get(id.client);
	return structs[findIndexCleanStart(transaction, structs, id.clock)];
};
/**
* Expects that id is actually in store. This function throws or is an infinite loop otherwise.
*
* @param {Transaction} transaction
* @param {StructStore} store
* @param {ID} id
* @return {Item}
*
* @private
* @function
*/
var getItemCleanEnd = (transaction, store, id) => {
	/**
	* @type {Array<Item>}
	*/
	const structs = store.clients.get(id.client);
	const index = findIndexSS(structs, id.clock);
	const struct = structs[index];
	if (id.clock !== struct.id.clock + struct.length - 1 && struct.constructor !== GC) structs.splice(index + 1, 0, splitItem(transaction, struct, id.clock - struct.id.clock + 1));
	return struct;
};
/**
* Replace `item` with `newitem` in store
* @param {StructStore} store
* @param {GC|Item} struct
* @param {GC|Item} newStruct
*
* @private
* @function
*/
var replaceStruct = (store, struct, newStruct) => {
	const structs = store.clients.get(struct.id.client);
	structs[findIndexSS(structs, struct.id.clock)] = newStruct;
};
/**
* Iterate over a range of structs
*
* @param {Transaction} transaction
* @param {Array<Item|GC>} structs
* @param {number} clockStart Inclusive start
* @param {number} len
* @param {function(GC|Item):void} f
*
* @function
*/
var iterateStructs = (transaction, structs, clockStart, len, f) => {
	if (len === 0) return;
	const clockEnd = clockStart + len;
	let index = findIndexCleanStart(transaction, structs, clockStart);
	let struct;
	do {
		struct = structs[index++];
		if (clockEnd < struct.id.clock + struct.length) findIndexCleanStart(transaction, structs, clockEnd);
		f(struct);
	} while (index < structs.length && structs[index].id.clock < clockEnd);
};
/**
* A transaction is created for every change on the Yjs model. It is possible
* to bundle changes on the Yjs model in a single transaction to
* minimize the number on messages sent and the number of observer calls.
* If possible the user of this library should bundle as many changes as
* possible. Here is an example to illustrate the advantages of bundling:
*
* @example
* const ydoc = new Y.Doc()
* const map = ydoc.getMap('map')
* // Log content when change is triggered
* map.observe(() => {
*   console.log('change triggered')
* })
* // Each change on the map type triggers a log message:
* map.set('a', 0) // => "change triggered"
* map.set('b', 0) // => "change triggered"
* // When put in a transaction, it will trigger the log after the transaction:
* ydoc.transact(() => {
*   map.set('a', 1)
*   map.set('b', 1)
* }) // => "change triggered"
*
* @public
*/
var Transaction = class {
	/**
	* @param {Doc} doc
	* @param {any} origin
	* @param {boolean} local
	*/
	constructor(doc, origin, local) {
		/**
		* The Yjs instance.
		* @type {Doc}
		*/
		this.doc = doc;
		/**
		* Describes the set of deleted items by ids
		* @type {DeleteSet}
		*/
		this.deleteSet = new DeleteSet();
		/**
		* Holds the state before the transaction started.
		* @type {Map<Number,Number>}
		*/
		this.beforeState = getStateVector(doc.store);
		/**
		* Holds the state after the transaction.
		* @type {Map<Number,Number>}
		*/
		this.afterState = /* @__PURE__ */ new Map();
		/**
		* All types that were directly modified (property added or child
		* inserted/deleted). New types are not included in this Set.
		* Maps from type to parentSubs (`item.parentSub = null` for YArray)
		* @type {Map<AbstractType<YEvent<any>>,Set<String|null>>}
		*/
		this.changed = /* @__PURE__ */ new Map();
		/**
		* Stores the events for the types that observe also child elements.
		* It is mainly used by `observeDeep`.
		* @type {Map<AbstractType<YEvent<any>>,Array<YEvent<any>>>}
		*/
		this.changedParentTypes = /* @__PURE__ */ new Map();
		/**
		* @type {Array<AbstractStruct>}
		*/
		this._mergeStructs = [];
		/**
		* @type {any}
		*/
		this.origin = origin;
		/**
		* Stores meta information on the transaction
		* @type {Map<any,any>}
		*/
		this.meta = /* @__PURE__ */ new Map();
		/**
		* Whether this change originates from this doc.
		* @type {boolean}
		*/
		this.local = local;
		/**
		* @type {Set<Doc>}
		*/
		this.subdocsAdded = /* @__PURE__ */ new Set();
		/**
		* @type {Set<Doc>}
		*/
		this.subdocsRemoved = /* @__PURE__ */ new Set();
		/**
		* @type {Set<Doc>}
		*/
		this.subdocsLoaded = /* @__PURE__ */ new Set();
		/**
		* @type {boolean}
		*/
		this._needFormattingCleanup = false;
	}
};
/**
* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
* @param {Transaction} transaction
* @return {boolean} Whether data was written.
*/
var writeUpdateMessageFromTransaction = (encoder, transaction) => {
	if (transaction.deleteSet.clients.size === 0 && !any(transaction.afterState, (clock, client) => transaction.beforeState.get(client) !== clock)) return false;
	sortAndMergeDeleteSet(transaction.deleteSet);
	writeStructsFromTransaction(encoder, transaction);
	writeDeleteSet(encoder, transaction.deleteSet);
	return true;
};
/**
* If `type.parent` was added in current transaction, `type` technically
* did not change, it was just added and we should not fire events for `type`.
*
* @param {Transaction} transaction
* @param {AbstractType<YEvent<any>>} type
* @param {string|null} parentSub
*/
var addChangedTypeToTransaction = (transaction, type, parentSub) => {
	const item = type._item;
	if (item === null || item.id.clock < (transaction.beforeState.get(item.id.client) || 0) && !item.deleted) setIfUndefined(transaction.changed, type, create$4).add(parentSub);
};
/**
* @param {Array<AbstractStruct>} structs
* @param {number} pos
* @return {number} # of merged structs
*/
var tryToMergeWithLefts = (structs, pos) => {
	let right = structs[pos];
	let left = structs[pos - 1];
	let i = pos;
	for (; i > 0; right = left, left = structs[--i - 1]) {
		if (left.deleted === right.deleted && left.constructor === right.constructor) {
			if (left.mergeWith(right)) {
				if (right instanceof Item && right.parentSub !== null && right.parent._map.get(right.parentSub) === right)
 /** @type {AbstractType<any>} */ right.parent._map.set(right.parentSub, left);
				continue;
			}
		}
		break;
	}
	const merged = pos - i;
	if (merged) structs.splice(pos + 1 - merged, merged);
	return merged;
};
/**
* @param {DeleteSet} ds
* @param {StructStore} store
* @param {function(Item):boolean} gcFilter
*/
var tryGcDeleteSet = (ds, store, gcFilter) => {
	for (const [client, deleteItems] of ds.clients.entries()) {
		const structs = store.clients.get(client);
		for (let di = deleteItems.length - 1; di >= 0; di--) {
			const deleteItem = deleteItems[di];
			const endDeleteItemClock = deleteItem.clock + deleteItem.len;
			for (let si = findIndexSS(structs, deleteItem.clock), struct = structs[si]; si < structs.length && struct.id.clock < endDeleteItemClock; struct = structs[++si]) {
				const struct = structs[si];
				if (deleteItem.clock + deleteItem.len <= struct.id.clock) break;
				if (struct instanceof Item && struct.deleted && !struct.keep && gcFilter(struct)) struct.gc(store, false);
			}
		}
	}
};
/**
* @param {DeleteSet} ds
* @param {StructStore} store
*/
var tryMergeDeleteSet = (ds, store) => {
	ds.clients.forEach((deleteItems, client) => {
		const structs = store.clients.get(client);
		for (let di = deleteItems.length - 1; di >= 0; di--) {
			const deleteItem = deleteItems[di];
			const mostRightIndexToCheck = min(structs.length - 1, 1 + findIndexSS(structs, deleteItem.clock + deleteItem.len - 1));
			for (let si = mostRightIndexToCheck, struct = structs[si]; si > 0 && struct.id.clock >= deleteItem.clock; struct = structs[si]) si -= 1 + tryToMergeWithLefts(structs, si);
		}
	});
};
/**
* @param {Array<Transaction>} transactionCleanups
* @param {number} i
*/
var cleanupTransactions = (transactionCleanups, i) => {
	if (i < transactionCleanups.length) {
		const transaction = transactionCleanups[i];
		const doc = transaction.doc;
		const store = doc.store;
		const ds = transaction.deleteSet;
		const mergeStructs = transaction._mergeStructs;
		try {
			sortAndMergeDeleteSet(ds);
			transaction.afterState = getStateVector(transaction.doc.store);
			doc.emit("beforeObserverCalls", [transaction, doc]);
			/**
			* An array of event callbacks.
			*
			* Each callback is called even if the other ones throw errors.
			*
			* @type {Array<function():void>}
			*/
			const fs = [];
			transaction.changed.forEach((subs, itemtype) => fs.push(() => {
				if (itemtype._item === null || !itemtype._item.deleted) itemtype._callObserver(transaction, subs);
			}));
			fs.push(() => {
				transaction.changedParentTypes.forEach((events, type) => {
					if (type._dEH.l.length > 0 && (type._item === null || !type._item.deleted)) {
						events = events.filter((event) => event.target._item === null || !event.target._item.deleted);
						events.forEach((event) => {
							event.currentTarget = type;
							event._path = null;
						});
						events.sort((event1, event2) => event1.path.length - event2.path.length);
						fs.push(() => {
							callEventHandlerListeners(type._dEH, events, transaction);
						});
					}
				});
				fs.push(() => doc.emit("afterTransaction", [transaction, doc]));
				fs.push(() => {
					if (transaction._needFormattingCleanup) cleanupYTextAfterTransaction(transaction);
				});
			});
			callAll(fs, []);
		} finally {
			if (doc.gc) tryGcDeleteSet(ds, store, doc.gcFilter);
			tryMergeDeleteSet(ds, store);
			transaction.afterState.forEach((clock, client) => {
				const beforeClock = transaction.beforeState.get(client) || 0;
				if (beforeClock !== clock) {
					const structs = store.clients.get(client);
					const firstChangePos = max(findIndexSS(structs, beforeClock), 1);
					for (let i = structs.length - 1; i >= firstChangePos;) i -= 1 + tryToMergeWithLefts(structs, i);
				}
			});
			for (let i = mergeStructs.length - 1; i >= 0; i--) {
				const { client, clock } = mergeStructs[i].id;
				const structs = store.clients.get(client);
				const replacedStructPos = findIndexSS(structs, clock);
				if (replacedStructPos + 1 < structs.length) {
					if (tryToMergeWithLefts(structs, replacedStructPos + 1) > 1) continue;
				}
				if (replacedStructPos > 0) tryToMergeWithLefts(structs, replacedStructPos);
			}
			if (!transaction.local && transaction.afterState.get(doc.clientID) !== transaction.beforeState.get(doc.clientID)) {
				print(ORANGE, BOLD, "[yjs] ", UNBOLD, RED, "Changed the client-id because another client seems to be using it.");
				doc.clientID = generateNewClientId();
			}
			doc.emit("afterTransactionCleanup", [transaction, doc]);
			if (doc._observers.has("update")) {
				const encoder = new UpdateEncoderV1();
				if (writeUpdateMessageFromTransaction(encoder, transaction)) doc.emit("update", [
					encoder.toUint8Array(),
					transaction.origin,
					doc,
					transaction
				]);
			}
			if (doc._observers.has("updateV2")) {
				const encoder = new UpdateEncoderV2();
				if (writeUpdateMessageFromTransaction(encoder, transaction)) doc.emit("updateV2", [
					encoder.toUint8Array(),
					transaction.origin,
					doc,
					transaction
				]);
			}
			const { subdocsAdded, subdocsLoaded, subdocsRemoved } = transaction;
			if (subdocsAdded.size > 0 || subdocsRemoved.size > 0 || subdocsLoaded.size > 0) {
				subdocsAdded.forEach((subdoc) => {
					subdoc.clientID = doc.clientID;
					if (subdoc.collectionid == null) subdoc.collectionid = doc.collectionid;
					doc.subdocs.add(subdoc);
				});
				subdocsRemoved.forEach((subdoc) => doc.subdocs.delete(subdoc));
				doc.emit("subdocs", [
					{
						loaded: subdocsLoaded,
						added: subdocsAdded,
						removed: subdocsRemoved
					},
					doc,
					transaction
				]);
				subdocsRemoved.forEach((subdoc) => subdoc.destroy());
			}
			if (transactionCleanups.length <= i + 1) {
				doc._transactionCleanups = [];
				doc.emit("afterAllTransactions", [doc, transactionCleanups]);
			} else cleanupTransactions(transactionCleanups, i + 1);
		}
	}
};
/**
* Implements the functionality of `y.transact(()=>{..})`
*
* @template T
* @param {Doc} doc
* @param {function(Transaction):T} f
* @param {any} [origin=true]
* @return {T}
*
* @function
*/
var transact = (doc, f, origin = null, local = true) => {
	const transactionCleanups = doc._transactionCleanups;
	let initialCall = false;
	/**
	* @type {any}
	*/
	let result = null;
	if (doc._transaction === null) {
		initialCall = true;
		doc._transaction = new Transaction(doc, origin, local);
		transactionCleanups.push(doc._transaction);
		if (transactionCleanups.length === 1) doc.emit("beforeAllTransactions", [doc]);
		doc.emit("beforeTransaction", [doc._transaction, doc]);
	}
	try {
		result = f(doc._transaction);
	} finally {
		if (initialCall) {
			const finishCleanup = doc._transaction === transactionCleanups[0];
			doc._transaction = null;
			if (finishCleanup) cleanupTransactions(transactionCleanups, 0);
		}
	}
	return result;
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
*/
function* lazyStructReaderGenerator(decoder) {
	const numOfStateUpdates = readVarUint(decoder.restDecoder);
	for (let i = 0; i < numOfStateUpdates; i++) {
		const numberOfStructs = readVarUint(decoder.restDecoder);
		const client = decoder.readClient();
		let clock = readVarUint(decoder.restDecoder);
		for (let i = 0; i < numberOfStructs; i++) {
			const info = decoder.readInfo();
			if (info === 10) {
				const len = readVarUint(decoder.restDecoder);
				yield new Skip(createID(client, clock), len);
				clock += len;
			} else if ((31 & info) !== 0) {
				const cantCopyParentInfo = (info & 192) === 0;
				const struct = new Item(createID(client, clock), null, (info & 128) === 128 ? decoder.readLeftID() : null, null, (info & 64) === 64 ? decoder.readRightID() : null, cantCopyParentInfo ? decoder.readParentInfo() ? decoder.readString() : decoder.readLeftID() : null, cantCopyParentInfo && (info & 32) === 32 ? decoder.readString() : null, readItemContent(decoder, info));
				yield struct;
				clock += struct.length;
			} else {
				const len = decoder.readLen();
				yield new GC(createID(client, clock), len);
				clock += len;
			}
		}
	}
}
var LazyStructReader = class {
	/**
	* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
	* @param {boolean} filterSkips
	*/
	constructor(decoder, filterSkips) {
		this.gen = lazyStructReaderGenerator(decoder);
		/**
		* @type {null | Item | Skip | GC}
		*/
		this.curr = null;
		this.done = false;
		this.filterSkips = filterSkips;
		this.next();
	}
	/**
	* @return {Item | GC | Skip |null}
	*/
	next() {
		do
			this.curr = this.gen.next().value || null;
		while (this.filterSkips && this.curr !== null && this.curr.constructor === Skip);
		return this.curr;
	}
};
var LazyStructWriter = class {
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	*/
	constructor(encoder) {
		this.currClient = 0;
		this.startClock = 0;
		this.written = 0;
		this.encoder = encoder;
		/**
		* We want to write operations lazily, but also we need to know beforehand how many operations we want to write for each client.
		*
		* This kind of meta-information (#clients, #structs-per-client-written) is written to the restEncoder.
		*
		* We fragment the restEncoder and store a slice of it per-client until we know how many clients there are.
		* When we flush (toUint8Array) we write the restEncoder using the fragments and the meta-information.
		*
		* @type {Array<{ written: number, restEncoder: Uint8Array }>}
		*/
		this.clientStructs = [];
	}
};
/**
* @param {Array<Uint8Array>} updates
* @return {Uint8Array}
*/
var mergeUpdates = (updates) => mergeUpdatesV2(updates, UpdateDecoderV1, UpdateEncoderV1);
/**
* This method is intended to slice any kind of struct and retrieve the right part.
* It does not handle side-effects, so it should only be used by the lazy-encoder.
*
* @param {Item | GC | Skip} left
* @param {number} diff
* @return {Item | GC}
*/
var sliceStruct = (left, diff) => {
	if (left.constructor === GC) {
		const { client, clock } = left.id;
		return new GC(createID(client, clock + diff), left.length - diff);
	} else if (left.constructor === Skip) {
		const { client, clock } = left.id;
		return new Skip(createID(client, clock + diff), left.length - diff);
	} else {
		const leftItem = left;
		const { client, clock } = leftItem.id;
		return new Item(createID(client, clock + diff), null, createID(client, clock + diff - 1), null, leftItem.rightOrigin, leftItem.parent, leftItem.parentSub, leftItem.content.splice(diff));
	}
};
/**
*
* This function works similarly to `readUpdateV2`.
*
* @param {Array<Uint8Array>} updates
* @param {typeof UpdateDecoderV1 | typeof UpdateDecoderV2} [YDecoder]
* @param {typeof UpdateEncoderV1 | typeof UpdateEncoderV2} [YEncoder]
* @return {Uint8Array}
*/
var mergeUpdatesV2 = (updates, YDecoder = UpdateDecoderV2, YEncoder = UpdateEncoderV2) => {
	if (updates.length === 1) return updates[0];
	const updateDecoders = updates.map((update) => new YDecoder(createDecoder(update)));
	let lazyStructDecoders = updateDecoders.map((decoder) => new LazyStructReader(decoder, true));
	/**
	* @todo we don't need offset because we always slice before
	* @type {null | { struct: Item | GC | Skip, offset: number }}
	*/
	let currWrite = null;
	const updateEncoder = new YEncoder();
	const lazyStructEncoder = new LazyStructWriter(updateEncoder);
	while (true) {
		lazyStructDecoders = lazyStructDecoders.filter((dec) => dec.curr !== null);
		lazyStructDecoders.sort(
			/** @type {function(any,any):number} */
			(dec1, dec2) => {
				if (dec1.curr.id.client === dec2.curr.id.client) {
					const clockDiff = dec1.curr.id.clock - dec2.curr.id.clock;
					if (clockDiff === 0) return dec1.curr.constructor === dec2.curr.constructor ? 0 : dec1.curr.constructor === Skip ? 1 : -1;
					else return clockDiff;
				} else return dec2.curr.id.client - dec1.curr.id.client;
			}
		);
		if (lazyStructDecoders.length === 0) break;
		const currDecoder = lazyStructDecoders[0];
		const firstClient = currDecoder.curr.id.client;
		if (currWrite !== null) {
			let curr = currDecoder.curr;
			let iterated = false;
			while (curr !== null && curr.id.clock + curr.length <= currWrite.struct.id.clock + currWrite.struct.length && curr.id.client >= currWrite.struct.id.client) {
				curr = currDecoder.next();
				iterated = true;
			}
			if (curr === null || curr.id.client !== firstClient || iterated && curr.id.clock > currWrite.struct.id.clock + currWrite.struct.length) continue;
			if (firstClient !== currWrite.struct.id.client) {
				writeStructToLazyStructWriter(lazyStructEncoder, currWrite.struct, currWrite.offset);
				currWrite = {
					struct: curr,
					offset: 0
				};
				currDecoder.next();
			} else if (currWrite.struct.id.clock + currWrite.struct.length < curr.id.clock) if (currWrite.struct.constructor === Skip) currWrite.struct.length = curr.id.clock + curr.length - currWrite.struct.id.clock;
			else {
				writeStructToLazyStructWriter(lazyStructEncoder, currWrite.struct, currWrite.offset);
				const diff = curr.id.clock - currWrite.struct.id.clock - currWrite.struct.length;
				currWrite = {
					struct: new Skip(createID(firstClient, currWrite.struct.id.clock + currWrite.struct.length), diff),
					offset: 0
				};
			}
			else {
				const diff = currWrite.struct.id.clock + currWrite.struct.length - curr.id.clock;
				if (diff > 0) if (currWrite.struct.constructor === Skip) currWrite.struct.length -= diff;
				else curr = sliceStruct(curr, diff);
				if (!currWrite.struct.mergeWith(curr)) {
					writeStructToLazyStructWriter(lazyStructEncoder, currWrite.struct, currWrite.offset);
					currWrite = {
						struct: curr,
						offset: 0
					};
					currDecoder.next();
				}
			}
		} else {
			currWrite = {
				struct: currDecoder.curr,
				offset: 0
			};
			currDecoder.next();
		}
		for (let next = currDecoder.curr; next !== null && next.id.client === firstClient && next.id.clock === currWrite.struct.id.clock + currWrite.struct.length && next.constructor !== Skip; next = currDecoder.next()) {
			writeStructToLazyStructWriter(lazyStructEncoder, currWrite.struct, currWrite.offset);
			currWrite = {
				struct: next,
				offset: 0
			};
		}
	}
	if (currWrite !== null) {
		writeStructToLazyStructWriter(lazyStructEncoder, currWrite.struct, currWrite.offset);
		currWrite = null;
	}
	finishLazyStructWriting(lazyStructEncoder);
	writeDeleteSet(updateEncoder, mergeDeleteSets(updateDecoders.map((decoder) => readDeleteSet(decoder))));
	return updateEncoder.toUint8Array();
};
/**
* @param {Uint8Array} update
* @param {Uint8Array} sv
* @param {typeof UpdateDecoderV1 | typeof UpdateDecoderV2} [YDecoder]
* @param {typeof UpdateEncoderV1 | typeof UpdateEncoderV2} [YEncoder]
*/
var diffUpdateV2 = (update, sv, YDecoder = UpdateDecoderV2, YEncoder = UpdateEncoderV2) => {
	const state = decodeStateVector(sv);
	const encoder = new YEncoder();
	const lazyStructWriter = new LazyStructWriter(encoder);
	const decoder = new YDecoder(createDecoder(update));
	const reader = new LazyStructReader(decoder, false);
	while (reader.curr) {
		const curr = reader.curr;
		const currClient = curr.id.client;
		const svClock = state.get(currClient) || 0;
		if (reader.curr.constructor === Skip) {
			reader.next();
			continue;
		}
		if (curr.id.clock + curr.length > svClock) {
			writeStructToLazyStructWriter(lazyStructWriter, curr, max(svClock - curr.id.clock, 0));
			reader.next();
			while (reader.curr && reader.curr.id.client === currClient) {
				writeStructToLazyStructWriter(lazyStructWriter, reader.curr, 0);
				reader.next();
			}
		} else while (reader.curr && reader.curr.id.client === currClient && reader.curr.id.clock + reader.curr.length <= svClock) reader.next();
	}
	finishLazyStructWriting(lazyStructWriter);
	writeDeleteSet(encoder, readDeleteSet(decoder));
	return encoder.toUint8Array();
};
/**
* @param {LazyStructWriter} lazyWriter
*/
var flushLazyStructWriter = (lazyWriter) => {
	if (lazyWriter.written > 0) {
		lazyWriter.clientStructs.push({
			written: lazyWriter.written,
			restEncoder: toUint8Array(lazyWriter.encoder.restEncoder)
		});
		lazyWriter.encoder.restEncoder = createEncoder();
		lazyWriter.written = 0;
	}
};
/**
* @param {LazyStructWriter} lazyWriter
* @param {Item | GC} struct
* @param {number} offset
*/
var writeStructToLazyStructWriter = (lazyWriter, struct, offset) => {
	if (lazyWriter.written > 0 && lazyWriter.currClient !== struct.id.client) flushLazyStructWriter(lazyWriter);
	if (lazyWriter.written === 0) {
		lazyWriter.currClient = struct.id.client;
		lazyWriter.encoder.writeClient(struct.id.client);
		writeVarUint(lazyWriter.encoder.restEncoder, struct.id.clock + offset);
	}
	struct.write(lazyWriter.encoder, offset);
	lazyWriter.written++;
};
/**
* Call this function when we collected all parts and want to
* put all the parts together. After calling this method,
* you can continue using the UpdateEncoder.
*
* @param {LazyStructWriter} lazyWriter
*/
var finishLazyStructWriting = (lazyWriter) => {
	flushLazyStructWriter(lazyWriter);
	const restEncoder = lazyWriter.encoder.restEncoder;
	/**
	* Now we put all the fragments together.
	* This works similarly to `writeClientsStructs`
	*/
	writeVarUint(restEncoder, lazyWriter.clientStructs.length);
	for (let i = 0; i < lazyWriter.clientStructs.length; i++) {
		const partStructs = lazyWriter.clientStructs[i];
		/**
		* Works similarly to `writeStructs`
		*/
		writeVarUint(restEncoder, partStructs.written);
		writeUint8Array(restEncoder, partStructs.restEncoder);
	}
};
/**
* @param {Uint8Array} update
* @param {function(Item|GC|Skip):Item|GC|Skip} blockTransformer
* @param {typeof UpdateDecoderV2 | typeof UpdateDecoderV1} YDecoder
* @param {typeof UpdateEncoderV2 | typeof UpdateEncoderV1 } YEncoder
*/
var convertUpdateFormat = (update, blockTransformer, YDecoder, YEncoder) => {
	const updateDecoder = new YDecoder(createDecoder(update));
	const lazyDecoder = new LazyStructReader(updateDecoder, false);
	const updateEncoder = new YEncoder();
	const lazyWriter = new LazyStructWriter(updateEncoder);
	for (let curr = lazyDecoder.curr; curr !== null; curr = lazyDecoder.next()) writeStructToLazyStructWriter(lazyWriter, blockTransformer(curr), 0);
	finishLazyStructWriting(lazyWriter);
	writeDeleteSet(updateEncoder, readDeleteSet(updateDecoder));
	return updateEncoder.toUint8Array();
};
/**
* @param {Uint8Array} update
*/
var convertUpdateFormatV2ToV1 = (update) => convertUpdateFormat(update, id, UpdateDecoderV2, UpdateEncoderV1);
var errorComputeChanges = "You must not compute changes after the event-handler fired.";
/**
* @template {AbstractType<any>} T
* YEvent describes the changes on a YType.
*/
var YEvent = class {
	/**
	* @param {T} target The changed type.
	* @param {Transaction} transaction
	*/
	constructor(target, transaction) {
		/**
		* The type on which this event was created on.
		* @type {T}
		*/
		this.target = target;
		/**
		* The current target on which the observe callback is called.
		* @type {AbstractType<any>}
		*/
		this.currentTarget = target;
		/**
		* The transaction that triggered this event.
		* @type {Transaction}
		*/
		this.transaction = transaction;
		/**
		* @type {Object|null}
		*/
		this._changes = null;
		/**
		* @type {null | Map<string, { action: 'add' | 'update' | 'delete', oldValue: any }>}
		*/
		this._keys = null;
		/**
		* @type {null | Array<{ insert?: string | Array<any> | object | AbstractType<any>, retain?: number, delete?: number, attributes?: Object<string, any> }>}
		*/
		this._delta = null;
		/**
		* @type {Array<string|number>|null}
		*/
		this._path = null;
	}
	/**
	* Computes the path from `y` to the changed type.
	*
	* @todo v14 should standardize on path: Array<{parent, index}> because that is easier to work with.
	*
	* The following property holds:
	* @example
	*   let type = y
	*   event.path.forEach(dir => {
	*     type = type.get(dir)
	*   })
	*   type === event.target // => true
	*/
	get path() {
		return this._path || (this._path = getPathTo(this.currentTarget, this.target));
	}
	/**
	* Check if a struct is deleted by this event.
	*
	* In contrast to change.deleted, this method also returns true if the struct was added and then deleted.
	*
	* @param {AbstractStruct} struct
	* @return {boolean}
	*/
	deletes(struct) {
		return isDeleted(this.transaction.deleteSet, struct.id);
	}
	/**
	* @type {Map<string, { action: 'add' | 'update' | 'delete', oldValue: any }>}
	*/
	get keys() {
		if (this._keys === null) {
			if (this.transaction.doc._transactionCleanups.length === 0) throw create$3(errorComputeChanges);
			const keys = /* @__PURE__ */ new Map();
			const target = this.target;
			this.transaction.changed.get(target).forEach((key) => {
				if (key !== null) {
					const item = target._map.get(key);
					/**
					* @type {'delete' | 'add' | 'update'}
					*/
					let action;
					let oldValue;
					if (this.adds(item)) {
						let prev = item.left;
						while (prev !== null && this.adds(prev)) prev = prev.left;
						if (this.deletes(item)) if (prev !== null && this.deletes(prev)) {
							action = "delete";
							oldValue = last(prev.content.getContent());
						} else return;
						else if (prev !== null && this.deletes(prev)) {
							action = "update";
							oldValue = last(prev.content.getContent());
						} else {
							action = "add";
							oldValue = void 0;
						}
					} else if (this.deletes(item)) {
						action = "delete";
						oldValue = last(
							/** @type {Item} */
							item.content.getContent()
						);
					} else return;
					keys.set(key, {
						action,
						oldValue
					});
				}
			});
			this._keys = keys;
		}
		return this._keys;
	}
	/**
	* This is a computed property. Note that this can only be safely computed during the
	* event call. Computing this property after other changes happened might result in
	* unexpected behavior (incorrect computation of deltas). A safe way to collect changes
	* is to store the `changes` or the `delta` object. Avoid storing the `transaction` object.
	*
	* @type {Array<{insert?: string | Array<any> | object | AbstractType<any>, retain?: number, delete?: number, attributes?: Object<string, any>}>}
	*/
	get delta() {
		return this.changes.delta;
	}
	/**
	* Check if a struct is added by this event.
	*
	* In contrast to change.deleted, this method also returns true if the struct was added and then deleted.
	*
	* @param {AbstractStruct} struct
	* @return {boolean}
	*/
	adds(struct) {
		return struct.id.clock >= (this.transaction.beforeState.get(struct.id.client) || 0);
	}
	/**
	* This is a computed property. Note that this can only be safely computed during the
	* event call. Computing this property after other changes happened might result in
	* unexpected behavior (incorrect computation of deltas). A safe way to collect changes
	* is to store the `changes` or the `delta` object. Avoid storing the `transaction` object.
	*
	* @type {{added:Set<Item>,deleted:Set<Item>,keys:Map<string,{action:'add'|'update'|'delete',oldValue:any}>,delta:Array<{insert?:Array<any>|string, delete?:number, retain?:number}>}}
	*/
	get changes() {
		let changes = this._changes;
		if (changes === null) {
			if (this.transaction.doc._transactionCleanups.length === 0) throw create$3(errorComputeChanges);
			const target = this.target;
			const added = create$4();
			const deleted = create$4();
			/**
			* @type {Array<{insert:Array<any>}|{delete:number}|{retain:number}>}
			*/
			const delta = [];
			changes = {
				added,
				deleted,
				delta,
				keys: this.keys
			};
			if (this.transaction.changed.get(target).has(null)) {
				/**
				* @type {any}
				*/
				let lastOp = null;
				const packOp = () => {
					if (lastOp) delta.push(lastOp);
				};
				for (let item = target._start; item !== null; item = item.right) if (item.deleted) {
					if (this.deletes(item) && !this.adds(item)) {
						if (lastOp === null || lastOp.delete === void 0) {
							packOp();
							lastOp = { delete: 0 };
						}
						lastOp.delete += item.length;
						deleted.add(item);
					}
				} else if (this.adds(item)) {
					if (lastOp === null || lastOp.insert === void 0) {
						packOp();
						lastOp = { insert: [] };
					}
					lastOp.insert = lastOp.insert.concat(item.content.getContent());
					added.add(item);
				} else {
					if (lastOp === null || lastOp.retain === void 0) {
						packOp();
						lastOp = { retain: 0 };
					}
					lastOp.retain += item.length;
				}
				if (lastOp !== null && lastOp.retain === void 0) packOp();
			}
			this._changes = changes;
		}
		return changes;
	}
};
/**
* Compute the path from this type to the specified target.
*
* @example
*   // `child` should be accessible via `type.get(path[0]).get(path[1])..`
*   const path = type.getPathTo(child)
*   // assuming `type instanceof YArray`
*   console.log(path) // might look like => [2, 'key1']
*   child === type.get(path[0]).get(path[1])
*
* @param {AbstractType<any>} parent
* @param {AbstractType<any>} child target
* @return {Array<string|number>} Path to the target
*
* @private
* @function
*/
var getPathTo = (parent, child) => {
	const path = [];
	while (child._item !== null && child !== parent) {
		if (child._item.parentSub !== null) path.unshift(child._item.parentSub);
		else {
			let i = 0;
			let c = child._item.parent._start;
			while (c !== child._item && c !== null) {
				if (!c.deleted && c.countable) i += c.length;
				c = c.right;
			}
			path.unshift(i);
		}
		child = child._item.parent;
	}
	return path;
};
/**
* https://docs.yjs.dev/getting-started/working-with-shared-types#caveats
*/
var warnPrematureAccess = () => {
	warn("Invalid access: Add Yjs type to a document before reading data.");
};
var maxSearchMarker = 80;
/**
* A unique timestamp that identifies each marker.
*
* Time is relative,.. this is more like an ever-increasing clock.
*
* @type {number}
*/
var globalSearchMarkerTimestamp = 0;
var ArraySearchMarker = class {
	/**
	* @param {Item} p
	* @param {number} index
	*/
	constructor(p, index) {
		p.marker = true;
		this.p = p;
		this.index = index;
		this.timestamp = globalSearchMarkerTimestamp++;
	}
};
/**
* @param {ArraySearchMarker} marker
*/
var refreshMarkerTimestamp = (marker) => {
	marker.timestamp = globalSearchMarkerTimestamp++;
};
/**
* This is rather complex so this function is the only thing that should overwrite a marker
*
* @param {ArraySearchMarker} marker
* @param {Item} p
* @param {number} index
*/
var overwriteMarker = (marker, p, index) => {
	marker.p.marker = false;
	marker.p = p;
	p.marker = true;
	marker.index = index;
	marker.timestamp = globalSearchMarkerTimestamp++;
};
/**
* @param {Array<ArraySearchMarker>} searchMarker
* @param {Item} p
* @param {number} index
*/
var markPosition = (searchMarker, p, index) => {
	if (searchMarker.length >= maxSearchMarker) {
		const marker = searchMarker.reduce((a, b) => a.timestamp < b.timestamp ? a : b);
		overwriteMarker(marker, p, index);
		return marker;
	} else {
		const pm = new ArraySearchMarker(p, index);
		searchMarker.push(pm);
		return pm;
	}
};
/**
* Search marker help us to find positions in the associative array faster.
*
* They speed up the process of finding a position without much bookkeeping.
*
* A maximum of `maxSearchMarker` objects are created.
*
* This function always returns a refreshed marker (updated timestamp)
*
* @param {AbstractType<any>} yarray
* @param {number} index
*/
var findMarker = (yarray, index) => {
	if (yarray._start === null || index === 0 || yarray._searchMarker === null) return null;
	const marker = yarray._searchMarker.length === 0 ? null : yarray._searchMarker.reduce((a, b) => abs(index - a.index) < abs(index - b.index) ? a : b);
	let p = yarray._start;
	let pindex = 0;
	if (marker !== null) {
		p = marker.p;
		pindex = marker.index;
		refreshMarkerTimestamp(marker);
	}
	while (p.right !== null && pindex < index) {
		if (!p.deleted && p.countable) {
			if (index < pindex + p.length) break;
			pindex += p.length;
		}
		p = p.right;
	}
	while (p.left !== null && pindex > index) {
		p = p.left;
		if (!p.deleted && p.countable) pindex -= p.length;
	}
	while (p.left !== null && p.left.id.client === p.id.client && p.left.id.clock + p.left.length === p.id.clock) {
		p = p.left;
		if (!p.deleted && p.countable) pindex -= p.length;
	}
	if (marker !== null && abs(marker.index - pindex) < p.parent.length / maxSearchMarker) {
		overwriteMarker(marker, p, pindex);
		return marker;
	} else return markPosition(yarray._searchMarker, p, pindex);
};
/**
* Update markers when a change happened.
*
* This should be called before doing a deletion!
*
* @param {Array<ArraySearchMarker>} searchMarker
* @param {number} index
* @param {number} len If insertion, len is positive. If deletion, len is negative.
*/
var updateMarkerChanges = (searchMarker, index, len) => {
	for (let i = searchMarker.length - 1; i >= 0; i--) {
		const m = searchMarker[i];
		if (len > 0) {
			/**
			* @type {Item|null}
			*/
			let p = m.p;
			p.marker = false;
			while (p && (p.deleted || !p.countable)) {
				p = p.left;
				if (p && !p.deleted && p.countable) m.index -= p.length;
			}
			if (p === null || p.marker === true) {
				searchMarker.splice(i, 1);
				continue;
			}
			m.p = p;
			p.marker = true;
		}
		if (index < m.index || len > 0 && index === m.index) m.index = max(index, m.index + len);
	}
};
/**
* Call event listeners with an event. This will also add an event to all
* parents (for `.observeDeep` handlers).
*
* @template EventType
* @param {AbstractType<EventType>} type
* @param {Transaction} transaction
* @param {EventType} event
*/
var callTypeObservers = (type, transaction, event) => {
	const changedType = type;
	const changedParentTypes = transaction.changedParentTypes;
	while (true) {
		setIfUndefined(changedParentTypes, type, () => []).push(event);
		if (type._item === null) break;
		type = type._item.parent;
	}
	callEventHandlerListeners(changedType._eH, event, transaction);
};
/**
* @template EventType
* Abstract Yjs Type class
*/
var AbstractType = class {
	constructor() {
		/**
		* @type {Item|null}
		*/
		this._item = null;
		/**
		* @type {Map<string,Item>}
		*/
		this._map = /* @__PURE__ */ new Map();
		/**
		* @type {Item|null}
		*/
		this._start = null;
		/**
		* @type {Doc|null}
		*/
		this.doc = null;
		this._length = 0;
		/**
		* Event handlers
		* @type {EventHandler<EventType,Transaction>}
		*/
		this._eH = createEventHandler();
		/**
		* Deep event handlers
		* @type {EventHandler<Array<YEvent<any>>,Transaction>}
		*/
		this._dEH = createEventHandler();
		/**
		* @type {null | Array<ArraySearchMarker>}
		*/
		this._searchMarker = null;
	}
	/**
	* @return {AbstractType<any>|null}
	*/
	get parent() {
		return this._item ? this._item.parent : null;
	}
	/**
	* Integrate this type into the Yjs instance.
	*
	* * Save this struct in the os
	* * This type is sent to other client
	* * Observer functions are fired
	*
	* @param {Doc} y The Yjs instance
	* @param {Item|null} item
	*/
	_integrate(y, item) {
		this.doc = y;
		this._item = item;
	}
	/**
	* @return {AbstractType<EventType>}
	*/
	_copy() {
		throw methodUnimplemented();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {AbstractType<EventType>}
	*/
	clone() {
		throw methodUnimplemented();
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} _encoder
	*/
	_write(_encoder) {}
	/**
	* The first non-deleted item
	*/
	get _first() {
		let n = this._start;
		while (n !== null && n.deleted) n = n.right;
		return n;
	}
	/**
	* Creates YEvent and calls all type observers.
	* Must be implemented by each type.
	*
	* @param {Transaction} transaction
	* @param {Set<null|string>} _parentSubs Keys changed on this type. `null` if list was modified.
	*/
	_callObserver(transaction, _parentSubs) {
		if (!transaction.local && this._searchMarker) this._searchMarker.length = 0;
	}
	/**
	* Observe all events that are created on this type.
	*
	* @param {function(EventType, Transaction):void} f Observer function
	*/
	observe(f) {
		addEventHandlerListener(this._eH, f);
	}
	/**
	* Observe all events that are created by this type and its children.
	*
	* @param {function(Array<YEvent<any>>,Transaction):void} f Observer function
	*/
	observeDeep(f) {
		addEventHandlerListener(this._dEH, f);
	}
	/**
	* Unregister an observer function.
	*
	* @param {function(EventType,Transaction):void} f Observer function
	*/
	unobserve(f) {
		removeEventHandlerListener(this._eH, f);
	}
	/**
	* Unregister an observer function.
	*
	* @param {function(Array<YEvent<any>>,Transaction):void} f Observer function
	*/
	unobserveDeep(f) {
		removeEventHandlerListener(this._dEH, f);
	}
	/**
	* @abstract
	* @return {any}
	*/
	toJSON() {}
};
/**
* @param {AbstractType<any>} type
* @param {number} start
* @param {number} end
* @return {Array<any>}
*
* @private
* @function
*/
var typeListSlice = (type, start, end) => {
	type.doc ?? warnPrematureAccess();
	if (start < 0) start = type._length + start;
	if (end < 0) end = type._length + end;
	let len = end - start;
	const cs = [];
	let n = type._start;
	while (n !== null && len > 0) {
		if (n.countable && !n.deleted) {
			const c = n.content.getContent();
			if (c.length <= start) start -= c.length;
			else {
				for (let i = start; i < c.length && len > 0; i++) {
					cs.push(c[i]);
					len--;
				}
				start = 0;
			}
		}
		n = n.right;
	}
	return cs;
};
/**
* @param {AbstractType<any>} type
* @return {Array<any>}
*
* @private
* @function
*/
var typeListToArray = (type) => {
	type.doc ?? warnPrematureAccess();
	const cs = [];
	let n = type._start;
	while (n !== null) {
		if (n.countable && !n.deleted) {
			const c = n.content.getContent();
			for (let i = 0; i < c.length; i++) cs.push(c[i]);
		}
		n = n.right;
	}
	return cs;
};
/**
* Executes a provided function on once on every element of this YArray.
*
* @param {AbstractType<any>} type
* @param {function(any,number,any):void} f A function to execute on every element of this YArray.
*
* @private
* @function
*/
var typeListForEach = (type, f) => {
	let index = 0;
	let n = type._start;
	type.doc ?? warnPrematureAccess();
	while (n !== null) {
		if (n.countable && !n.deleted) {
			const c = n.content.getContent();
			for (let i = 0; i < c.length; i++) f(c[i], index++, type);
		}
		n = n.right;
	}
};
/**
* @template C,R
* @param {AbstractType<any>} type
* @param {function(C,number,AbstractType<any>):R} f
* @return {Array<R>}
*
* @private
* @function
*/
var typeListMap = (type, f) => {
	/**
	* @type {Array<any>}
	*/
	const result = [];
	typeListForEach(type, (c, i) => {
		result.push(f(c, i, type));
	});
	return result;
};
/**
* @param {AbstractType<any>} type
* @return {IterableIterator<any>}
*
* @private
* @function
*/
var typeListCreateIterator = (type) => {
	let n = type._start;
	/**
	* @type {Array<any>|null}
	*/
	let currentContent = null;
	let currentContentIndex = 0;
	return {
		[Symbol.iterator]() {
			return this;
		},
		next: () => {
			if (currentContent === null) {
				while (n !== null && n.deleted) n = n.right;
				if (n === null) return {
					done: true,
					value: void 0
				};
				currentContent = n.content.getContent();
				currentContentIndex = 0;
				n = n.right;
			}
			const value = currentContent[currentContentIndex++];
			if (currentContent.length <= currentContentIndex) currentContent = null;
			return {
				done: false,
				value
			};
		}
	};
};
/**
* @param {AbstractType<any>} type
* @param {number} index
* @return {any}
*
* @private
* @function
*/
var typeListGet = (type, index) => {
	type.doc ?? warnPrematureAccess();
	const marker = findMarker(type, index);
	let n = type._start;
	if (marker !== null) {
		n = marker.p;
		index -= marker.index;
	}
	for (; n !== null; n = n.right) if (!n.deleted && n.countable) {
		if (index < n.length) return n.content.getContent()[index];
		index -= n.length;
	}
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {Item?} referenceItem
* @param {Array<Object<string,any>|Array<any>|boolean|number|null|string|Uint8Array>} content
*
* @private
* @function
*/
var typeListInsertGenericsAfter = (transaction, parent, referenceItem, content) => {
	let left = referenceItem;
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	const store = doc.store;
	const right = referenceItem === null ? parent._start : referenceItem.right;
	/**
	* @type {Array<Object|Array<any>|number|null>}
	*/
	let jsonContent = [];
	const packJsonContent = () => {
		if (jsonContent.length > 0) {
			left = new Item(createID(ownClientId, getState(store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentAny(jsonContent));
			left.integrate(transaction, 0);
			jsonContent = [];
		}
	};
	content.forEach((c) => {
		if (c === null) jsonContent.push(c);
		else switch (c.constructor) {
			case Number:
			case Object:
			case Boolean:
			case Array:
			case String:
				jsonContent.push(c);
				break;
			default:
				packJsonContent();
				switch (c.constructor) {
					case Uint8Array:
					case ArrayBuffer:
						left = new Item(createID(ownClientId, getState(store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentBinary(new Uint8Array(c)));
						left.integrate(transaction, 0);
						break;
					case Doc:
						left = new Item(createID(ownClientId, getState(store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentDoc(c));
						left.integrate(transaction, 0);
						break;
					default: if (c instanceof AbstractType) {
						left = new Item(createID(ownClientId, getState(store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentType(c));
						left.integrate(transaction, 0);
					} else throw new Error("Unexpected content type in insert operation");
				}
		}
	});
	packJsonContent();
};
var lengthExceeded = () => create$3("Length exceeded!");
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {number} index
* @param {Array<Object<string,any>|Array<any>|number|null|string|Uint8Array>} content
*
* @private
* @function
*/
var typeListInsertGenerics = (transaction, parent, index, content) => {
	if (index > parent._length) throw lengthExceeded();
	if (index === 0) {
		if (parent._searchMarker) updateMarkerChanges(parent._searchMarker, index, content.length);
		return typeListInsertGenericsAfter(transaction, parent, null, content);
	}
	const startIndex = index;
	const marker = findMarker(parent, index);
	let n = parent._start;
	if (marker !== null) {
		n = marker.p;
		index -= marker.index;
		if (index === 0) {
			n = n.prev;
			index += n && n.countable && !n.deleted ? n.length : 0;
		}
	}
	for (; n !== null; n = n.right) if (!n.deleted && n.countable) {
		if (index <= n.length) {
			if (index < n.length) getItemCleanStart(transaction, createID(n.id.client, n.id.clock + index));
			break;
		}
		index -= n.length;
	}
	if (parent._searchMarker) updateMarkerChanges(parent._searchMarker, startIndex, content.length);
	return typeListInsertGenericsAfter(transaction, parent, n, content);
};
/**
* Pushing content is special as we generally want to push after the last item. So we don't have to update
* the search marker.
*
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {Array<Object<string,any>|Array<any>|number|null|string|Uint8Array>} content
*
* @private
* @function
*/
var typeListPushGenerics = (transaction, parent, content) => {
	let n = (parent._searchMarker || []).reduce((maxMarker, currMarker) => currMarker.index > maxMarker.index ? currMarker : maxMarker, {
		index: 0,
		p: parent._start
	}).p;
	if (n) while (n.right) n = n.right;
	return typeListInsertGenericsAfter(transaction, parent, n, content);
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {number} index
* @param {number} length
*
* @private
* @function
*/
var typeListDelete = (transaction, parent, index, length) => {
	if (length === 0) return;
	const startIndex = index;
	const startLength = length;
	const marker = findMarker(parent, index);
	let n = parent._start;
	if (marker !== null) {
		n = marker.p;
		index -= marker.index;
	}
	for (; n !== null && index > 0; n = n.right) if (!n.deleted && n.countable) {
		if (index < n.length) getItemCleanStart(transaction, createID(n.id.client, n.id.clock + index));
		index -= n.length;
	}
	while (length > 0 && n !== null) {
		if (!n.deleted) {
			if (length < n.length) getItemCleanStart(transaction, createID(n.id.client, n.id.clock + length));
			n.delete(transaction);
			length -= n.length;
		}
		n = n.right;
	}
	if (length > 0) throw lengthExceeded();
	if (parent._searchMarker) updateMarkerChanges(parent._searchMarker, startIndex, -startLength + length);
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {string} key
*
* @private
* @function
*/
var typeMapDelete = (transaction, parent, key) => {
	const c = parent._map.get(key);
	if (c !== void 0) c.delete(transaction);
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {string} key
* @param {Object|number|null|Array<any>|string|Uint8Array|AbstractType<any>} value
*
* @private
* @function
*/
var typeMapSet = (transaction, parent, key, value) => {
	const left = parent._map.get(key) || null;
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	let content;
	if (value == null) content = new ContentAny([value]);
	else switch (value.constructor) {
		case Number:
		case Object:
		case Boolean:
		case Array:
		case String:
		case Date:
		case BigInt:
			content = new ContentAny([value]);
			break;
		case Uint8Array:
			content = new ContentBinary(value);
			break;
		case Doc:
			content = new ContentDoc(value);
			break;
		default: if (value instanceof AbstractType) content = new ContentType(value);
		else throw new Error("Unexpected content type");
	}
	new Item(createID(ownClientId, getState(doc.store, ownClientId)), left, left && left.lastId, null, null, parent, key, content).integrate(transaction, 0);
};
/**
* @param {AbstractType<any>} parent
* @param {string} key
* @return {Object<string,any>|number|null|Array<any>|string|Uint8Array|AbstractType<any>|undefined}
*
* @private
* @function
*/
var typeMapGet = (parent, key) => {
	parent.doc ?? warnPrematureAccess();
	const val = parent._map.get(key);
	return val !== void 0 && !val.deleted ? val.content.getContent()[val.length - 1] : void 0;
};
/**
* @param {AbstractType<any>} parent
* @return {Object<string,Object<string,any>|number|null|Array<any>|string|Uint8Array|AbstractType<any>|undefined>}
*
* @private
* @function
*/
var typeMapGetAll = (parent) => {
	/**
	* @type {Object<string,any>}
	*/
	const res = {};
	parent.doc ?? warnPrematureAccess();
	parent._map.forEach((value, key) => {
		if (!value.deleted) res[key] = value.content.getContent()[value.length - 1];
	});
	return res;
};
/**
* @param {AbstractType<any>} parent
* @param {string} key
* @return {boolean}
*
* @private
* @function
*/
var typeMapHas = (parent, key) => {
	parent.doc ?? warnPrematureAccess();
	const val = parent._map.get(key);
	return val !== void 0 && !val.deleted;
};
/**
* @param {AbstractType<any>} parent
* @param {Snapshot} snapshot
* @return {Object<string,Object<string,any>|number|null|Array<any>|string|Uint8Array|AbstractType<any>|undefined>}
*
* @private
* @function
*/
var typeMapGetAllSnapshot = (parent, snapshot) => {
	/**
	* @type {Object<string,any>}
	*/
	const res = {};
	parent._map.forEach((value, key) => {
		/**
		* @type {Item|null}
		*/
		let v = value;
		while (v !== null && (!snapshot.sv.has(v.id.client) || v.id.clock >= (snapshot.sv.get(v.id.client) || 0))) v = v.left;
		if (v !== null && isVisible(v, snapshot)) res[key] = v.content.getContent()[v.length - 1];
	});
	return res;
};
/**
* @param {AbstractType<any> & { _map: Map<string, Item> }} type
* @return {IterableIterator<Array<any>>}
*
* @private
* @function
*/
var createMapIterator = (type) => {
	type.doc ?? warnPrematureAccess();
	return iteratorFilter(
		type._map.entries(),
		/** @param {any} entry */
		(entry) => !entry[1].deleted
	);
};
/**
* @module YArray
*/
/**
* Event that describes the changes on a YArray
* @template T
* @extends YEvent<YArray<T>>
*/
var YArrayEvent = class extends YEvent {};
/**
* A shared Array implementation.
* @template T
* @extends AbstractType<YArrayEvent<T>>
* @implements {Iterable<T>}
*/
var YArray = class YArray extends AbstractType {
	constructor() {
		super();
		/**
		* @type {Array<any>?}
		* @private
		*/
		this._prelimContent = [];
		/**
		* @type {Array<ArraySearchMarker>}
		*/
		this._searchMarker = [];
	}
	/**
	* Construct a new YArray containing the specified items.
	* @template {Object<string,any>|Array<any>|number|null|string|Uint8Array} T
	* @param {Array<T>} items
	* @return {YArray<T>}
	*/
	static from(items) {
		/**
		* @type {YArray<T>}
		*/
		const a = new YArray();
		a.push(items);
		return a;
	}
	/**
	* Integrate this type into the Yjs instance.
	*
	* * Save this struct in the os
	* * This type is sent to other client
	* * Observer functions are fired
	*
	* @param {Doc} y The Yjs instance
	* @param {Item} item
	*/
	_integrate(y, item) {
		super._integrate(y, item);
		this.insert(0, this._prelimContent);
		this._prelimContent = null;
	}
	/**
	* @return {YArray<T>}
	*/
	_copy() {
		return new YArray();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YArray<T>}
	*/
	clone() {
		/**
		* @type {YArray<T>}
		*/
		const arr = new YArray();
		arr.insert(0, this.toArray().map((el) => el instanceof AbstractType ? el.clone() : el));
		return arr;
	}
	get length() {
		this.doc ?? warnPrematureAccess();
		return this._length;
	}
	/**
	* Creates YArrayEvent and calls observers.
	*
	* @param {Transaction} transaction
	* @param {Set<null|string>} parentSubs Keys changed on this type. `null` if list was modified.
	*/
	_callObserver(transaction, parentSubs) {
		super._callObserver(transaction, parentSubs);
		callTypeObservers(this, transaction, new YArrayEvent(this, transaction));
	}
	/**
	* Inserts new content at an index.
	*
	* Important: This function expects an array of content. Not just a content
	* object. The reason for this "weirdness" is that inserting several elements
	* is very efficient when it is done as a single operation.
	*
	* @example
	*  // Insert character 'a' at position 0
	*  yarray.insert(0, ['a'])
	*  // Insert numbers 1, 2 at position 1
	*  yarray.insert(1, [1, 2])
	*
	* @param {number} index The index to insert content at.
	* @param {Array<T>} content The array of content
	*/
	insert(index, content) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeListInsertGenerics(transaction, this, index, content);
		});
		else
 /** @type {Array<any>} */ this._prelimContent.splice(index, 0, ...content);
	}
	/**
	* Appends content to this YArray.
	*
	* @param {Array<T>} content Array of content to append.
	*
	* @todo Use the following implementation in all types.
	*/
	push(content) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeListPushGenerics(transaction, this, content);
		});
		else
 /** @type {Array<any>} */ this._prelimContent.push(...content);
	}
	/**
	* Prepends content to this YArray.
	*
	* @param {Array<T>} content Array of content to prepend.
	*/
	unshift(content) {
		this.insert(0, content);
	}
	/**
	* Deletes elements starting from an index.
	*
	* @param {number} index Index at which to start deleting elements
	* @param {number} length The number of elements to remove. Defaults to 1.
	*/
	delete(index, length = 1) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeListDelete(transaction, this, index, length);
		});
		else
 /** @type {Array<any>} */ this._prelimContent.splice(index, length);
	}
	/**
	* Returns the i-th element from a YArray.
	*
	* @param {number} index The index of the element to return from the YArray
	* @return {T}
	*/
	get(index) {
		return typeListGet(this, index);
	}
	/**
	* Transforms this YArray to a JavaScript Array.
	*
	* @return {Array<T>}
	*/
	toArray() {
		return typeListToArray(this);
	}
	/**
	* Returns a portion of this YArray into a JavaScript Array selected
	* from start to end (end not included).
	*
	* @param {number} [start]
	* @param {number} [end]
	* @return {Array<T>}
	*/
	slice(start = 0, end = this.length) {
		return typeListSlice(this, start, end);
	}
	/**
	* Transforms this Shared Type to a JSON object.
	*
	* @return {Array<any>}
	*/
	toJSON() {
		return this.map((c) => c instanceof AbstractType ? c.toJSON() : c);
	}
	/**
	* Returns an Array with the result of calling a provided function on every
	* element of this YArray.
	*
	* @template M
	* @param {function(T,number,YArray<T>):M} f Function that produces an element of the new Array
	* @return {Array<M>} A new array with each element being the result of the
	*                 callback function
	*/
	map(f) {
		return typeListMap(this, f);
	}
	/**
	* Executes a provided function once on every element of this YArray.
	*
	* @param {function(T,number,YArray<T>):void} f A function to execute on every element of this YArray.
	*/
	forEach(f) {
		typeListForEach(this, f);
	}
	/**
	* @return {IterableIterator<T>}
	*/
	[Symbol.iterator]() {
		return typeListCreateIterator(this);
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	*/
	_write(encoder) {
		encoder.writeTypeRef(YArrayRefID);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} _decoder
*
* @private
* @function
*/
var readYArray = (_decoder) => new YArray();
/**
* @module YMap
*/
/**
* @template T
* @extends YEvent<YMap<T>>
* Event that describes the changes on a YMap.
*/
var YMapEvent = class extends YEvent {
	/**
	* @param {YMap<T>} ymap The YArray that changed.
	* @param {Transaction} transaction
	* @param {Set<any>} subs The keys that changed.
	*/
	constructor(ymap, transaction, subs) {
		super(ymap, transaction);
		this.keysChanged = subs;
	}
};
/**
* @template MapType
* A shared Map implementation.
*
* @extends AbstractType<YMapEvent<MapType>>
* @implements {Iterable<[string, MapType]>}
*/
var YMap = class YMap extends AbstractType {
	/**
	*
	* @param {Iterable<readonly [string, any]>=} entries - an optional iterable to initialize the YMap
	*/
	constructor(entries) {
		super();
		/**
		* @type {Map<string,any>?}
		* @private
		*/
		this._prelimContent = null;
		if (entries === void 0) this._prelimContent = /* @__PURE__ */ new Map();
		else this._prelimContent = new Map(entries);
	}
	/**
	* Integrate this type into the Yjs instance.
	*
	* * Save this struct in the os
	* * This type is sent to other client
	* * Observer functions are fired
	*
	* @param {Doc} y The Yjs instance
	* @param {Item} item
	*/
	_integrate(y, item) {
		super._integrate(y, item);
		/** @type {Map<string, any>} */ this._prelimContent.forEach((value, key) => {
			this.set(key, value);
		});
		this._prelimContent = null;
	}
	/**
	* @return {YMap<MapType>}
	*/
	_copy() {
		return new YMap();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YMap<MapType>}
	*/
	clone() {
		/**
		* @type {YMap<MapType>}
		*/
		const map = new YMap();
		this.forEach((value, key) => {
			map.set(key, value instanceof AbstractType ? value.clone() : value);
		});
		return map;
	}
	/**
	* Creates YMapEvent and calls observers.
	*
	* @param {Transaction} transaction
	* @param {Set<null|string>} parentSubs Keys changed on this type. `null` if list was modified.
	*/
	_callObserver(transaction, parentSubs) {
		callTypeObservers(this, transaction, new YMapEvent(this, transaction, parentSubs));
	}
	/**
	* Transforms this Shared Type to a JSON object.
	*
	* @return {Object<string,any>}
	*/
	toJSON() {
		this.doc ?? warnPrematureAccess();
		/**
		* @type {Object<string,MapType>}
		*/
		const map = {};
		this._map.forEach((item, key) => {
			if (!item.deleted) {
				const v = item.content.getContent()[item.length - 1];
				map[key] = v instanceof AbstractType ? v.toJSON() : v;
			}
		});
		return map;
	}
	/**
	* Returns the size of the YMap (count of key/value pairs)
	*
	* @return {number}
	*/
	get size() {
		return [...createMapIterator(this)].length;
	}
	/**
	* Returns the keys for each element in the YMap Type.
	*
	* @return {IterableIterator<string>}
	*/
	keys() {
		return iteratorMap(
			createMapIterator(this),
			/** @param {any} v */
			(v) => v[0]
		);
	}
	/**
	* Returns the values for each element in the YMap Type.
	*
	* @return {IterableIterator<MapType>}
	*/
	values() {
		return iteratorMap(
			createMapIterator(this),
			/** @param {any} v */
			(v) => v[1].content.getContent()[v[1].length - 1]
		);
	}
	/**
	* Returns an Iterator of [key, value] pairs
	*
	* @return {IterableIterator<[string, MapType]>}
	*/
	entries() {
		return iteratorMap(
			createMapIterator(this),
			/** @param {any} v */
			(v) => [v[0], v[1].content.getContent()[v[1].length - 1]]
		);
	}
	/**
	* Executes a provided function on once on every key-value pair.
	*
	* @param {function(MapType,string,YMap<MapType>):void} f A function to execute on every element of this YArray.
	*/
	forEach(f) {
		this.doc ?? warnPrematureAccess();
		this._map.forEach((item, key) => {
			if (!item.deleted) f(item.content.getContent()[item.length - 1], key, this);
		});
	}
	/**
	* Returns an Iterator of [key, value] pairs
	*
	* @return {IterableIterator<[string, MapType]>}
	*/
	[Symbol.iterator]() {
		return this.entries();
	}
	/**
	* Remove a specified element from this YMap.
	*
	* @param {string} key The key of the element to remove.
	*/
	delete(key) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapDelete(transaction, this, key);
		});
		else
 /** @type {Map<string, any>} */ this._prelimContent.delete(key);
	}
	/**
	* Adds or updates an element with a specified key and value.
	* @template {MapType} VAL
	*
	* @param {string} key The key of the element to add to this YMap
	* @param {VAL} value The value of the element to add
	* @return {VAL}
	*/
	set(key, value) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapSet(transaction, this, key, value);
		});
		else
 /** @type {Map<string, any>} */ this._prelimContent.set(key, value);
		return value;
	}
	/**
	* Returns a specified element from this YMap.
	*
	* @param {string} key
	* @return {MapType|undefined}
	*/
	get(key) {
		return typeMapGet(this, key);
	}
	/**
	* Returns a boolean indicating whether the specified key exists or not.
	*
	* @param {string} key The key to test.
	* @return {boolean}
	*/
	has(key) {
		return typeMapHas(this, key);
	}
	/**
	* Removes all elements from this YMap.
	*/
	clear() {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			this.forEach(function(_value, key, map) {
				typeMapDelete(transaction, map, key);
			});
		});
		else
 /** @type {Map<string, any>} */ this._prelimContent.clear();
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	*/
	_write(encoder) {
		encoder.writeTypeRef(YMapRefID);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} _decoder
*
* @private
* @function
*/
var readYMap = (_decoder) => new YMap();
/**
* @module YText
*/
/**
* @param {any} a
* @param {any} b
* @return {boolean}
*/
var equalAttrs = (a, b) => a === b || typeof a === "object" && typeof b === "object" && a && b && equalFlat(a, b);
var ItemTextListPosition = class {
	/**
	* @param {Item|null} left
	* @param {Item|null} right
	* @param {number} index
	* @param {Map<string,any>} currentAttributes
	*/
	constructor(left, right, index, currentAttributes) {
		this.left = left;
		this.right = right;
		this.index = index;
		this.currentAttributes = currentAttributes;
	}
	/**
	* Only call this if you know that this.right is defined
	*/
	forward() {
		if (this.right === null) unexpectedCase();
		switch (this.right.content.constructor) {
			case ContentFormat:
				if (!this.right.deleted) updateCurrentAttributes(this.currentAttributes, this.right.content);
				break;
			default:
				if (!this.right.deleted) this.index += this.right.length;
				break;
		}
		this.left = this.right;
		this.right = this.right.right;
	}
};
/**
* @param {Transaction} transaction
* @param {ItemTextListPosition} pos
* @param {number} count steps to move forward
* @return {ItemTextListPosition}
*
* @private
* @function
*/
var findNextPosition = (transaction, pos, count) => {
	while (pos.right !== null && count > 0) {
		switch (pos.right.content.constructor) {
			case ContentFormat:
				if (!pos.right.deleted) updateCurrentAttributes(pos.currentAttributes, pos.right.content);
				break;
			default:
				if (!pos.right.deleted) {
					if (count < pos.right.length) getItemCleanStart(transaction, createID(pos.right.id.client, pos.right.id.clock + count));
					pos.index += pos.right.length;
					count -= pos.right.length;
				}
				break;
		}
		pos.left = pos.right;
		pos.right = pos.right.right;
	}
	return pos;
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {number} index
* @param {boolean} useSearchMarker
* @return {ItemTextListPosition}
*
* @private
* @function
*/
var findPosition = (transaction, parent, index, useSearchMarker) => {
	const currentAttributes = /* @__PURE__ */ new Map();
	const marker = useSearchMarker ? findMarker(parent, index) : null;
	if (marker) return findNextPosition(transaction, new ItemTextListPosition(marker.p.left, marker.p, marker.index, currentAttributes), index - marker.index);
	else return findNextPosition(transaction, new ItemTextListPosition(null, parent._start, 0, currentAttributes), index);
};
/**
* Negate applied formats
*
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {ItemTextListPosition} currPos
* @param {Map<string,any>} negatedAttributes
*
* @private
* @function
*/
var insertNegatedAttributes = (transaction, parent, currPos, negatedAttributes) => {
	while (currPos.right !== null && (currPos.right.deleted === true || currPos.right.content.constructor === ContentFormat && equalAttrs(
		negatedAttributes.get(
			/** @type {ContentFormat} */
			currPos.right.content.key
		),
		/** @type {ContentFormat} */
		currPos.right.content.value
	))) {
		if (!currPos.right.deleted) negatedAttributes.delete(
			/** @type {ContentFormat} */
			currPos.right.content.key
		);
		currPos.forward();
	}
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	negatedAttributes.forEach((val, key) => {
		const left = currPos.left;
		const right = currPos.right;
		const nextFormat = new Item(createID(ownClientId, getState(doc.store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentFormat(key, val));
		nextFormat.integrate(transaction, 0);
		currPos.right = nextFormat;
		currPos.forward();
	});
};
/**
* @param {Map<string,any>} currentAttributes
* @param {ContentFormat} format
*
* @private
* @function
*/
var updateCurrentAttributes = (currentAttributes, format) => {
	const { key, value } = format;
	if (value === null) currentAttributes.delete(key);
	else currentAttributes.set(key, value);
};
/**
* @param {ItemTextListPosition} currPos
* @param {Object<string,any>} attributes
*
* @private
* @function
*/
var minimizeAttributeChanges = (currPos, attributes) => {
	while (true) {
		if (currPos.right === null) break;
		else if (currPos.right.deleted || currPos.right.content.constructor === ContentFormat && equalAttrs(
			attributes[currPos.right.content.key] ?? null,
			/** @type {ContentFormat} */
			currPos.right.content.value
		));
		else break;
		currPos.forward();
	}
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {ItemTextListPosition} currPos
* @param {Object<string,any>} attributes
* @return {Map<string,any>}
*
* @private
* @function
**/
var insertAttributes = (transaction, parent, currPos, attributes) => {
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	const negatedAttributes = /* @__PURE__ */ new Map();
	for (const key in attributes) {
		const val = attributes[key];
		const currentVal = currPos.currentAttributes.get(key) ?? null;
		if (!equalAttrs(currentVal, val)) {
			negatedAttributes.set(key, currentVal);
			const { left, right } = currPos;
			currPos.right = new Item(createID(ownClientId, getState(doc.store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, new ContentFormat(key, val));
			currPos.right.integrate(transaction, 0);
			currPos.forward();
		}
	}
	return negatedAttributes;
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {ItemTextListPosition} currPos
* @param {string|object|AbstractType<any>} text
* @param {Object<string,any>} attributes
*
* @private
* @function
**/
var insertText = (transaction, parent, currPos, text, attributes) => {
	currPos.currentAttributes.forEach((_val, key) => {
		if (attributes[key] === void 0) attributes[key] = null;
	});
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	minimizeAttributeChanges(currPos, attributes);
	const negatedAttributes = insertAttributes(transaction, parent, currPos, attributes);
	const content = text.constructor === String ? new ContentString(text) : text instanceof AbstractType ? new ContentType(text) : new ContentEmbed(text);
	let { left, right, index } = currPos;
	if (parent._searchMarker) updateMarkerChanges(parent._searchMarker, currPos.index, content.getLength());
	right = new Item(createID(ownClientId, getState(doc.store, ownClientId)), left, left && left.lastId, right, right && right.id, parent, null, content);
	right.integrate(transaction, 0);
	currPos.right = right;
	currPos.index = index;
	currPos.forward();
	insertNegatedAttributes(transaction, parent, currPos, negatedAttributes);
};
/**
* @param {Transaction} transaction
* @param {AbstractType<any>} parent
* @param {ItemTextListPosition} currPos
* @param {number} length
* @param {Object<string,any>} attributes
*
* @private
* @function
*/
var formatText = (transaction, parent, currPos, length, attributes) => {
	const doc = transaction.doc;
	const ownClientId = doc.clientID;
	minimizeAttributeChanges(currPos, attributes);
	const negatedAttributes = insertAttributes(transaction, parent, currPos, attributes);
	iterationLoop: while (currPos.right !== null && (length > 0 || negatedAttributes.size > 0 && (currPos.right.deleted || currPos.right.content.constructor === ContentFormat))) {
		if (!currPos.right.deleted) switch (currPos.right.content.constructor) {
			case ContentFormat: {
				const { key, value } = currPos.right.content;
				const attr = attributes[key];
				if (attr !== void 0) {
					if (equalAttrs(attr, value)) negatedAttributes.delete(key);
					else {
						if (length === 0) break iterationLoop;
						negatedAttributes.set(key, value);
					}
					currPos.right.delete(transaction);
				} else currPos.currentAttributes.set(key, value);
				break;
			}
			default:
				if (length < currPos.right.length) getItemCleanStart(transaction, createID(currPos.right.id.client, currPos.right.id.clock + length));
				length -= currPos.right.length;
				break;
		}
		currPos.forward();
	}
	if (length > 0) {
		let newlines = "";
		for (; length > 0; length--) newlines += "\n";
		currPos.right = new Item(createID(ownClientId, getState(doc.store, ownClientId)), currPos.left, currPos.left && currPos.left.lastId, currPos.right, currPos.right && currPos.right.id, parent, null, new ContentString(newlines));
		currPos.right.integrate(transaction, 0);
		currPos.forward();
	}
	insertNegatedAttributes(transaction, parent, currPos, negatedAttributes);
};
/**
* Call this function after string content has been deleted in order to
* clean up formatting Items.
*
* @param {Transaction} transaction
* @param {Item} start
* @param {Item|null} curr exclusive end, automatically iterates to the next Content Item
* @param {Map<string,any>} startAttributes
* @param {Map<string,any>} currAttributes
* @return {number} The amount of formatting Items deleted.
*
* @function
*/
var cleanupFormattingGap = (transaction, start, curr, startAttributes, currAttributes) => {
	/**
	* @type {Item|null}
	*/
	let end = start;
	/**
	* @type {Map<string,ContentFormat>}
	*/
	const endFormats = create$5();
	while (end && (!end.countable || end.deleted)) {
		if (!end.deleted && end.content.constructor === ContentFormat) {
			const cf = end.content;
			endFormats.set(cf.key, cf);
		}
		end = end.right;
	}
	let cleanups = 0;
	let reachedCurr = false;
	while (start !== end) {
		if (curr === start) reachedCurr = true;
		if (!start.deleted) {
			const content = start.content;
			switch (content.constructor) {
				case ContentFormat: {
					const { key, value } = content;
					const startAttrValue = startAttributes.get(key) ?? null;
					if (endFormats.get(key) !== content || startAttrValue === value) {
						start.delete(transaction);
						cleanups++;
						if (!reachedCurr && (currAttributes.get(key) ?? null) === value && startAttrValue !== value) if (startAttrValue === null) currAttributes.delete(key);
						else currAttributes.set(key, startAttrValue);
					}
					if (!reachedCurr && !start.deleted) updateCurrentAttributes(currAttributes, content);
					break;
				}
			}
		}
		start = start.right;
	}
	return cleanups;
};
/**
* @param {Transaction} transaction
* @param {Item | null} item
*/
var cleanupContextlessFormattingGap = (transaction, item) => {
	while (item && item.right && (item.right.deleted || !item.right.countable)) item = item.right;
	const attrs = /* @__PURE__ */ new Set();
	while (item && (item.deleted || !item.countable)) {
		if (!item.deleted && item.content.constructor === ContentFormat) {
			const key = item.content.key;
			if (attrs.has(key)) item.delete(transaction);
			else attrs.add(key);
		}
		item = item.left;
	}
};
/**
* This function is experimental and subject to change / be removed.
*
* Ideally, we don't need this function at all. Formatting attributes should be cleaned up
* automatically after each change. This function iterates twice over the complete YText type
* and removes unnecessary formatting attributes. This is also helpful for testing.
*
* This function won't be exported anymore as soon as there is confidence that the YText type works as intended.
*
* @param {YText} type
* @return {number} How many formatting attributes have been cleaned up.
*/
var cleanupYTextFormatting = (type) => {
	let res = 0;
	transact(type.doc, (transaction) => {
		let start = type._start;
		let end = type._start;
		let startAttributes = create$5();
		const currentAttributes = copy(startAttributes);
		while (end) {
			if (end.deleted === false) switch (end.content.constructor) {
				case ContentFormat:
					updateCurrentAttributes(currentAttributes, end.content);
					break;
				default:
					res += cleanupFormattingGap(transaction, start, end, startAttributes, currentAttributes);
					startAttributes = copy(currentAttributes);
					start = end;
					break;
			}
			end = end.right;
		}
	});
	return res;
};
/**
* This will be called by the transaction once the event handlers are called to potentially cleanup
* formatting attributes.
*
* @param {Transaction} transaction
*/
var cleanupYTextAfterTransaction = (transaction) => {
	/**
	* @type {Set<YText>}
	*/
	const needFullCleanup = /* @__PURE__ */ new Set();
	const doc = transaction.doc;
	for (const [client, afterClock] of transaction.afterState.entries()) {
		const clock = transaction.beforeState.get(client) || 0;
		if (afterClock === clock) continue;
		iterateStructs(transaction, doc.store.clients.get(client), clock, afterClock, (item) => {
			if (!item.deleted && item.content.constructor === ContentFormat && item.constructor !== GC) needFullCleanup.add(
				/** @type {any} */
				item.parent
			);
		});
	}
	transact(doc, (t) => {
		iterateDeletedStructs(transaction, transaction.deleteSet, (item) => {
			if (item instanceof GC || !item.parent._hasFormatting || needFullCleanup.has(item.parent)) return;
			const parent = item.parent;
			if (item.content.constructor === ContentFormat) needFullCleanup.add(parent);
			else cleanupContextlessFormattingGap(t, item);
		});
		for (const yText of needFullCleanup) cleanupYTextFormatting(yText);
	});
};
/**
* @param {Transaction} transaction
* @param {ItemTextListPosition} currPos
* @param {number} length
* @return {ItemTextListPosition}
*
* @private
* @function
*/
var deleteText = (transaction, currPos, length) => {
	const startLength = length;
	const startAttrs = copy(currPos.currentAttributes);
	const start = currPos.right;
	while (length > 0 && currPos.right !== null) {
		if (currPos.right.deleted === false) switch (currPos.right.content.constructor) {
			case ContentType:
			case ContentEmbed:
			case ContentString:
				if (length < currPos.right.length) getItemCleanStart(transaction, createID(currPos.right.id.client, currPos.right.id.clock + length));
				length -= currPos.right.length;
				currPos.right.delete(transaction);
				break;
		}
		currPos.forward();
	}
	if (start) cleanupFormattingGap(transaction, start, currPos.right, startAttrs, currPos.currentAttributes);
	const parent = (currPos.left || currPos.right).parent;
	if (parent._searchMarker) updateMarkerChanges(parent._searchMarker, currPos.index, -startLength + length);
	return currPos;
};
/**
* The Quill Delta format represents changes on a text document with
* formatting information. For more information visit {@link https://quilljs.com/docs/delta/|Quill Delta}
*
* @example
*   {
*     ops: [
*       { insert: 'Gandalf', attributes: { bold: true } },
*       { insert: ' the ' },
*       { insert: 'Grey', attributes: { color: '#cccccc' } }
*     ]
*   }
*
*/
/**
* Attributes that can be assigned to a selection of text.
*
* @example
*   {
*     bold: true,
*     font-size: '40px'
*   }
*
* @typedef {Object} TextAttributes
*/
/**
* @extends YEvent<YText>
* Event that describes the changes on a YText type.
*/
var YTextEvent = class extends YEvent {
	/**
	* @param {YText} ytext
	* @param {Transaction} transaction
	* @param {Set<any>} subs The keys that changed
	*/
	constructor(ytext, transaction, subs) {
		super(ytext, transaction);
		/**
		* Whether the children changed.
		* @type {Boolean}
		* @private
		*/
		this.childListChanged = false;
		/**
		* Set of all changed attributes.
		* @type {Set<string>}
		*/
		this.keysChanged = /* @__PURE__ */ new Set();
		subs.forEach((sub) => {
			if (sub === null) this.childListChanged = true;
			else this.keysChanged.add(sub);
		});
	}
	/**
	* @type {{added:Set<Item>,deleted:Set<Item>,keys:Map<string,{action:'add'|'update'|'delete',oldValue:any}>,delta:Array<{insert?:Array<any>|string, delete?:number, retain?:number}>}}
	*/
	get changes() {
		if (this._changes === null) this._changes = {
			keys: this.keys,
			delta: this.delta,
			added: /* @__PURE__ */ new Set(),
			deleted: /* @__PURE__ */ new Set()
		};
		return this._changes;
	}
	/**
	* Compute the changes in the delta format.
	* A {@link https://quilljs.com/docs/delta/|Quill Delta}) that represents the changes on the document.
	*
	* @type {Array<{insert?:string|object|AbstractType<any>, delete?:number, retain?:number, attributes?: Object<string,any>}>}
	*
	* @public
	*/
	get delta() {
		if (this._delta === null) {
			const y = this.target.doc;
			/**
			* @type {Array<{insert?:string|object|AbstractType<any>, delete?:number, retain?:number, attributes?: Object<string,any>}>}
			*/
			const delta = [];
			transact(y, (transaction) => {
				const currentAttributes = /* @__PURE__ */ new Map();
				const oldAttributes = /* @__PURE__ */ new Map();
				let item = this.target._start;
				/**
				* @type {string?}
				*/
				let action = null;
				/**
				* @type {Object<string,any>}
				*/
				const attributes = {};
				/**
				* @type {string|object}
				*/
				let insert = "";
				let retain = 0;
				let deleteLen = 0;
				const addOp = () => {
					if (action !== null) {
						/**
						* @type {any}
						*/
						let op = null;
						switch (action) {
							case "delete":
								if (deleteLen > 0) op = { delete: deleteLen };
								deleteLen = 0;
								break;
							case "insert":
								if (typeof insert === "object" || insert.length > 0) {
									op = { insert };
									if (currentAttributes.size > 0) {
										op.attributes = {};
										currentAttributes.forEach((value, key) => {
											if (value !== null) op.attributes[key] = value;
										});
									}
								}
								insert = "";
								break;
							case "retain":
								if (retain > 0) {
									op = { retain };
									if (!isEmpty(attributes)) op.attributes = assign({}, attributes);
								}
								retain = 0;
								break;
						}
						if (op) delta.push(op);
						action = null;
					}
				};
				while (item !== null) {
					switch (item.content.constructor) {
						case ContentType:
						case ContentEmbed:
							if (this.adds(item)) {
								if (!this.deletes(item)) {
									addOp();
									action = "insert";
									insert = item.content.getContent()[0];
									addOp();
								}
							} else if (this.deletes(item)) {
								if (action !== "delete") {
									addOp();
									action = "delete";
								}
								deleteLen += 1;
							} else if (!item.deleted) {
								if (action !== "retain") {
									addOp();
									action = "retain";
								}
								retain += 1;
							}
							break;
						case ContentString:
							if (this.adds(item)) {
								if (!this.deletes(item)) {
									if (action !== "insert") {
										addOp();
										action = "insert";
									}
									insert += item.content.str;
								}
							} else if (this.deletes(item)) {
								if (action !== "delete") {
									addOp();
									action = "delete";
								}
								deleteLen += item.length;
							} else if (!item.deleted) {
								if (action !== "retain") {
									addOp();
									action = "retain";
								}
								retain += item.length;
							}
							break;
						case ContentFormat: {
							const { key, value } = item.content;
							if (this.adds(item)) {
								if (!this.deletes(item)) {
									if (!equalAttrs(currentAttributes.get(key) ?? null, value)) {
										if (action === "retain") addOp();
										if (equalAttrs(value, oldAttributes.get(key) ?? null)) delete attributes[key];
										else attributes[key] = value;
									} else if (value !== null) item.delete(transaction);
								}
							} else if (this.deletes(item)) {
								oldAttributes.set(key, value);
								const curVal = currentAttributes.get(key) ?? null;
								if (!equalAttrs(curVal, value)) {
									if (action === "retain") addOp();
									attributes[key] = curVal;
								}
							} else if (!item.deleted) {
								oldAttributes.set(key, value);
								const attr = attributes[key];
								if (attr !== void 0) {
									if (!equalAttrs(attr, value)) {
										if (action === "retain") addOp();
										if (value === null) delete attributes[key];
										else attributes[key] = value;
									} else if (attr !== null) item.delete(transaction);
								}
							}
							if (!item.deleted) {
								if (action === "insert") addOp();
								updateCurrentAttributes(currentAttributes, item.content);
							}
							break;
						}
					}
					item = item.right;
				}
				addOp();
				while (delta.length > 0) {
					const lastOp = delta[delta.length - 1];
					if (lastOp.retain !== void 0 && lastOp.attributes === void 0) delta.pop();
					else break;
				}
			});
			this._delta = delta;
		}
		return this._delta;
	}
};
/**
* Type that represents text with formatting information.
*
* This type replaces y-richtext as this implementation is able to handle
* block formats (format information on a paragraph), embeds (complex elements
* like pictures and videos), and text formats (**bold**, *italic*).
*
* @extends AbstractType<YTextEvent>
*/
var YText = class YText extends AbstractType {
	/**
	* @param {String} [string] The initial value of the YText.
	*/
	constructor(string) {
		super();
		/**
		* Array of pending operations on this type
		* @type {Array<function():void>?}
		*/
		this._pending = string !== void 0 ? [() => this.insert(0, string)] : [];
		/**
		* @type {Array<ArraySearchMarker>|null}
		*/
		this._searchMarker = [];
		/**
		* Whether this YText contains formatting attributes.
		* This flag is updated when a formatting item is integrated (see ContentFormat.integrate)
		*/
		this._hasFormatting = false;
	}
	/**
	* Number of characters of this text type.
	*
	* @type {number}
	*/
	get length() {
		this.doc ?? warnPrematureAccess();
		return this._length;
	}
	/**
	* @param {Doc} y
	* @param {Item} item
	*/
	_integrate(y, item) {
		super._integrate(y, item);
		try {
			/** @type {Array<function>} */ this._pending.forEach((f) => f());
		} catch (e) {
			console.error(e);
		}
		this._pending = null;
	}
	_copy() {
		return new YText();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YText}
	*/
	clone() {
		const text = new YText();
		text.applyDelta(this.toDelta());
		return text;
	}
	/**
	* Creates YTextEvent and calls observers.
	*
	* @param {Transaction} transaction
	* @param {Set<null|string>} parentSubs Keys changed on this type. `null` if list was modified.
	*/
	_callObserver(transaction, parentSubs) {
		super._callObserver(transaction, parentSubs);
		const event = new YTextEvent(this, transaction, parentSubs);
		callTypeObservers(this, transaction, event);
		if (!transaction.local && this._hasFormatting) transaction._needFormattingCleanup = true;
	}
	/**
	* Returns the unformatted string representation of this YText type.
	*
	* @public
	*/
	toString() {
		this.doc ?? warnPrematureAccess();
		let str = "";
		/**
		* @type {Item|null}
		*/
		let n = this._start;
		while (n !== null) {
			if (!n.deleted && n.countable && n.content.constructor === ContentString) str += n.content.str;
			n = n.right;
		}
		return str;
	}
	/**
	* Returns the unformatted string representation of this YText type.
	*
	* @return {string}
	* @public
	*/
	toJSON() {
		return this.toString();
	}
	/**
	* Apply a {@link Delta} on this shared YText type.
	*
	* @param {Array<any>} delta The changes to apply on this element.
	* @param {object}  opts
	* @param {boolean} [opts.sanitize] Sanitize input delta. Removes ending newlines if set to true.
	*
	*
	* @public
	*/
	applyDelta(delta, { sanitize = true } = {}) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			const currPos = new ItemTextListPosition(null, this._start, 0, /* @__PURE__ */ new Map());
			for (let i = 0; i < delta.length; i++) {
				const op = delta[i];
				if (op.insert !== void 0) {
					const ins = !sanitize && typeof op.insert === "string" && i === delta.length - 1 && currPos.right === null && op.insert.slice(-1) === "\n" ? op.insert.slice(0, -1) : op.insert;
					if (typeof ins !== "string" || ins.length > 0) insertText(transaction, this, currPos, ins, op.attributes || {});
				} else if (op.retain !== void 0) formatText(transaction, this, currPos, op.retain, op.attributes || {});
				else if (op.delete !== void 0) deleteText(transaction, currPos, op.delete);
			}
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.applyDelta(delta));
	}
	/**
	* Returns the Delta representation of this YText type.
	*
	* @param {Snapshot} [snapshot]
	* @param {Snapshot} [prevSnapshot]
	* @param {function('removed' | 'added', ID):any} [computeYChange]
	* @return {any} The Delta representation of this type.
	*
	* @public
	*/
	toDelta(snapshot, prevSnapshot, computeYChange) {
		this.doc ?? warnPrematureAccess();
		/**
		* @type{Array<any>}
		*/
		const ops = [];
		const currentAttributes = /* @__PURE__ */ new Map();
		const doc = this.doc;
		let str = "";
		let n = this._start;
		function packStr() {
			if (str.length > 0) {
				/**
				* @type {Object<string,any>}
				*/
				const attributes = {};
				let addAttributes = false;
				currentAttributes.forEach((value, key) => {
					addAttributes = true;
					attributes[key] = value;
				});
				/**
				* @type {Object<string,any>}
				*/
				const op = { insert: str };
				if (addAttributes) op.attributes = attributes;
				ops.push(op);
				str = "";
			}
		}
		const computeDelta = () => {
			while (n !== null) {
				if (isVisible(n, snapshot) || prevSnapshot !== void 0 && isVisible(n, prevSnapshot)) switch (n.content.constructor) {
					case ContentString: {
						const cur = currentAttributes.get("ychange");
						if (snapshot !== void 0 && !isVisible(n, snapshot)) {
							if (cur === void 0 || cur.user !== n.id.client || cur.type !== "removed") {
								packStr();
								currentAttributes.set("ychange", computeYChange ? computeYChange("removed", n.id) : { type: "removed" });
							}
						} else if (prevSnapshot !== void 0 && !isVisible(n, prevSnapshot)) {
							if (cur === void 0 || cur.user !== n.id.client || cur.type !== "added") {
								packStr();
								currentAttributes.set("ychange", computeYChange ? computeYChange("added", n.id) : { type: "added" });
							}
						} else if (cur !== void 0) {
							packStr();
							currentAttributes.delete("ychange");
						}
						str += n.content.str;
						break;
					}
					case ContentType:
					case ContentEmbed: {
						packStr();
						/**
						* @type {Object<string,any>}
						*/
						const op = { insert: n.content.getContent()[0] };
						if (currentAttributes.size > 0) {
							const attrs = {};
							op.attributes = attrs;
							currentAttributes.forEach((value, key) => {
								attrs[key] = value;
							});
						}
						ops.push(op);
						break;
					}
					case ContentFormat:
						if (isVisible(n, snapshot)) {
							packStr();
							updateCurrentAttributes(currentAttributes, n.content);
						}
						break;
				}
				n = n.right;
			}
			packStr();
		};
		if (snapshot || prevSnapshot) transact(doc, (transaction) => {
			if (snapshot) splitSnapshotAffectedStructs(transaction, snapshot);
			if (prevSnapshot) splitSnapshotAffectedStructs(transaction, prevSnapshot);
			computeDelta();
		}, "cleanup");
		else computeDelta();
		return ops;
	}
	/**
	* Insert text at a given index.
	*
	* @param {number} index The index at which to start inserting.
	* @param {String} text The text to insert at the specified position.
	* @param {TextAttributes} [attributes] Optionally define some formatting
	*                                    information to apply on the inserted
	*                                    Text.
	* @public
	*/
	insert(index, text, attributes) {
		if (text.length <= 0) return;
		const y = this.doc;
		if (y !== null) transact(y, (transaction) => {
			const pos = findPosition(transaction, this, index, !attributes);
			if (!attributes) {
				attributes = {};
				pos.currentAttributes.forEach((v, k) => {
					attributes[k] = v;
				});
			}
			insertText(transaction, this, pos, text, attributes);
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.insert(index, text, attributes));
	}
	/**
	* Inserts an embed at a index.
	*
	* @param {number} index The index to insert the embed at.
	* @param {Object | AbstractType<any>} embed The Object that represents the embed.
	* @param {TextAttributes} [attributes] Attribute information to apply on the
	*                                    embed
	*
	* @public
	*/
	insertEmbed(index, embed, attributes) {
		const y = this.doc;
		if (y !== null) transact(y, (transaction) => {
			const pos = findPosition(transaction, this, index, !attributes);
			insertText(transaction, this, pos, embed, attributes || {});
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.insertEmbed(index, embed, attributes || {}));
	}
	/**
	* Deletes text starting from an index.
	*
	* @param {number} index Index at which to start deleting.
	* @param {number} length The number of characters to remove. Defaults to 1.
	*
	* @public
	*/
	delete(index, length) {
		if (length === 0) return;
		const y = this.doc;
		if (y !== null) transact(y, (transaction) => {
			deleteText(transaction, findPosition(transaction, this, index, true), length);
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.delete(index, length));
	}
	/**
	* Assigns properties to a range of text.
	*
	* @param {number} index The position where to start formatting.
	* @param {number} length The amount of characters to assign properties to.
	* @param {TextAttributes} attributes Attribute information to apply on the
	*                                    text.
	*
	* @public
	*/
	format(index, length, attributes) {
		if (length === 0) return;
		const y = this.doc;
		if (y !== null) transact(y, (transaction) => {
			const pos = findPosition(transaction, this, index, false);
			if (pos.right === null) return;
			formatText(transaction, this, pos, length, attributes);
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.format(index, length, attributes));
	}
	/**
	* Removes an attribute.
	*
	* @note Xml-Text nodes don't have attributes. You can use this feature to assign properties to complete text-blocks.
	*
	* @param {String} attributeName The attribute name that is to be removed.
	*
	* @public
	*/
	removeAttribute(attributeName) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapDelete(transaction, this, attributeName);
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.removeAttribute(attributeName));
	}
	/**
	* Sets or updates an attribute.
	*
	* @note Xml-Text nodes don't have attributes. You can use this feature to assign properties to complete text-blocks.
	*
	* @param {String} attributeName The attribute name that is to be set.
	* @param {any} attributeValue The attribute value that is to be set.
	*
	* @public
	*/
	setAttribute(attributeName, attributeValue) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapSet(transaction, this, attributeName, attributeValue);
		});
		else
 /** @type {Array<function>} */ this._pending.push(() => this.setAttribute(attributeName, attributeValue));
	}
	/**
	* Returns an attribute value that belongs to the attribute name.
	*
	* @note Xml-Text nodes don't have attributes. You can use this feature to assign properties to complete text-blocks.
	*
	* @param {String} attributeName The attribute name that identifies the
	*                               queried value.
	* @return {any} The queried attribute value.
	*
	* @public
	*/
	getAttribute(attributeName) {
		return typeMapGet(this, attributeName);
	}
	/**
	* Returns all attribute name/value pairs in a JSON Object.
	*
	* @note Xml-Text nodes don't have attributes. You can use this feature to assign properties to complete text-blocks.
	*
	* @return {Object<string, any>} A JSON Object that describes the attributes.
	*
	* @public
	*/
	getAttributes() {
		return typeMapGetAll(this);
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	*/
	_write(encoder) {
		encoder.writeTypeRef(YTextRefID);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} _decoder
* @return {YText}
*
* @private
* @function
*/
var readYText = (_decoder) => new YText();
/**
* @module YXml
*/
/**
* Define the elements to which a set of CSS queries apply.
* {@link https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Selectors|CSS_Selectors}
*
* @example
*   query = '.classSelector'
*   query = 'nodeSelector'
*   query = '#idSelector'
*
* @typedef {string} CSS_Selector
*/
/**
* Dom filter function.
*
* @callback domFilter
* @param {string} nodeName The nodeName of the element
* @param {Map} attributes The map of attributes.
* @return {boolean} Whether to include the Dom node in the YXmlElement.
*/
/**
* Represents a subset of the nodes of a YXmlElement / YXmlFragment and a
* position within them.
*
* Can be created with {@link YXmlFragment#createTreeWalker}
*
* @public
* @implements {Iterable<YXmlElement|YXmlText|YXmlElement|YXmlHook>}
*/
var YXmlTreeWalker = class {
	/**
	* @param {YXmlFragment | YXmlElement} root
	* @param {function(AbstractType<any>):boolean} [f]
	*/
	constructor(root, f = () => true) {
		this._filter = f;
		this._root = root;
		/**
		* @type {Item}
		*/
		this._currentNode = root._start;
		this._firstCall = true;
		root.doc ?? warnPrematureAccess();
	}
	[Symbol.iterator]() {
		return this;
	}
	/**
	* Get the next node.
	*
	* @return {IteratorResult<YXmlElement|YXmlText|YXmlHook>} The next node.
	*
	* @public
	*/
	next() {
		/**
		* @type {Item|null}
		*/
		let n = this._currentNode;
		let type = n && n.content && n.content.type;
		if (n !== null && (!this._firstCall || n.deleted || !this._filter(type))) do {
			type = n.content.type;
			if (!n.deleted && (type.constructor === YXmlElement || type.constructor === YXmlFragment) && type._start !== null) n = type._start;
			else while (n !== null) {
				/**
				* @type {Item | null}
				*/
				const nxt = n.next;
				if (nxt !== null) {
					n = nxt;
					break;
				} else if (n.parent === this._root) n = null;
				else n = n.parent._item;
			}
		} while (n !== null && (n.deleted || !this._filter(
			/** @type {ContentType} */
			n.content.type
		)));
		this._firstCall = false;
		if (n === null) return {
			value: void 0,
			done: true
		};
		this._currentNode = n;
		return {
			value: n.content.type,
			done: false
		};
	}
};
/**
* Represents a list of {@link YXmlElement}.and {@link YXmlText} types.
* A YxmlFragment is similar to a {@link YXmlElement}, but it does not have a
* nodeName and it does not have attributes. Though it can be bound to a DOM
* element - in this case the attributes and the nodeName are not shared.
*
* @public
* @extends AbstractType<YXmlEvent>
*/
var YXmlFragment = class YXmlFragment extends AbstractType {
	constructor() {
		super();
		/**
		* @type {Array<any>|null}
		*/
		this._prelimContent = [];
	}
	/**
	* @type {YXmlElement|YXmlText|null}
	*/
	get firstChild() {
		const first = this._first;
		return first ? first.content.getContent()[0] : null;
	}
	/**
	* Integrate this type into the Yjs instance.
	*
	* * Save this struct in the os
	* * This type is sent to other client
	* * Observer functions are fired
	*
	* @param {Doc} y The Yjs instance
	* @param {Item} item
	*/
	_integrate(y, item) {
		super._integrate(y, item);
		this.insert(0, this._prelimContent);
		this._prelimContent = null;
	}
	_copy() {
		return new YXmlFragment();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YXmlFragment}
	*/
	clone() {
		const el = new YXmlFragment();
		el.insert(0, this.toArray().map((item) => item instanceof AbstractType ? item.clone() : item));
		return el;
	}
	get length() {
		this.doc ?? warnPrematureAccess();
		return this._prelimContent === null ? this._length : this._prelimContent.length;
	}
	/**
	* Create a subtree of childNodes.
	*
	* @example
	* const walker = elem.createTreeWalker(dom => dom.nodeName === 'div')
	* for (let node in walker) {
	*   // `node` is a div node
	*   nop(node)
	* }
	*
	* @param {function(AbstractType<any>):boolean} filter Function that is called on each child element and
	*                          returns a Boolean indicating whether the child
	*                          is to be included in the subtree.
	* @return {YXmlTreeWalker} A subtree and a position within it.
	*
	* @public
	*/
	createTreeWalker(filter) {
		return new YXmlTreeWalker(this, filter);
	}
	/**
	* Returns the first YXmlElement that matches the query.
	* Similar to DOM's {@link querySelector}.
	*
	* Query support:
	*   - tagname
	* TODO:
	*   - id
	*   - attribute
	*
	* @param {CSS_Selector} query The query on the children.
	* @return {YXmlElement|YXmlText|YXmlHook|null} The first element that matches the query or null.
	*
	* @public
	*/
	querySelector(query) {
		query = query.toUpperCase();
		const next = new YXmlTreeWalker(this, (element) => element.nodeName && element.nodeName.toUpperCase() === query).next();
		if (next.done) return null;
		else return next.value;
	}
	/**
	* Returns all YXmlElements that match the query.
	* Similar to Dom's {@link querySelectorAll}.
	*
	* @todo Does not yet support all queries. Currently only query by tagName.
	*
	* @param {CSS_Selector} query The query on the children
	* @return {Array<YXmlElement|YXmlText|YXmlHook|null>} The elements that match this query.
	*
	* @public
	*/
	querySelectorAll(query) {
		query = query.toUpperCase();
		return from(new YXmlTreeWalker(this, (element) => element.nodeName && element.nodeName.toUpperCase() === query));
	}
	/**
	* Creates YXmlEvent and calls observers.
	*
	* @param {Transaction} transaction
	* @param {Set<null|string>} parentSubs Keys changed on this type. `null` if list was modified.
	*/
	_callObserver(transaction, parentSubs) {
		callTypeObservers(this, transaction, new YXmlEvent(this, parentSubs, transaction));
	}
	/**
	* Get the string representation of all the children of this YXmlFragment.
	*
	* @return {string} The string representation of all children.
	*/
	toString() {
		return typeListMap(this, (xml) => xml.toString()).join("");
	}
	/**
	* @return {string}
	*/
	toJSON() {
		return this.toString();
	}
	/**
	* Creates a Dom Element that mirrors this YXmlElement.
	*
	* @param {Document} [_document=document] The document object (you must define
	*                                        this when calling this method in
	*                                        nodejs)
	* @param {Object<string, any>} [hooks={}] Optional property to customize how hooks
	*                                             are presented in the DOM
	* @param {any} [binding] You should not set this property. This is
	*                               used if DomBinding wants to create a
	*                               association to the created DOM type.
	* @return {Node} The {@link https://developer.mozilla.org/en-US/docs/Web/API/Element|Dom Element}
	*
	* @public
	*/
	toDOM(_document = document, hooks = {}, binding) {
		const fragment = _document.createDocumentFragment();
		if (binding !== void 0) binding._createAssociation(fragment, this);
		typeListForEach(this, (xmlType) => {
			fragment.insertBefore(xmlType.toDOM(_document, hooks, binding), null);
		});
		return fragment;
	}
	/**
	* Inserts new content at an index.
	*
	* @example
	*  // Insert character 'a' at position 0
	*  xml.insert(0, [new Y.XmlText('text')])
	*
	* @param {number} index The index to insert content at
	* @param {Array<YXmlElement|YXmlText>} content The array of content
	*/
	insert(index, content) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeListInsertGenerics(transaction, this, index, content);
		});
		else this._prelimContent.splice(index, 0, ...content);
	}
	/**
	* Inserts new content at an index.
	*
	* @example
	*  // Insert character 'a' at position 0
	*  xml.insert(0, [new Y.XmlText('text')])
	*
	* @param {null|Item|YXmlElement|YXmlText} ref The index to insert content at
	* @param {Array<YXmlElement|YXmlText>} content The array of content
	*/
	insertAfter(ref, content) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			const refItem = ref && ref instanceof AbstractType ? ref._item : ref;
			typeListInsertGenericsAfter(transaction, this, refItem, content);
		});
		else {
			const pc = this._prelimContent;
			const index = ref === null ? 0 : pc.findIndex((el) => el === ref) + 1;
			if (index === 0 && ref !== null) throw create$3("Reference item not found");
			pc.splice(index, 0, ...content);
		}
	}
	/**
	* Deletes elements starting from an index.
	*
	* @param {number} index Index at which to start deleting elements
	* @param {number} [length=1] The number of elements to remove. Defaults to 1.
	*/
	delete(index, length = 1) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeListDelete(transaction, this, index, length);
		});
		else this._prelimContent.splice(index, length);
	}
	/**
	* Transforms this YArray to a JavaScript Array.
	*
	* @return {Array<YXmlElement|YXmlText|YXmlHook>}
	*/
	toArray() {
		return typeListToArray(this);
	}
	/**
	* Appends content to this YArray.
	*
	* @param {Array<YXmlElement|YXmlText>} content Array of content to append.
	*/
	push(content) {
		this.insert(this.length, content);
	}
	/**
	* Prepends content to this YArray.
	*
	* @param {Array<YXmlElement|YXmlText>} content Array of content to prepend.
	*/
	unshift(content) {
		this.insert(0, content);
	}
	/**
	* Returns the i-th element from a YArray.
	*
	* @param {number} index The index of the element to return from the YArray
	* @return {YXmlElement|YXmlText}
	*/
	get(index) {
		return typeListGet(this, index);
	}
	/**
	* Returns a portion of this YXmlFragment into a JavaScript Array selected
	* from start to end (end not included).
	*
	* @param {number} [start]
	* @param {number} [end]
	* @return {Array<YXmlElement|YXmlText>}
	*/
	slice(start = 0, end = this.length) {
		return typeListSlice(this, start, end);
	}
	/**
	* Executes a provided function on once on every child element.
	*
	* @param {function(YXmlElement|YXmlText,number, typeof self):void} f A function to execute on every element of this YArray.
	*/
	forEach(f) {
		typeListForEach(this, f);
	}
	/**
	* Transform the properties of this type to binary and write it to an
	* BinaryEncoder.
	*
	* This is called when this Item is sent to a remote peer.
	*
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder The encoder to write data to.
	*/
	_write(encoder) {
		encoder.writeTypeRef(YXmlFragmentRefID);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} _decoder
* @return {YXmlFragment}
*
* @private
* @function
*/
var readYXmlFragment = (_decoder) => new YXmlFragment();
/**
* @typedef {Object|number|null|Array<any>|string|Uint8Array|AbstractType<any>} ValueTypes
*/
/**
* An YXmlElement imitates the behavior of a
* https://developer.mozilla.org/en-US/docs/Web/API/Element|Dom Element
*
* * An YXmlElement has attributes (key value pairs)
* * An YXmlElement has childElements that must inherit from YXmlElement
*
* @template {{ [key: string]: ValueTypes }} [KV={ [key: string]: string }]
*/
var YXmlElement = class YXmlElement extends YXmlFragment {
	constructor(nodeName = "UNDEFINED") {
		super();
		this.nodeName = nodeName;
		/**
		* @type {Map<string, any>|null}
		*/
		this._prelimAttrs = /* @__PURE__ */ new Map();
	}
	/**
	* @type {YXmlElement|YXmlText|null}
	*/
	get nextSibling() {
		const n = this._item ? this._item.next : null;
		return n ? n.content.type : null;
	}
	/**
	* @type {YXmlElement|YXmlText|null}
	*/
	get prevSibling() {
		const n = this._item ? this._item.prev : null;
		return n ? n.content.type : null;
	}
	/**
	* Integrate this type into the Yjs instance.
	*
	* * Save this struct in the os
	* * This type is sent to other client
	* * Observer functions are fired
	*
	* @param {Doc} y The Yjs instance
	* @param {Item} item
	*/
	_integrate(y, item) {
		super._integrate(y, item);
		this._prelimAttrs.forEach((value, key) => {
			this.setAttribute(key, value);
		});
		this._prelimAttrs = null;
	}
	/**
	* Creates an Item with the same effect as this Item (without position effect)
	*
	* @return {YXmlElement}
	*/
	_copy() {
		return new YXmlElement(this.nodeName);
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YXmlElement<KV>}
	*/
	clone() {
		/**
		* @type {YXmlElement<KV>}
		*/
		const el = new YXmlElement(this.nodeName);
		forEach(this.getAttributes(), (value, key) => {
			el.setAttribute(key, value);
		});
		el.insert(0, this.toArray().map((v) => v instanceof AbstractType ? v.clone() : v));
		return el;
	}
	/**
	* Returns the XML serialization of this YXmlElement.
	* The attributes are ordered by attribute-name, so you can easily use this
	* method to compare YXmlElements
	*
	* @return {string} The string representation of this type.
	*
	* @public
	*/
	toString() {
		const attrs = this.getAttributes();
		const stringBuilder = [];
		const keys = [];
		for (const key in attrs) keys.push(key);
		keys.sort();
		const keysLen = keys.length;
		for (let i = 0; i < keysLen; i++) {
			const key = keys[i];
			stringBuilder.push(key + "=\"" + attrs[key] + "\"");
		}
		const nodeName = this.nodeName.toLocaleLowerCase();
		return `<${nodeName}${stringBuilder.length > 0 ? " " + stringBuilder.join(" ") : ""}>${super.toString()}</${nodeName}>`;
	}
	/**
	* Removes an attribute from this YXmlElement.
	*
	* @param {string} attributeName The attribute name that is to be removed.
	*
	* @public
	*/
	removeAttribute(attributeName) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapDelete(transaction, this, attributeName);
		});
		else
 /** @type {Map<string,any>} */ this._prelimAttrs.delete(attributeName);
	}
	/**
	* Sets or updates an attribute.
	*
	* @template {keyof KV & string} KEY
	*
	* @param {KEY} attributeName The attribute name that is to be set.
	* @param {KV[KEY]} attributeValue The attribute value that is to be set.
	*
	* @public
	*/
	setAttribute(attributeName, attributeValue) {
		if (this.doc !== null) transact(this.doc, (transaction) => {
			typeMapSet(transaction, this, attributeName, attributeValue);
		});
		else
 /** @type {Map<string, any>} */ this._prelimAttrs.set(attributeName, attributeValue);
	}
	/**
	* Returns an attribute value that belongs to the attribute name.
	*
	* @template {keyof KV & string} KEY
	*
	* @param {KEY} attributeName The attribute name that identifies the
	*                               queried value.
	* @return {KV[KEY]|undefined} The queried attribute value.
	*
	* @public
	*/
	getAttribute(attributeName) {
		return typeMapGet(this, attributeName);
	}
	/**
	* Returns whether an attribute exists
	*
	* @param {string} attributeName The attribute name to check for existence.
	* @return {boolean} whether the attribute exists.
	*
	* @public
	*/
	hasAttribute(attributeName) {
		return typeMapHas(this, attributeName);
	}
	/**
	* Returns all attribute name/value pairs in a JSON Object.
	*
	* @param {Snapshot} [snapshot]
	* @return {{ [Key in Extract<keyof KV,string>]?: KV[Key]}} A JSON Object that describes the attributes.
	*
	* @public
	*/
	getAttributes(snapshot) {
		return snapshot ? typeMapGetAllSnapshot(this, snapshot) : typeMapGetAll(this);
	}
	/**
	* Creates a Dom Element that mirrors this YXmlElement.
	*
	* @param {Document} [_document=document] The document object (you must define
	*                                        this when calling this method in
	*                                        nodejs)
	* @param {Object<string, any>} [hooks={}] Optional property to customize how hooks
	*                                             are presented in the DOM
	* @param {any} [binding] You should not set this property. This is
	*                               used if DomBinding wants to create a
	*                               association to the created DOM type.
	* @return {Node} The {@link https://developer.mozilla.org/en-US/docs/Web/API/Element|Dom Element}
	*
	* @public
	*/
	toDOM(_document = document, hooks = {}, binding) {
		const dom = _document.createElement(this.nodeName);
		const attrs = this.getAttributes();
		for (const key in attrs) {
			const value = attrs[key];
			if (typeof value === "string") dom.setAttribute(key, value);
		}
		typeListForEach(this, (yxml) => {
			dom.appendChild(yxml.toDOM(_document, hooks, binding));
		});
		if (binding !== void 0) binding._createAssociation(dom, this);
		return dom;
	}
	/**
	* Transform the properties of this type to binary and write it to an
	* BinaryEncoder.
	*
	* This is called when this Item is sent to a remote peer.
	*
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder The encoder to write data to.
	*/
	_write(encoder) {
		encoder.writeTypeRef(YXmlElementRefID);
		encoder.writeKey(this.nodeName);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {YXmlElement}
*
* @function
*/
var readYXmlElement = (decoder) => new YXmlElement(decoder.readKey());
/**
* @extends YEvent<YXmlElement|YXmlText|YXmlFragment>
* An Event that describes changes on a YXml Element or Yxml Fragment
*/
var YXmlEvent = class extends YEvent {
	/**
	* @param {YXmlElement|YXmlText|YXmlFragment} target The target on which the event is created.
	* @param {Set<string|null>} subs The set of changed attributes. `null` is included if the
	*                   child list changed.
	* @param {Transaction} transaction The transaction instance with which the
	*                                  change was created.
	*/
	constructor(target, subs, transaction) {
		super(target, transaction);
		/**
		* Whether the children changed.
		* @type {Boolean}
		* @private
		*/
		this.childListChanged = false;
		/**
		* Set of all changed attributes.
		* @type {Set<string>}
		*/
		this.attributesChanged = /* @__PURE__ */ new Set();
		subs.forEach((sub) => {
			if (sub === null) this.childListChanged = true;
			else this.attributesChanged.add(sub);
		});
	}
};
/**
* You can manage binding to a custom type with YXmlHook.
*
* @extends {YMap<any>}
*/
var YXmlHook = class YXmlHook extends YMap {
	/**
	* @param {string} hookName nodeName of the Dom Node.
	*/
	constructor(hookName) {
		super();
		/**
		* @type {string}
		*/
		this.hookName = hookName;
	}
	/**
	* Creates an Item with the same effect as this Item (without position effect)
	*/
	_copy() {
		return new YXmlHook(this.hookName);
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YXmlHook}
	*/
	clone() {
		const el = new YXmlHook(this.hookName);
		this.forEach((value, key) => {
			el.set(key, value);
		});
		return el;
	}
	/**
	* Creates a Dom Element that mirrors this YXmlElement.
	*
	* @param {Document} [_document=document] The document object (you must define
	*                                        this when calling this method in
	*                                        nodejs)
	* @param {Object.<string, any>} [hooks] Optional property to customize how hooks
	*                                             are presented in the DOM
	* @param {any} [binding] You should not set this property. This is
	*                               used if DomBinding wants to create a
	*                               association to the created DOM type
	* @return {Element} The {@link https://developer.mozilla.org/en-US/docs/Web/API/Element|Dom Element}
	*
	* @public
	*/
	toDOM(_document = document, hooks = {}, binding) {
		const hook = hooks[this.hookName];
		let dom;
		if (hook !== void 0) dom = hook.createDom(this);
		else dom = document.createElement(this.hookName);
		dom.setAttribute("data-yjs-hook", this.hookName);
		if (binding !== void 0) binding._createAssociation(dom, this);
		return dom;
	}
	/**
	* Transform the properties of this type to binary and write it to an
	* BinaryEncoder.
	*
	* This is called when this Item is sent to a remote peer.
	*
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder The encoder to write data to.
	*/
	_write(encoder) {
		encoder.writeTypeRef(YXmlHookRefID);
		encoder.writeKey(this.hookName);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {YXmlHook}
*
* @private
* @function
*/
var readYXmlHook = (decoder) => new YXmlHook(decoder.readKey());
/**
* Represents text in a Dom Element. In the future this type will also handle
* simple formatting information like bold and italic.
*/
var YXmlText = class YXmlText extends YText {
	/**
	* @type {YXmlElement|YXmlText|null}
	*/
	get nextSibling() {
		const n = this._item ? this._item.next : null;
		return n ? n.content.type : null;
	}
	/**
	* @type {YXmlElement|YXmlText|null}
	*/
	get prevSibling() {
		const n = this._item ? this._item.prev : null;
		return n ? n.content.type : null;
	}
	_copy() {
		return new YXmlText();
	}
	/**
	* Makes a copy of this data type that can be included somewhere else.
	*
	* Note that the content is only readable _after_ it has been included somewhere in the Ydoc.
	*
	* @return {YXmlText}
	*/
	clone() {
		const text = new YXmlText();
		text.applyDelta(this.toDelta());
		return text;
	}
	/**
	* Creates a Dom Element that mirrors this YXmlText.
	*
	* @param {Document} [_document=document] The document object (you must define
	*                                        this when calling this method in
	*                                        nodejs)
	* @param {Object<string, any>} [hooks] Optional property to customize how hooks
	*                                             are presented in the DOM
	* @param {any} [binding] You should not set this property. This is
	*                               used if DomBinding wants to create a
	*                               association to the created DOM type.
	* @return {Text} The {@link https://developer.mozilla.org/en-US/docs/Web/API/Element|Dom Element}
	*
	* @public
	*/
	toDOM(_document = document, hooks, binding) {
		const dom = _document.createTextNode(this.toString());
		if (binding !== void 0) binding._createAssociation(dom, this);
		return dom;
	}
	toString() {
		return this.toDelta().map((delta) => {
			const nestedNodes = [];
			for (const nodeName in delta.attributes) {
				const attrs = [];
				for (const key in delta.attributes[nodeName]) attrs.push({
					key,
					value: delta.attributes[nodeName][key]
				});
				attrs.sort((a, b) => a.key < b.key ? -1 : 1);
				nestedNodes.push({
					nodeName,
					attrs
				});
			}
			nestedNodes.sort((a, b) => a.nodeName < b.nodeName ? -1 : 1);
			let str = "";
			for (let i = 0; i < nestedNodes.length; i++) {
				const node = nestedNodes[i];
				str += `<${node.nodeName}`;
				for (let j = 0; j < node.attrs.length; j++) {
					const attr = node.attrs[j];
					str += ` ${attr.key}="${attr.value}"`;
				}
				str += ">";
			}
			str += delta.insert;
			for (let i = nestedNodes.length - 1; i >= 0; i--) str += `</${nestedNodes[i].nodeName}>`;
			return str;
		}).join("");
	}
	/**
	* @return {string}
	*/
	toJSON() {
		return this.toString();
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	*/
	_write(encoder) {
		encoder.writeTypeRef(YXmlTextRefID);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {YXmlText}
*
* @private
* @function
*/
var readYXmlText = (decoder) => new YXmlText();
var AbstractStruct = class {
	/**
	* @param {ID} id
	* @param {number} length
	*/
	constructor(id, length) {
		this.id = id;
		this.length = length;
	}
	/**
	* @type {boolean}
	*/
	get deleted() {
		throw methodUnimplemented();
	}
	/**
	* Merge this struct with the item to the right.
	* This method is already assuming that `this.id.clock + this.length === this.id.clock`.
	* Also this method does *not* remove right from StructStore!
	* @param {AbstractStruct} right
	* @return {boolean} whether this merged with right
	*/
	mergeWith(right) {
		return false;
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder The encoder to write data to.
	* @param {number} offset
	* @param {number} encodingRef
	*/
	write(encoder, offset, encodingRef) {
		throw methodUnimplemented();
	}
	/**
	* @param {Transaction} transaction
	* @param {number} offset
	*/
	integrate(transaction, offset) {
		throw methodUnimplemented();
	}
};
var structGCRefNumber = 0;
/**
* @private
*/
var GC = class extends AbstractStruct {
	get deleted() {
		return true;
	}
	delete() {}
	/**
	* @param {GC} right
	* @return {boolean}
	*/
	mergeWith(right) {
		if (this.constructor !== right.constructor) return false;
		this.length += right.length;
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {number} offset
	*/
	integrate(transaction, offset) {
		if (offset > 0) {
			this.id.clock += offset;
			this.length -= offset;
		}
		addStruct(transaction.doc.store, this);
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeInfo(structGCRefNumber);
		encoder.writeLen(this.length - offset);
	}
	/**
	* @param {Transaction} transaction
	* @param {StructStore} store
	* @return {null | number}
	*/
	getMissing(transaction, store) {
		return null;
	}
};
var ContentBinary = class ContentBinary {
	/**
	* @param {Uint8Array} content
	*/
	constructor(content) {
		this.content = content;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return 1;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [this.content];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentBinary}
	*/
	copy() {
		return new ContentBinary(this.content);
	}
	/**
	* @param {number} offset
	* @return {ContentBinary}
	*/
	splice(offset) {
		throw methodUnimplemented();
	}
	/**
	* @param {ContentBinary} right
	* @return {boolean}
	*/
	mergeWith(right) {
		return false;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeBuf(this.content);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 3;
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2 } decoder
* @return {ContentBinary}
*/
var readContentBinary = (decoder) => new ContentBinary(decoder.readBuf());
var ContentDeleted = class ContentDeleted {
	/**
	* @param {number} len
	*/
	constructor(len) {
		this.len = len;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return this.len;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return false;
	}
	/**
	* @return {ContentDeleted}
	*/
	copy() {
		return new ContentDeleted(this.len);
	}
	/**
	* @param {number} offset
	* @return {ContentDeleted}
	*/
	splice(offset) {
		const right = new ContentDeleted(this.len - offset);
		this.len = offset;
		return right;
	}
	/**
	* @param {ContentDeleted} right
	* @return {boolean}
	*/
	mergeWith(right) {
		this.len += right.len;
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {
		addToDeleteSet(transaction.deleteSet, item.id.client, item.id.clock, this.len);
		item.markDeleted();
	}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeLen(this.len - offset);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 1;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2 } decoder
* @return {ContentDeleted}
*/
var readContentDeleted = (decoder) => new ContentDeleted(decoder.readLen());
/**
* @param {string} guid
* @param {Object<string, any>} opts
*/
var createDocFromOpts = (guid, opts) => new Doc({
	guid,
	...opts,
	shouldLoad: opts.shouldLoad || opts.autoLoad || false
});
/**
* @private
*/
var ContentDoc = class ContentDoc {
	/**
	* @param {Doc} doc
	*/
	constructor(doc) {
		if (doc._item) console.error("This document was already integrated as a sub-document. You should create a second instance instead with the same guid.");
		/**
		* @type {Doc}
		*/
		this.doc = doc;
		/**
		* @type {any}
		*/
		const opts = {};
		this.opts = opts;
		if (!doc.gc) opts.gc = false;
		if (doc.autoLoad) opts.autoLoad = true;
		if (doc.meta !== null) opts.meta = doc.meta;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return 1;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [this.doc];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentDoc}
	*/
	copy() {
		return new ContentDoc(createDocFromOpts(this.doc.guid, this.opts));
	}
	/**
	* @param {number} offset
	* @return {ContentDoc}
	*/
	splice(offset) {
		throw methodUnimplemented();
	}
	/**
	* @param {ContentDoc} right
	* @return {boolean}
	*/
	mergeWith(right) {
		return false;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {
		this.doc._item = item;
		transaction.subdocsAdded.add(this.doc);
		if (this.doc.shouldLoad) transaction.subdocsLoaded.add(this.doc);
	}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {
		if (transaction.subdocsAdded.has(this.doc)) transaction.subdocsAdded.delete(this.doc);
		else transaction.subdocsRemoved.add(this.doc);
	}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeString(this.doc.guid);
		encoder.writeAny(this.opts);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 9;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentDoc}
*/
var readContentDoc = (decoder) => new ContentDoc(createDocFromOpts(decoder.readString(), decoder.readAny()));
/**
* @private
*/
var ContentEmbed = class ContentEmbed {
	/**
	* @param {Object} embed
	*/
	constructor(embed) {
		this.embed = embed;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return 1;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [this.embed];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentEmbed}
	*/
	copy() {
		return new ContentEmbed(this.embed);
	}
	/**
	* @param {number} offset
	* @return {ContentEmbed}
	*/
	splice(offset) {
		throw methodUnimplemented();
	}
	/**
	* @param {ContentEmbed} right
	* @return {boolean}
	*/
	mergeWith(right) {
		return false;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeJSON(this.embed);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 5;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentEmbed}
*/
var readContentEmbed = (decoder) => new ContentEmbed(decoder.readJSON());
/**
* @private
*/
var ContentFormat = class ContentFormat {
	/**
	* @param {string} key
	* @param {Object} value
	*/
	constructor(key, value) {
		this.key = key;
		this.value = value;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return 1;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return false;
	}
	/**
	* @return {ContentFormat}
	*/
	copy() {
		return new ContentFormat(this.key, this.value);
	}
	/**
	* @param {number} _offset
	* @return {ContentFormat}
	*/
	splice(_offset) {
		throw methodUnimplemented();
	}
	/**
	* @param {ContentFormat} _right
	* @return {boolean}
	*/
	mergeWith(_right) {
		return false;
	}
	/**
	* @param {Transaction} _transaction
	* @param {Item} item
	*/
	integrate(_transaction, item) {
		const p = item.parent;
		p._searchMarker = null;
		p._hasFormatting = true;
	}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeKey(this.key);
		encoder.writeJSON(this.value);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 6;
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentFormat}
*/
var readContentFormat = (decoder) => new ContentFormat(decoder.readKey(), decoder.readJSON());
/**
* @private
*/
var ContentJSON = class ContentJSON {
	/**
	* @param {Array<any>} arr
	*/
	constructor(arr) {
		/**
		* @type {Array<any>}
		*/
		this.arr = arr;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return this.arr.length;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return this.arr;
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentJSON}
	*/
	copy() {
		return new ContentJSON(this.arr);
	}
	/**
	* @param {number} offset
	* @return {ContentJSON}
	*/
	splice(offset) {
		const right = new ContentJSON(this.arr.slice(offset));
		this.arr = this.arr.slice(0, offset);
		return right;
	}
	/**
	* @param {ContentJSON} right
	* @return {boolean}
	*/
	mergeWith(right) {
		this.arr = this.arr.concat(right.arr);
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		const len = this.arr.length;
		encoder.writeLen(len - offset);
		for (let i = offset; i < len; i++) {
			const c = this.arr[i];
			encoder.writeString(c === void 0 ? "undefined" : JSON.stringify(c));
		}
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 2;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentJSON}
*/
var readContentJSON = (decoder) => {
	const len = decoder.readLen();
	const cs = [];
	for (let i = 0; i < len; i++) {
		const c = decoder.readString();
		if (c === "undefined") cs.push(void 0);
		else cs.push(JSON.parse(c));
	}
	return new ContentJSON(cs);
};
var isDevMode = getVariable("node_env") === "development";
var ContentAny = class ContentAny {
	/**
	* @param {Array<any>} arr
	*/
	constructor(arr) {
		/**
		* @type {Array<any>}
		*/
		this.arr = arr;
		isDevMode && deepFreeze(arr);
	}
	/**
	* @return {number}
	*/
	getLength() {
		return this.arr.length;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return this.arr;
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentAny}
	*/
	copy() {
		return new ContentAny(this.arr);
	}
	/**
	* @param {number} offset
	* @return {ContentAny}
	*/
	splice(offset) {
		const right = new ContentAny(this.arr.slice(offset));
		this.arr = this.arr.slice(0, offset);
		return right;
	}
	/**
	* @param {ContentAny} right
	* @return {boolean}
	*/
	mergeWith(right) {
		this.arr = this.arr.concat(right.arr);
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		const len = this.arr.length;
		encoder.writeLen(len - offset);
		for (let i = offset; i < len; i++) {
			const c = this.arr[i];
			encoder.writeAny(c);
		}
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 8;
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentAny}
*/
var readContentAny = (decoder) => {
	const len = decoder.readLen();
	const cs = [];
	for (let i = 0; i < len; i++) cs.push(decoder.readAny());
	return new ContentAny(cs);
};
/**
* @private
*/
var ContentString = class ContentString {
	/**
	* @param {string} str
	*/
	constructor(str) {
		/**
		* @type {string}
		*/
		this.str = str;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return this.str.length;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return this.str.split("");
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentString}
	*/
	copy() {
		return new ContentString(this.str);
	}
	/**
	* @param {number} offset
	* @return {ContentString}
	*/
	splice(offset) {
		const right = new ContentString(this.str.slice(offset));
		this.str = this.str.slice(0, offset);
		const firstCharCode = this.str.charCodeAt(offset - 1);
		if (firstCharCode >= 55296 && firstCharCode <= 56319) {
			this.str = this.str.slice(0, offset - 1) + "�";
			right.str = "�" + right.str.slice(1);
		}
		return right;
	}
	/**
	* @param {ContentString} right
	* @return {boolean}
	*/
	mergeWith(right) {
		this.str += right.str;
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {}
	/**
	* @param {StructStore} store
	*/
	gc(store) {}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeString(offset === 0 ? this.str : this.str.slice(offset));
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 4;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentString}
*/
var readContentString = (decoder) => new ContentString(decoder.readString());
/**
* @type {Array<function(UpdateDecoderV1 | UpdateDecoderV2):AbstractType<any>>}
* @private
*/
var typeRefs = [
	readYArray,
	readYMap,
	readYText,
	readYXmlElement,
	readYXmlFragment,
	readYXmlHook,
	readYXmlText
];
var YArrayRefID = 0;
var YMapRefID = 1;
var YTextRefID = 2;
var YXmlElementRefID = 3;
var YXmlFragmentRefID = 4;
var YXmlHookRefID = 5;
var YXmlTextRefID = 6;
/**
* @private
*/
var ContentType = class ContentType {
	/**
	* @param {AbstractType<any>} type
	*/
	constructor(type) {
		/**
		* @type {AbstractType<any>}
		*/
		this.type = type;
	}
	/**
	* @return {number}
	*/
	getLength() {
		return 1;
	}
	/**
	* @return {Array<any>}
	*/
	getContent() {
		return [this.type];
	}
	/**
	* @return {boolean}
	*/
	isCountable() {
		return true;
	}
	/**
	* @return {ContentType}
	*/
	copy() {
		return new ContentType(this.type._copy());
	}
	/**
	* @param {number} offset
	* @return {ContentType}
	*/
	splice(offset) {
		throw methodUnimplemented();
	}
	/**
	* @param {ContentType} right
	* @return {boolean}
	*/
	mergeWith(right) {
		return false;
	}
	/**
	* @param {Transaction} transaction
	* @param {Item} item
	*/
	integrate(transaction, item) {
		this.type._integrate(transaction.doc, item);
	}
	/**
	* @param {Transaction} transaction
	*/
	delete(transaction) {
		let item = this.type._start;
		while (item !== null) {
			if (!item.deleted) item.delete(transaction);
			else if (item.id.clock < (transaction.beforeState.get(item.id.client) || 0)) transaction._mergeStructs.push(item);
			item = item.right;
		}
		this.type._map.forEach((item) => {
			if (!item.deleted) item.delete(transaction);
			else if (item.id.clock < (transaction.beforeState.get(item.id.client) || 0)) transaction._mergeStructs.push(item);
		});
		transaction.changed.delete(this.type);
	}
	/**
	* @param {StructStore} store
	*/
	gc(store) {
		let item = this.type._start;
		while (item !== null) {
			item.gc(store, true);
			item = item.right;
		}
		this.type._start = null;
		this.type._map.forEach(
			/** @param {Item | null} item */
			(item) => {
				while (item !== null) {
					item.gc(store, true);
					item = item.left;
				}
			}
		);
		this.type._map = /* @__PURE__ */ new Map();
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		this.type._write(encoder);
	}
	/**
	* @return {number}
	*/
	getRef() {
		return 7;
	}
};
/**
* @private
*
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @return {ContentType}
*/
var readContentType = (decoder) => new ContentType(typeRefs[decoder.readTypeRef()](decoder));
/**
* Split leftItem into two items
* @param {Transaction} transaction
* @param {Item} leftItem
* @param {number} diff
* @return {Item}
*
* @function
* @private
*/
var splitItem = (transaction, leftItem, diff) => {
	const { client, clock } = leftItem.id;
	const rightItem = new Item(createID(client, clock + diff), leftItem, createID(client, clock + diff - 1), leftItem.right, leftItem.rightOrigin, leftItem.parent, leftItem.parentSub, leftItem.content.splice(diff));
	if (leftItem.deleted) rightItem.markDeleted();
	if (leftItem.keep) rightItem.keep = true;
	if (leftItem.redone !== null) rightItem.redone = createID(leftItem.redone.client, leftItem.redone.clock + diff);
	leftItem.right = rightItem;
	if (rightItem.right !== null) rightItem.right.left = rightItem;
	transaction._mergeStructs.push(rightItem);
	if (rightItem.parentSub !== null && rightItem.right === null)
 /** @type {AbstractType<any>} */ rightItem.parent._map.set(rightItem.parentSub, rightItem);
	leftItem.length = diff;
	return rightItem;
};
/**
* Abstract class that represents any content.
*/
var Item = class Item extends AbstractStruct {
	/**
	* @param {ID} id
	* @param {Item | null} left
	* @param {ID | null} origin
	* @param {Item | null} right
	* @param {ID | null} rightOrigin
	* @param {AbstractType<any>|ID|null} parent Is a type if integrated, is null if it is possible to copy parent from left or right, is ID before integration to search for it.
	* @param {string | null} parentSub
	* @param {AbstractContent} content
	*/
	constructor(id, left, origin, right, rightOrigin, parent, parentSub, content) {
		super(id, content.getLength());
		/**
		* The item that was originally to the left of this item.
		* @type {ID | null}
		*/
		this.origin = origin;
		/**
		* The item that is currently to the left of this item.
		* @type {Item | null}
		*/
		this.left = left;
		/**
		* The item that is currently to the right of this item.
		* @type {Item | null}
		*/
		this.right = right;
		/**
		* The item that was originally to the right of this item.
		* @type {ID | null}
		*/
		this.rightOrigin = rightOrigin;
		/**
		* @type {AbstractType<any>|ID|null}
		*/
		this.parent = parent;
		/**
		* If the parent refers to this item with some kind of key (e.g. YMap, the
		* key is specified here. The key is then used to refer to the list in which
		* to insert this item. If `parentSub = null` type._start is the list in
		* which to insert to. Otherwise it is `parent._map`.
		* @type {String | null}
		*/
		this.parentSub = parentSub;
		/**
		* If this type's effect is redone this type refers to the type that undid
		* this operation.
		* @type {ID | null}
		*/
		this.redone = null;
		/**
		* @type {AbstractContent}
		*/
		this.content = content;
		/**
		* bit1: keep
		* bit2: countable
		* bit3: deleted
		* bit4: mark - mark node as fast-search-marker
		* @type {number} byte
		*/
		this.info = this.content.isCountable() ? 2 : 0;
	}
	/**
	* This is used to mark the item as an indexed fast-search marker
	*
	* @type {boolean}
	*/
	set marker(isMarked) {
		if ((this.info & 8) > 0 !== isMarked) this.info ^= 8;
	}
	get marker() {
		return (this.info & 8) > 0;
	}
	/**
	* If true, do not garbage collect this Item.
	*/
	get keep() {
		return (this.info & 1) > 0;
	}
	set keep(doKeep) {
		if (this.keep !== doKeep) this.info ^= 1;
	}
	get countable() {
		return (this.info & 2) > 0;
	}
	/**
	* Whether this item was deleted or not.
	* @type {Boolean}
	*/
	get deleted() {
		return (this.info & 4) > 0;
	}
	set deleted(doDelete) {
		if (this.deleted !== doDelete) this.info ^= 4;
	}
	markDeleted() {
		this.info |= 4;
	}
	/**
	* Return the creator clientID of the missing op or define missing items and return null.
	*
	* @param {Transaction} transaction
	* @param {StructStore} store
	* @return {null | number}
	*/
	getMissing(transaction, store) {
		if (this.origin && this.origin.client !== this.id.client && this.origin.clock >= getState(store, this.origin.client)) return this.origin.client;
		if (this.rightOrigin && this.rightOrigin.client !== this.id.client && this.rightOrigin.clock >= getState(store, this.rightOrigin.client)) return this.rightOrigin.client;
		if (this.parent && this.parent.constructor === ID && this.id.client !== this.parent.client && this.parent.clock >= getState(store, this.parent.client)) return this.parent.client;
		if (this.origin) {
			this.left = getItemCleanEnd(transaction, store, this.origin);
			this.origin = this.left.lastId;
		}
		if (this.rightOrigin) {
			this.right = getItemCleanStart(transaction, this.rightOrigin);
			this.rightOrigin = this.right.id;
		}
		if (this.left && this.left.constructor === GC || this.right && this.right.constructor === GC) this.parent = null;
		else if (!this.parent) {
			if (this.left && this.left.constructor === Item) {
				this.parent = this.left.parent;
				this.parentSub = this.left.parentSub;
			} else if (this.right && this.right.constructor === Item) {
				this.parent = this.right.parent;
				this.parentSub = this.right.parentSub;
			}
		} else if (this.parent.constructor === ID) {
			const parentItem = getItem(store, this.parent);
			if (parentItem.constructor === GC) this.parent = null;
			else this.parent = parentItem.content.type;
		}
		return null;
	}
	/**
	* @param {Transaction} transaction
	* @param {number} offset
	*/
	integrate(transaction, offset) {
		if (offset > 0) {
			this.id.clock += offset;
			this.left = getItemCleanEnd(transaction, transaction.doc.store, createID(this.id.client, this.id.clock - 1));
			this.origin = this.left.lastId;
			this.content = this.content.splice(offset);
			this.length -= offset;
		}
		if (this.parent) {
			if (!this.left && (!this.right || this.right.left !== null) || this.left && this.left.right !== this.right) {
				/**
				* @type {Item|null}
				*/
				let left = this.left;
				/**
				* @type {Item|null}
				*/
				let o;
				if (left !== null) o = left.right;
				else if (this.parentSub !== null) {
					o = this.parent._map.get(this.parentSub) || null;
					while (o !== null && o.left !== null) o = o.left;
				} else o = this.parent._start;
				/**
				* @type {Set<Item>}
				*/
				const conflictingItems = /* @__PURE__ */ new Set();
				/**
				* @type {Set<Item>}
				*/
				const itemsBeforeOrigin = /* @__PURE__ */ new Set();
				while (o !== null && o !== this.right) {
					itemsBeforeOrigin.add(o);
					conflictingItems.add(o);
					if (compareIDs(this.origin, o.origin)) {
						if (o.id.client < this.id.client) {
							left = o;
							conflictingItems.clear();
						} else if (compareIDs(this.rightOrigin, o.rightOrigin)) break;
					} else if (o.origin !== null && itemsBeforeOrigin.has(getItem(transaction.doc.store, o.origin))) {
						if (!conflictingItems.has(getItem(transaction.doc.store, o.origin))) {
							left = o;
							conflictingItems.clear();
						}
					} else break;
					o = o.right;
				}
				this.left = left;
			}
			if (this.left !== null) {
				this.right = this.left.right;
				this.left.right = this;
			} else {
				let r;
				if (this.parentSub !== null) {
					r = this.parent._map.get(this.parentSub) || null;
					while (r !== null && r.left !== null) r = r.left;
				} else {
					r = this.parent._start;
					/** @type {AbstractType<any>} */ this.parent._start = this;
				}
				this.right = r;
			}
			if (this.right !== null) this.right.left = this;
			else if (this.parentSub !== null) {
				/** @type {AbstractType<any>} */ this.parent._map.set(this.parentSub, this);
				if (this.left !== null) this.left.delete(transaction);
			}
			if (this.parentSub === null && this.countable && !this.deleted)
 /** @type {AbstractType<any>} */ this.parent._length += this.length;
			addStruct(transaction.doc.store, this);
			this.content.integrate(transaction, this);
			addChangedTypeToTransaction(transaction, this.parent, this.parentSub);
			if (this.parent._item !== null && this.parent._item.deleted || this.parentSub !== null && this.right !== null) this.delete(transaction);
		} else new GC(this.id, this.length).integrate(transaction, 0);
	}
	/**
	* Returns the next non-deleted item
	*/
	get next() {
		let n = this.right;
		while (n !== null && n.deleted) n = n.right;
		return n;
	}
	/**
	* Returns the previous non-deleted item
	*/
	get prev() {
		let n = this.left;
		while (n !== null && n.deleted) n = n.left;
		return n;
	}
	/**
	* Computes the last content address of this Item.
	*/
	get lastId() {
		return this.length === 1 ? this.id : createID(this.id.client, this.id.clock + this.length - 1);
	}
	/**
	* Try to merge two items
	*
	* @param {Item} right
	* @return {boolean}
	*/
	mergeWith(right) {
		if (this.constructor === right.constructor && compareIDs(right.origin, this.lastId) && this.right === right && compareIDs(this.rightOrigin, right.rightOrigin) && this.id.client === right.id.client && this.id.clock + this.length === right.id.clock && this.deleted === right.deleted && this.redone === null && right.redone === null && this.content.constructor === right.content.constructor && this.content.mergeWith(right.content)) {
			const searchMarker = this.parent._searchMarker;
			if (searchMarker) searchMarker.forEach((marker) => {
				if (marker.p === right) {
					marker.p = this;
					if (!this.deleted && this.countable) marker.index -= this.length;
				}
			});
			if (right.keep) this.keep = true;
			this.right = right.right;
			if (this.right !== null) this.right.left = this;
			this.length += right.length;
			return true;
		}
		return false;
	}
	/**
	* Mark this Item as deleted.
	*
	* @param {Transaction} transaction
	*/
	delete(transaction) {
		if (!this.deleted) {
			const parent = this.parent;
			if (this.countable && this.parentSub === null) parent._length -= this.length;
			this.markDeleted();
			addToDeleteSet(transaction.deleteSet, this.id.client, this.id.clock, this.length);
			addChangedTypeToTransaction(transaction, parent, this.parentSub);
			this.content.delete(transaction);
		}
	}
	/**
	* @param {StructStore} store
	* @param {boolean} parentGCd
	*/
	gc(store, parentGCd) {
		if (!this.deleted) throw unexpectedCase();
		this.content.gc(store);
		if (parentGCd) replaceStruct(store, this, new GC(this.id, this.length));
		else this.content = new ContentDeleted(this.length);
	}
	/**
	* Transform the properties of this type to binary and write it to an
	* BinaryEncoder.
	*
	* This is called when this Item is sent to a remote peer.
	*
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder The encoder to write data to.
	* @param {number} offset
	*/
	write(encoder, offset) {
		const origin = offset > 0 ? createID(this.id.client, this.id.clock + offset - 1) : this.origin;
		const rightOrigin = this.rightOrigin;
		const parentSub = this.parentSub;
		const info = this.content.getRef() & 31 | (origin === null ? 0 : 128) | (rightOrigin === null ? 0 : 64) | (parentSub === null ? 0 : 32);
		encoder.writeInfo(info);
		if (origin !== null) encoder.writeLeftID(origin);
		if (rightOrigin !== null) encoder.writeRightID(rightOrigin);
		if (origin === null && rightOrigin === null) {
			const parent = this.parent;
			if (parent._item !== void 0) {
				const parentItem = parent._item;
				if (parentItem === null) {
					const ykey = findRootTypeKey(parent);
					encoder.writeParentInfo(true);
					encoder.writeString(ykey);
				} else {
					encoder.writeParentInfo(false);
					encoder.writeLeftID(parentItem.id);
				}
			} else if (parent.constructor === String) {
				encoder.writeParentInfo(true);
				encoder.writeString(parent);
			} else if (parent.constructor === ID) {
				encoder.writeParentInfo(false);
				encoder.writeLeftID(parent);
			} else unexpectedCase();
			if (parentSub !== null) encoder.writeString(parentSub);
		}
		this.content.write(encoder, offset);
	}
};
/**
* @param {UpdateDecoderV1 | UpdateDecoderV2} decoder
* @param {number} info
*/
var readItemContent = (decoder, info) => contentRefs[info & 31](decoder);
/**
* A lookup map for reading Item content.
*
* @type {Array<function(UpdateDecoderV1 | UpdateDecoderV2):AbstractContent>}
*/
var contentRefs = [
	() => {
		unexpectedCase();
	},
	readContentDeleted,
	readContentJSON,
	readContentBinary,
	readContentString,
	readContentEmbed,
	readContentFormat,
	readContentType,
	readContentAny,
	readContentDoc,
	() => {
		unexpectedCase();
	}
];
var structSkipRefNumber = 10;
/**
* @private
*/
var Skip = class extends AbstractStruct {
	get deleted() {
		return true;
	}
	delete() {}
	/**
	* @param {Skip} right
	* @return {boolean}
	*/
	mergeWith(right) {
		if (this.constructor !== right.constructor) return false;
		this.length += right.length;
		return true;
	}
	/**
	* @param {Transaction} transaction
	* @param {number} offset
	*/
	integrate(transaction, offset) {
		unexpectedCase();
	}
	/**
	* @param {UpdateEncoderV1 | UpdateEncoderV2} encoder
	* @param {number} offset
	*/
	write(encoder, offset) {
		encoder.writeInfo(structSkipRefNumber);
		writeVarUint(encoder.restEncoder, this.length - offset);
	}
	/**
	* @param {Transaction} transaction
	* @param {StructStore} store
	* @return {null | number}
	*/
	getMissing(transaction, store) {
		return null;
	}
};
/** eslint-env browser */
var glo = typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : {};
var importIdentifier = "__ $YJS$ __";
if (glo[importIdentifier] === true)
 /**
* Dear reader of this message. Please take this seriously.
*
* If you see this message, make sure that you only import one version of Yjs. In many cases,
* your package manager installs two versions of Yjs that are used by different packages within your project.
* Another reason for this message is that some parts of your project use the commonjs version of Yjs
* and others use the EcmaScript version of Yjs.
*
* This often leads to issues that are hard to debug. We often need to perform constructor checks,
* e.g. `struct instanceof GC`. If you imported different versions of Yjs, it is impossible for us to
* do the constructor checks anymore - which might break the CRDT algorithm.
*
* https://github.com/yjs/yjs/issues/438
*/
console.error("Yjs was already imported. This breaks constructor checks and will lead to issues! - https://github.com/yjs/yjs/issues/438");
glo[importIdentifier] = true;
//#endregion
//#region \0vite/preload-helper.js
var scriptRel = "modulepreload";
var assetsURL = function(dep, importerUrl) {
	return new URL(dep, importerUrl).href;
};
var seen = {};
var __vitePreload = function preload(baseModule, deps, importerUrl) {
	let promise = Promise.resolve();
	if (deps && deps.length > 0) {
		const links = document.getElementsByTagName("link");
		const cspNonceMeta = document.querySelector("meta[property=csp-nonce]");
		const cspNonce = cspNonceMeta?.nonce || cspNonceMeta?.getAttribute("nonce");
		function allSettled(promises) {
			return Promise.all(promises.map((p) => Promise.resolve(p).then((value) => ({
				status: "fulfilled",
				value
			}), (reason) => ({
				status: "rejected",
				reason
			}))));
		}
		promise = allSettled(deps.map((dep) => {
			dep = assetsURL(dep, importerUrl);
			if (dep in seen) return;
			seen[dep] = true;
			const isCss = dep.endsWith(".css");
			const cssSelector = isCss ? "[rel=\"stylesheet\"]" : "";
			if (!!importerUrl) for (let i = links.length - 1; i >= 0; i--) {
				const link = links[i];
				if (link.href === dep && (!isCss || link.rel === "stylesheet")) return;
			}
			else if (document.querySelector(`link[href="${dep}"]${cssSelector}`)) return;
			const link = document.createElement("link");
			link.rel = isCss ? "stylesheet" : scriptRel;
			if (!isCss) link.as = "script";
			link.crossOrigin = "";
			link.href = dep;
			if (cspNonce) link.setAttribute("nonce", cspNonce);
			document.head.appendChild(link);
			if (isCss) return new Promise((res, rej) => {
				link.addEventListener("load", res);
				link.addEventListener("error", () => rej(/* @__PURE__ */ new Error(`Unable to preload CSS for ${dep}`)));
			});
		}));
	}
	function handlePreloadError(err) {
		const e = new Event("vite:preloadError", { cancelable: true });
		e.payload = err;
		window.dispatchEvent(e);
		if (!e.defaultPrevented) throw err;
	}
	return promise.then((res) => {
		for (const item of res || []) {
			if (item.status !== "rejected") continue;
			handlePreloadError(item.reason);
		}
		return baseModule().catch(handlePreloadError);
	});
};
//#endregion
//#region ../polyfills/graph-sync/dist/index.js
var GraphDiff = class {
	revision;
	additions;
	removals;
	dependencies;
	author;
	timestamp;
	constructor(opts) {
		this.revision = opts.revision;
		this.additions = Object.freeze([...opts.additions]);
		this.removals = Object.freeze([...opts.removals]);
		this.dependencies = Object.freeze([...opts.dependencies]);
		this.author = opts.author;
		this.timestamp = opts.timestamp;
		Object.freeze(this);
	}
};
var SignalEvent = class extends Event {
	senderDid;
	payload;
	constructor(senderDid, payload) {
		super("signal");
		this.senderDid = senderDid;
		this.payload = payload;
	}
};
var PeerEvent = class extends Event {
	did;
	constructor(type, did) {
		super(type);
		this.did = did;
	}
};
var SyncStateChangeEvent = class extends Event {
	state;
	constructor(state) {
		super("syncstatechange");
		this.state = state;
	}
};
var DiffEvent = class extends Event {
	diff;
	constructor(diff) {
		super("diff");
		this.diff = diff;
	}
};
function tripleKey(t) {
	return `${t.data.source}|${t.data.predicate ?? ""}|${t.data.target}`;
}
function serialiseTriple(t) {
	return {
		source: t.data.source,
		predicate: t.data.predicate,
		target: t.data.target,
		author: t.author,
		timestamp: t.timestamp,
		proofKey: t.proof.key,
		proofSignature: t.proof.signature
	};
}
function deserialiseTriple(record) {
	return {
		data: {
			source: record.source,
			target: record.target,
			predicate: record.predicate
		},
		author: record.author,
		timestamp: record.timestamp,
		proof: {
			key: record.proofKey,
			signature: record.proofSignature
		}
	};
}
var YjsBridge = class {
	doc;
	tripleMap;
	suppressEcho = false;
	onRemoteChange = null;
	constructor(doc) {
		this.doc = doc;
		this.tripleMap = doc.getMap("triples");
		this.tripleMap.observe((event) => {
			if (this.suppressEcho) return;
			if (!this.onRemoteChange) return;
			const additions = [];
			const removals = [];
			event.changes.keys.forEach((change, key) => {
				if (change.action === "add" || change.action === "update") {
					const val = this.tripleMap.get(key);
					if (val) additions.push(deserialiseTriple(val));
				} else if (change.action === "delete") {
					if (change.oldValue) removals.push(deserialiseTriple(change.oldValue));
				}
			});
			if (additions.length > 0 || removals.length > 0) this.onRemoteChange(additions, removals);
		});
	}
	setOnRemoteChange(cb) {
		this.onRemoteChange = cb;
	}
	/**
	* Push a locally-added triple into Y.js (will propagate to peers).
	*/
	localAdd(triple) {
		const key = tripleKey(triple);
		this.suppressEcho = true;
		try {
			this.tripleMap.set(key, serialiseTriple(triple));
		} finally {
			this.suppressEcho = false;
		}
	}
	/**
	* Push a local removal into Y.js.
	*/
	localRemove(triple) {
		const key = tripleKey(triple);
		this.suppressEcho = true;
		try {
			this.tripleMap.delete(key);
		} finally {
			this.suppressEcho = false;
		}
	}
	/**
	* Get all triples currently in the Y.Map.
	*/
	allTriples() {
		const result = [];
		this.tripleMap.forEach((val) => {
			result.push(deserialiseTriple(val));
		});
		return result;
	}
	/**
	* Check if a triple exists in the Y.Map.
	*/
	has(triple) {
		return this.tripleMap.has(tripleKey(triple));
	}
	destroy() {
		this.onRemoteChange = null;
	}
};
function computeRevision(additions, removals, dependencies) {
	const addCanon = (0, import_canonicalize.default)(additions.map((t) => (0, import_canonicalize.default)(tripleToCanonical(t))).sort()) ?? "";
	const remCanon = (0, import_canonicalize.default)(removals.map((t) => (0, import_canonicalize.default)(tripleToCanonical(t))).sort()) ?? "";
	const depsSorted = [...dependencies].sort().join(",");
	const input = addCanon + remCanon + depsSorted;
	return bytesToHex(sha256(new TextEncoder().encode(input)));
}
function tripleToCanonical(t) {
	return {
		s: t.data.source,
		p: t.data.predicate,
		t: t.data.target,
		a: t.author,
		ts: t.timestamp,
		sig: t.proof.signature
	};
}
function createGraphDiff(additions, removals, dependencies, author) {
	return new GraphDiff({
		revision: computeRevision(additions, removals, dependencies),
		additions,
		removals,
		dependencies,
		author,
		timestamp: Date.now()
	});
}
var GRAPH_URI_REGEX = /^graph:\/\/([^/]+)\/([^?]+)(?:\?(.+))?$/;
function parseGraphURI(uri) {
	const match = uri.match(GRAPH_URI_REGEX);
	if (!match) throw new DOMException(`Invalid Graph URI: ${uri}. Expected format: graph://<relay>/<id>?module=<hash>`, "SyntaxError");
	const [, relayStr, graphId, queryStr] = match;
	const relays = relayStr.split(",").map((r) => r.trim()).filter(Boolean);
	if (relays.length === 0) throw new DOMException(`Invalid Graph URI: no relay endpoints specified`, "SyntaxError");
	if (!graphId) throw new DOMException(`Invalid Graph URI: no graph ID specified`, "SyntaxError");
	let moduleHash = null;
	if (queryStr) moduleHash = new URLSearchParams(queryStr).get("module");
	return {
		relays,
		graphId,
		moduleHash,
		raw: uri
	};
}
function buildGraphURI(relays, graphId, moduleHash) {
	let uri = `graph://${relays.join(",")}/${graphId}`;
	if (moduleHash) uri += `?module=${moduleHash}`;
	return uri;
}
var SharedGraph = class _SharedGraph extends EventTarget {
	uri;
	moduleHash;
	_syncState = "idle";
	_peers = /* @__PURE__ */ new Map();
	_bridge;
	_identity;
	_triples = [];
	_revisionDAG = [];
	_currentRevision = null;
	_name;
	_description;
	_destroyed = false;
	_onpeerjoined = null;
	_onpeerleft = null;
	_onsyncstatechange = null;
	_onsignal = null;
	_ondiff = null;
	_connectedPeers = /* @__PURE__ */ new Map();
	_signalHandlers = /* @__PURE__ */ new Map();
	_channel = null;
	_instanceId;
	_applyingRemote = false;
	constructor(uri, doc, identity, opts) {
		super();
		this.uri = uri;
		this.moduleHash = opts?.moduleHash ?? "default";
		this._identity = identity;
		this._name = opts?.name;
		this._description = opts?.description;
		this._bridge = new YjsBridge(doc);
		this._instanceId = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : v4();
		if (typeof BroadcastChannel !== "undefined") {
			this._channel = new BroadcastChannel(`living-web-shared-graph-${this.uri}`);
			this._channel.onmessage = (event) => {
				if (event.data.origin === this._instanceId) return;
				const msg = event.data;
				if (msg.type === "DIFF") {
					this._applyingRemote = true;
					if (msg.update) applyUpdate(this._bridge.doc, new Uint8Array(msg.update));
					this._applyingRemote = false;
				}
			};
			this._bridge.doc.on("update", (update, origin) => {
				if (this._applyingRemote) return;
				this._channel?.postMessage({
					type: "DIFF",
					revision: this._currentRevision ?? "",
					additions: [],
					removals: [],
					dependencies: this._currentRevision ? [this._currentRevision] : [],
					update: Array.from(update),
					origin: this._instanceId
				});
			});
		}
		this._bridge.setOnRemoteChange((additions, removals) => {
			const verifiedAdditions = [];
			for (const triple of additions) if (triple.proof?.signature && triple.proof?.key) verifiedAdditions.push(triple);
			for (const triple of removals) {
				const idx = this._findTripleIndexByKey(triple);
				if (idx !== -1) this._triples.splice(idx, 1);
			}
			for (const t of verifiedAdditions) {
				const existingIdx = this._findTripleIndexByKey(t);
				if (existingIdx !== -1) this._triples[existingIdx] = t;
				else this._triples.push(t);
			}
			if (additions.length > 0 || removals.length > 0) {
				const diff = createGraphDiff(additions, removals, this._currentRevision ? [this._currentRevision] : [], additions[0]?.author ?? removals[0]?.author ?? "unknown");
				this._currentRevision = diff.revision;
				this._revisionDAG.push({
					revision: diff.revision,
					parents: diff.dependencies,
					timestamp: diff.timestamp
				});
				this.dispatchEvent(new DiffEvent(diff));
			}
		});
	}
	get doc() {
		return this._bridge.doc;
	}
	get syncState() {
		return this._syncState;
	}
	get name() {
		return this._name;
	}
	get onpeerjoined() {
		return this._onpeerjoined;
	}
	set onpeerjoined(h) {
		if (this._onpeerjoined) this.removeEventListener("peerjoined", this._onpeerjoined);
		this._onpeerjoined = h;
		if (h) this.addEventListener("peerjoined", h);
	}
	get onpeerleft() {
		return this._onpeerleft;
	}
	set onpeerleft(h) {
		if (this._onpeerleft) this.removeEventListener("peerleft", this._onpeerleft);
		this._onpeerleft = h;
		if (h) this.addEventListener("peerleft", h);
	}
	get onsyncstatechange() {
		return this._onsyncstatechange;
	}
	set onsyncstatechange(h) {
		if (this._onsyncstatechange) this.removeEventListener("syncstatechange", this._onsyncstatechange);
		this._onsyncstatechange = h;
		if (h) this.addEventListener("syncstatechange", h);
	}
	get onsignal() {
		return this._onsignal;
	}
	set onsignal(h) {
		if (this._onsignal) this.removeEventListener("signal", this._onsignal);
		this._onsignal = h;
		if (h) this.addEventListener("signal", h);
	}
	get ondiff() {
		return this._ondiff;
	}
	set ondiff(h) {
		if (this._ondiff) this.removeEventListener("diff", this._ondiff);
		this._ondiff = h;
		if (h) this.addEventListener("diff", h);
	}
	async addTriple(triple) {
		const { signTriple } = await __vitePreload(async () => {
			const { signTriple } = await Promise.resolve().then(() => dist_exports);
			return { signTriple };
		}, void 0, import.meta.url);
		const signed = await signTriple(triple, this._identity);
		this._triples.push(signed);
		this._bridge.localAdd(signed);
		const diff = createGraphDiff([signed], [], this._currentRevision ? [this._currentRevision] : [], signed.author);
		this._currentRevision = diff.revision;
		this._revisionDAG.push({
			revision: diff.revision,
			parents: diff.dependencies,
			timestamp: diff.timestamp
		});
		this._syncToPeers();
		this.dispatchEvent(new TripleEvent("tripleadded", signed));
		return signed;
	}
	async removeTriple(triple) {
		const idx = this._findTripleIndex(triple);
		if (idx === -1) return false;
		const removed = this._triples.splice(idx, 1)[0];
		this._bridge.localRemove(removed);
		const diff = createGraphDiff([], [removed], this._currentRevision ? [this._currentRevision] : [], removed.author);
		this._currentRevision = diff.revision;
		this._revisionDAG.push({
			revision: diff.revision,
			parents: diff.dependencies,
			timestamp: diff.timestamp
		});
		this._syncToPeers();
		this.dispatchEvent(new TripleEvent("tripleremoved", removed));
		return true;
	}
	async queryTriples(query) {
		return this._triples.filter((t) => {
			if (query.source != null && t.data.source !== query.source) return false;
			if (query.target != null && t.data.target !== query.target) return false;
			if (query.predicate != null && t.data.predicate !== query.predicate) return false;
			return true;
		});
	}
	async snapshot() {
		return [...this._triples].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
	}
	async peers() {
		return Array.from(this._peers.entries()).map(([did, info]) => ({
			did,
			lastSeen: info.lastSeen,
			online: true
		}));
	}
	async onlinePeers() {
		return Array.from(this._peers.entries()).map(([did, info]) => ({
			did,
			lastSeen: info.lastSeen,
			online: true
		}));
	}
	async sendSignal(remoteDid, payload) {
		const peer = this._connectedPeers.get(remoteDid);
		if (peer) peer.dispatchEvent(new SignalEvent(this._identity.getDID(), payload));
	}
	async broadcast(payload) {
		const myDid = this._identity.getDID();
		for (const [_did, peer] of this._connectedPeers) peer.dispatchEvent(new SignalEvent(myDid, payload));
	}
	revisionDAG() {
		return [...this._revisionDAG];
	}
	async currentRevision() {
		return this._currentRevision;
	}
	/**
	* Connect two SharedGraph instances for direct sync.
	* This simulates P2P — in a real browser, y-webrtc would handle this.
	*/
	connectPeer(peer) {
		const peerDid = peer._identity.getDID();
		const myDid = this._identity.getDID();
		if (this._connectedPeers.has(peerDid)) return;
		this._connectedPeers.set(peerDid, peer);
		this._peers.set(peerDid, { lastSeen: Date.now() });
		peer._connectedPeers.set(myDid, this);
		peer._peers.set(myDid, { lastSeen: Date.now() });
		const myState = encodeStateAsUpdate(this._bridge.doc);
		const peerState = encodeStateAsUpdate(peer._bridge.doc);
		applyUpdate(peer._bridge.doc, myState);
		applyUpdate(this._bridge.doc, peerState);
		const myHandler = (update, origin) => {
			if (origin === peer._bridge.doc) return;
			applyUpdate(peer._bridge.doc, update, this._bridge.doc);
		};
		const peerHandler = (update, origin) => {
			if (origin === this._bridge.doc) return;
			applyUpdate(this._bridge.doc, update, peer._bridge.doc);
		};
		this._bridge.doc.on("update", myHandler);
		peer._bridge.doc.on("update", peerHandler);
		this._setSyncState("synced");
		peer._setSyncState("synced");
		this.dispatchEvent(new PeerEvent("peerjoined", peerDid));
		peer.dispatchEvent(new PeerEvent("peerjoined", myDid));
	}
	disconnectPeer(peerDid) {
		const peer = this._connectedPeers.get(peerDid);
		if (!peer) return;
		const myDid = this._identity.getDID();
		this._connectedPeers.delete(peerDid);
		this._peers.delete(peerDid);
		peer._connectedPeers.delete(myDid);
		peer._peers.delete(myDid);
		this.dispatchEvent(new PeerEvent("peerleft", peerDid));
		peer.dispatchEvent(new PeerEvent("peerleft", myDid));
		if (this._connectedPeers.size === 0) this._setSyncState("idle");
		if (peer._connectedPeers.size === 0) peer._setSyncState("idle");
	}
	async leave(opts) {
		const retain = opts?.retainLocalCopy ?? true;
		for (const [did] of this._connectedPeers) this.disconnectPeer(did);
		this._setSyncState("idle");
		this._destroyed = true;
		if (!retain) {
			this._triples = [];
			this._revisionDAG = [];
			this._currentRevision = null;
		}
		this._bridge.destroy();
	}
	_setSyncState(state) {
		if (this._syncState === state) return;
		this._syncState = state;
		this.dispatchEvent(new SyncStateChangeEvent(state));
	}
	_syncToPeers() {}
	_findTripleIndex(triple) {
		return this._triples.findIndex((t) => t.data.source === triple.data.source && t.data.target === triple.data.target && t.data.predicate === triple.data.predicate && t.author === triple.author && t.timestamp === triple.timestamp);
	}
	_findTripleIndexByKey(triple) {
		const key = tripleKey(triple);
		return this._triples.findIndex((t) => tripleKey(t) === key);
	}
	_hasTriple(triple) {
		return this._findTripleIndexByKey(triple) !== -1;
	}
	/** §10.3 Resolve a peer DID to their public key */
	_resolvePeerPublicKey(did) {
		for (const [peerDid, peer] of this._connectedPeers) if (peerDid === did) return peer._identity.getPublicKey();
		if (did === this._identity.getDID()) return this._identity.getPublicKey();
		return null;
	}
	static create(identity, name, opts) {
		const graphId = v4();
		const relays = opts?.relays ?? ["localhost"];
		const moduleHash = opts?.module ?? "default";
		return new _SharedGraph(buildGraphURI(relays, graphId, moduleHash), new Doc(), identity, {
			name: opts?.meta?.name ?? name,
			description: opts?.meta?.description,
			moduleHash
		});
	}
	static join(uri, identity) {
		const doc = new Doc();
		let moduleHash = "default";
		try {
			moduleHash = parseGraphURI(uri).moduleHash ?? "default";
		} catch {}
		return new _SharedGraph(uri, doc, identity, { moduleHash });
	}
};
var SharedGraphManager = class {
	sharedGraphs = /* @__PURE__ */ new Map();
	identity;
	constructor(identity) {
		this.identity = identity;
	}
	/**
	* Share a new graph — creates a SharedGraph with a unique URI.
	*/
	async share(name, opts) {
		const graph = SharedGraph.create(this.identity, name, opts);
		this.sharedGraphs.set(graph.uri, graph);
		return graph;
	}
	/**
	* Join an existing shared graph by URI.
	* MUST reject with NotSupportedError if protocol is unavailable.
	*/
	async join(uri) {
		if (this.sharedGraphs.has(uri)) return this.sharedGraphs.get(uri);
		if (!uri.startsWith("graph://") && !uri.startsWith("shared-graph://")) throw new DOMException(`Unsupported protocol in URI: ${uri}`, "NotSupportedError");
		const graph = SharedGraph.join(uri, this.identity);
		this.sharedGraphs.set(uri, graph);
		return graph;
	}
	/**
	* List all shared graphs.
	*/
	async listShared() {
		return Array.from(this.sharedGraphs.values()).map((g) => ({
			uri: g.uri,
			name: g.name,
			moduleHash: g.moduleHash,
			syncState: g.syncState,
			peerCount: 0
		}));
	}
	/**
	* Get a shared graph by URI.
	*/
	async get(uri) {
		return this.sharedGraphs.get(uri) ?? null;
	}
	/**
	* Leave a shared graph.
	*/
	async leave(uri, opts) {
		const graph = this.sharedGraphs.get(uri);
		if (!graph) return false;
		await graph.leave(opts);
		if (!opts?.retainLocalCopy) this.sharedGraphs.delete(uri);
		return true;
	}
};
//#endregion
//#region ../polyfills/graph-sync/dist/polyfill.js
function install(manager) {
	if (typeof globalThis.navigator === "undefined") return;
	const nav = globalThis.navigator;
	if (!nav.graph) nav.graph = {};
	if (typeof nav.graph.join === "function" && typeof nav.graph.share === "function") {
		console.info("[living-web] Native graph sync detected — polyfill skipped");
		return;
	}
	console.info("[living-web] Graph sync polyfill installed (no native support detected)");
	nav.graph.join = (uri) => manager.join(uri);
	nav.graph.share = (name, opts) => manager.share(name, opts);
	nav.graph.listShared = () => manager.listShared();
}
//#endregion
//#region ../polyfills/shape-validation/dist/chunk-TLWMFQHH.js
var SHAPE_PREDICATE = "shacl://has_shape";
var SHAPE_NAME_PREDICATE = "shacl://shape_name";
function validateShapeDefinition(json) {
	let parsed;
	try {
		parsed = JSON.parse(json);
	} catch {
		throw new DOMException("Invalid JSON in shape definition", "SyntaxError");
	}
	if (!parsed.targetClass || typeof parsed.targetClass !== "string") throw new DOMException("Shape MUST have a targetClass string", "ConstraintError");
	if (!Array.isArray(parsed.properties)) throw new DOMException("Shape MUST have a properties array", "ConstraintError");
	if (!Array.isArray(parsed.constructor)) throw new DOMException("Shape MUST have a constructor array", "ConstraintError");
	const namesSeen = /* @__PURE__ */ new Set();
	for (const prop of parsed.properties) validatePropertyDef(prop, namesSeen);
	for (const action of parsed.constructor) validateConstructorAction(action);
	return parsed;
}
function validatePropertyDef(prop, namesSeen) {
	if (!prop.path || typeof prop.path !== "string") throw new DOMException("Property MUST have a path string", "ConstraintError");
	if (!prop.name || typeof prop.name !== "string") throw new DOMException("Property MUST have a name string", "ConstraintError");
	if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(prop.name)) throw new DOMException(`Property name "${prop.name}" MUST match [a-zA-Z_][a-zA-Z0-9_]*`, "ConstraintError");
	if (namesSeen.has(prop.name)) throw new DOMException(`Duplicate property name "${prop.name}"`, "ConstraintError");
	namesSeen.add(prop.name);
}
function validateConstructorAction(action) {
	if (!action.action || ![
		"addLink",
		"setSingleTarget",
		"addCollectionTarget"
	].includes(action.action)) throw new DOMException("Constructor action MUST be addLink, setSingleTarget, or addCollectionTarget", "ConstraintError");
	if (action.source !== "this") throw new DOMException("Constructor action source MUST be \"this\"", "ConstraintError");
	if (!action.predicate || typeof action.predicate !== "string") throw new DOMException("Constructor action MUST have a predicate string", "ConstraintError");
	if (action.target === void 0 || action.target === null) throw new DOMException("Constructor action MUST have a target", "ConstraintError");
}
var XSD_VALIDATORS = {
	"xsd:string": () => true,
	"xsd:integer": (v) => /^-?\d+$/.test(v),
	"xsd:float": (v) => !isNaN(parseFloat(v)) && isFinite(Number(v)),
	"xsd:double": (v) => !isNaN(parseFloat(v)) && isFinite(Number(v)),
	"xsd:boolean": (v) => v === "true" || v === "false",
	"xsd:dateTime": (v) => !isNaN(Date.parse(v)) && /T/.test(v),
	"xsd:date": (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v)),
	"URI": (v) => /^[a-zA-Z][a-zA-Z0-9+\-.]*:.+$/.test(v)
};
function validateDatatype(value, datatype) {
	const validator = XSD_VALIDATORS[datatype];
	if (!validator) return true;
	return validator(value);
}
function contentAddress(shapeJson) {
	const canonical = (0, import_canonicalize.default)(JSON.parse(shapeJson));
	return `shacl://shape/${bytesToHex(sha256(new TextEncoder().encode(canonical)))}`;
}
var shapeRegistries = /* @__PURE__ */ new WeakMap();
function getRegistry(graph) {
	let reg = shapeRegistries.get(graph);
	if (!reg) {
		reg = /* @__PURE__ */ new Map();
		shapeRegistries.set(graph, reg);
	}
	return reg;
}
function getPropertyDef(shape, propName) {
	const prop = shape.properties.find((p) => p.name === propName);
	if (!prop) throw new TypeError(`Property "${propName}" not found in shape`);
	return prop;
}
function isScalar(prop) {
	return prop.maxCount === 1;
}
function isWritable(prop) {
	if (prop.readOnly) return false;
	return prop.writable !== false;
}
function resolveTarget(target, propertyNames, initialValues) {
	if (propertyNames.has(target)) {
		const val = initialValues[target];
		return val !== void 0 ? String(val) : target;
	}
	return target;
}
function getDiscriminator(shape) {
	for (const action of shape.constructor) if (action.predicate === "rdf:type" && action.target === shape.targetClass) return {
		predicate: "rdf:type",
		value: shape.targetClass
	};
	for (const action of shape.constructor) {
		const prop = shape.properties.find((p) => p.path === action.predicate);
		if (prop && !isWritable(prop) && !shape.properties.some((p) => p.name === action.target)) return {
			predicate: action.predicate,
			value: action.target
		};
	}
	return null;
}
async function addShape(name, shapeJson) {
	const registry = getRegistry(this);
	if (registry.has(name)) throw new DOMException(`Shape "${name}" already exists`, "ConstraintError");
	const definition = validateShapeDefinition(shapeJson);
	const address = contentAddress(shapeJson);
	const graphUri = this.uuid.includes(":") ? this.uuid : `urn:uuid:${this.uuid}`;
	await this.addTriple(new SemanticTriple(graphUri, address, SHAPE_PREDICATE));
	await this.addTriple(new SemanticTriple(address, name, SHAPE_NAME_PREDICATE));
	await this.addTriple(new SemanticTriple(address, shapeJson, "shacl://shape_content"));
	registry.set(name, {
		name,
		definition,
		address
	});
}
async function getShapes() {
	const registry = getRegistry(this);
	const result = [];
	for (const [, shape] of registry) result.push({
		name: shape.name,
		targetClass: shape.definition.targetClass,
		definitionAddress: shape.address,
		properties: shape.definition.properties.map(propToPublic)
	});
	return result;
}
function propToPublic(prop) {
	return {
		name: prop.name,
		path: prop.path,
		datatype: prop.datatype,
		minCount: prop.minCount ?? 0,
		maxCount: prop.maxCount,
		writable: isWritable(prop),
		readOnly: prop.readOnly ?? false
	};
}
async function createShapeInstance(shapeName, address, initialValues = {}) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const def = shape.definition;
	const propertyNames = new Set(def.properties.map((p) => p.name));
	for (const prop of def.properties) if ((prop.minCount ?? 0) > 0 && isWritable(prop) && initialValues[prop.name] === void 0) {
		if (!def.constructor.some((a) => a.predicate === prop.path && !propertyNames.has(a.target))) throw new TypeError(`Required property "${prop.name}" missing from initialValues`);
	}
	for (const action of def.constructor) {
		const source = address;
		const target = resolveTarget(action.target, propertyNames, initialValues);
		const prop = def.properties.find((p) => p.path === action.predicate);
		if (prop && prop.datatype && propertyNames.has(action.target)) {
			const val = initialValues[action.target];
			if (val !== void 0 && !validateDatatype(String(val), prop.datatype)) throw new TypeError(`Value "${val}" does not match datatype ${prop.datatype} for property "${prop.name}"`);
		}
		switch (action.action) {
			case "setSingleTarget": {
				const existing = await this.queryTriples({
					source,
					predicate: action.predicate
				});
				for (const t of existing) await this.removeTriple(t);
				await this.addTriple(new SemanticTriple(source, target, action.predicate));
				break;
			}
			case "addLink":
			case "addCollectionTarget":
				await this.addTriple(new SemanticTriple(source, target, action.predicate));
				break;
		}
	}
	return address;
}
async function getShapeInstances(shapeName) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const disc = getDiscriminator(shape.definition);
	if (!disc) return [];
	const triples = await this.queryTriples({
		predicate: disc.predicate,
		target: disc.value
	});
	return [...new Set(triples.map((t) => t.data.source))];
}
async function getShapeInstanceData(shapeName, address) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const def = shape.definition;
	const result = {};
	for (const prop of def.properties) {
		if (prop.getter) {
			try {
				const sparql = prop.getter.replace(/\?this/g, `<${address}>`);
				const sparqlResult = await this.querySparql(sparql);
				if (sparqlResult.bindings.length > 0) {
					const firstBinding = sparqlResult.bindings[0];
					const keys = Object.keys(firstBinding);
					result[prop.name] = keys.length > 0 ? firstBinding[keys[0]] : null;
				} else result[prop.name] = null;
			} catch {
				result[prop.name] = null;
			}
			continue;
		}
		const triples = await this.queryTriples({
			source: address,
			predicate: prop.path
		});
		if (isScalar(prop)) result[prop.name] = triples.length > 0 ? triples[0].data.target : null;
		else result[prop.name] = triples.map((t) => t.data.target);
	}
	return result;
}
async function setShapeProperty(shapeName, address, property, value) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const prop = getPropertyDef(shape.definition, property);
	if (!isWritable(prop)) throw new TypeError(`Property "${property}" is not writable`);
	if (!isScalar(prop)) throw new TypeError(`Property "${property}" is a collection (maxCount \u2260 1), use addToShapeCollection`);
	if (prop.datatype && !validateDatatype(String(value), prop.datatype)) throw new TypeError(`Value "${value}" does not match datatype ${prop.datatype}`);
	const existing = await this.queryTriples({
		source: address,
		predicate: prop.path
	});
	for (const t of existing) await this.removeTriple(t);
	await this.addTriple(new SemanticTriple(address, String(value), prop.path));
}
async function addToShapeCollection(shapeName, address, collection, value) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const prop = getPropertyDef(shape.definition, collection);
	if (!isWritable(prop)) throw new TypeError(`Property "${collection}" is not writable`);
	if (isScalar(prop)) throw new TypeError(`Property "${collection}" is scalar (maxCount = 1), use setShapeProperty`);
	if (prop.datatype && !validateDatatype(String(value), prop.datatype)) throw new TypeError(`Value "${value}" does not match datatype ${prop.datatype}`);
	if (prop.maxCount !== void 0) {
		if ((await this.queryTriples({
			source: address,
			predicate: prop.path
		})).length >= prop.maxCount) throw new DOMException(`Adding value would exceed maxCount (${prop.maxCount}) for "${collection}"`, "ConstraintError");
	}
	await this.addTriple(new SemanticTriple(address, String(value), prop.path));
}
async function removeFromShapeCollection(shapeName, address, collection, value) {
	const shape = getRegistry(this).get(shapeName);
	if (!shape) throw new TypeError(`Shape "${shapeName}" not found`);
	const prop = getPropertyDef(shape.definition, collection);
	const existing = await this.queryTriples({
		source: address,
		predicate: prop.path
	});
	const toRemove = existing.find((t) => t.data.target === String(value));
	if (!toRemove) throw new DOMException(`Value "${value}" not found in collection "${collection}"`, "NotFoundError");
	const minCount = prop.minCount ?? 0;
	if (existing.length <= minCount) throw new DOMException(`Removing value would violate minCount (${minCount}) for "${collection}"`, "ConstraintError");
	await this.removeTriple(toRemove);
}
function installShapeExtension(GraphClass) {
	const proto = GraphClass.prototype;
	proto.addShape = addShape;
	proto.getShapes = getShapes;
	proto.createShapeInstance = createShapeInstance;
	proto.getShapeInstances = getShapeInstances;
	proto.getShapeInstanceData = getShapeInstanceData;
	proto.setShapeProperty = setShapeProperty;
	proto.addToShapeCollection = addToShapeCollection;
	proto.removeFromShapeCollection = removeFromShapeCollection;
}
//#endregion
//#region src/content-script.ts
/**
* Living Web Extension — Content Script
* Injected into every page's MAIN world via Manifest V3.
* Feature-detects native support and only installs polyfills if needed.
*/
if (typeof navigator !== "undefined" && "graph" in navigator && navigator.graph?.__native) console.info("[Living Web Extension] Native support detected — skipped");
else {
	const identity = new EphemeralIdentity();
	const graphManager = new PersonalGraphManager(identity);
	navigator.graph = graphManager;
	install$1();
	installShapeExtension(PersonalGraph);
	install(new SharedGraphManager(identity));
	console.info("[Living Web Extension] Polyfill installed");
}
//#endregion

//# sourceMappingURL=content-script.js.map