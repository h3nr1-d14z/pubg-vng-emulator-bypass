// Frida script: Network-level ANOGS 0x4013 payload patcher
// Intercept send/sendto -> decrypt AES -> patch TLV -> re-encrypt -> forward
// Also intercepts recv/recvfrom to auto-extract AES key from auth response 0x1002
// Target: PUBG Mobile VNG port 17500

var ANOGS_PORT = 17500;
var AES_KEY = null; // 16-byte ArrayBuffer, extracted from 0x1002
var AES_IV = new Uint8Array(16); // zeros

function log(msg) {
    console.log("[ANOGS-PATCH] " + msg);
}

function bytesToHex(buffer) {
    var arr = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < arr.length; i++) {
        hex += ("0" + arr[i].toString(16)).slice(-2);
    }
    return hex;
}

// Parse ANOGS header: returns {opcode, seq, body_len}
function parseAnogsHeader(buf) {
    return {
        magic: (buf[0] << 8) | buf[1],
        opcode: (buf[6] << 8) | buf[7],
        seq: (buf[11] << 24) | (buf[10] << 16) | (buf[9] << 8) | buf[8],
        body_len: (buf[15] << 24) | (buf[14] << 16) | (buf[13] << 8) | buf[12]
    };
}

// Extract token from 0x1002 response (server -> client)
// Token is located in trailer starting at offset 6, length up to 16 bytes
function extractToken(buf, len) {
    if (len < 32) return null;
    var hdr = parseAnogsHeader(buf);
    if (hdr.magic !== 0x3366 || hdr.opcode !== 0x1002) return null;

    // Trailer starts after header (16 bytes) + body_len
    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 22 > len) return null;

    // Based on analysis: token starts at trailer+6, take 16 bytes and strip nulls
    var tokenOffset = trailerOffset + 6;
    var tokenLen = 0;
    for (var i = 0; i < 16; i++) {
        if (buf[tokenOffset + i] !== 0) tokenLen++;
        else break;
    }
    if (tokenLen === 0) return null;

    var key = new Uint8Array(16);
    for (var j = 0; j < 16; j++) {
        key[j] = j < tokenLen ? buf[tokenOffset + j] : 0;
    }
    return key.buffer;
}

// Call Java AES via javax.crypto.Cipher
function callJavaAes(dataArray, keyArray, ivArray, mode) {
    var result = null;
    var ready = false;
    Java.perform(function() {
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            var jKey = SecretKeySpec.$new(keyArray, "AES");
            var jIv = IvParameterSpec.$new(ivArray);
            var modeInt = (mode === "encrypt") ? 1 : 2;
            cipher.init(modeInt, jKey, jIv);

            var jData = Java.array('byte', Array.from(dataArray));
            var jResult = cipher.doFinal(jData);
            result = jResult;
            ready = true;
        } catch (e) {
            log("Java AES error: " + e);
        }
    });
    if (!ready || !result) return null;
    // Convert Java byte[] back to Uint8Array
    var out = new Uint8Array(result.length);
    for (var i = 0; i < result.length; i++) {
        out[i] = result[i];
        if (out[i] < 0) out[i] += 256;
    }
    return out;
}

// Patch TLV fields in decrypted plaintext
function patchTelemetry(plain) {
    // TLV type 0x03: [0x03][len:1][value]
    var out = [];
    var i = 0;
    while (i < plain.length - 2) {
        var t = plain[i];
        var l = plain[i + 1];
        if (l > 128 || i + 2 + l > plain.length) {
            out.push(plain[i]);
            i++;
            continue;
        }
        var v = plain.slice(i + 2, i + 2 + l);
        var modified = false;

        if (t === 0x03) {
            try {
                var str = "";
                for (var si = 0; si < v.length; si++) str += String.fromCharCode(v[si]);

                if (str.indexOf("LeiDian") !== -1 || str.indexOf("X86") !== -1 || str === "EmulatorName") {
                    log("Patching EmulatorName at offset " + i + ": " + str);
                    var newVal = "SM-S928B";
                    out.push(0x03);
                    out.push(newVal.length);
                    for (var k = 0; k < newVal.length; k++) out.push(newVal.charCodeAt(k));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("GenericGPUBrand") !== -1 || str === "GLRender") {
                    log("Patching GLRender at offset " + i + ": " + str);
                    var newVal2 = "Adreno (TM) 750";
                    out.push(0x03);
                    out.push(newVal2.length);
                    for (var k2 = 0; k2 < newVal2.length; k2++) out.push(newVal2.charCodeAt(k2));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("ASUS_AI2401_A") !== -1 || str.indexOf("asus_ai2401_a") !== -1 || str === "DeviceModel") {
                    log("Patching DeviceModel at offset " + i + ": " + str);
                    var newVal3 = "SM-S928B";
                    out.push(0x03);
                    out.push(newVal3.length);
                    for (var k3 = 0; k3 < newVal3.length; k3++) out.push(newVal3.charCodeAt(k3));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("rog") !== -1 && str.length < 10) {
                    log("Patching DeviceMake at offset " + i + ": " + str);
                    var newVal4 = "samsung";
                    out.push(0x03);
                    out.push(newVal4.length);
                    for (var k4 = 0; k4 < newVal4.length; k4++) out.push(newVal4.charCodeAt(k4));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("ROG+ASUS") !== -1 || str === "SystemHardware") {
                    log("Patching SystemHardware at offset " + i + ": " + str);
                    var newVal5 = "qcom+samsung";
                    out.push(0x03);
                    out.push(newVal5.length);
                    for (var k5 = 0; k5 < newVal5.length; k5++) out.push(newVal5.charCodeAt(k5));
                    i += 2 + l;
                    modified = true;
                }
            } catch (e) {}
        }

        if (!modified) {
            out.push(plain[i]);
            out.push(plain[i + 1]);
            for (var j = 0; j < l; j++) out.push(plain[i + 2 + j]);
            i += 2 + l;
        }
    }
    return new Uint8Array(out);
}

function processSend(bufPtr, len) {
    if (len < 21) return null;

    var buf = new Uint8Array(Memory.readByteArray(bufPtr, len));
    if (buf[0] !== 0x33 || buf[1] !== 0x66) return null;

    var hdr = parseAnogsHeader(buf);
    if (hdr.opcode !== 0x4013) return null;

    log("Intercepted 0x4013 C->S, body_len=" + hdr.body_len + ", total=" + len);

    if (!AES_KEY) {
        log("AES key not available yet, skipping patch");
        return null;
    }

    // Trailer starts after header (16) + body_len
    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 6 >= len) return null;

    // Skip 5 bytes trailer header (d0 00 00 00 00)
    var encOffset = trailerOffset + 5;
    var encLen = len - encOffset;
    if (encLen <= 0 || encLen > 65535) return null;

    // Pad to 16-byte boundary for AES block
    var pad = 16 - (encLen % 16);
    if (pad === 16) pad = 0;

    var encrypted = buf.slice(encOffset, encOffset + encLen);
    var encryptedPadded = new Uint8Array(encLen + pad);
    encryptedPadded.set(encrypted);

    var keyArr = new Uint8Array(AES_KEY);
    var plain = callJavaAes(encryptedPadded, keyArr, AES_IV, "decrypt");
    if (!plain) {
        log("Decrypt failed");
        return null;
    }

    log("Decrypted " + plain.length + " bytes");

    var patched = patchTelemetry(plain);
    log("Patched " + patched.length + " bytes");

    // Re-encrypt patched data (Java PKCS5Padding will handle padding)
    var reEncrypted = callJavaAes(patched, keyArr, AES_IV, "encrypt");
    if (!reEncrypted) {
        log("Re-encrypt failed");
        return null;
    }

    // Build new packet
    var newPacket = new Uint8Array(len);
    newPacket.set(buf.slice(0, encOffset));
    newPacket.set(reEncrypted.slice(0, Math.min(reEncrypted.length, len - encOffset)), encOffset);

    var newBuf = Memory.alloc(len);
    Memory.writeByteArray(newBuf, newPacket.buffer);
    log("Forwarding patched packet");
    return newBuf;
}

function hookSend() {
    var sendAddr = Module.findExportByName("libc.so", "send");
    var sendtoAddr = Module.findExportByName("libc.so", "sendto");

    function installSend(impl, name) {
        Interceptor.attach(impl, {
            onEnter: function(args) {
                this.bufPtr = args[1];
                this.len = args[2].toInt32();
                this.newBuf = processSend(this.bufPtr, this.len);
                if (this.newBuf) {
                    args[1] = this.newBuf;
                }
            }
        });
        log("Hooked " + name + "()");
    }

    if (sendAddr) installSend(sendAddr, "send");
    if (sendtoAddr) installSend(sendtoAddr, "sendto");
}

function hookRecv() {
    var recvAddr = Module.findExportByName("libc.so", "recv");
    var recvfromAddr = Module.findExportByName("libc.so", "recvfrom");

    function processRecv(bufPtr, len) {
        if (len < 32) return;
        var buf = new Uint8Array(Memory.readByteArray(bufPtr, len));
        if (buf[0] !== 0x33 || buf[1] !== 0x66) return;

        var key = extractToken(buf, len);
        if (key) {
            AES_KEY = key;
            log("Extracted AES key from 0x1002: " + bytesToHex(key));
        }
    }

    function installRecv(impl, name) {
        Interceptor.attach(impl, {
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0 && this.bufPtr) {
                    processRecv(this.bufPtr, n);
                }
            },
            onEnter: function(args) {
                this.bufPtr = args[1];
            }
        });
        log("Hooked " + name + "()");
    }

    if (recvAddr) installRecv(recvAddr, "recv");
    if (recvfromAddr) installRecv(recvfromAddr, "recvfrom");
}

// Scan libanogs.so / libTdataMaster.so for encrypt-related exports (informational)
function scanAntiCheatModules() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        if (mod.name.indexOf("anogs") !== -1 || mod.name.indexOf("TDataMaster") !== -1 ||
            mod.name.indexOf("gsdk") !== -1) {
            log("Found module: " + mod.name + " @ " + mod.base);
            var exports = Module.enumerateExports(mod.name);
            for (var j = 0; j < exports.length; j++) {
                var exp = exports[j];
                if (exp.name.indexOf("Encrypt") !== -1 || exp.name.indexOf("encrypt") !== -1 ||
                    exp.name.indexOf("Encode") !== -1 || exp.name.indexOf("Cipher") !== -1 ||
                    exp.name.indexOf("crypto") !== -1 || exp.name.indexOf("aes") !== -1) {
                    log("  Export: " + exp.name + " @ " + exp.address);
                }
            }
        }
    }
}

Java.perform(function() {
    log("ANOGS Network Patch started");
    hookSend();
    hookRecv();
    scanAntiCheatModules();
});
