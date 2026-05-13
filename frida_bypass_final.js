// Final bypass - stealth (property + GPU + file + ptrace + thread rename) + network hooks
function log(msg) { console.log("[BYPASS] " + msg); }

function safeReadUtf8(ptr) {
    try { if (!ptr || ptr.isNull()) return null; return ptr.readUtf8String(); } catch(e) { return null; }
}

function wrap(name, fn) {
    return function() {
        try { return fn.apply(this, arguments); }
        catch(e) { log("ERR " + name + ": " + e); }
    };
}

function readBufferSafe(ptr, len) {
    if (!ptr || ptr.isNull() || len <= 0 || len > 65535) return null;
    try {
        var raw = Memory.readByteArray(ptr, len);
        if (!raw) return null;
        return new Uint8Array(raw);
    } catch(e) { return null; }
}

// ==================== THREAD RENAMING ====================

function renameFridaThreads() {
    try {
        var pthread = Process.findModuleByName("libc.so");
        if (!pthread) return;
        var setname = pthread.findExportByName("pthread_setname_np");
        if (!setname || setname.isNull()) return;

        var newNames = ["RenderThread", "WorkerThread", "JobThread", "GLThread", "NetworkThread", "IOThread", "AudioThread"];
        var threads = Process.enumerateThreads();
        var nameIdx = 0;
        for (var i = 0; i < threads.length; i++) {
            var t = threads[i];
            var tname = t.name || "";
            if (tname.indexOf("frida") !== -1 || tname.indexOf("gum") !== -1 ||
                tname.indexOf("pool") !== -1 || tname.indexOf("agent") !== -1 ||
                tname === "main" || tname === "threaded-ml" || tname === "") {
                var newName = Memory.allocUtf8String(newNames[nameIdx % newNames.length]);
                var fn = new NativeFunction(setname, 'int', ['pointer', 'pointer']);
                fn(ptr(t.id), newName);
                log("Renamed thread " + t.id + " (" + tname + ") -> " + newNames[nameIdx % newNames.length]);
                nameIdx++;
            }
        }
    } catch(e) { log("renameFridaThreads error: " + e); }
}

// ==================== PROPERTY SPOOFING ====================

function hookPropertyGet() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) { log("libc not found"); return; }
        var exps = libc.enumerateExports();
        var addr = null;
        for (var i = 0; i < exps.length; i++) { if (exps[i].name === "__system_property_get") { addr = exps[i].address; break; } }
        if (!addr) { log("prop_get not found"); return; }

        var fp = {
            "ro.hardware": "qcom",
            "ro.product.model": "SM-S928B",
            "ro.product.device": "e3q",
            "ro.product.brand": "samsung",
            "ro.product.manufacturer": "samsung",
            "ro.kernel.qemu": "0",
            "ro.kernel.qemu.gles": "0",
            "ro.product.cpu.abi": "arm64-v8a",
            "ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a,armeabi",
            "ro.product.cpu.abilist32": "armeabi-v7a,armeabi",
            "ro.product.cpu.abilist64": "arm64-v8a",
            "ro.boot.hardware": "qcom",
            "ro.board.platform": "sm8650",
            "ro.arch": "arm64",
            "ro.product.board": "e3q",
            "ro.build.product": "e3q",
            "ro.build.version.release": "14",
            "ro.build.version.sdk": "34",
            "ro.build.id": "UP1A.231005.007",
            "ro.build.tags": "release-keys",
            "ro.build.type": "user",
            "ro.build.user": "dpi",
            "ro.build.host": "swdk-at-slave-258",
            "ro.build.flavor": "e3qxxx-user",
            "ro.bootloader": "S928BXXU1AWM9",
            "ro.boot.mode": "unknown",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.warranty_bit": "0",
            "ro.warranty_bit": "0",
            "ro.secure": "1",
            "ro.debuggable": "0",
            "ro.build.characteristics": "phone",
            "ro.setupwizard.mode": "DISABLED",
            "ro.com.google.clientidbase": "android-samsung",
            "ro.product.first_api_level": "34",
            "ro.opengles.version": "196610",
            "ro.sf.lcd_density": "450"
        };

        Interceptor.attach(addr, {
            onEnter: wrap("prop.onEnter", function(args) {
                this.key = safeReadUtf8(args[0]);
                this.buf = args[1];
            }),
            onLeave: wrap("prop.onLeave", function(retval) {
                if (!this.key || !this.buf) return;
                if (fp[this.key]) {
                    log("Prop " + this.key + " -> " + fp[this.key]);
                    this.buf.writeUtf8String(fp[this.key]);
                    retval.replace(fp[this.key].length);
                }
            })
        });
        log("property_get hooked");
    } catch(e) { log("hookPropertyGet error: " + e); }
}

// ==================== FILE REDIRECTION ====================

var fakeCpuinfo = Memory.allocUtf8String("/data/local/tmp/fake_cpuinfo");
var fakeBuildProp = Memory.allocUtf8String("/data/local/tmp/fake_build.prop");
var fakeStatus = Memory.allocUtf8String("/data/local/tmp/fake_status");
var fakeMaps = Memory.allocUtf8String("/data/local/tmp/fake_maps");
var fakeNotExist = Memory.allocUtf8String("/data/local/tmp/.nonexistent_root_hide");

var rootPaths = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/system/bin/.ext/.su", "/system/xbin/.ext/.su",
    "/system/app/Superuser.apk", "/system/app/SuperSU",
    "/system/bin/magisk", "/system/xbin/magisk", "/sbin/magisk",
    "/magisk", "/.magisk", "/sbin/.magisk",
    "/data/adb/magisk", "/data/adb/ksu"
];

function redirectPath(pathPtr, pathStr) {
    if (!pathStr) return pathPtr;
    if (pathStr === "/proc/cpuinfo") return fakeCpuinfo;
    if (pathStr === "/system/build.prop") return fakeBuildProp;
    if (pathStr === "/proc/self/status") return fakeStatus;
    if (pathStr === "/proc/self/maps") {
        log("Redirect maps");
        return fakeMaps;
    }
    for (var i = 0; i < rootPaths.length; i++) {
        if (pathStr === rootPaths[i] || pathStr.indexOf(rootPaths[i]) === 0) {
            log("Hide root: " + pathStr);
            return fakeNotExist;
        }
    }
    return pathPtr;
}

function hookFopen() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var fopen = libc.findExportByName("fopen");
        var fopen64 = libc.findExportByName("fopen64");
        function attach(name, addr) {
            if (!addr || addr.isNull()) return;
            Interceptor.attach(addr, {
                onEnter: wrap("fopen("+name+")", function(args) {
                    var path = safeReadUtf8(args[0]);
                    args[0] = redirectPath(args[0], path);
                })
            });
            log("Hooked " + name);
        }
        attach("fopen", fopen);
        attach("fopen64", fopen64);
    } catch(e) { log("hookFopen error: " + e); }
}

function hookOpen() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var names = ["open", "openat", "open64", "openat64", "__open", "__openat"];
        names.forEach(function(n) {
            var addr = libc.findExportByName(n);
            var pathIdx = (n.indexOf("openat") !== -1) ? 1 : 0;
            if (addr && !addr.isNull()) {
                Interceptor.attach(addr, {
                    onEnter: wrap("open("+n+")", function(args) {
                        var path = safeReadUtf8(args[pathIdx]);
                        args[pathIdx] = redirectPath(args[pathIdx], path);
                    })
                });
                log("Hooked " + n);
            }
        });
    } catch(e) { log("hookOpen error: " + e); }
}

function hookAccess() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var access = libc.findExportByName("access");
        var faccessat = libc.findExportByName("faccessat");
        function attach(name, addr, pathIdx) {
            if (!addr || addr.isNull()) return;
            Interceptor.attach(addr, {
                onEnter: wrap("access("+name+")", function(args) {
                    var path = safeReadUtf8(args[pathIdx]);
                    args[pathIdx] = redirectPath(args[pathIdx], path);
                })
            });
            log("Hooked " + name);
        }
        attach("access", access, 0);
        attach("faccessat", faccessat, 1);
    } catch(e) { log("hookAccess error: " + e); }
}

function hookStat() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var stats = ["stat", "fstatat", "lstat", "stat64", "lstat64"];
        stats.forEach(function(n) {
            var addr = libc.findExportByName(n);
            var pathIdx = (n.indexOf("fstatat") !== -1) ? 1 : 0;
            if (addr && !addr.isNull()) {
                Interceptor.attach(addr, {
                    onEnter: wrap("stat("+n+")", function(args) {
                        var path = safeReadUtf8(args[pathIdx]);
                        args[pathIdx] = redirectPath(args[pathIdx], path);
                    })
                });
                log("Hooked " + n);
            }
        });
    } catch(e) { log("hookStat error: " + e); }
}

// ==================== GPU SPOOFING ====================

var fakeGlVendor = Memory.allocUtf8String("Qualcomm");
var fakeGlRenderer = Memory.allocUtf8String("Adreno (TM) 750");
var fakeGlVersion = Memory.allocUtf8String("OpenGL ES 3.2 V@0502.0");
var fakeEglVendor = Memory.allocUtf8String("Qualcomm");
var fakeEglVersion = Memory.allocUtf8String("1.5");

function hookGlGetString() {
    try {
        ["libGLESv2.so", "libGLESv3.so", "libEGL.so"].forEach(function(name) {
            var mod = Process.findModuleByName(name);
            if (!mod) return;
            var addr = null;
            var exps = mod.enumerateExports();
            for (var i = 0; i < exps.length; i++) { if (exps[i].name === "glGetString") { addr = exps[i].address; break; } }
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: wrap("gl.onEnter", function(args) { this.name = args[0].toInt32(); }),
                onLeave: wrap("gl.onLeave", function(retval) {
                    if (this.name === 0x1F00) retval.replace(fakeGlVendor);
                    else if (this.name === 0x1F01) retval.replace(fakeGlRenderer);
                    else if (this.name === 0x1B02) retval.replace(fakeGlVersion);
                })
            });
            log("glGetString hooked in " + name);
        });
    } catch(e) { log("hookGlGetString error: " + e); }
}

function hookEglQueryString() {
    try {
        var mod = Process.findModuleByName("libEGL.so");
        if (!mod) return;
        var addr = null;
        var exps = mod.enumerateExports();
        for (var i = 0; i < exps.length; i++) { if (exps[i].name === "eglQueryString") { addr = exps[i].address; break; } }
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: wrap("egl.onEnter", function(args) { this.name = args[1].toInt32(); }),
            onLeave: wrap("egl.onLeave", function(retval) {
                if (this.name === 0x3053) retval.replace(fakeEglVendor);
                else if (this.name === 0x3054) retval.replace(fakeEglVersion);
            })
        });
        log("eglQueryString hooked");
    } catch(e) { log("hookEglQueryString error: " + e); }
}

// ==================== PTRACE ====================

function hookPtrace() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var addr = libc.findExportByName("ptrace");
        if (!addr || addr.isNull()) return;
        Interceptor.attach(addr, {
            onEnter: wrap("ptrace.onEnter", function(args) { this.request = args[0].toInt32(); }),
            onLeave: wrap("ptrace.onLeave", function(retval) {
                if (this.request === 0) { log("Blocked PTRACE_TRACEME"); retval.replace(0); }
            })
        });
        log("ptrace hooked");
    } catch(e) { log("hookPtrace error: " + e); }
}

// ==================== NETWORK PATCH ====================

var ANOGS_PORT = 17500;
var AES_KEY = null;
var AES_IV = new Uint8Array(16);

function bytesToHex(buffer) {
    var arr = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < arr.length; i++) {
        hex += ("0" + arr[i].toString(16)).slice(-2);
    }
    return hex;
}

function parseAnogsHeader(buf) {
    return {
        magic: (buf[0] << 8) | buf[1],
        opcode: (buf[6] << 8) | buf[7],
        seq: (buf[11] << 24) | (buf[10] << 16) | (buf[9] << 8) | buf[8],
        body_len: (buf[15] << 24) | (buf[14] << 16) | (buf[13] << 8) | buf[12]
    };
}

function extractToken(buf, len) {
    if (len < 32) return null;
    var hdr = parseAnogsHeader(buf);
    if (hdr.magic !== 0x3366 || hdr.opcode !== 0x1002) return null;
    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 22 > len) return null;
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

function callJavaAes(dataArray, keyArray, ivArray, mode) {
    var result = null;
    var ready = false;
    if (typeof Java === 'undefined' || !Java.available) {
        log("Java not available for AES");
        return null;
    }
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
    var out = new Uint8Array(result.length);
    for (var i = 0; i < result.length; i++) {
        out[i] = result[i];
        if (out[i] < 0) out[i] += 256;
    }
    return out;
}

function calcDeviceHash() {
    return "9fe5bc9ba47e3ed39c9b6860d2eb15d8bce6b2a95d24ec67eb152557b2883b4d";
}

function patchTelemetry(plain) {
    var out = [];
    var i = 0;
    var newXid = calcDeviceHash();
    var keyMap = [
        ["EmulatorName", "SM-S928B"],
        ["GLRender", "Adreno (TM) 750"],
        ["DeviceModel", "SM-S928B"],
        ["DeviceName", "SM-S928B"],
        ["DeviceMake", "samsung"],
        ["SystemHardware", "qcom+samsung"],
        ["XID", newXid]
    ];

    while (i < plain.length) {
        var matched = false;
        for (var ki = 0; ki < keyMap.length; ki++) {
            var kstr = keyMap[ki][0];
            var klen = kstr.length;
            if (i + 2 + klen <= plain.length && plain[i] === 0x03 && plain[i+1] === klen) {
                var match = true;
                for (var ci = 0; ci < klen; ci++) {
                    if (plain[i + 2 + ci] !== kstr.charCodeAt(ci)) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    out.push(0x03); out.push(klen);
                    for (var c = 0; c < klen; c++) out.push(kstr.charCodeAt(c));
                    i += 2 + klen;

                    if (i + 1 < plain.length) {
                        var vt = plain[i];
                        var vl = plain[i+1];
                        if (vl <= 200 && i + 2 + vl <= plain.length) {
                            var newVal = keyMap[ki][1];
                            if (newVal) {
                                log("Patch " + kstr + " -> " + newVal);
                                out.push(0x03); out.push(newVal.length);
                                for (var vi = 0; vi < newVal.length; vi++) out.push(newVal.charCodeAt(vi));
                                i += 2 + vl;
                                matched = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (!matched) {
            out.push(plain[i]);
            i++;
        }
    }
    return new Uint8Array(out);
}

function processSend(bufPtr, len) {
    if (len < 21) return null;
    var buf = readBufferSafe(bufPtr, len);
    if (!buf || buf[0] !== 0x33 || buf[1] !== 0x66) return null;
    var hdr = parseAnogsHeader(buf);
    if (hdr.opcode !== 0x4013) return null;
    log("Intercepted 0x4013 C->S, body_len=" + hdr.body_len + ", total=" + len);
    if (!AES_KEY) {
        log("AES key not available yet, skipping patch");
        return null;
    }
    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 6 >= len) return null;
    var encOffset = trailerOffset + 5;
    var encLen = len - encOffset;
    if (encLen <= 0 || encLen > 65535) return null;
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
    var reEncrypted = callJavaAes(patched, keyArr, AES_IV, "encrypt");
    if (!reEncrypted) {
        log("Re-encrypt failed");
        return null;
    }
    var newPacket = new Uint8Array(len);
    newPacket.set(buf.slice(0, encOffset));
    newPacket.set(reEncrypted.slice(0, Math.min(reEncrypted.length, len - encOffset)), encOffset);
    var newBuf = Memory.alloc(len);
    Memory.writeByteArray(newBuf, newPacket.buffer);
    log("Forwarding patched packet");
    return newBuf;
}

function processRecv(bufPtr, len) {
    if (len < 32) return;
    var buf = readBufferSafe(bufPtr, len);
    if (!buf || buf[0] !== 0x33 || buf[1] !== 0x66) return;
    var key = extractToken(buf, len);
    if (key) {
        AES_KEY = key;
        log("Extracted AES key from 0x1002: " + bytesToHex(key));
    }
}

function hookSend() {
    try {
        var libc = Process.findModuleByName("libc.so");
        var sendAddr = null;
        var sendtoAddr = null;
        if (libc) {
            var exps = libc.enumerateExports();
            for (var i = 0; i < exps.length; i++) {
                if (exps[i].name === "send") sendAddr = exps[i].address;
                if (exps[i].name === "sendto") sendtoAddr = exps[i].address;
            }
        }
        log("sendAddr=" + sendAddr + " sendtoAddr=" + sendtoAddr);
        function installSend(impl, name) {
            if (!impl || impl.isNull()) return;
            Interceptor.attach(impl, {
                onEnter: wrap("send.onEnter("+name+")", function(args) {
                    this.bufPtr = args[1];
                    this.len = args[2].toInt32();
                    this.newBuf = processSend(this.bufPtr, this.len);
                    if (this.newBuf) {
                        args[1] = this.newBuf;
                    }
                })
            });
            log("Hooked " + name + "()");
        }
        if (sendAddr) installSend(sendAddr, "send");
        if (sendtoAddr) installSend(sendtoAddr, "sendto");
    } catch(e) { log("hookSend error: " + e); }
}

function hookRecv() {
    try {
        var libc = Process.findModuleByName("libc.so");
        var recvAddr = null;
        var recvfromAddr = null;
        if (libc) {
            var exps = libc.enumerateExports();
            for (var i = 0; i < exps.length; i++) {
                if (exps[i].name === "recv") recvAddr = exps[i].address;
                if (exps[i].name === "recvfrom") recvfromAddr = exps[i].address;
            }
        }
        log("recvAddr=" + recvAddr + " recvfromAddr=" + recvfromAddr);
        function installRecv(impl, name) {
            if (!impl || impl.isNull()) return;
            Interceptor.attach(impl, {
                onEnter: wrap("recv.onEnter("+name+")", function(args) {
                    this.bufPtr = args[1];
                }),
                onLeave: wrap("recv.onLeave("+name+")", function(retval) {
                    var n = retval.toInt32();
                    if (n > 0 && this.bufPtr) {
                        processRecv(this.bufPtr, n);
                    }
                })
            });
            log("Hooked " + name + "()");
        }
        if (recvAddr) installRecv(recvAddr, "recv");
        if (recvfromAddr) installRecv(recvfromAddr, "recvfrom");
    } catch(e) { log("hookRecv error: " + e); }
}

function hookConnect() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var connect = libc.findExportByName("connect");
        if (connect && !connect.isNull()) {
            Interceptor.attach(connect, {
                onEnter: wrap("connect.onEnter", function(args) {
                    var sockaddr = args[1];
                    if (!sockaddr || sockaddr.isNull()) return;
                    try {
                        var family = Memory.readU16(sockaddr);
                        if (family === 2) {
                            var port = (Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3));
                            var ip = Memory.readU8(sockaddr.add(4)) + "." + Memory.readU8(sockaddr.add(5)) + "." + Memory.readU8(sockaddr.add(6)) + "." + Memory.readU8(sockaddr.add(7));
                            log("connect " + ip + ":" + port);
                            if (port === 17500) {
                                log("*** ANOGS CONNECTION DETECTED ***");
                            }
                        }
                    } catch(e) {}
                })
            });
            log("Hooked connect()");
        }
    } catch(e) { log("hookConnect error: " + e); }
}

// ==================== MAIN ====================

function main() {
    log("=== Final Bypass Starting ===");
    try {
        Process.setExceptionHandler(function(details) {
            log("CRASH: type=" + details.type + " addr=" + details.address +
                " pc=" + (details.context ? details.context.pc : "n/a"));
            return false;
        });
    } catch(e) {}

    hookPropertyGet();
    hookFopen();
    hookOpen();
    hookAccess();
    hookStat();
    hookGlGetString();
    hookEglQueryString();
    hookPtrace();
    hookSend();
    hookRecv();
    hookConnect();

    renameFridaThreads();

    setInterval(function() {
        renameFridaThreads();
    }, 5000);

    log("=== Final Bypass Ready ===");
}

main();
