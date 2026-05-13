// Emulator bypass - DIAGNOSTIC VERSION (Consolidated)
// Wrapped callbacks to identify TypeError source
// Integrated: stealth Java hooks, syscall fallback, safe ptrace, XID patcher

var ANOGS_PORT = 17500;
var AES_KEY = null;
var AES_IV = new Uint8Array(16);
var FAKE_MAPS_PATH = "/data/local/tmp/fake_maps";
var ERROR_COUNTS = {};

function log(msg) {
    console.log("[BYPASS] " + msg);
}

function logError(hookName, err) {
    var key = hookName + ": " + err.toString();
    if (!ERROR_COUNTS[key]) ERROR_COUNTS[key] = 0;
    ERROR_COUNTS[key]++;
    if (ERROR_COUNTS[key] <= 3) {
        console.log("[ERROR] " + hookName + ": " + err + " (stack: " + err.stack + ")");
    }
}

function safeReadUtf8(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return ptr.readUtf8String();
    } catch(e) { return null; }
}

function wrap(hookName, fn) {
    return function() {
        try {
            return fn.apply(this, arguments);
        } catch(e) {
            logError(hookName, e);
        }
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

function buildFakeMaps() {
    try {
        var f = new File(FAKE_MAPS_PATH, "r");
        f.close();
        log("Fake maps already exists");
    } catch(e) {
        log("Fake maps missing, skipping maps build");
    }
}

// ==================== PROPERTY SPOOFING ====================

function hookPropertyGet() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) { log("libc.so not found"); return; }
        var exports = libc.enumerateExports();
        var propGet = exports.find(s => s.name === "__system_property_get");
        if (!propGet) { log("__system_property_get not found"); return; }

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

        Interceptor.attach(propGet.address, {
            onEnter: wrap("propGet.onEnter", function(args) {
                this.key = safeReadUtf8(args[0]);
                this.buf = args[1];
            }),
            onLeave: wrap("propGet.onLeave", function(retval) {
                if (!this.key) return;
                var val = safeReadUtf8(this.buf);
                if (fp[this.key]) {
                    log("Prop " + this.key + " -> " + fp[this.key]);
                    this.buf.writeUtf8String(fp[this.key]);
                    retval.replace(fp[this.key].length);
                } else if (val && (val.indexOf("x86") !== -1 || val.indexOf("amd") !== -1 || val.indexOf("AMD") !== -1 || val.indexOf("houdini") !== -1)) {
                    log("SUS Prop " + this.key + " = " + val);
                }
            })
        });
        log("__system_property_get hooked");
    } catch(e) { log("hookPropertyGet error: " + e); }
}

function hookPropertyRead() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var readFn = libc.findExportByName("__system_property_read");
        if (readFn && !readFn.isNull()) {
            Interceptor.attach(readFn, {
                onEnter: wrap("propRead.onEnter", function(args) {
                    this.pi = args[0];
                    this.name = args[1];
                    this.value = args[2];
                }),
                onLeave: wrap("propRead.onLeave", function(retval) {
                    if (this.name) {
                        var name = safeReadUtf8(this.name);
                        if (name && name.indexOf("x86") !== -1) {
                            log("__system_property_read: " + name);
                        }
                    }
                })
            });
            log("__system_property_read hooked");
        }
    } catch(e) { log("hookPropertyRead error: " + e); }
}

// ==================== FILE REDIRECTION ====================

var fakeCpuinfo = Memory.allocUtf8String("/data/local/tmp/fake_cpuinfo");
var fakeBuildProp = Memory.allocUtf8String("/data/local/tmp/fake_build.prop");
var fakeStatus = Memory.allocUtf8String("/data/local/tmp/fake_status");
var fakeMaps = Memory.allocUtf8String(FAKE_MAPS_PATH);
var fakeSelinux = Memory.allocUtf8String("/data/local/tmp/fake_selinux");
var devnull = Memory.allocUtf8String("/dev/null");
var fakeNotExist = Memory.allocUtf8String("/data/local/tmp/.nonexistent_root_hide");

var rootPaths = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/system/bin/.ext/.su", "/system/xbin/.ext/.su",
    "/system/app/Superuser.apk", "/system/app/SuperSU",
    "/system/bin/magisk", "/system/xbin/magisk", "/sbin/magisk",
    "/magisk", "/.magisk", "/sbin/.magisk",
    "/data/adb/magisk", "/data/adb/ksu",
    "/system/etc/init.d", "/system/sbin",
    "/vendor/bin/su", "/vendor/xbin/su"
];

function redirectPath(pathPtr, pathStr) {
    if (!pathStr) return pathPtr;
    if (pathStr === "/proc/cpuinfo") {
        log("Redirect cpuinfo");
        return fakeCpuinfo;
    }
    if (pathStr === "/system/build.prop") {
        log("Redirect build.prop");
        return fakeBuildProp;
    }
    if (pathStr === "/proc/self/status") {
        log("Redirect status");
        return fakeStatus;
    }
    if (pathStr === "/proc/self/maps") {
        log("Redirect maps");
        return fakeMaps;
    }
    if (pathStr === "/sys/fs/selinux/enforce") {
        log("Redirect selinux enforce");
        return fakeSelinux;
    }
    if (pathStr.indexOf("/sys/devices/system/cpu/") !== -1 && pathStr.indexOf("topology") !== -1) {
        log("Block topology: " + pathStr);
        return devnull;
    }
    for (var i = 0; i < rootPaths.length; i++) {
        if (pathStr === rootPaths[i] || pathStr.indexOf(rootPaths[i]) === 0) {
            log("Hide root path: " + pathStr);
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

        function attachFopen(name, addr) {
            if (addr && !addr.isNull()) {
                Interceptor.attach(addr, {
                    onEnter: wrap("fopen.onEnter("+name+")", function(args) {
                        var path = safeReadUtf8(args[0]);
                        args[0] = redirectPath(args[0], path);
                    })
                });
                log("Hooked " + name);
            }
        }
        attachFopen("fopen", fopen);
        attachFopen("fopen64", fopen64);
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
                    onEnter: wrap("open.onEnter("+n+")", function(args) {
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
            if (addr && !addr.isNull()) {
                Interceptor.attach(addr, {
                    onEnter: wrap("access.onEnter("+name+")", function(args) {
                        var path = safeReadUtf8(args[pathIdx]);
                        args[pathIdx] = redirectPath(args[pathIdx], path);
                    })
                });
                log("Hooked " + name);
            }
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
                    onEnter: wrap("stat.onEnter("+n+")", function(args) {
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
var fakeGlVersion = Memory.allocUtf8String("OpenGL ES 3.2 V@0502.0 (GIT@6b5250b, I229597d848, 1702482879) (Date:12/13/23)");
var fakeEglVendor = Memory.allocUtf8String("Qualcomm");
var fakeEglVersion = Memory.allocUtf8String("1.5");

function hookGlGetString() {
    try {
        var libGLESv2 = Process.findModuleByName("libGLESv2.so");
        var libGLESv3 = Process.findModuleByName("libGLESv3.so");
        var libEGL = Process.findModuleByName("libEGL.so");

        function attachToModule(mod) {
            if (!mod) return;
            var exps = mod.enumerateExports();
            var addr = null;
            for (var i = 0; i < exps.length; i++) {
                if (exps[i].name === "glGetString") {
                    addr = exps[i].address;
                    break;
                }
            }
            if (!addr || addr.isNull()) return;
            Interceptor.attach(addr, {
                onLeave: wrap("glGetString.onLeave", function(retval) {
                    var name = this.name;
                    if (name === 0x1F00) {
                        log("glGetString(GL_VENDOR) -> Qualcomm");
                        retval.replace(fakeGlVendor);
                    } else if (name === 0x1F01) {
                        log("glGetString(GL_RENDERER) -> Adreno (TM) 750");
                        retval.replace(fakeGlRenderer);
                    } else if (name === 0x1B02) {
                        log("glGetString(GL_VERSION) -> OpenGL ES 3.2");
                        retval.replace(fakeGlVersion);
                    }
                }),
                onEnter: wrap("glGetString.onEnter", function(args) {
                    this.name = args[0].toInt32();
                })
            });
            log("Hooked glGetString in " + mod.name);
        }

        attachToModule(libGLESv2);
        attachToModule(libGLESv3);
        attachToModule(libEGL);
    } catch(e) { log("hookGlGetString error: " + e); }
}

function hookEglQueryString() {
    try {
        var libEGL = Process.findModuleByName("libEGL.so");
        if (!libEGL) return;
        var exps = libEGL.enumerateExports();
        var addr = null;
        for (var i = 0; i < exps.length; i++) {
            if (exps[i].name === "eglQueryString") {
                addr = exps[i].address;
                break;
            }
        }
        if (!addr || addr.isNull()) return;
        Interceptor.attach(addr, {
            onEnter: wrap("eglQueryString.onEnter", function(args) {
                this.name = args[1].toInt32();
            }),
            onLeave: wrap("eglQueryString.onLeave", function(retval) {
                var n = this.name;
                if (n === 0x3053) {
                    log("eglQueryString(EGL_VENDOR) -> Qualcomm");
                    retval.replace(fakeEglVendor);
                } else if (n === 0x3054) {
                    log("eglQueryString(EGL_VERSION) -> 1.5");
                    retval.replace(fakeEglVersion);
                }
            })
        });
        log("Hooked eglQueryString");
    } catch(e) { log("hookEglQueryString error: " + e); }
}

// ==================== NETWORK PATCH ====================

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
    if (typeof Java === 'undefined' || !Java.available) {
        return "9fe5bc9ba47e3ed39c9b6860d2eb15d8bce6b2a95d24ec67eb152557b2883b4d";
    }
    var hash = null;
    try {
        Java.perform(function() {
            try {
                var MessageDigest = Java.use("java.security.MessageDigest");
                var md = MessageDigest.getInstance("SHA-256");
                var input = "samsung|SM-S928B|e3q|qcom|14|UP1A.231005.007|S928BXXU1AWM9|pineapple|release-keys|user";
                var jBytes = Java.array('byte', Array.from(input).map(function(c) { return c.charCodeAt(0); }));
                var digest = md.digest(jBytes);
                hash = Array.from(digest).map(function(b) {
                    var ub = b < 0 ? b + 256 : b;
                    return ("0" + ub.toString(16)).slice(-2);
                }).join("");
            } catch (e) {}
        });
    } catch (e) { log("calcDeviceHash error: " + e); }
    return hash || "9fe5bc9ba47e3ed39c9b6860d2eb15d8bce6b2a95d24ec67eb152557b2883b4d";
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

// ==================== PTRACE ANTI-DEBUG ====================

function hookPtrace() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var ptraceAddr = libc.findExportByName("ptrace");
        if (!ptraceAddr || ptraceAddr.isNull()) return;
        Interceptor.attach(ptraceAddr, {
            onEnter: wrap("ptrace.onEnter", function(args) {
                this.request = args[0].toInt32();
            }),
            onLeave: wrap("ptrace.onLeave", function(retval) {
                if (this.request === 0) {
                    log("Blocked PTRACE_TRACEME");
                    retval.replace(0);
                }
            })
        });
        log("Hooked ptrace (anti-debug)");
    } catch(e) { log("hookPtrace error: " + e); }
}

// ==================== MAIN ====================

function installNativeHooks() {
    log("=== Native Hooks ===");
    buildFakeMaps();
    hookPropertyGet();
    hookPropertyRead();
    hookFopen();
    hookOpen();
    hookAccess();
    hookStat();
    hookSend();
    hookRecv();
    hookConnect();
    hookGlGetString();
    hookEglQueryString();
    hookPtrace();
    log("=== Native hooks installed ===");
}

function installJavaHooks() {
    if (typeof Java === 'undefined') {
        log("Java not available, skipping Java hooks");
        return;
    }
    try {
        Java.perform(function() {
            log("Java.perform started");

            // --- Build fields via reflection ---
            try {
                var Build = Java.use("android.os.Build");
                var buildMap = {
                    "MODEL": "SM-S928B",
                    "DEVICE": "e3q",
                    "MANUFACTURER": "samsung",
                    "BRAND": "samsung",
                    "HARDWARE": "qcom",
                    "PRODUCT": "e3qxxx",
                    "BOARD": "e3q",
                    "FINGERPRINT": "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
                    "BOOTLOADER": "S928BXXU1AWM9",
                    "ID": "UP1A.231005.007",
                    "HOST": "android-build",
                    "TAGS": "release-keys",
                    "TYPE": "user",
                    "USER": "dpi",
                    "DISPLAY": "S928BXXU1AWM9",
                    "CPU_ABI": "arm64-v8a",
                    "CPU_ABI2": "armeabi-v7a"
                };
                for (var key in buildMap) {
                    (function(k, v) {
                        try {
                            var field = Build.class.getDeclaredField(k);
                            field.setAccessible(true);
                            field.set(null, v);
                            log("Build." + k + " -> " + v);
                        } catch(e) {
                            log("Build." + k + " failed: " + e);
                        }
                    })(key, buildMap[key]);
                }
                // SUPPORTED_ABIS array
                try {
                    var abisField = Build.class.getDeclaredField("SUPPORTED_ABIS");
                    abisField.setAccessible(true);
                    var abis = Java.array('java.lang.String', ["arm64-v8a", "armeabi-v7a", "armeabi"]);
                    abisField.set(null, abis);
                    log("Build.SUPPORTED_ABIS patched");
                } catch(e) { log("Build.SUPPORTED_ABIS failed: " + e); }
            } catch(e) { log("Build hook failed: " + e); }

            // --- SystemProperties ---
            try {
                var SP = Java.use("android.os.SystemProperties");
                var fakeProps = {
                    "ro.hardware": "qcom",
                    "ro.product.model": "SM-S928B",
                    "ro.product.device": "e3q",
                    "ro.product.brand": "samsung",
                    "ro.product.manufacturer": "samsung",
                    "ro.product.name": "e3qxxx",
                    "ro.build.fingerprint": "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
                    "ro.build.product": "e3q",
                    "ro.board.platform": "sm8650",
                    "ro.bootloader": "S928BXXU1AWM9",
                    "ro.build.id": "UP1A.231005.007",
                    "ro.build.tags": "release-keys",
                    "ro.build.type": "user",
                    "ro.build.user": "dpi",
                    "ro.build.host": "android-build",
                    "ro.kernel.qemu": "0",
                    "ro.hardware.vm": "0",
                    "ro.boot.hardware": "qcom",
                    "ro.product.board": "e3q",
                    "ro.boot.qemu": "0"
                };
                SP.get.overload('java.lang.String').implementation = function(key) {
                    if (fakeProps.hasOwnProperty(key)) return fakeProps[key];
                    var kl = key.toLowerCase();
                    if (kl.indexOf("qemu") !== -1 || kl.indexOf("ldplayer") !== -1 ||
                        kl.indexOf("vbox") !== -1 || kl.indexOf("hyperv") !== -1 ||
                        kl.indexOf("virtio") !== -1) return null;
                    return this.get(key);
                };
                try {
                    SP.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                        if (fakeProps.hasOwnProperty(key)) return fakeProps[key] || def;
                        var kl = key.toLowerCase();
                        if (kl.indexOf("qemu") !== -1 || kl.indexOf("ldplayer") !== -1 ||
                            kl.indexOf("vbox") !== -1 || kl.indexOf("hyperv") !== -1 ||
                            kl.indexOf("virtio") !== -1) return def;
                        return this.get(key, def);
                    };
                } catch(e) {}
                log("SystemProperties.get hooked");
            } catch(e) { log("SystemProperties.get hook failed: " + e); }

            // --- OpenGL (Java layer) ---
            try {
                var GLES20 = Java.use("android.opengl.GLES20");
                var glImpl = function(name) {
                    if (name === 0x1F00) return "Qualcomm";
                    if (name === 0x1F01) return "Adreno (TM) 750";
                    if (name === 0x1F02) return "OpenGL ES 3.2 V@0750.0";
                    return this.glGetString(name);
                };
                GLES20.glGetString.implementation = glImpl;
                try {
                    Java.use("android.opengl.GLES30").glGetString.implementation = glImpl;
                } catch(e) {}
                log("OpenGL Java hooked");
            } catch(e) { log("OpenGL Java hook failed: " + e); }

            // --- NetworkInterface MAC ---
            try {
                var NI = Java.use("java.net.NetworkInterface");
                NI.getHardwareAddress.implementation = function() {
                    var n = this.getName();
                    if (n && n.toString().indexOf("wlan") !== -1) {
                        return Java.array('byte', [0x5c,0x02,0x14,0x12,0x34,0x56]);
                    }
                    if (n && (n.toString().indexOf("eth") !== -1 || n.toString().indexOf("vbox") !== -1)) return null;
                    return this.getHardwareAddress();
                };
                log("MAC hooked");
            } catch(e) { log("MAC hook failed: " + e); }

            // --- Settings.Secure ---
            try {
                var Secure = Java.use("android.provider.Settings$Secure");
                Secure.getString.overload('android.content.ContentResolver','java.lang.String').implementation = function(resolver, name) {
                    if (name === "android_id") return "a1b2c3d4e5f67890";
                    if (name === "bluetooth_name") return "Galaxy S24 Ultra";
                    return this.getString(resolver, name);
                };
                log("Settings.Secure hooked");
            } catch(e) { log("Settings.Secure hook failed: " + e); }

            // --- Telephony ---
            try {
                var TM = Java.use("android.telephony.TelephonyManager");
                TM.getDeviceId.overload().implementation = function() { return "355123456789012"; };
                try { TM.getDeviceId.overload('int').implementation = function(s) { return "355123456789012"; }; } catch(e){}
                try { TM.getImei.overload().implementation = function() { return "355123456789012"; }; } catch(e){}
                try { TM.getSubscriberId.overload().implementation = function() { return "310260123456789"; }; } catch(e){}
                log("Telephony hooked");
            } catch(e) { log("Telephony hook failed: " + e); }

            // --- Sensors ---
            try {
                var SensorManager = Java.use("android.hardware.SensorManager");
                var originalRegister = SensorManager.registerListener.overload('android.hardware.SensorEventListener','android.hardware.Sensor','int');
                originalRegister.implementation = function(listener, sensor, rate) {
                    log("Sensor registered: type=" + (sensor ? sensor.getType() : "null"));
                    return originalRegister.call(this, listener, sensor, rate);
                };
                log("SensorManager hooked");
            } catch(e) { log("SensorManager hook failed: " + e); }

            // --- Battery ---
            try {
                var Intent = Java.use("android.content.Intent");
                Intent.getIntExtra.overload('java.lang.String','int').implementation = function(key, def) {
                    if (key === "level") return 87;
                    if (key === "scale") return 100;
                    if (key === "voltage") return 4200;
                    if (key === "temperature") return 310;
                    if (key === "status") return 2;
                    if (key === "health") return 2;
                    if (key === "plugged") return 1;
                    if (key === "technology") return "Li-ion";
                    return this.getIntExtra(key, def);
                };
                log("Battery hooked");
            } catch(e) { log("Battery hook failed: " + e); }

            // --- PackageManager block emulator apps ---
            try {
                var PM = Java.use("android.content.pm.PackageManager");
                PM.getPackageInfo.overload('java.lang.String','int').implementation = function(pkg, flags) {
                    var s = pkg.toString().toLowerCase();
                    if (s.indexOf("ldplayer") !== -1 || s.indexOf("bluestacks") !== -1 ||
                        s.indexOf("nox") !== -1 || s.indexOf("memu") !== -1 ||
                        s.indexOf("emulator") !== -1) {
                        throw PM.NameNotFoundException.$new(pkg);
                    }
                    return this.getPackageInfo(pkg, flags);
                };
                log("PackageManager hooked");
            } catch(e) { log("PackageManager hook failed: " + e); }

            // --- Tencent Hawk Anti-Cheat ---
            try {
                var HawkNative = Java.use("com.tencent.hawk.bridge.HawkNative");
                var hawkMethods = ["checkEmulator", "checkAntiData"];
                hawkMethods.forEach(function(m) {
                    try {
                        var overloads = HawkNative[m].overloads;
                        overloads.forEach(function(ovl) {
                            ovl.implementation = function() {
                                log("HawkNative." + m + " -> 0");
                                return 0;
                            };
                        });
                    } catch(e) {}
                });
                log("HawkNative hooked");
            } catch(e) { log("HawkNative hook failed: " + e); }
        });
    } catch(e) { log("installJavaHooks error: " + e); }
}

function main() {
    log("=== Emulator Bypass Starting ===");

    try {
        Process.setExceptionHandler(function(details) {
            log("NATIVE CRASH: type=" + details.type + " address=" + details.address +
                " memory=" + (details.memory ? details.memory.address : "n/a") +
                " context pc=" + (details.context ? details.context.pc : "n/a"));
            return false;
        });
        log("Exception handler installed");
    } catch(e) {
        log("Exception handler failed: " + e);
    }

    installNativeHooks();

    // Quick Java check — LD Player's libhoudini breaks Frida Java bridge entirely
    setTimeout(function() {
        try {
            if (typeof Java !== 'undefined' && Java.available) {
                log("Java available, installing hooks");
                installJavaHooks();
            } else {
                log("Java unavailable (normal on LD Player), using native hooks only");
            }
        } catch(e) {
            log("Java check error: " + e);
        }
    }, 2000);
}

main();
