// Emulator bypass - DIAGNOSTIC VERSION
// Wrapped callbacks to identify TypeError source

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

// Wrap a callback to catch and log errors
function wrap(hookName, fn) {
    return function() {
        try {
            return fn.apply(this, arguments);
        } catch(e) {
            logError(hookName, e);
        }
    };
}

// Build fake maps file by filtering current process maps
function buildFakeMaps() {
    try {
        var f = new File(FAKE_MAPS_PATH, "r");
        f.close();
        log("Fake maps already exists");
    } catch(e) {
        log("Fake maps missing, skipping maps build");
    }
}

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

var fakeCpuinfo = Memory.allocUtf8String("/data/local/tmp/fake_cpuinfo");
var fakeBuildProp = Memory.allocUtf8String("/data/local/tmp/fake_build.prop");
var fakeStatus = Memory.allocUtf8String("/data/local/tmp/fake_status");
var fakeMaps = Memory.allocUtf8String(FAKE_MAPS_PATH);

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
    if (pathStr.indexOf("/sys/devices/system/cpu/") !== -1 && pathStr.indexOf("topology") !== -1) {
        log("Block topology: " + pathStr);
        var devnull = Memory.allocUtf8String("/dev/null");
        return devnull;
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

function patchTelemetry(plain) {
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

                if (str.indexOf("LeiDian") !== -1 || str.indexOf("X86") !== -1 || str === "EmulatorName" ||
                    str.indexOf("LDPlayer") !== -1 || str.indexOf("ldplayer") !== -1 ||
                    str.indexOf("x86") !== -1 || str.indexOf("houdini") !== -1) {
                    log("Patching EmulatorName at offset " + i + ": " + str);
                    var newVal = "SM-S928B";
                    out.push(0x03);
                    out.push(newVal.length);
                    for (var k = 0; k < newVal.length; k++) out.push(newVal.charCodeAt(k));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("GenericGPUBrand") !== -1 || str === "GLRender" ||
                           str.indexOf("Adreno") === -1 && str.indexOf("Mali") === -1 && str.indexOf("PowerVR") === -1 && str.length > 3) {
                    log("Patching GLRender at offset " + i + ": " + str);
                    var newVal2 = "Adreno (TM) 750";
                    out.push(0x03);
                    out.push(newVal2.length);
                    for (var k2 = 0; k2 < newVal2.length; k2++) out.push(newVal2.charCodeAt(k2));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("ASUS") !== -1 || str.indexOf("asus") !== -1 || str === "DeviceModel" ||
                           str.indexOf("ROG") !== -1 || str.indexOf("rog") !== -1 ||
                           str.indexOf("ai2401") !== -1 || str.indexOf("AI2401") !== -1) {
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
                } else if (str.indexOf("ROG+ASUS") !== -1 || str === "SystemHardware" ||
                           str.indexOf("ASUS") !== -1) {
                    log("Patching SystemHardware at offset " + i + ": " + str);
                    var newVal5 = "qcom+samsung";
                    out.push(0x03);
                    out.push(newVal5.length);
                    for (var k5 = 0; k5 < newVal5.length; k5++) out.push(newVal5.charCodeAt(k5));
                    i += 2 + l;
                    modified = true;
                } else if (str.indexOf("AuthenticAMD") !== -1 || str.indexOf("AMD") !== -1 || str.indexOf("Intel") !== -1) {
                    log("Patching CPU vendor at offset " + i + ": " + str);
                    var newVal6 = "ARM";
                    out.push(0x03);
                    out.push(newVal6.length);
                    for (var k6 = 0; k6 < newVal6.length; k6++) out.push(newVal6.charCodeAt(k6));
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

function readBufferSafe(ptr, len) {
    if (!ptr || ptr.isNull() || len <= 0 || len > 65535) return null;
    try {
        var raw = Memory.readByteArray(ptr, len);
        if (!raw) return null;
        return new Uint8Array(raw);
    } catch(e) { return null; }
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
                        if (family === 2) { // AF_INET
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
                    if (name === 0x1F00) { // GL_VENDOR
                        log("glGetString(GL_VENDOR) -> Qualcomm");
                        retval.replace(fakeGlVendor);
                    } else if (name === 0x1F01) { // GL_RENDERER
                        log("glGetString(GL_RENDERER) -> Adreno (TM) 750");
                        retval.replace(fakeGlRenderer);
                    } else if (name === 0x1B02) { // GL_VERSION
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
                if (n === 0x3053) { // EGL_VENDOR
                    log("eglQueryString(EGL_VENDOR) -> Qualcomm");
                    retval.replace(fakeEglVendor);
                } else if (n === 0x3054) { // EGL_VERSION
                    log("eglQueryString(EGL_VERSION) -> 1.5");
                    retval.replace(fakeEglVersion);
                }
            })
        });
        log("Hooked eglQueryString");
    } catch(e) { log("hookEglQueryString error: " + e); }
}

function hookWriteRead() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var exps = libc.enumerateExports();
        var writeAddr = null;
        var readAddr = null;
        for (var i = 0; i < exps.length; i++) {
            if (exps[i].name === "write") writeAddr = exps[i].address;
            if (exps[i].name === "read") readAddr = exps[i].address;
        }
        if (writeAddr && !writeAddr.isNull()) {
            Interceptor.attach(writeAddr, {
                onEnter: wrap("write.onEnter", function(args) {
                    var fd = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    if (fd >= 0) {
                        var newBuf = processSend(buf, len);
                        if (newBuf) args[1] = newBuf;
                    }
                })
            });
            log("Hooked write()");
        }
        if (readAddr && !readAddr.isNull()) {
            Interceptor.attach(readAddr, {
                onEnter: wrap("read.onEnter", function(args) {
                    this.bufPtr = args[1];
                }),
                onLeave: wrap("read.onLeave", function(retval) {
                    var n = retval.toInt32();
                    if (n > 0 && this.bufPtr) {
                        processRecv(this.bufPtr, n);
                    }
                })
            });
            log("Hooked read()");
        }
    } catch(e) { log("hookWriteRead error: " + e); }
}

function hookSSL() {
    try {
        var libssl = Process.findModuleByName("libssl.so");
        if (!libssl) {
            log("libssl.so not found");
            return;
        }
        var exps = libssl.enumerateExports();
        var sslWriteAddr = null;
        var sslReadAddr = null;
        for (var i = 0; i < exps.length; i++) {
            if (exps[i].name === "SSL_write") sslWriteAddr = exps[i].address;
            if (exps[i].name === "SSL_read") sslReadAddr = exps[i].address;
        }
        function installSSLWrite(addr) {
            if (!addr || addr.isNull()) return;
            Interceptor.attach(addr, {
                onEnter: wrap("SSL_write.onEnter", function(args) {
                    var buf = args[1];
                    var len = args[2].toInt32();
                    var newBuf = processSend(buf, len);
                    if (newBuf) args[1] = newBuf;
                })
            });
            log("Hooked SSL_write");
        }
        function installSSLRead(addr) {
            if (!addr || addr.isNull()) return;
            Interceptor.attach(addr, {
                onEnter: wrap("SSL_read.onEnter", function(args) {
                    this.bufPtr = args[1];
                }),
                onLeave: wrap("SSL_read.onLeave", function(retval) {
                    var n = retval.toInt32();
                    if (n > 0 && this.bufPtr) {
                        processRecv(this.bufPtr, n);
                    }
                })
            });
            log("Hooked SSL_read");
        }
        installSSLWrite(sslWriteAddr);
        installSSLRead(sslReadAddr);
    } catch(e) { log("hookSSL error: " + e); }
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
    // hookStrStr(); // disabled for testing
    hookSend();
    hookRecv();
    hookConnect();
    hookGlGetString();
    hookEglQueryString();
    hookWriteRead();
    hookSSL();
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
            try {
                var Build = Java.use("android.os.Build");
                var fields = {
                    "MODEL": "SM-S928B",
                    "DEVICE": "e3q",
                    "MANUFACTURER": "samsung",
                    "BRAND": "samsung",
                    "HARDWARE": "qcom",
                    "PRODUCT": "e3qxxx",
                    "BOARD": "e3q"
                };
                for (var key in fields) {
                    (function(k, v) {
                        try {
                            var field = Build.class.getDeclaredField(k);
                            field.setAccessible(true);
                            field.set(null, v);
                            log("Build." + k + " -> " + v);
                        } catch(e) {
                            log("Build." + k + " failed: " + e);
                        }
                    })(key, fields[key]);
                }
            } catch(e) { log("Build hook failed: " + e); }

            try {
                var SystemProperties = Java.use("android.os.SystemProperties");
                var origGet = SystemProperties.get.overload('java.lang.String');
                origGet.implementation = function(key) {
                    var fp = {
                        "ro.hardware": "qcom",
                        "ro.product.model": "SM-S928B",
                        "ro.product.device": "e3q",
                        "ro.product.brand": "samsung",
                        "ro.product.manufacturer": "samsung",
                        "ro.kernel.qemu": "0",
                        "ro.product.cpu.abi": "arm64-v8a",
                        "ro.arch": "arm64"
                    };
                    if (fp[key]) {
                        log("Java Prop " + key + " -> " + fp[key]);
                        return fp[key];
                    }
                    var val = origGet.call(this, key);
                    if (val && (val.indexOf("x86") !== -1 || val.indexOf("amd") !== -1 || val.indexOf("AMD") !== -1)) {
                        log("Java SUS Prop " + key + " = " + val);
                    }
                    return val;
                };
                log("SystemProperties.get hooked");
            } catch(e) { log("SystemProperties.get hook failed: " + e); }
        });
    } catch(e) { log("installJavaHooks error: " + e); }
}

function main() {
    log("=== Emulator Bypass Starting ===");
    installNativeHooks();

    // Defer Java hooks until runtime is ready
    var javaAttempts = 0;
    var javaInterval = setInterval(function() {
        javaAttempts++;
        try {
            if (typeof Java !== 'undefined' && Java.available) {
                clearInterval(javaInterval);
                installJavaHooks();
            } else if (javaAttempts > 100) {
                clearInterval(javaInterval);
                log("Java never became available");
            }
        } catch(e) {
            log("Java check error: " + e);
        }
    }, 100);
}

main();
