// Frida Stealth Bypass — PUBG Mobile VNG
// Tich hop: anti-detection, syscall-level interception, XID patch, sensors, filesystem
// Muc tieu: khong de anti-cheat phat hien ra device da bi hook

var ANOGS_PORT = 17500;
var AES_KEY = null;
var AES_IV = new Uint8Array(16);
var IS_64BIT = Process.pointerSize === 8;
// Hardcoded SHA-256 of samsung|SM-S928B|e3q|qcom|14|UP1A.231005.007|S928BXXU1AWM9|pineapple|release-keys|user
var NEW_XID = "9fe5bc9ba47e3ed39c9b6860d2eb15d8bce6b2a95d24ec67eb152557b2883b4d";

function log(msg) {
    console.log("[STEALTH] " + msg);
}

// ============================================================================
// 1. ANTI-FRIDA DETECTION — Hide from /proc/self/maps and ptrace
// ============================================================================

function antiDetectFrida() {
    try {
        var fopen = Module.getGlobalExportByName("fopen");
        var fopen64 = Module.getGlobalExportByName("fopen64");

        function makeFopenHook(impl, name) {
            if (!impl || impl.isNull()) return;
            try {
                var func = new NativeFunction(impl, 'pointer', ['pointer', 'pointer']);
                Interceptor.replace(impl, new NativeCallback(function(path, mode) {
                    var p = path.readUtf8String();
                    if (p.indexOf("/proc/") !== -1 && p.indexOf("maps") !== -1) {
                        log("Hiding maps access: " + p);
                        var devnull = Memory.allocUtf8String("/dev/null");
                        return func(devnull, mode);
                    }
                    return func(path, mode);
                }, 'pointer', ['pointer', 'pointer']));
                log("Hooked " + name);
            } catch(e) {
                log("Hook " + name + " failed: " + e);
            }
        }

        makeFopenHook(fopen, "fopen");
        makeFopenHook(fopen64, "fopen64");

        var ptrace = Module.getGlobalExportByName("ptrace");
        if (ptrace && !ptrace.isNull()) {
            try {
                Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
                    if (request === 0) {
                        log("Blocked PTRACE_TRACEME");
                        return 0;
                    }
                    return -1;
                }, 'long', ['int', 'int', 'pointer', 'pointer']));
                log("Hooked ptrace");
            } catch(e) {
                log("Hook ptrace failed: " + e);
            }
        }
    } catch(e) {
        log("antiDetectFrida error: " + e);
    }
}

// ============================================================================
// 2. SYSCALL-LEVEL INTERCEPTION — ARM64 svc #0 hook for sendto/recvfrom
// ============================================================================

function hookSyscall() {
    try {
        var syscallFn = Process.findModuleByName("libc.so").findExportByName("syscall");
        if (syscallFn && !syscallFn.isNull()) {
            Interceptor.attach(syscallFn, {
                onEnter: function(args) {
                    var num = args[0].toInt32();
                    if (num === 206) {
                        this.isSend = true;
                        var res = processSend(args[2], args[3].toInt32());
                        if (res) {
                            args[2] = res.ptr;
                            args[3] = ptr(res.len.toString());
                        }
                    } else if (num === 207) {
                        this.isRecv = true;
                        this.bufPtr = args[2];
                        this.len = args[3].toInt32();
                    }
                },
                onLeave: function(retval) {
                    if (this.isRecv && retval.toInt32() > 0) {
                        extractKeyFromRecv(this.bufPtr, retval.toInt32());
                    }
                }
            });
            log("Hooked libc syscall()");
            hookSendRecvLibc();
        } else {
            throw new Error("syscall() not found");
        }
    } catch(e) {
        log("syscall() hook failed: " + e + ", falling back to send/recv hooks");
        hookSendRecvLibc();
    }
}

// Fallback libc hooks (also covers direct PLT calls)
function hookSendRecvLibc() {
    var sendto = Module.getGlobalExportByName("sendto");
    var send   = Module.getGlobalExportByName("send");
    var recvfrom = Module.getGlobalExportByName("recvfrom");
    var recv   = Module.getGlobalExportByName("recv");

    function attachSend(impl, name) {
        if (!impl || impl.isNull()) return;
        Interceptor.attach(impl, {
            onEnter: function(args) {
                var res = processSend(args[1], args[2].toInt32());
                if (res) {
                    args[1] = res.ptr;
                    args[2] = ptr(res.len.toString());
                }
            }
        });
        log("Hooked " + name + "()");
    }

    function attachRecv(impl, name) {
        if (!impl || impl.isNull()) return;
        Interceptor.attach(impl, {
            onEnter: function(args) {
                this.bufPtr = args[1];
            },
            onLeave: function(retval) {
                var n = retval.toInt32();
                if (n > 0 && this.bufPtr) {
                    extractKeyFromRecv(this.bufPtr, n);
                }
            }
        });
        log("Hooked " + name + "()");
    }

    attachSend(sendto, "sendto");
    attachSend(send, "send");
    attachRecv(recvfrom, "recvfrom");
    attachRecv(recv, "recv");
}

// ============================================================================
// 3. ANOGS PACKET PROCESSING
// ============================================================================

function parseAnogsHeader(buf) {
    return {
        magic: (buf[0] << 8) | buf[1],
        opcode: (buf[6] << 8) | buf[7],
        seq: (buf[11] << 24) | (buf[10] << 16) | (buf[9] << 8) | buf[8],
        body_len: (buf[15] << 24) | (buf[14] << 16) | (buf[13] << 8) | buf[12]
    };
}

function extractKeyFromRecv(bufPtr, len) {
    if (len < 32) return;
    var buf = new Uint8Array(bufPtr.readByteArray(len));
    if (buf[0] !== 0x33 || buf[1] !== 0x66) return;
    var hdr = parseAnogsHeader(buf);
    if (hdr.opcode !== 0x1002) return;

    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 22 > len) return;

    var tokenOffset = trailerOffset + 6;
    var tokenLen = 0;
    for (var i = 0; i < 16; i++) {
        if (buf[tokenOffset + i] !== 0) tokenLen++;
        else break;
    }
    if (tokenLen === 0) return;

    var key = new Uint8Array(16);
    for (var j = 0; j < 16; j++) {
        key[j] = j < tokenLen ? buf[tokenOffset + j] : 0;
    }
    AES_KEY = key.buffer;
    log("Extracted AES key from 0x1002: " + Array.from(key).map(b => ("0"+b.toString(16)).slice(-2)).join(""));
}

function callJavaAes(dataArray, keyArray, ivArray, mode) {
    if (typeof Java === 'undefined' || !Java.available) {
        log("callJavaAes: Java not ready, skipping AES op");
        return null;
    }
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
            // silent
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
        log("calcDeviceHash: Java not ready, using hardcoded XID");
        return NEW_XID;
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
            } catch (e) {
                log("calcDeviceHash inner error: " + e);
            }
        });
    } catch (e) {
        log("calcDeviceHash error: " + e);
    }
    return hash || NEW_XID;
}

function patchTelemetry(plain) {
    var out = [];
    var i = 0;
    var newXid = NEW_XID;
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
                    // Write Key TLV
                    out.push(0x03); out.push(klen);
                    for (var c = 0; c < klen; c++) out.push(kstr.charCodeAt(c));
                    i += 2 + klen;

                    // Patch Value TLV
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
    var buf = new Uint8Array(bufPtr.readByteArray(len));
    if (buf[0] !== 0x33 || buf[1] !== 0x66) return null;
    var hdr = parseAnogsHeader(buf);
    if (hdr.opcode !== 0x4013) return null;

    if (!AES_KEY) return null;

    var trailerOffset = 16 + hdr.body_len;
    if (trailerOffset + 6 >= len) return null;

    var encOffset = trailerOffset + 5;
    var encLen = len - encOffset;
    if (encLen <= 0) return null;

    var pad = 16 - (encLen % 16);
    if (pad === 16) pad = 0;

    var encrypted = buf.slice(encOffset, encOffset + encLen);
    var encryptedPadded = new Uint8Array(encLen + pad);
    encryptedPadded.set(encrypted);

    var keyArr = new Uint8Array(AES_KEY);
    var plain = callJavaAes(encryptedPadded, keyArr, AES_IV, "decrypt");
    if (!plain) return null;

    var patched = patchTelemetry(plain);
    var reEncrypted = callJavaAes(patched, keyArr, AES_IV, "encrypt");
    if (!reEncrypted) return null;

    var newLen = encOffset + reEncrypted.length;
    var newPacket = new Uint8Array(newLen);
    newPacket.set(buf.slice(0, encOffset));
    newPacket.set(reEncrypted, encOffset);

    var newBuf = Memory.alloc(newLen);
    newBuf.writeByteArray(newPacket.buffer);
    log("Patched 0x4013: " + len + " -> " + newLen);
    return {ptr: newBuf, len: newLen};
}

// ============================================================================
// 4. JAVA LAYER HOOKS — Build, Sensors, Battery, Filesystem
// ============================================================================

function hookJavaLayer() {
    Java.perform(function() {
        // --- Build ---
        var Build = Java.use("android.os.Build");
        var SP = Java.use("android.os.SystemProperties");

        var buildMap = {
            MODEL: "SM-S928B", DEVICE: "e3q", PRODUCT: "e3qxxx",
            MANUFACTURER: "samsung", BRAND: "samsung", HARDWARE: "qcom",
            FINGERPRINT: "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
            BOARD: "pineapple", BOOTLOADER: "S928BXXU1AWM9",
            ID: "UP1A.231005.007", HOST: "android-build",
            TAGS: "release-keys", TYPE: "user", USER: "dpi",
            DISPLAY: "S928BXXU1AWM9"
        };
        for (var k in buildMap) {
            try { Build[k].value = buildMap[k]; } catch(e) {}
        }
        log("Build patched");

        SP.get.overload('java.lang.String').implementation = function(key) {
            var fake = {
                "ro.hardware":"qcom","ro.product.model":"SM-S928B","ro.product.device":"e3q",
                "ro.product.brand":"samsung","ro.product.manufacturer":"samsung","ro.product.name":"e3qxxx",
                "ro.build.fingerprint":"samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
                "ro.build.product":"e3q","ro.board.platform":"pineapple","ro.bootloader":"S928BXXU1AWM9",
                "ro.build.id":"UP1A.231005.007","ro.build.tags":"release-keys","ro.build.type":"user",
                "ro.build.user":"dpi","ro.build.host":"android-build","ro.kernel.qemu":"0",
                "ro.hardware.vm":"0","init.svc.qemud":null,"qemu.hw.mainkeys":null,
                "ro.boot.hardware":"qcom","ro.product.board":"pineapple","ro.boot.qemu":"0"
            };
            if (fake.hasOwnProperty(key)) return fake[key] || null;
            var kl = key.toLowerCase();
            if (kl.indexOf("qemu")!==-1||kl.indexOf("ldplayer")!==-1||kl.indexOf("vbox")!==-1||
                kl.indexOf("hyperv")!==-1||kl.indexOf("virtio")!==-1) return null;
            return this.get(key);
        };
        log("SystemProperties hooked");

        // --- OpenGL ---
        var GLES20 = Java.use("android.opengl.GLES20");
        GLES20.glGetString.implementation = function(name) {
            if (name === 0x1F01) return "Qualcomm";
            if (name === 0x1F02) return "Adreno (TM) 750";
            if (name === 0x1F00) return "OpenGL ES 3.2 V@0750.0";
            return this.glGetString(name);
        };
        try {
            Java.use("android.opengl.GLES30").glGetString.implementation = GLES20.glGetString.implementation;
        } catch(e) {}
        log("OpenGL hooked");

        // --- NetworkInterface MAC ---
        try {
            var NI = Java.use("java.net.NetworkInterface");
            NI.getHardwareAddress.implementation = function() {
                var n = this.getName();
                if (n && n.toString().indexOf("wlan") !== -1) {
                    return Java.array('byte', [0x5c,0x02,0x14,0x12,0x34,0x56]);
                }
                if (n && (n.toString().indexOf("eth")!==-1||n.toString().indexOf("vbox")!==-1)) return null;
                return this.getHardwareAddress();
            };
            log("MAC hooked");
        } catch(e) {}

        // --- Settings.Secure ---
        try {
            var Secure = Java.use("android.provider.Settings$Secure");
            Secure.getString.overload('android.content.ContentResolver','java.lang.String').implementation = function(resolver, name) {
                if (name === "android_id") return "a1b2c3d4e5f67890";
                if (name === "bluetooth_name") return "Galaxy S24 Ultra";
                return this.getString(resolver, name);
            };
            log("Settings.Secure hooked");
        } catch(e) {}

        // --- Telephony ---
        try {
            var TM = Java.use("android.telephony.TelephonyManager");
            TM.getDeviceId.overload().implementation = function() { return "355123456789012"; };
            try { TM.getDeviceId.overload('int').implementation = function(s) { return "355123456789012"; }; } catch(e){}
            try { TM.getImei.overload().implementation = function() { return "355123456789012"; }; } catch(e){}
            try { TM.getSubscriberId.overload().implementation = function() { return "310260123456789"; }; } catch(e){}
            log("Telephony hooked");
        } catch(e) {}

        // --- Sensors ---
        try {
            var SensorManager = Java.use("android.hardware.SensorManager");
            var Sensor = Java.use("android.hardware.Sensor");
            SensorManager.getDefaultSensor.overload('int').implementation = function(type) {
                // Return null for sensors that real device might not have, or fake realistic values later
                // Most emulators return perfect zeros for accelerometer/gyro — we should hook registerListener
                return this.getDefaultSensor(type);
            };
            var originalRegister = SensorManager.registerListener.overload('android.hardware.SensorEventListener','android.hardware.Sensor','int');
            originalRegister.implementation = function(listener, sensor, rate) {
                // We could wrap listener to inject fake non-perfect values
                log("Sensor registered: type=" + (sensor ? sensor.getType() : "null"));
                return originalRegister.call(this, listener, sensor, rate);
            };
            log("SensorManager hooked");
        } catch(e) {}

        // --- BatteryManager ---
        try {
            var Intent = Java.use("android.content.Intent");
            var BMC = Java.use("android.os.BatteryManager");
            // Hooking Intent.getIntExtra for battery level/temperature/status
            Intent.getIntExtra.overload('java.lang.String','int').implementation = function(key, def) {
                if (key === "level") return 87;
                if (key === "scale") return 100;
                if (key === "voltage") return 4200;
                if (key === "temperature") return 310; // 31.0 C
                if (key === "status") return 2; // BATTERY_STATUS_CHARGING
                if (key === "health") return 2; // BATTERY_HEALTH_GOOD
                if (key === "plugged") return 1; // AC
                if (key === "technology") return "Li-ion";
                return this.getIntExtra(key, def);
            };
            log("Battery hooked");
        } catch(e) {}

        // --- PackageManager block emulator apps ---
        try {
            var PM = Java.use("android.content.pm.PackageManager");
            PM.getPackageInfo.overload('java.lang.String','int').implementation = function(pkg, flags) {
                var s = pkg.toString();
                if (s.indexOf("ldplayer")!==-1||s.indexOf("bluestacks")!==-1||s.indexOf("nox")!==-1||
                    s.indexOf("memu")!==-1||s.indexOf("emulator")!==-1) {
                    throw PM.NameNotFoundException.$new(pkg);
                }
                return this.getPackageInfo(pkg, flags);
            };
            log("PackageManager hooked");
        } catch(e) {}

        // --- Tencent Hawk Anti-Cheat ---
        try {
            var HawkNative = Java.use("com.tencent.hawk.bridge.HawkNative");
            try {
                HawkNative.checkEmulator.overload().implementation = function() {
                    log("HawkNative.checkEmulator() -> 0");
                    return 0;
                };
            } catch(e) {}
            try {
                HawkNative.checkEmulator.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
                    log("HawkNative.checkEmulator(" + a + ", " + b + ") -> 0");
                    return 0;
                };
            } catch(e) {}
            try {
                HawkNative.checkAntiData.overload().implementation = function() {
                    log("HawkNative.checkAntiData() -> 0");
                    return 0;
                };
            } catch(e) {}
            log("HawkNative hooked");
        } catch(e) {}
    });
}

// ============================================================================
// 5. NATIVE LAYER HOOKS — __system_property_get, CPU info, stat
// ============================================================================

function hookNativeLayer() {
    var libc = Process.findModuleByName("libc.so");
    if (!libc) { log("libc.so not found"); return; }

    var exports = libc.enumerateExports();
    var propGet = exports.find(s => s.name === "__system_property_get");
    if (propGet) {
        Interceptor.attach(propGet.address, {
            onEnter: function(args) { this.key = args[0].readUtf8String(); this.buf = args[1]; },
            onLeave: function(retval) {
                var fp = {"ro.hardware":"qcom","ro.product.model":"SM-S928B","ro.product.device":"e3q",
                          "ro.product.brand":"samsung","ro.product.manufacturer":"samsung","ro.kernel.qemu":"0"};
                if (fp[this.key]) { this.buf.writeUtf8String(fp[this.key]); retval.replace(fp[this.key].length); }
            }
        });
        log("native __system_property_get hooked");
    }
}

// ============================================================================
// 6. XID HASH RECALCULATION (if we can locate the native hash function)
// ============================================================================

function hookXIDGenerator() {
    // Strategy: scan libanogs.so for strings related to XID or SHA256 computation.
    // Without RE, we fallback to patching the decrypted payload (done in processSend).
    // If you find the hash function via reverse engineering, add Interceptor.attach here.
    log("XID hook: relying on network payload patch. Add native hash hook here if RE reveals symbol.");
}

// ============================================================================
// MAIN
// ============================================================================

function installJavaHooks() {
    if (typeof Java === 'undefined' || !Java.available) {
        log("Java not available yet, retrying in 500ms...");
        setTimeout(installJavaHooks, 500);
        return;
    }
    try {
        var computed = calcDeviceHash();
        if (computed) NEW_XID = computed;
        log("Precomputed XID: " + NEW_XID);
        hookJavaLayer();
        log("=== Java hooks installed ===");
    } catch (e) {
        log("installJavaHooks error: " + e);
        setTimeout(installJavaHooks, 500);
    }
}

function main() {
    log("=== Stealth Bypass Starting ===");
    antiDetectFrida();
    hookSyscall();
    hookNativeLayer();
    hookXIDGenerator();
    log("=== Native hooks installed ===");
    installJavaHooks();
}

main();
