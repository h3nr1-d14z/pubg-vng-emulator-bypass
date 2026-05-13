// Stealth bypass - property + GPU + file hooks + thread renaming + agent string wipe
function log(msg) { console.log("[STEALTH] " + msg); }

function safeReadUtf8(ptr) {
    try { if (!ptr || ptr.isNull()) return null; return ptr.readUtf8String(); } catch(e) { return null; }
}

function wrap(name, fn) {
    return function() {
        try { return fn.apply(this, arguments); }
        catch(e) { log("ERR " + name + ": " + e); }
    };
}

// ==================== THREAD RENAMING ====================

var _setnameFn = null;

function renameFridaThreads() {
    try {
        if (!_setnameFn) {
            var pthread = Process.findModuleByName("libc.so");
            if (!pthread) return;
            var setname = pthread.findExportByName("pthread_setname_np");
            if (!setname || setname.isNull()) return;
            _setnameFn = new NativeFunction(setname, 'int', ['pointer', 'pointer']);
        }

        var newNames = ["RenderThread", "WorkerThread", "JobThread", "GLThread", "NetworkThread", "IOThread", "AudioThread"];
        var threads = Process.enumerateThreads();
        var nameIdx = 0;
        for (var i = 0; i < threads.length; i++) {
            var t = threads[i];
            var tname = t.name || "";
            // Only rename threads with suspicious names (Frida/agent/gum related)
            if (tname.indexOf("frida") !== -1 || tname.indexOf("gum") !== -1 ||
                tname.indexOf("agent") !== -1 || tname === "threaded-ml") {
                var newNameStr = newNames[nameIdx % newNames.length];
                var newName = Memory.allocUtf8String(newNameStr);
                _setnameFn(ptr(t.id), newName);
                log("Renamed thread " + t.id + " (" + tname + ") -> " + newNameStr);
                nameIdx++;
            }
        }
    } catch(e) { log("renameFridaThreads error: " + e); }
}

// ==================== MEMORY WIPE ====================

function wipeFridaStrings() {
    try {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var mod = modules[i];
            if (mod.name.indexOf("frida") !== -1 || mod.name.indexOf("gum") !== -1) {
                log("Found module: " + mod.name + " at " + mod.base);
                // We can't easily unload it, but we can try to overwrite some strings
            }
        }
    } catch(e) { log("wipeFridaStrings error: " + e); }
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

        var x86Hide = {
            "dalvik.vm.isa.x86.features": true,
            "dalvik.vm.isa.x86.variant": true,
            "dalvik.vm.isa.x86_64.features": true,
            "dalvik.vm.isa.x86_64.variant": true,
            "ro.dalvik.vm.native.bridge": true,
            "ro.enable.native.bridge.exec": true,
            "ro.enable.native.bridge.exec64": true
        };

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
            "ro.vendor.product.cpu.abi": "arm64-v8a",
            "ro.vendor.product.cpu.abilist": "arm64-v8a,armeabi-v7a,armeabi",
            "ro.vendor.product.cpu.abilist32": "armeabi-v7a,armeabi",
            "ro.vendor.product.cpu.abilist64": "arm64-v8a",
            "ro.dalvik.vm.isa.arm": "arm64-v8a",
            "ro.dalvik.vm.isa.arm64": "arm64-v8a",
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
            "ro.build.fingerprint": "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
            "ro.bootimage.build.fingerprint": "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
            "ro.vendor.build.fingerprint": "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AWM9:user/release-keys",
            "ro.build.version.incremental": "S928BXXU1AWM9",
            "ro.build.version.security_patch": "2024-01-01",
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

        var fpPtrs = {};
        for (var k in fp) { fpPtrs[k] = Memory.allocUtf8String(fp[k]); }

        function applyPropSpoof(key, valuePtr) {
            if (!key || !valuePtr) return false;
            if (x86Hide[key]) {
                log("Hide x86 prop: " + key);
                valuePtr.writeUtf8String("");
                return true;
            }
            if (fp[key]) {
                log("Prop " + key + " -> " + fp[key]);
                valuePtr.writeUtf8String(fp[key]);
                return true;
            }
            return false;
        }

        Interceptor.attach(addr, {
            onEnter: wrap("prop.onEnter", function(args) {
                this.key = safeReadUtf8(args[0]);
                this.buf = args[1];
            }),
            onLeave: wrap("prop.onLeave", function(retval) {
                if (!this.key || !this.buf) return;
                if (applyPropSpoof(this.key, this.buf)) {
                    retval.replace(fp[this.key] ? fp[this.key].length : 0);
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
    "/data/adb/magisk", "/data/adb/ksu",
    "/system/bin/houdini", "/system/bin/houdini64",
    "/system/lib/libhoudini.so", "/system/lib64/libhoudini.so",
    "/system/lib/libnb.so", "/system/lib64/libnb.so"
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

function hookSyscall() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;
        var syscall = libc.findExportByName("syscall");
        if (!syscall || syscall.isNull()) return;
        Interceptor.attach(syscall, {
            onEnter: wrap("syscall", function(args) {
                var num = args[0].toInt32();
                // openat syscall on arm64 = 56, on x86_64 = 257
                if (num === 56 || num === 257) {
                    var path = safeReadUtf8(args[1]);
                    if (path && (path === "/proc/self/maps" || path === "/proc/self/status")) {
                        log("syscall openat: " + path);
                    }
                }
            })
        });
        log("Hooked syscall()");
    } catch(e) { log("hookSyscall error: " + e); }
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

// ==================== MAIN ====================

function main() {
    log("=== Stealth Bypass Starting ===");
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
    // hookSyscall(); // DISABLED: causes game freeze on libhoudini
    hookGlGetString();
    hookEglQueryString();
    hookPtrace();

    // Stealth measures
    renameFridaThreads();
    wipeFridaStrings();

    // Periodic thread re-check (every 30s to avoid overhead)
    setInterval(function() {
        renameFridaThreads();
    }, 30000);

    log("=== Stealth Bypass Ready ===");
}

main();
