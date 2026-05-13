// Minimal test script to identify which hook breaks the game
var TEST_FLAGS = {
    antidetect: true,
    syscall: true,
    native_props: true,
    hawk_native: true
};

function log(msg) {
    console.log("[TEST] " + msg);
}

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
                    if (p && p.indexOf("/proc/") !== -1 && p.indexOf("maps") !== -1) {
                        if (p.indexOf("frida") !== -1 || p.indexOf("gadget") !== -1 || p.indexOf("server") !== -1) {
                            log("Hiding maps: " + p);
                            var devnull = Memory.allocUtf8String("/dev/null");
                            return func(devnull, mode);
                        }
                    }
                    return func(path, mode);
                }, 'pointer', ['pointer', 'pointer']));
                log("Hooked " + name);
            } catch(e) { log("Hook " + name + " failed: " + e); }
        }
        makeFopenHook(fopen, "fopen");
        makeFopenHook(fopen64, "fopen64");

        var ptrace = Module.getGlobalExportByName("ptrace");
        if (ptrace && !ptrace.isNull()) {
            var origPtrace = new NativeFunction(ptrace, 'long', ['int', 'int', 'pointer', 'pointer']);
            Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
                if (request === 0) { log("Blocked PTRACE_TRACEME"); return 0; }
                return origPtrace(request, pid, addr, data);
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
            log("Hooked ptrace");
        }
    } catch(e) { log("antiDetectFrida error: " + e); }
}

function hookSyscall() {
    try {
        var syscallFn = Process.findModuleByName("libc.so").findExportByName("syscall");
        if (syscallFn && !syscallFn.isNull()) {
            Interceptor.attach(syscallFn, {
                onEnter: function(args) {
                    var num = args[0].toInt32();
                    if (num === 206 || num === 207) {
                        log("syscall " + num + " (sendto/recvfrom)");
                    }
                }
            });
            log("Hooked syscall (logging only)");
        }
    } catch(e) { log("syscall hook failed: " + e); }
}

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
                if (fp[this.key]) {
                    log("Prop " + this.key + " -> " + fp[this.key]);
                    this.buf.writeUtf8String(fp[this.key]);
                    retval.replace(fp[this.key].length);
                }
            }
        });
        log("native __system_property_get hooked");
    }
}

var hawkRetryCount = 0;
function hookHawkNative() {
    var hawk = Process.findModuleByName("libcubehawk.so");
    if (!hawk) {
        hawkRetryCount++;
        if (hawkRetryCount % 10 === 0) log("libcubehawk.so not found after " + hawkRetryCount + " tries");
        setTimeout(hookHawkNative, 1000);
        return;
    }
    log("Found " + hawk.name + " at " + hawk.base);

    var exports = Module.enumerateExports(hawk.name);
    log("Exports count: " + exports.length);
    var targets = [
        "Java_com_tencent_hawk_bridge_HawkNative_checkEmulator",
        "Java_com_tencent_hawk_bridge_HawkNative_checkAntiData"
    ];
    targets.forEach(function(sym) {
        var exp = exports.find(e => e.name === sym);
        if (exp) {
            Interceptor.attach(exp.address, {
                onLeave: function(retval) {
                    log(sym + " -> 0");
                    retval.replace(0);
                }
            });
            log("Hooked " + sym);
        } else {
            log("Symbol not found: " + sym);
        }
    });
}

var openLogCount = 0;
function hookOpenFiles() {
    var libc = Process.findModuleByName("libc.so");
    if (!libc) { log("libc.so not found for open hooks"); return; }

    var openFn = libc.findExportByName("open");
    var openatFn = libc.findExportByName("openat");

    var fakeCpuinfo = Memory.allocUtf8String("/data/local/tmp/fake_cpuinfo");
    var fakeBuildProp = Memory.allocUtf8String("/data/local/tmp/fake_build.prop");
    var fakeStatus = Memory.allocUtf8String("/data/local/tmp/fake_status");

    function redirectPath(pathPtr, pathStr, flags) {
        if (!pathStr) return pathPtr;
        if (pathStr === "/proc/cpuinfo") {
            log("Redirect /proc/cpuinfo -> fake_cpuinfo");
            return fakeCpuinfo;
        }
        if (pathStr === "/system/build.prop") {
            log("Redirect /system/build.prop -> fake_build.prop");
            return fakeBuildProp;
        }
        if (pathStr === "/proc/self/status") {
            log("Redirect /proc/self/status -> fake_status");
            return fakeStatus;
        }
        return pathPtr;
    }

    function logOpen(pathStr) {
        if (!pathStr) return;
        openLogCount++;
        if (openLogCount <= 200) {
            var suspicious = ["/proc/", "/system/", "cpuinfo", "build.prop", "maps", "status", "x86", "amd", "ro.product", "frida", "gadget"];
            var isSus = suspicious.some(s => pathStr.indexOf(s) !== -1);
            if (isSus || openLogCount <= 50) {
                log("OPEN: " + pathStr);
            }
        }
    }

    if (openFn && !openFn.isNull()) {
        Interceptor.attach(openFn, {
            onEnter: function(args) {
                var path = args[0].readUtf8String();
                logOpen(path);
                args[0] = redirectPath(args[0], path, args[1].toInt32());
            }
        });
        log("Hooked open (redirecting)");
    }

    if (openatFn && !openatFn.isNull()) {
        Interceptor.attach(openatFn, {
            onEnter: function(args) {
                var path = args[1].readUtf8String();
                logOpen(path);
                args[1] = redirectPath(args[1], path, args[2].toInt32());
            }
        });
        log("Hooked openat (redirecting)");
    }
}

function main() {
    log("=== Minimal Test Starting ===");
    if (TEST_FLAGS.antidetect) antiDetectFrida();
    if (TEST_FLAGS.syscall) hookSyscall();
    if (TEST_FLAGS.native_props) hookNativeLayer();
    if (TEST_FLAGS.hawk_native) hookHawkNative();
    hookOpenFiles();
    log("=== Hooks installed ===");
}

main();
