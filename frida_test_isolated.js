// Isolated test - only native props
var TEST_FLAGS = {
    antidetect: false,
    syscall: false,
    native_props: true,
    hawk_native: false
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
        var modules = Process.enumerateModules();
        var libc = modules.find(m => m.name === "libc.so" || (m.path && m.path.indexOf("libc.so") !== -1));
        if (!libc) { log("libc.so not found for syscall"); return; }
        var syscallFn = libc.findExportByName("syscall");
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

function findArm64Libc() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var m = modules[i];
        if (m.path && m.path.indexOf("arm64/nb/libc.so") !== -1) {
            return m;
        }
        if (m.name === "libc.so" && m.path && m.path.indexOf("lib64/arm64") !== -1) {
            return m;
        }
    }
    return Process.findModuleByName("libc.so");
}

function hookNativeLayer() {
    var libc = findArm64Libc();
    if (!libc) { log("libc.so not found"); return; }
    log("Using libc: " + libc.name + " @ " + libc.base + " path=" + (libc.path || "unknown"));
    var exports = libc.enumerateExports();
    var propGet = exports.find(s => s.name === "__system_property_get");
    if (propGet) {
        Interceptor.attach(propGet.address, {
            onEnter: function(args) { this.key = args[0].readUtf8String(); this.buf = args[1]; },
            onLeave: function(retval) {
                var val = this.buf.readUtf8String();
                if (val && val.indexOf("x86") !== -1 || val.indexOf("amd") !== -1 || val.indexOf("AMD") !== -1 || val.indexOf("rosc") !== -1 || val.indexOf("gapp") !== -1) {
                    log("SUS Prop " + this.key + " = " + val);
                }
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
    } else {
        log("__system_property_get not found in libc");
    }
}

function findModuleByMaps(name) {
    var maps = File.readAllText("/proc/self/maps");
    var lines = maps.split("\n");
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (line.indexOf(name) !== -1) {
            var parts = line.trim().split(/\s+/);
            if (parts.length >= 6) {
                var addrRange = parts[0];
                var path = parts[5];
                if (path.indexOf(name) !== -1) {
                    var base = ptr("0x" + addrRange.split("-")[0]);
                    log("Found " + name + " in maps @ " + base + " path=" + path);
                    return { name: name, base: base, path: path };
                }
            }
        }
    }
    return null;
}

function hookHawkNative() {
    var hawk = findModuleByMaps("libcubehawk.so");
    if (!hawk) {
        log("libcubehawk.so not found in maps");
        return;
    }

    function readElfExports(base) {
        var exports = [];
        try {
            var e_shoff = Memory.readU64(base.add(0x28));
            var e_shentsize = Memory.readU16(base.add(0x3A));
            var e_shnum = Memory.readU16(base.add(0x3C));
            var e_shstrndx = Memory.readU16(base.add(0x3E));
            if (e_shnum === 0 || e_shoff === 0) return exports;

            var shstrtabAddr = base.add(e_shoff).add(e_shstrndx * e_shentsize);
            var shstrtabOff = Memory.readU64(shstrtabAddr.add(0x18)).toNumber();
            var shstrtabSize = Memory.readU64(shstrtabAddr.add(0x20)).toNumber();
            var shstrtab = base.add(shstrtabOff);

            var dynsym = null, dynstr = null, dynstrAddr = null;
            for (var i = 0; i < e_shnum; i++) {
                var sh = base.add(e_shoff).add(i * e_shentsize);
                var sh_name = Memory.readU32(sh.add(0x00));
                var sh_type = Memory.readU32(sh.add(0x04));
                var sh_addr = Memory.readU64(sh.add(0x10)).toNumber();
                var sh_size = Memory.readU64(sh.add(0x20)).toNumber();
                var name = Memory.readUtf8String(shstrtab.add(sh_name));
                if (name === ".dynsym") dynsym = { addr: base.add(sh_addr), size: sh_size };
                if (name === ".dynstr") dynstr = { addr: base.add(sh_addr), size: sh_size };
            }
            if (!dynsym || !dynstr) return exports;

            var symSize = 24;
            for (var i = 0; i < dynsym.size / symSize; i++) {
                var sym = dynsym.addr.add(i * symSize);
                var st_name = Memory.readU32(sym.add(0x00));
                var st_value = Memory.readU64(sym.add(0x08)).toNumber();
                var st_info = Memory.readU8(sym.add(0x04));
                if (st_name === 0) continue;
                var symName = Memory.readUtf8String(dynstr.addr.add(st_name));
                if (symName && st_value !== 0) {
                    exports.push({ name: symName, address: base.add(st_value) });
                }
            }
        } catch(e) { log("readElfExports error: " + e); }
        return exports;
    }

    var exports = readElfExports(hawk.base);
    log("libcubehawk.so exports count: " + exports.length);
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
            log("Hooked " + sym + " @ " + exp.address);
        } else {
            log("Symbol not found: " + sym);
        }
    });
}

var openLogCount = 0;
function hookOpenFiles() {
    var libc = findArm64Libc();
    if (!libc) { log("libc.so not found for open hooks"); return; }
    log("Hooking open in: " + libc.name + " @ " + libc.base);

    var openFn = libc.findExportByName("open");
    var openatFn = libc.findExportByName("openat");
    var open64Fn = libc.findExportByName("open64");
    var openat64Fn = libc.findExportByName("openat64");
    var __openFn = libc.findExportByName("__open");
    var __openatFn = libc.findExportByName("__openat");

    var fakeCpuinfo = Memory.allocUtf8String("/data/local/tmp/fake_cpuinfo");
    var fakeBuildProp = Memory.allocUtf8String("/data/local/tmp/fake_build.prop");

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

    function attachOpen(name, addr, pathIdx) {
        if (addr && !addr.isNull()) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    var path = args[pathIdx].readUtf8String();
                    logOpen(path);
                    args[pathIdx] = redirectPath(args[pathIdx], path, args[pathIdx+1].toInt32());
                }
            });
            log("Hooked " + name);
        } else {
            log(name + " not found");
        }
    }

    attachOpen("open", openFn, 0);
    attachOpen("openat", openatFn, 1);
    attachOpen("open64", open64Fn, 0);
    attachOpen("openat64", openat64Fn, 1);
    attachOpen("__open", __openFn, 0);
    attachOpen("__openat", __openatFn, 1);
}

function main() {
    log("=== Isolated Test Starting ===");
    log("Flags: antidetect=" + TEST_FLAGS.antidetect +
        " syscall=" + TEST_FLAGS.syscall +
        " native_props=" + TEST_FLAGS.native_props +
        " hawk_native=" + TEST_FLAGS.hawk_native);
    if (TEST_FLAGS.antidetect) antiDetectFrida();
    if (TEST_FLAGS.syscall) hookSyscall();
    if (TEST_FLAGS.native_props) hookNativeLayer();
    if (TEST_FLAGS.hawk_native) hookHawkNative();
    hookOpenFiles();
    log("=== Hooks installed ===");
}

main();
