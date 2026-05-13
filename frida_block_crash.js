// Block anti-cheat self-kill by replacing abort/assert/exit
function log(msg) { console.log("[BLOCK] " + msg); }

function blockAbort() {
    try {
        var libc = Process.findModuleByName("libc.so");
        if (!libc) return;

        function replaceNoop(name) {
            var addr = libc.findExportByName(name);
            if (!addr || addr.isNull()) return;
            var noop = new NativeCallback(function() {
                log("BLOCKED " + name + "() call");
            }, 'void', []);
            Interceptor.replace(addr, noop);
            log("Replaced " + name + " with no-op");
        }

        function replaceExit(name) {
            var addr = libc.findExportByName(name);
            if (!addr || addr.isNull()) return;
            var fn = new NativeCallback(function(code) {
                log("BLOCKED " + name + "(" + code + ")");
            }, 'void', ['int']);
            Interceptor.replace(addr, fn);
            log("Replaced " + name + " with no-op");
        }

        replaceNoop("abort");
        replaceExit("exit");
        replaceExit("_exit");
        replaceExit("__exit");

        // Also hook __android_log_assert which often calls abort
        var logAssert = libc.findExportByName("__android_log_assert");
        if (logAssert && !logAssert.isNull()) {
            var noopAssert = new NativeCallback(function(cond, tag, fmt) {
                log("BLOCKED __android_log_assert: " + (tag ? Memory.readUtf8String(tag) : "null"));
            }, 'void', ['pointer', 'pointer', 'pointer']);
            Interceptor.replace(logAssert, noopAssert);
            log("Replaced __android_log_assert with no-op");
        }

        // Hook tgkill to block SIGABRT (signal 6)
        var tgkill = libc.findExportByName("tgkill");
        if (tgkill && !tgkill.isNull()) {
            Interceptor.attach(tgkill, {
                onEnter: function(args) {
                    var sig = args[2].toInt32();
                    if (sig === 6) {
                        log("BLOCKED tgkill(SIGABRT)");
                        args[2] = ptr(0); // replace with signal 0 (no-op)
                    }
                }
            });
            log("Hooked tgkill to block SIGABRT");
        }

        // Hook raise to block SIGABRT
        var raise = libc.findExportByName("raise");
        if (raise && !raise.isNull()) {
            Interceptor.attach(raise, {
                onEnter: function(args) {
                    var sig = args[0].toInt32();
                    if (sig === 6) {
                        log("BLOCKED raise(SIGABRT)");
                        args[0] = ptr(0);
                    }
                }
            });
            log("Hooked raise to block SIGABRT");
        }

    } catch(e) { log("blockAbort error: " + e); }
}

function main() {
    log("=== Crash Blocker Starting ===");
    try {
        Process.setExceptionHandler(function(details) {
            log("EXCEPTION: type=" + details.type + " addr=" + details.address);
            return false;
        });
    } catch(e) {}
    blockAbort();
    log("=== Crash Blocker Ready ===");
}

main();
