// Minimal bypass test - only property + GPU hooks
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

// Property spoofing
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

// GPU spoofing
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

function main() {
    log("=== MINIMAL BYPASS ===");
    try {
        Process.setExceptionHandler(function(details) {
            log("CRASH: type=" + details.type + " addr=" + details.address);
            return false;
        });
    } catch(e) {}
    hookPropertyGet();
    hookGlGetString();
    hookEglQueryString();
    log("=== DONE ===");
}

main();
