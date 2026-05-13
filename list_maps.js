var maps = File.readAllText("/proc/self/maps");
var lines = maps.split("\n");
var seen = {};
lines.forEach(function(line) {
    if (line.indexOf("libc.so") !== -1) {
        var parts = line.trim().split(/\s+/);
        var path = parts.length >= 6 ? parts[5] : "";
        if (path && !seen[path]) {
            seen[path] = true;
            var base = "0x" + parts[0].split("-")[0];
            console.log("MAPS libc: base=" + base + " path=" + path);
        }
    }
});
