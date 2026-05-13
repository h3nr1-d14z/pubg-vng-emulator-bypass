var maps = File.readAllText("/proc/self/maps");
var lines = maps.split("\n");
var seen = {};
lines.forEach(function(line) {
    var parts = line.trim().split(/\s+/);
    if (parts.length >= 6) {
        var path = parts[5];
        if (path && (path.indexOf("nb") !== -1 || path.indexOf("houdini") !== -1 || path.indexOf("bridge") !== -1 || path.indexOf("arm64") !== -1 || path.indexOf("aarch64") !== -1)) {
            if (!seen[path]) {
                seen[path] = true;
                console.log("BRIDGE: " + path);
            }
        }
    }
});
