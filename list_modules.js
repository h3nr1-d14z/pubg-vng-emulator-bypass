var modules = Process.enumerateModules();
console.log("Total modules: " + modules.length);
var libcs = modules.filter(m => m.name.indexOf("libc.so") !== -1 || (m.path && m.path.indexOf("libc.so") !== -1));
console.log("libc modules found: " + libcs.length);
libcs.forEach(function(m) {
    console.log("libc: name=" + m.name + " base=" + m.base + " path=" + (m.path || "null"));
});
