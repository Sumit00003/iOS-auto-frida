/*
 * enumerate_basic_info.js
 * Prints basic process/module info once attached. Useful as a first
 * sanity-check hook before loading anything more specific.
 */

send("[*] Attached. Process: " + ObjC.classes.NSProcessInfo.processInfo().processName());

try {
    var bundle = ObjC.classes.NSBundle.mainBundle();
    var info = bundle.infoDictionary();
    send("[*] Bundle ID : " + bundle.bundleIdentifier());
    send("[*] Version   : " + info.objectForKey_("CFBundleShortVersionString"));
    send("[*] Executable: " + bundle.executablePath());
} catch (e) {
    send("[!] Could not read bundle info: " + e);
}

send("[*] Loaded modules: " + Process.enumerateModules().length);
send("[*] Ready for further hooks.");
