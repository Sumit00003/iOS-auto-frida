/*
 * bypass_proxy_detection.js – ENHANCED
 * 
 * Hides proxy configuration from the app. Now includes:
 *   - CFNetworkCopySystemProxySettings (main)
 *   - NSURLSessionConfiguration.connectionProxyDictionary
 *   - Also hook NSURLSessionConfiguration defaultConfiguration to clear proxy
 *   - Hook CFNetworkCopyProxiesForURL (if used)
 */

var CFNetworkCopySystemProxySettings = Module.findExportByName("CFNetwork", "CFNetworkCopySystemProxySettings");
if (CFNetworkCopySystemProxySettings) {
    Interceptor.attach(CFNetworkCopySystemProxySettings, {
        onLeave: function (retval) {
            if (retval.isNull()) return;
            try {
                var dict = new ObjC.Object(retval);
                send("[proxy-bypass] Reporting empty proxy settings to caller (real dict had " + dict.count() + " keys)");
                var empty = ObjC.classes.NSDictionary.dictionary();
                retval.replace(empty.handle);
            } catch (e) {
                send("[proxy-bypass] CFNetworkCopySystemProxySettings hook error: " + e);
            }
        }
    });
}

if (ObjC.available) {
    // NSURLSessionConfiguration connectionProxyDictionary
    try {
        var configClass = ObjC.classes.NSURLSessionConfiguration;
        var getter = configClass["- connectionProxyDictionary"];
        if (getter) {
            Interceptor.attach(getter.implementation, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        send("[proxy-bypass] connectionProxyDictionary -> reported nil");
                        retval.replace(ptr(0));
                    }
                }
            });
        }
        // Also override defaultConfiguration to remove proxy
        var defaultConfig = configClass["+ defaultSessionConfiguration"];
        if (defaultConfig) {
            Interceptor.attach(defaultConfig.implementation, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        var config = new ObjC.Object(retval);
                        config.setValue_forKey_(null, "connectionProxyDictionary");
                        send("[proxy-bypass] defaultSessionConfiguration cleared proxy dictionary");
                    }
                }
            });
        }
    } catch (e) {}

    // CFNetworkCopyProxiesForURL – sometimes used
    try {
        var copyProxies = Module.findExportByName("CFNetwork", "CFNetworkCopyProxiesForURL");
        if (copyProxies) {
            Interceptor.attach(copyProxies, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        send("[proxy-bypass] CFNetworkCopyProxiesForURL -> returning empty array");
                        var emptyArray = ObjC.classes.NSArray.array();
                        retval.replace(emptyArray);
                    }
                }
            });
        }
    } catch (e) {}
}

send("[proxy-bypass] Enhanced hooks installed.");
