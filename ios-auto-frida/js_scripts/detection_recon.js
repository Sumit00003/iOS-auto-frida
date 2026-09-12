/*
 * detection_recon.js
 *
 * PASSIVE ONLY — patches nothing. Logs which pinning/detection
 * primitives the target app actually calls, across every technique
 * family apps commonly use, so you know which bypass script(s) are
 * actually relevant before loading anything blind. Run this alone
 * first, interact with the app (trigger a login/API call), and read
 * the [recon] lines.
 *
 * Categories covered:
 *   1. Jailbreak indicator checks (paths, URL schemes, native calls)
 *   2. Security.framework certificate/trust APIs
 *   3. URL Loading System (NSURLSession/NSURLConnection) delegate methods
 *   4. Third-party networking libraries (presence + key entry points)
 *   5. Manual chain/public-key pinning primitives
 *   6. Native TLS libraries bundled by the app (OpenSSL/BoringSSL/LibreSSL)
 *   7. Apple's newer Network.framework / sec_protocol_options
 *   8. Proxy-configuration checks
 */

function logOnce(tag, detail) {
    send("[recon] " + tag + (detail !== undefined ? (": " + detail) : ""));
}

// ---------------------------------------------------------------------
// 1) Jailbreak indicators (quick pass — see bypass_jailbreak_detection.js
// for the full list this cross-references)
// ---------------------------------------------------------------------
const jbHints = ["Cydia", "Sileo", "Zebra", "MobileSubstrate", "apt", "/bin/bash",
                 "sshd", "ssh-keysign", "cycript", "substrate", "frida"];

if (ObjC.available) {
    ["fileExistsAtPath:", "isReadableFileAtPath:"].forEach(function (sel) {
        var m = ObjC.classes.NSFileManager["- " + sel];
        if (!m) return;
        Interceptor.attach(m.implementation, {
            onEnter: function (args) {
                try {
                    var path = ObjC.Object(args[2]).toString();
                    for (var i = 0; i < jbHints.length; i++) {
                        if (path.indexOf(jbHints[i]) !== -1) { logOnce("NSFileManager " + sel, path); break; }
                    }
                } catch (e) {}
            }
        });
    });
}
["fork", "system", "popen", "ptrace"].forEach(function (fn) {
    var addr = Module.findExportByName(null, fn);
    if (addr) Interceptor.attach(addr, { onEnter: function () { logOnce("native call: " + fn + "()"); } });
});

// ---------------------------------------------------------------------
// 2) Security.framework certificate/trust APIs
// ---------------------------------------------------------------------
const securityExports = [
    "SecTrustEvaluate", "SecTrustEvaluateWithError", "SecTrustGetTrustResult",
    "SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificatesOnly",
    "SecTrustCopyProperties", "SecTrustSetPolicies", "SecPolicyCreateSSL",
    "SecPolicyCreateBasicX509", "SecCertificateCopyData",
    "SecCertificateCopyNormalizedIssuerSequence", "SecCertificateCopyNormalizedSubjectSequence",
    "SecTrustCopyCertificateChain", "SecTrustGetCertificateAtIndex", "SecTrustGetCertificateCount",
    "SecTrustCopyKey", "SecKeyCopyExternalRepresentation", "SecKeyCopyPublicKey"
];
securityExports.forEach(function (name) {
    var addr = Module.findExportByName("Security", name);
    if (addr) {
        Interceptor.attach(addr, { onEnter: function () { logOnce("Security.framework: " + name + "()"); } });
    }
});

// ---------------------------------------------------------------------
// 3) URL Loading System delegate methods
// ---------------------------------------------------------------------
if (ObjC.available) {
    const urlDelegateSelectors = [
        "URLSession:didReceiveChallenge:completionHandler:",
        "URLSession:task:didReceiveChallenge:completionHandler:",
        "URLSession:dataTask:didReceiveChallenge:completionHandler:",
        "connection:canAuthenticateAgainstProtectionSpace:",
        "connection:didReceiveAuthenticationChallenge:",
        "connection:willSendRequestForAuthenticationChallenge:"
    ];
    var loggedClasses = {};
    Object.keys(ObjC.classes).forEach(function (className) {
        var cls = ObjC.classes[className];
        urlDelegateSelectors.forEach(function (sel) {
            var m = cls["- " + sel];
            if (!m) return;
            try {
                Interceptor.attach(m.implementation, {
                    onEnter: function () {
                        var key = className + "#" + sel;
                        if (!loggedClasses[key]) {
                            loggedClasses[key] = true;
                            logOnce("URL Loading delegate", className + " implements " + sel);
                        }
                    }
                });
            } catch (e) {}
        });
    });
}

// ---------------------------------------------------------------------
// 4) Third-party networking libraries — presence + key entry points
// ---------------------------------------------------------------------
if (ObjC.available) {
    const libraryClasses = {
        "AFNetworking": ["AFSecurityPolicy", "AFHTTPSessionManager"],
        "Alamofire": ["Alamofire.ServerTrustManager", "Alamofire.SessionDelegate", "Alamofire.Session"],
        "TrustKit": ["TSKPinningValidator", "TrustKit"],
        "Starscream": ["WebSocket", "SSLSecurity", "SSLCert"],
        "gRPC": ["GRPCCall", "GRPCChannel", "GRPCCallOptions"],
        "CocoaAsyncSocket": ["GCDAsyncSocket", "GCDAsyncSocketDelegate"],
        "ASIHTTPRequest": ["ASIHTTPRequest"]
    };
    Object.keys(libraryClasses).forEach(function (lib) {
        libraryClasses[lib].forEach(function (cls) {
            if (ObjC.classes[cls]) {
                logOnce("Library present", lib + " (found class " + cls + ")");
            }
        });
    });

    // Alamofire's ServerTrustEvaluating conformers are usually plain
    // Swift and may not surface individual methods to the ObjC
    // runtime, but the class itself showing up above is a strong signal.
    var afSecPolicy = ObjC.classes.AFSecurityPolicy;
    if (afSecPolicy) {
        var evalMethod = afSecPolicy["- evaluateServerTrust:forDomain:"];
        if (evalMethod) {
            Interceptor.attach(evalMethod.implementation, {
                onEnter: function () { logOnce("AFSecurityPolicy evaluateServerTrust:forDomain: called"); }
            });
        }
    }
    var tsk = ObjC.classes.TSKPinningValidator;
    if (tsk) {
        var tskEval = tsk["- evaluateTrust:forHostname:"];
        if (tskEval) {
            Interceptor.attach(tskEval.implementation, {
                onEnter: function () { logOnce("TrustKit evaluateTrust:forHostname: called"); }
            });
        }
    }
}

// ---------------------------------------------------------------------
// 5) Manual chain / public-key pinning primitives
// (already partly covered above under Security.framework; flagged
// again here specifically because seeing these WITHOUT SecTrustEvaluate
// being the final word is the signature of manual pinning)
// ---------------------------------------------------------------------
["memcmp", "CC_SHA256"].forEach(function (fn) {
    var addr = Module.findExportByName(null, fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // Extremely chatty if hooked unconditionally — only log
                // a sample so recon output stays readable.
                if (!this.__sampled && Math.random() < 0.05) {
                    this.__sampled = true;
                    logOnce("native call: " + fn + "() (sampled — may be cert/pubkey hash comparison)");
                }
            }
        });
    }
});

// ---------------------------------------------------------------------
// 6) Native TLS libraries bundled by the app
// ---------------------------------------------------------------------
const nativeTlsExports = [
    "SSL_CTX_set_verify", "SSL_get_verify_result", "SSL_get_peer_certificate",
    "X509_verify_cert", "SSL_CTX_new", "SSL_new"
];
Process.enumerateModules().forEach(function (mod) {
    var lname = mod.name.toLowerCase();
    if (lname.indexOf("ssl") !== -1 || lname.indexOf("crypto") !== -1 || lname.indexOf("boringssl") !== -1) {
        logOnce("Native TLS module loaded", mod.name);
    }
});
nativeTlsExports.forEach(function (name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, { onEnter: function () { logOnce("Native TLS call: " + name + "()"); } });
    }
});

// ---------------------------------------------------------------------
// 7) Network.framework (Apple's newer stack)
// ---------------------------------------------------------------------
["nw_connection_create", "nw_parameters_create_secure_tcp",
 "sec_protocol_options_set_verify_block", "sec_protocol_options_set_peer_authentication_required"
].forEach(function (name) {
    var addr = Module.findExportByName("Network", name) || Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, { onEnter: function () { logOnce("Network.framework: " + name + "()"); } });
    }
});

// ---------------------------------------------------------------------
// 8) Proxy configuration checks
// ---------------------------------------------------------------------
var proxyCheck = Module.findExportByName("CFNetwork", "CFNetworkCopySystemProxySettings");
if (proxyCheck) {
    Interceptor.attach(proxyCheck, { onEnter: function () { logOnce("CFNetworkCopySystemProxySettings called (proxy check)"); } });
}

send("[recon] Passive hooks installed across all categories — interact with the app now.");
