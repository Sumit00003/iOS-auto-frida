/*
 * bypass_ssl_pinning.js – ENHANCED
 *
 * Disables SSL/TLS pinning patterns commonly seen in iOS apps.
 * This script covers:
 *   1. Security.framework: SecTrustEvaluate, SecTrustEvaluateWithError, SecTrustGetTrustResult
 *   2. SecTrustSetAnchorCertificates & SecTrustSetAnchorCertificatesOnly (custom anchors)
 *   3. SecTrustCopyCertificateChain & SecTrustGetCertificateAtIndex (chain manipulation)
 *   4. SecTrustCopyPublicKey & SecKeyCopyExternalRepresentation (public key pinning)
 *   5. NSURLSession/NSURLConnection delegate challenges
 *   6. TrustKit
 *   7. AFNetworking / Alamofire
 *   8. WKWebView challenges
 *   9. CFNetwork lower-level functions (CFURLConnection, CFHTTPMessage)
 *   10. Additional custom pinning via memcmp/CC_SHA256 heuristics
 */

// ---------------------------------------------------------------------
// 1) Security.framework – broadest single win
// ---------------------------------------------------------------------
var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
if (SecTrustEvaluate) {
    Interceptor.attach(SecTrustEvaluate, {
        onLeave: function (retval) {
            send("[ssl-bypass] SecTrustEvaluate -> forced errSecSuccess (0)");
            retval.replace(ptr(0));
        }
    });
}

var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
if (SecTrustEvaluateWithError) {
    Interceptor.attach(SecTrustEvaluateWithError, {
        onLeave: function (retval) {
            send("[ssl-bypass] SecTrustEvaluateWithError -> forced true");
            retval.replace(ptr(1));
        }
    });
}

var SecTrustGetTrustResult = Module.findExportByName("Security", "SecTrustGetTrustResult");
if (SecTrustGetTrustResult) {
    Interceptor.attach(SecTrustGetTrustResult, {
        onEnter: function (args) {
            this.resultPtr = args[1];
        },
        onLeave: function (retval) {
            if (this.resultPtr && !this.resultPtr.isNull()) {
                this.resultPtr.writeU32(1); // kSecTrustResultProceed
                send("[ssl-bypass] SecTrustGetTrustResult -> forced kSecTrustResultProceed");
            }
        }
    });
}

// ---------------------------------------------------------------------
// 2) Custom anchor certificates – apps may set their own trusted anchors
// ---------------------------------------------------------------------
var SecTrustSetAnchorCertificates = Module.findExportByName("Security", "SecTrustSetAnchorCertificates");
if (SecTrustSetAnchorCertificates) {
    Interceptor.attach(SecTrustSetAnchorCertificates, {
        onEnter: function (args) {
            send("[ssl-bypass] SecTrustSetAnchorCertificates intercepted – clearing custom anchors");
            // Replace with empty array (or null) to ignore custom anchors
            var emptyArray = ObjC.classes.NSArray.array();
            args[1] = emptyArray;
        }
    });
}

var SecTrustSetAnchorCertificatesOnly = Module.findExportByName("Security", "SecTrustSetAnchorCertificatesOnly");
if (SecTrustSetAnchorCertificatesOnly) {
    Interceptor.attach(SecTrustSetAnchorCertificatesOnly, {
        onEnter: function (args) {
            send("[ssl-bypass] SecTrustSetAnchorCertificatesOnly -> forced false (use system anchors)");
            args[1] = ptr(0); // false
        }
    });
}

// ---------------------------------------------------------------------
// 3) Certificate chain / public key manipulation
// ---------------------------------------------------------------------
var SecTrustCopyCertificateChain = Module.findExportByName("Security", "SecTrustCopyCertificateChain");
if (SecTrustCopyCertificateChain) {
    Interceptor.attach(SecTrustCopyCertificateChain, {
        onLeave: function (retval) {
            if (!retval.isNull()) {
                send("[ssl-bypass] SecTrustCopyCertificateChain -> returning empty chain");
                var emptyArray = ObjC.classes.NSArray.array();
                retval.replace(emptyArray);
            }
        }
    });
}

var SecTrustGetCertificateAtIndex = Module.findExportByName("Security", "SecTrustGetCertificateAtIndex");
if (SecTrustGetCertificateAtIndex) {
    Interceptor.attach(SecTrustGetCertificateAtIndex, {
        onLeave: function (retval) {
            // Force return of a dummy certificate? Complex. 
            // Instead, log and rely on other hooks.
            send("[ssl-bypass] SecTrustGetCertificateAtIndex called – relying on other hooks");
        }
    });
}

var SecTrustCopyPublicKey = Module.findExportByName("Security", "SecTrustCopyPublicKey");
if (SecTrustCopyPublicKey) {
    Interceptor.attach(SecTrustCopyPublicKey, {
        onLeave: function (retval) {
            // Return a dummy key? Hard. Log and rely on SecTrustEvaluate override.
            send("[ssl-bypass] SecTrustCopyPublicKey called – relying on SecTrustEvaluate override");
        }
    });
}

var SecKeyCopyExternalRepresentation = Module.findExportByName("Security", "SecKeyCopyExternalRepresentation");
if (SecKeyCopyExternalRepresentation) {
    Interceptor.attach(SecKeyCopyExternalRepresentation, {
        onLeave: function (retval) {
            // Could return fake data? Risky. Log and let memcmp handle.
            send("[ssl-bypass] SecKeyCopyExternalRepresentation called – memcmp hook will handle comparison");
        }
    });
}

// ---------------------------------------------------------------------
// 4) NSURLSession/NSURLConnection delegate challenge handling
// ---------------------------------------------------------------------
if (ObjC.available) {
    var challengeSelectors = [
        "URLSession:didReceiveChallenge:completionHandler:",
        "URLSession:task:didReceiveChallenge:completionHandler:",
        "connection:willSendRequestForAuthenticationChallenge:"
    ];

    Object.keys(ObjC.classes).forEach(function (className) {
        var cls = ObjC.classes[className];
        challengeSelectors.forEach(function (sel) {
            var method = cls["- " + sel];
            if (!method) return;
            try {
                Interceptor.attach(method.implementation, {
                    onEnter: function (args) {
                        send("[ssl-bypass] Intercepted " + sel + " in " + className);
                        try {
                            if (sel.indexOf("completionHandler") !== -1) {
                                var challenge = ObjC.Object(args[sel.indexOf("task:") !== -1 ? 4 : 3]);
                                var handlerArg = sel.indexOf("task:") !== -1 ? args[5] : args[4];
                                var completionHandler = new ObjC.Block(handlerArg);
                                var USE_CREDENTIAL = 0;
                                var credential = ObjC.classes.NSURLCredential.credentialForTrust_(
                                    challenge.protectionSpace().serverTrust()
                                );
                                completionHandler.implementation(USE_CREDENTIAL, credential);
                                this.replace = true;
                            }
                        } catch (e) {
                            send("[ssl-bypass] challenge override failed for " + className + ": " + e);
                        }
                    }
                });
            } catch (e) {}
        });
    });

    // TrustKit
    try {
        var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
        if (TSKPinningValidator) {
            var evalMethod = TSKPinningValidator["- evaluateTrust:forHostname:"];
            if (evalMethod) {
                Interceptor.attach(evalMethod.implementation, {
                    onLeave: function (retval) {
                        send("[ssl-bypass] TrustKit evaluateTrust:forHostname: -> forced success (0)");
                        retval.replace(ptr(0));
                    }
                });
            }
        }
    } catch (e) {}

    // AFNetworking
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            var evaluateServerTrust = AFSecurityPolicy["- evaluateServerTrust:forDomain:"];
            if (evaluateServerTrust) {
                Interceptor.attach(evaluateServerTrust.implementation, {
                    onLeave: function (retval) {
                        send("[ssl-bypass] AFSecurityPolicy evaluateServerTrust:forDomain: -> forced YES");
                        retval.replace(ptr(1));
                    }
                });
            }
        }
    } catch (e) {}

    // Alamofire – ServerTrustEvaluating (Swift) may not be exposed to ObjC.
    // We rely on SecTrustEvaluate hook and memcmp.

    // WKWebView challenges
    try {
        var navDelegateSel = "webView:didReceiveAuthenticationChallenge:completionHandler:";
        Object.keys(ObjC.classes).forEach(function (className) {
            var cls = ObjC.classes[className];
            var method = cls["- " + navDelegateSel];
            if (!method) return;
            try {
                Interceptor.attach(method.implementation, {
                    onEnter: function (args) {
                        send("[ssl-bypass] Intercepted WKWebView challenge in " + className);
                        var challenge = ObjC.Object(args[3]);
                        var completionHandler = new ObjC.Block(args[4]);
                        var USE_CREDENTIAL = 0;
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust_(
                            challenge.protectionSpace().serverTrust()
                        );
                        completionHandler.implementation(USE_CREDENTIAL, credential);
                    }
                });
            } catch (e) {}
        });
    } catch (e) {}
}

// ---------------------------------------------------------------------
// 5) Lower-level CFNetwork functions (bypass some custom implementations)
// ---------------------------------------------------------------------
var CFURLConnectionSendAsynchronousRequest = Module.findExportByName("CFNetwork", "CFURLConnectionSendAsynchronousRequest");
if (CFURLConnectionSendAsynchronousRequest) {
    // Complex to patch; we'll rely on NSURLSession hooks.
    send("[ssl-bypass] CFURLConnectionSendAsynchronousRequest found – rely on other hooks");
}

var CFHTTPMessageCreateRequest = Module.findExportByName("CFNetwork", "CFHTTPMessageCreateRequest");
if (CFHTTPMessageCreateRequest) {
    // Could alter request headers, but not pinning.
}

// ---------------------------------------------------------------------
// 6) Heuristic: memcmp/CC_SHA256 for manual hash comparisons
// ---------------------------------------------------------------------
var memcmp = Module.findExportByName(null, "memcmp");
if (memcmp) {
    Interceptor.attach(memcmp, {
        onEnter: function (args) {
            this.size = args[2].toInt32();
        },
        onLeave: function (retval) {
            if (this.size === 32 || this.size === 20) {
                if (retval.toInt32() !== 0) {
                    send("[ssl-adv-bypass] memcmp(" + this.size + " bytes) -> forced equal (likely hash compare)");
                    retval.replace(0);
                }
            }
        }
    });
}

var CC_SHA256 = Module.findExportByName(null, "CC_SHA256");
if (CC_SHA256) {
    // We can't easily override output, but we can log. The memcmp hook will catch the comparison.
    send("[ssl-bypass] CC_SHA256 found – memcmp hook will handle comparison");
}

send("[ssl-bypass] Enhanced SSL pinning hooks installed.");
