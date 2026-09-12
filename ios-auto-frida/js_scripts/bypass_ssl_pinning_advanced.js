/*
 * bypass_ssl_pinning_advanced.js
 *
 * Covers the pinning implementations that keep working even after
 * bypass_ssl_pinning.js patches SecTrustEvaluate — because the app
 * does its own comparison *after* the system trust check passes, or
 * bypasses Security.framework entirely with a bundled TLS stack.
 *
 * Load this ALONGSIDE bypass_ssl_pinning.js, not instead of it — the
 * two target different points in the validation flow. Run
 * detection_recon.js first to confirm which of these actually apply
 * to your target before assuming you need all of them.
 *
 * Sections:
 *   A. Manual DER-certificate / SHA-256 pinning
 *   B. Public-key / SPKI pinning
 *   C. Native TLS libraries (OpenSSL / BoringSSL / LibreSSL)
 *   D. Apple's Network.framework (sec_protocol_options)
 *
 * IMPORTANT CAVEAT: Sections A and B use heuristics (patching generic
 * comparison primitives) because the actual hash/bytes being compared
 * against are hardcoded inside the target app and unknown to us ahead
 * of time. Heuristic hooks can produce false positives in a chatty
 * app; if something breaks, comment out the relevant section and
 * instead find the app's specific comparison call via
 * detection_recon.js + a disassembler and hook that exact call site.
 */

// ---------------------------------------------------------------------
// A. Manual DER-certificate pinning
//
// Typical flow: SecTrustCopyCertificateChain/SecTrustGetCertificateAtIndex
// -> SecCertificateCopyData -> CC_SHA256 -> memcmp against a hardcoded
// hash. We can't know the hardcoded hash, but we CAN make the final
// comparison always report "equal" — this is the same heuristic
// SSL-pinning bypass tools have used for years, scoped as tightly as
// possible (short, hash-length buffers only) to reduce collateral hits
// on unrelated memcmp() calls elsewhere in the app.
// ---------------------------------------------------------------------
var memcmp = Module.findExportByName(null, "memcmp");
if (memcmp) {
    Interceptor.attach(memcmp, {
        onEnter: function (args) {
            this.size = args[2].toInt32();
        },
        onLeave: function (retval) {
            // SHA-256 digests are 32 bytes; SHA-1 are 20. Restrict the
            // heuristic to those exact lengths so we don't blanket-patch
            // every memcmp() in the process (string comparisons, etc).
            if (this.size === 32 || this.size === 20) {
                if (retval.toInt32() !== 0) {
                    send("[ssl-adv-bypass] memcmp(" + this.size + " bytes) -> forced equal (likely hash compare)");
                    retval.replace(0);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------
// B. Public-key / SPKI pinning
//
// Flow: SecTrustCopyKey/SecKeyCopyPublicKey -> SecKeyCopyExternalRepresentation
// -> hash -> compare. Same caveat as above: we can't forge the "right"
// key bytes, so the practical move is to log every call (so you can see
// pinning is SPKI-based) and rely on the memcmp/CC_SHA256 hooks above
// to catch the final comparison, since the hashing step is common to
// both certificate and public-key pinning.
// ---------------------------------------------------------------------
["SecTrustCopyKey", "SecKeyCopyExternalRepresentation", "SecKeyCopyPublicKey"].forEach(function (name) {
    var addr = Module.findExportByName("Security", name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function () { send("[ssl-adv-bypass] " + name + "() called (SPKI pinning path) — see memcmp hook for the actual comparison"); }
        });
    }
});

// ---------------------------------------------------------------------
// C. Native TLS libraries bundled by the app (OpenSSL / BoringSSL / LibreSSL)
//
// These bypass Security.framework/CFNetwork entirely, so section-A/B
// hooks above won't see them. Symbol names are consistent across the
// three libraries for the calls that matter here, but whether they're
// *exported* (visible to Module.findExportByName) depends on how the
// app statically linked the library — if these don't fire, the app may
// have stripped/inlined them and you'll need to find the call sites by
// pattern-matching in a disassembler instead.
// ---------------------------------------------------------------------
["SSL_get_verify_result"].forEach(function (name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                send("[ssl-adv-bypass] SSL_get_verify_result -> forced X509_V_OK (0)");
                retval.replace(0);
            }
        });
    }
});

["X509_verify_cert"].forEach(function (name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                send("[ssl-adv-bypass] X509_verify_cert -> forced success (1)");
                retval.replace(1);
            }
        });
    }
});

// SSL_CTX_set_verify(ctx, mode, verify_callback) — apps sometimes pass
// a custom verify_callback that does its own pinning check independent
// of the standard chain result. Forcing mode to SSL_VERIFY_NONE (0)
// disables both the standard chain check AND the custom callback.
var SSL_CTX_set_verify = Module.findExportByName(null, "SSL_CTX_set_verify");
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function (args) {
            send("[ssl-adv-bypass] SSL_CTX_set_verify -> forcing SSL_VERIFY_NONE");
            args[1] = ptr(0); // SSL_VERIFY_NONE
        }
    });
}

// ---------------------------------------------------------------------
// D. Apple's Network.framework (nw_connection / sec_protocol_options)
//
// Apps using the newer Network.framework stack (rather than
// NSURLSession) configure trust evaluation via a verify block passed
// to sec_protocol_options_set_verify_block. Replacing that block with
// one that always calls "complete(true)" mirrors the approach used by
// SSLKillSwitch2/objection for this API family.
// ---------------------------------------------------------------------
var setVerifyBlock = Module.findExportByName("Network", "sec_protocol_options_set_verify_block")
                   || Module.findExportByName(null, "sec_protocol_options_set_verify_block");
if (setVerifyBlock) {
    Interceptor.attach(setVerifyBlock, {
        onEnter: function (args) {
            send("[ssl-adv-bypass] sec_protocol_options_set_verify_block intercepted — replacing with always-trust block");
            try {
                // args[1] is the verify block: void (^)(sec_protocol_metadata_t,
                // sec_trust_t, sec_protocol_verify_complete_t complete)
                var originalBlock = new ObjC.Block(args[1]);
                var newBlock = new ObjC.Block({
                    retType: "void",
                    argTypes: ["pointer", "pointer", "pointer"],
                    implementation: function (metadata, trustRef, completeHandlePtr) {
                        try {
                            var complete = new ObjC.Block(completeHandlePtr);
                            complete.implementation(1); // true
                        } catch (e) {
                            send("[ssl-adv-bypass] verify_block replacement failed: " + e);
                        }
                    }
                });
                args[1] = newBlock;
            } catch (e) {
                send("[ssl-adv-bypass] Could not replace verify block: " + e);
            }
        }
    });
} else {
    send("[ssl-adv-bypass] sec_protocol_options_set_verify_block not found (app likely isn't using Network.framework directly)");
}

send("[ssl-adv-bypass] Advanced hooks installed.");
