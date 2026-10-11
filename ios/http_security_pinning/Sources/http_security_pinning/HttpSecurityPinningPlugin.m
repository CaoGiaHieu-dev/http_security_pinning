// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "./include/http_security_pinning/HttpSecurityPinningPlugin.h"

#import <Security/Security.h>

static NSString *const HSPChannelName = @"http_security_pinning";

// Reads the certificate chain of a server during the TLS handshake and then
// cancels the authentication challenge, so the connection is dropped before
// any request is sent. The chain is never trusted by this class: the Dart side
// only uses it to pick the certificates that match the configured pins.
@interface HSPCertificateFetcher : NSObject <NSURLSessionTaskDelegate>

- (instancetype)initWithTimeout:(NSTimeInterval)timeout
                 proxyCredential:(nullable NSURLCredential *)proxyCredential;

// Returns an NSArray<FlutterStandardTypedData *> or a FlutterError.
- (id)fetchURL:(NSURL *)url
     proxyHost:(nullable NSString *)proxyHost
     proxyPort:(NSInteger)proxyPort;

@end

@implementation HSPCertificateFetcher {
    NSTimeInterval _timeout;
    NSURLCredential *_proxyCredential;
    NSArray<FlutterStandardTypedData *> *_certificates;
    FlutterError *_error;
    BOOL _proxyCredentialUsed;
}

- (instancetype)initWithTimeout:(NSTimeInterval)timeout
                 proxyCredential:(NSURLCredential *)proxyCredential {
    self = [super init];
    if (self) {
        _timeout = timeout;
        _proxyCredential = proxyCredential;
    }
    return self;
}

- (id)fetchURL:(NSURL *)url proxyHost:(NSString *)proxyHost proxyPort:(NSInteger)proxyPort {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.timeoutIntervalForRequest = _timeout;
    config.timeoutIntervalForResource = _timeout;
    config.URLCache = nil;
    config.HTTPCookieStorage = nil;
    if (proxyHost != nil) {
        // CFNetwork proxy dictionary keys (kCFNetworkProxiesHTTPSEnable,
        // kCFNetworkProxiesHTTPSProxy, kCFNetworkProxiesHTTPSPort) written as
        // literals because those constants are not exported on iOS.
        config.connectionProxyDictionary = @{
            @"HTTPSEnable" : @YES,
            @"HTTPSProxy" : proxyHost,
            @"HTTPSPort" : @(proxyPort),
        };
    } else {
        // Connect directly, like dart:io does, instead of using the system
        // proxy: the probe must take the same route as the real request.
        config.connectionProxyDictionary = @{};
    }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:self
                                                     delegateQueue:nil];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"HEAD";
    request.timeoutInterval = _timeout;

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    NSURLSessionTask *task = [session dataTaskWithRequest:request
                                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error != nil && error.code != NSURLErrorCancelled) {
            NSString *code = (error.code == NSURLErrorTimedOut) ? @"TIMEOUT" : @"CONNECTION_FAILED";
            [self setErrorIfNone:[FlutterError errorWithCode:code
                                                     message:[NSString stringWithFormat:@"Connection failed (%@ %ld).",
                                                                                        error.domain, (long)error.code]
                                                     details:nil]];
        }
        dispatch_semaphore_signal(done);
    }];
    [task resume];

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, (int64_t)((_timeout + 1.0) * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(done, deadline) != 0) {
        [task cancel];
        [self setErrorIfNone:[FlutterError errorWithCode:@"TIMEOUT"
                                                 message:@"Certificate fetch timed out."
                                                 details:nil]];
    }
    [session invalidateAndCancel];

    @synchronized (self) {
        if (_certificates.count > 0) {
            return _certificates;
        }
        if (_error != nil) {
            return _error;
        }
    }
    return [FlutterError errorWithCode:@"NO_CERTIFICATES"
                               message:@"Server returned no certificates."
                               details:nil];
}

- (void)setErrorIfNone:(FlutterError *)error {
    @synchronized (self) {
        if (_error == nil && _certificates.count == 0) {
            _error = error;
        }
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *_Nullable))completionHandler {
    NSURLProtectionSpace *space = challenge.protectionSpace;

    if (space.isProxy) {
        BOOL useCredential = NO;
        @synchronized (self) {
            useCredential = (_proxyCredential != nil && !_proxyCredentialUsed);
            _proxyCredentialUsed = YES;
        }
        if (useCredential) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, _proxyCredential);
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        }
        return;
    }

    if (![space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        // Never answer other challenges: the probe must not authenticate.
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    SecTrustRef serverTrust = space.serverTrust;
    if (serverTrust == NULL) {
        [self setErrorIfNone:[FlutterError errorWithCode:@"NO_CERTIFICATES"
                                                 message:@"The server trust object is missing."
                                                 details:nil]];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Build the chain the way the system would before reading it. The result
    // is deliberately ignored: this probe never trusts the server.
    CFErrorRef evaluationError = NULL;
    (void)SecTrustEvaluateWithError(serverTrust, &evaluationError);
    if (evaluationError != NULL) {
        CFRelease(evaluationError);
    }

    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray array];
    if (@available(iOS 15.0, macOS 12.0, *)) {
        NSArray *chain = (NSArray *)CFBridgingRelease(SecTrustCopyCertificateChain(serverTrust));
        for (id item in chain) {
            NSData *der = (NSData *)CFBridgingRelease(SecCertificateCopyData((__bridge SecCertificateRef)item));
            if (der != nil) {
                [certs addObject:[FlutterStandardTypedData typedDataWithBytes:der]];
            }
        }
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CFIndex count = SecTrustGetCertificateCount(serverTrust);
        for (CFIndex i = 0; i < count; i++) {
            SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, i);
            NSData *der = (NSData *)CFBridgingRelease(SecCertificateCopyData(cert));
            if (der != nil) {
                [certs addObject:[FlutterStandardTypedData typedDataWithBytes:der]];
            }
        }
#pragma clang diagnostic pop
    }

    @synchronized (self) {
        if (certs.count > 0) {
            _certificates = [certs copy];
        }
    }
    // Abort: only the chain was wanted, no request may be sent.
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end

@implementation HttpSecurityPinningPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar> *)registrar {
    FlutterMethodChannel *channel = [FlutterMethodChannel methodChannelWithName:HSPChannelName
                                                                binaryMessenger:[registrar messenger]];
    HttpSecurityPinningPlugin *instance = [[HttpSecurityPinningPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

+ (BOOL)isValidHost:(NSString *)host {
    if (host.length == 0 || host.length > 253) {
        return NO;
    }
    NSCharacterSet *forbidden = [NSCharacterSet characterSetWithCharactersInString:@"/?#@[]\\ \t\r\n%"];
    return [host rangeOfCharacterFromSet:forbidden].location == NSNotFound;
}

+ (nullable NSURLCredential *)credentialFromAuthorization:(nullable NSString *)authorization {
    if (![authorization hasPrefix:@"Basic "]) {
        return nil;
    }
    NSData *decoded = [[NSData alloc] initWithBase64EncodedString:[authorization substringFromIndex:6]
                                                          options:0];
    NSString *userInfo = decoded ? [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding] : nil;
    NSRange colon = [userInfo rangeOfString:@":"];
    if (userInfo == nil || colon.location == NSNotFound) {
        return nil;
    }
    return [NSURLCredential credentialWithUser:[userInfo substringToIndex:colon.location]
                                      password:[userInfo substringFromIndex:colon.location + 1]
                                   persistence:NSURLCredentialPersistenceNone];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if (![@"fetchHostCertificates" isEqualToString:call.method]) {
        result(FlutterMethodNotImplemented);
        return;
    }
    NSDictionary *args = [call.arguments isKindOfClass:[NSDictionary class]] ? call.arguments : @{};
    id host = args[@"host"];
    id port = args[@"port"];
    id timeoutMs = args[@"timeout"];
    id proxyHost = args[@"proxyHost"];
    id proxyPort = args[@"proxyPort"];
    id proxyAuthorization = args[@"proxyAuthorization"];

    if (![host isKindOfClass:[NSString class]] || ![HttpSecurityPinningPlugin isValidHost:host]) {
        result([FlutterError errorWithCode:@"INVALID_ARGS" message:@"The host argument is missing or invalid." details:nil]);
        return;
    }
    if (![port isKindOfClass:[NSNumber class]] || [port integerValue] < 1 || [port integerValue] > 65535) {
        result([FlutterError errorWithCode:@"INVALID_ARGS" message:@"The port argument is missing or invalid." details:nil]);
        return;
    }
    if (![timeoutMs isKindOfClass:[NSNumber class]] || [timeoutMs doubleValue] <= 0) {
        result([FlutterError errorWithCode:@"INVALID_ARGS"
                                   message:@"The timeout must be a positive number of milliseconds."
                                   details:nil]);
        return;
    }
    if (proxyHost != nil && proxyHost != [NSNull null]) {
        if (![proxyHost isKindOfClass:[NSString class]] || ![HttpSecurityPinningPlugin isValidHost:proxyHost] ||
            ![proxyPort isKindOfClass:[NSNumber class]] || [proxyPort integerValue] < 1 ||
            [proxyPort integerValue] > 65535) {
            result([FlutterError errorWithCode:@"INVALID_ARGS" message:@"The proxy arguments are invalid." details:nil]);
            return;
        }
    } else {
        proxyHost = nil;
    }

    // Only the origin is ever used; IPv6 literals need brackets.
    NSString *hostPart = [host containsString:@":"] ? [NSString stringWithFormat:@"[%@]", host] : host;
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@:%ld/", hostPart, (long)[port integerValue]]];
    if (url == nil) {
        result([FlutterError errorWithCode:@"INVALID_ARGS" message:@"The host argument is invalid." details:nil]);
        return;
    }

    NSTimeInterval timeout = [timeoutMs doubleValue] / 1000.0;
    NSURLCredential *credential = [proxyAuthorization isKindOfClass:[NSString class]]
        ? [HttpSecurityPinningPlugin credentialFromAuthorization:proxyAuthorization]
        : nil;
    NSInteger proxyPortValue = [proxyPort isKindOfClass:[NSNumber class]] ? [proxyPort integerValue] : 0;

    // Probes run concurrently off the main thread; one slow host does not
    // delay the others. Results are delivered on the main thread.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        HSPCertificateFetcher *fetcher = [[HSPCertificateFetcher alloc] initWithTimeout:timeout
                                                                       proxyCredential:credential];
        id outcome = [fetcher fetchURL:url proxyHost:proxyHost proxyPort:proxyPortValue];
        dispatch_async(dispatch_get_main_queue(), ^{
            result(outcome);
        });
    });
}

@end
