#import "HttpSecurityPinningPlugin.h"

// Definition for a special class to fetch host certificates by implementing a NSURLSessionTaskDelegate
// that is called upon initial connection to get the certificates but the connection is dropped at that point.
@interface HostCertificatesFetcher: NSObject<NSURLSessionTaskDelegate>

// Host certificates for the current connection
@property NSArray<FlutterStandardTypedData *> *hostCertificates;

// Error that occurred during fetching
@property FlutterError *error;

// Get the host certificates for an URL
- (void)fetchCertificates:(NSURL *)url withTimeout:(NSTimeInterval)timeout;

@end


@implementation HttpSecurityPinningPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    NSObject<FlutterTaskQueue>* taskQueue = [[registrar messenger] makeBackgroundTaskQueue];
    FlutterMethodChannel* channel = [[FlutterMethodChannel alloc]
                 initWithName: @"http_security_pinning"
              binaryMessenger: [registrar messenger]
                        codec: [FlutterStandardMethodCodec sharedInstance]
                    taskQueue: taskQueue];
    HttpSecurityPinningPlugin* instance = [[HttpSecurityPinningPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}


- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"fetchHostCertificates" isEqualToString:call.method]) {
        NSString* urlString = call.arguments[@"url"];
        NSNumber* timeoutMs = call.arguments[@"timeout"];

        if (urlString == nil || [urlString length] == 0) {
            result([FlutterError errorWithCode:@"INVALID_URL"
                                       message:@"URL is null or empty."
                                       details:nil]);
            return;
        }
        if (timeoutMs == nil) {
            result([FlutterError errorWithCode:@"INVALID_ARGS"
                                       message:@"Timeout argument is missing."
                                       details:nil]);
            return;
        }

        NSURL *url = [NSURL URLWithString:urlString];
        if (url == nil) {
            result([FlutterError errorWithCode:@"INVALID_URL"
                                       message:[NSString stringWithFormat:@"Malformed URL: %@", urlString]
                                       details:nil]);
            return;
        }

        HostCertificatesFetcher *hostCertificatesFetcher = [[HostCertificatesFetcher alloc] init];
        NSTimeInterval timeoutSeconds = [timeoutMs doubleValue] / 1000.0;
        [hostCertificatesFetcher fetchCertificates:url withTimeout:timeoutSeconds];

        if (hostCertificatesFetcher.error) {
            result(hostCertificatesFetcher.error);
        } else if (hostCertificatesFetcher.hostCertificates == nil || [hostCertificatesFetcher.hostCertificates count] == 0) {
            result([FlutterError errorWithCode:@"NO_CERTIFICATES"
                                       message:@"Failed to retrieve certificate chain."
                                       details:@"The native process returned no certificates."]);
        } else {
            result(hostCertificatesFetcher.hostCertificates);
        }
    } else {
        result(FlutterMethodNotImplemented);
    }
}

@end

// Implementation of the HostCertificatesFetcher
@implementation HostCertificatesFetcher

- (void)fetchCertificates:(NSURL *)url withTimeout:(NSTimeInterval)timeout
{
    _hostCertificates = nil;
    _error = nil;

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    sessionConfig.timeoutIntervalForResource = timeout;
    sessionConfig.timeoutIntervalForRequest = timeout;
    NSURLSession* URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];

    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:timeout];
    [certFetchRequest setHTTPMethod:@"GET"];

    dispatch_semaphore_t certFetchComplete = dispatch_semaphore_create(0);

    NSURLSessionTask *certFetchTask = [URLSession dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            if (error && error.code != NSURLErrorCancelled) {
                self->_error = [FlutterError errorWithCode:@"CONNECTION_FAILED"
                                                   message:error.localizedDescription
                                                   details:error.domain];
            }
            dispatch_semaphore_signal(certFetchComplete);
        }];

    [certFetchTask resume];

    // Wait on the semaphore with a timeout to prevent hanging the background thread indefinitely.
    dispatch_time_t timeoutTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 1.0) * NSEC_PER_SEC));
    intptr_t waitResult = dispatch_semaphore_wait(certFetchComplete, timeoutTime);

    if (waitResult != 0) {
        [certFetchTask cancel];
        self->_error = [FlutterError errorWithCode:@"TIMEOUT"
                                           message:@"Certificate fetch timed out."
                                           details:nil];
    }

    [URLSession finishTasksAndInvalidate];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        _error = [FlutterError errorWithCode:@"TRUST_EVALUATION_FAILED"
                                     message:@"Server trust evaluation failed: serverTrust was null."
                                     details:nil];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray array];

    if (@available(iOS 15.0, macOS 12.0, *)) {
        NSArray *certArray = (NSArray *)CFBridgingRelease(SecTrustCopyCertificateChain(serverTrust));
        if (certArray) {
            for (id item in certArray) {
                SecCertificateRef cert = (__bridge SecCertificateRef)item;
                NSData *certData = (NSData *)CFBridgingRelease(SecCertificateCopyData(cert));
                if (certData) {
                    [certs addObject:[FlutterStandardTypedData typedDataWithBytes:certData]];
                }
            }
        }
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
        for (int certIndex = 0; certIndex < certCount; certIndex++) {
            SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, certIndex);
            NSData *certData = (NSData *)CFBridgingRelease(SecCertificateCopyData(cert));
            if (certData) {
                [certs addObject:[FlutterStandardTypedData typedDataWithBytes:certData]];
            }
        }
#pragma clang diagnostic pop
    }

    if ([certs count] == 0) {
        _error = [FlutterError errorWithCode:@"NO_CERTIFICATES"
                                     message:@"Server certificate chain is empty."
                                     details:nil];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    _hostCertificates = certs;

    // Abort challenge as we only wanted the certificate chain during the TLS handshake.
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end