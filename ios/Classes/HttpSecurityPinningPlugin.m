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

        // The fetcher will run synchronously and set its properties on completion.
        HostCertificatesFetcher *hostCertificatesFetcher = [[HostCertificatesFetcher alloc] init];
        NSTimeInterval timeoutSeconds = [timeoutMs doubleValue] / 1000.0;
        [hostCertificatesFetcher fetchCertificates:url withTimeout:timeoutSeconds];

        if (hostCertificatesFetcher.error) {
            result(hostCertificatesFetcher.error);
        } else if (hostCertificatesFetcher.hostCertificates == nil) {
            result([FlutterError errorWithCode:@"NO_CERTIFICATES"
                                       message:@"Failed to retrieve certificate chain."
                                       details:@"The native process returned no certificates and no error."]);
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

// Fetches the certificates for a host by setting up an HTTPS GET request and harvesting the certificates.
// This is a synchronous method that uses a semaphore to wait for the async network call to complete.
- (void)fetchCertificates:(NSURL *)url withTimeout:(NSTimeInterval)timeout
{
    // There are no certificates or errors initially
    _hostCertificates = nil;
    _error = nil;

    // Create the Session
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    sessionConfig.timeoutIntervalForResource = timeout;
    NSURLSession* URLSession = [NSURLSession sessionWithConfiguration:sessionConfig delegate:self delegateQueue:nil];

    // Create the request
    NSMutableURLRequest *certFetchRequest = [NSMutableURLRequest requestWithURL:url];
    [certFetchRequest setTimeoutInterval:timeout];
    [certFetchRequest setHTTPMethod:@"GET"];

    // Set up a semaphore so we can block until the request completes
    dispatch_semaphore_t certFetchComplete = dispatch_semaphore_create(0);

    // Get session task to issue the request. The completion handler will set the error property
    // and signal the semaphore. The certificates themselves are harvested in the delegate method below.
    NSURLSessionTask *certFetchTask = [URLSession dataTaskWithRequest:certFetchRequest
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
        {
            // If an error occurred that was NOT a cancellation, it's a real problem.
            // The cancellation is expected because we abort the challenge in the delegate.
            if (error && error.code != NSURLErrorCancelled) {
                self->_error = [FlutterError errorWithCode:@"CONNECTION_FAILED"
                                                   message:error.localizedDescription
                                                   details:error.domain];
            }
            dispatch_semaphore_signal(certFetchComplete);
        }];

    // Make the request
    [certFetchTask resume];

    // Wait on the semaphore which shows when the network request is completed.
    dispatch_semaphore_wait(certFetchComplete, DISPATCH_TIME_FOREVER);

    // After waiting, either _hostCertificates or _error will be set.
    // The calling method is responsible for checking them.
}

// Collect the host certificates using the certificate check of the NSURLSessionTaskDelegate protocol
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // Ignore any requests that are not related to server trust
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    // Check we have a server trust
    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    if (!serverTrust) {
        _error = [FlutterError errorWithCode:@"TRUST_EVALUATION_FAILED"
                                     message:@"Server trust evaluation failed: serverTrust was null."
                                     details:nil];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Collect all the certs in the chain
    CFIndex certCount = SecTrustGetCertificateCount(serverTrust);
    if (certCount == 0) {
        _error = [FlutterError errorWithCode:@"NO_CERTIFICATES"
                                     message:@"Server certificate chain is empty."
                                     details:nil];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    NSMutableArray<FlutterStandardTypedData *> *certs = [NSMutableArray arrayWithCapacity:(NSUInteger)certCount];
    for (int certIndex = 0; certIndex < certCount; certIndex++) {
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(serverTrust, certIndex);
        NSData *certData = (NSData *) CFBridgingRelease(SecCertificateCopyData(cert));
        FlutterStandardTypedData *certFSTD = [FlutterStandardTypedData typedDataWithBytes:certData];
        [certs addObject:certFSTD];
    }

    // Set the host certs to be returned
    _hostCertificates = certs;

    // Fail the challenge as we only wanted the certificates. This is the expected flow.
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

@end