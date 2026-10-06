// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.StandardMethodCodec;

/**
 * Main plugin class, responsible for bridging Flutter and native Android.
 */
public class HttpSecurityPinningPlugin implements FlutterPlugin, MethodCallHandler {

    private static class CertificateFetchException extends Exception {
        final String code;

        CertificateFetchException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /**
     * Harvests the certificate chain presented by a server during a TLS handshake.
     *
     * An all-accepting TrustManager is used solely to observe the handshake and
     * retrieve the certificate chain, including for servers using private or self-signed
     * CAs. No application data is ever sent on this connection. The actual trust decision
     * is strictly enforced by Dart's SecurityContext with the configured pins.
     */
    private static class HostCertificatesFetcher {

        private final SSLSocketFactory probeSocketFactory;

        HostCertificatesFetcher() {
            SSLSocketFactory factory = null;
            try {
                TrustManager[] probeTrustManagers = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    }
                };
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, probeTrustManagers, new java.security.SecureRandom());
                factory = sslContext.getSocketFactory();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                // Fallback to default if TLS initialization fails
                factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            }
            this.probeSocketFactory = factory;
        }

        public List<byte[]> fetch(@NonNull String urlString, int timeoutMs) throws CertificateFetchException {
            if (urlString.trim().isEmpty()) {
                throw new CertificateFetchException("INVALID_URL", "URL is null or empty.");
            }

            final String host;
            final int port;
            try {
                URL url = new URL(urlString);
                host = url.getHost();
                int parsedPort = url.getPort();
                port = (parsedPort != -1) ? parsedPort : (url.getDefaultPort() != -1 ? url.getDefaultPort() : 443);
            } catch (MalformedURLException e) {
                throw new CertificateFetchException("INVALID_URL", "Malformed URL: " + e.getMessage());
            }

            Socket plainSocket = null;
            SSLSocket sslSocket = null;
            try {
                plainSocket = new Socket();
                plainSocket.connect(new InetSocketAddress(host, port), timeoutMs);
                plainSocket.setSoTimeout(timeoutMs);

                sslSocket = (SSLSocket) probeSocketFactory.createSocket(plainSocket, host, port, true);
                sslSocket.startHandshake();

                Certificate[] certificates = sslSocket.getSession().getPeerCertificates();
                if (certificates == null || certificates.length == 0) {
                    throw new CertificateFetchException("NO_CERTIFICATES", "Server returned no certificates.");
                }

                final List<byte[]> hostCertificates = new ArrayList<>(certificates.length);
                for (Certificate certificate : certificates) {
                    hostCertificates.add(certificate.getEncoded());
                }
                return hostCertificates;
            } catch (SocketTimeoutException e) {
                throw new CertificateFetchException("TIMEOUT", "Connection or handshake timed out: " + e.getMessage());
            } catch (CertificateEncodingException e) {
                throw new CertificateFetchException("CERTIFICATE_ERROR", "Failed to encode certificate: " + e.getMessage());
            } catch (IOException e) {
                throw new CertificateFetchException("CONNECTION_FAILED", "Connection failed: " + e.getMessage());
            } catch (Exception e) {
                throw new CertificateFetchException("UNEXPECTED_ERROR", "Unexpected error: " + e.getMessage());
            } finally {
                if (sslSocket != null) {
                    try {
                        sslSocket.close();
                    } catch (IOException ignored) {}
                }
                if (plainSocket != null) {
                    try {
                        plainSocket.close();
                    } catch (IOException ignored) {}
                }
            }
        }
    }

    private MethodChannel channel;
    private final HostCertificatesFetcher hostCertificatesFetcher = new HostCertificatesFetcher();

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
        BinaryMessenger messenger = flutterPluginBinding.getBinaryMessenger();
        channel = new MethodChannel(messenger, "http_security_pinning",
                StandardMethodCodec.INSTANCE, messenger.makeBackgroundTaskQueue());
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (call.method.equals("fetchHostCertificates")) {
            try {
                final String urlString = call.argument("url");
                final Integer timeoutMs = call.argument("timeout");

                if (urlString == null) {
                    result.error("INVALID_ARGS", "URL argument is missing.", null);
                    return;
                }
                if (timeoutMs == null) {
                    result.error("INVALID_ARGS", "Timeout argument is missing.", null);
                    return;
                }

                List<byte[]> certificates = hostCertificatesFetcher.fetch(urlString, timeoutMs);
                result.success(certificates);
            } catch (CertificateFetchException e) {
                result.error(e.code, e.getMessage(), null);
            } catch (Exception e) {
                result.error("PLUGIN_ERROR", "An unexpected plugin error occurred: " + e.getMessage(), null);
            }
        } else {
            result.notImplemented();
        }
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        if (channel != null) {
            channel.setMethodCallHandler(null);
            channel = null;
        }
    }
}