// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import android.annotation.SuppressLint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Reads the certificate chain a server presents during a TLS handshake.
 *
 * <p>The probe never trusts anything: its trust manager records the chain and
 * then <b>rejects</b> it, so the handshake is aborted before any application
 * data could be exchanged. The recorded chain is only used by the Dart side
 * to pick which certificates match the configured SPKI pins; the real request
 * is then validated by Dart against those certificates alone.
 *
 * <p>Every probe runs on its own thread and is bounded by one overall deadline
 * that covers DNS resolution, the TCP connection, an optional proxy tunnel and
 * the TLS handshake.
 *
 * <p>This class has no Flutter dependency so that it can be unit tested on the
 * JVM.
 */
final class CertificateProbe {

    static final int MAX_PROXY_RESPONSE_BYTES = 16 * 1024;

    private static final java.util.regex.Pattern HOST_NAME =
            java.util.regex.Pattern.compile("^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*$");
    private static final java.util.regex.Pattern IPV6 =
            java.util.regex.Pattern.compile("^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$");

    /** Whether host is a plain DNS name or IP literal (no CR/LF, spaces, ...). */
    static boolean isValidHost(String host) {
        return host != null && host.length() <= 253
                && (HOST_NAME.matcher(host).matches() || IPV6.matcher(host).matches());
    }

    /** A probe failure with a machine readable code understood by Dart. */
    static final class ProbeException extends Exception {
        final String code;

        ProbeException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /** Thrown by {@link ChainCaptor} to abort the handshake once captured. */
    static final class ChainCapturedException extends CertificateException {
        ChainCapturedException() {
            super("Certificate chain captured by the http_security_pinning probe; handshake aborted.");
        }
    }

    /**
     * A trust manager that records the server chain and rejects it. It never
     * accepts a certificate (see {@code CertificateProbeTest}), so the lint
     * warning about custom trust managers that weaken validation does not
     * apply. The trust-all checks stay enabled as errors in build.gradle.kts.
     */
    @SuppressLint("CustomX509TrustManager")
    static final class ChainCaptor implements X509TrustManager {
        final AtomicReference<X509Certificate[]> captured = new AtomicReference<>();

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("Client certificates are not supported by the probe.");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain != null && chain.length > 0) {
                captured.set(chain.clone());
            }
            throw new ChainCapturedException();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /** The parameters of one probe. */
    static final class Request {
        final String host;
        final int port;
        final int timeoutMs;
        final String proxyHost;
        final int proxyPort;
        final String proxyAuthorization;

        /**
         * @param proxyHost          HTTP proxy to tunnel through with CONNECT, or null.
         * @param proxyAuthorization value of a Proxy-Authorization header, or null.
         */
        Request(String host, int port, int timeoutMs, String proxyHost, int proxyPort,
                String proxyAuthorization) throws ProbeException {
            if (!isValidHost(host)) {
                throw new ProbeException("INVALID_ARGS", "The host argument is missing or invalid.");
            }
            if (port < 1 || port > 65535) {
                throw new ProbeException("INVALID_ARGS", "The port argument is invalid.");
            }
            if (timeoutMs <= 0) {
                // A socket timeout of 0 would mean "wait forever".
                throw new ProbeException("INVALID_ARGS",
                        "The timeout must be a positive number of milliseconds.");
            }
            if (proxyHost != null && (!isValidHost(proxyHost) || proxyPort < 1 || proxyPort > 65535)) {
                throw new ProbeException("INVALID_ARGS", "The proxy arguments are invalid.");
            }
            if (proxyAuthorization != null
                    && (proxyAuthorization.indexOf('\r') >= 0 || proxyAuthorization.indexOf('\n') >= 0)) {
                throw new ProbeException("INVALID_ARGS", "The proxyAuthorization argument is invalid.");
            }
            this.host = host;
            this.port = port;
            this.timeoutMs = timeoutMs;
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
            this.proxyAuthorization = proxyAuthorization;
        }
    }

    // At most MAX_THREADS probes run at once (a thread blocked in DNS cannot
    // be interrupted); further probes wait in the queue and are bounded by
    // their own deadline.
    static final int MAX_THREADS = 16;

    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            MAX_THREADS, MAX_THREADS, 30, TimeUnit.SECONDS,
            new LinkedBlockingQueue<Runnable>(),
            runnable -> {
                Thread thread = new Thread(runnable, "http_security_pinning-probe");
                thread.setDaemon(true);
                return thread;
            });

    CertificateProbe() {
        executor.allowCoreThreadTimeOut(true);
    }

    /** Returns the DER encoded chain presented by the server, leaf first. */
    List<byte[]> fetch(final Request request) throws ProbeException {
        final AtomicReference<Socket> openSocket = new AtomicReference<>();
        Future<List<byte[]>> future = executor.submit(() -> probe(request, openSocket));
        try {
            return future.get(request.timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            closeQuietly(openSocket.get());
            throw new ProbeException("TIMEOUT", "Certificate fetch timed out.");
        } catch (InterruptedException e) {
            future.cancel(true);
            closeQuietly(openSocket.get());
            Thread.currentThread().interrupt();
            throw new ProbeException("CONNECTION_FAILED", "Certificate fetch was interrupted.");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ProbeException) {
                throw (ProbeException) cause;
            }
            if (cause instanceof SocketTimeoutException) {
                throw new ProbeException("TIMEOUT", "Certificate fetch timed out.");
            }
            if (cause instanceof IOException) {
                throw new ProbeException("CONNECTION_FAILED",
                        "Connection failed (" + cause.getClass().getSimpleName() + ").");
            }
            throw new ProbeException("UNEXPECTED_ERROR", "Unexpected probe error ("
                    + (cause == null ? "unknown" : cause.getClass().getSimpleName()) + ").");
        }
    }

    void shutdown() {
        executor.shutdownNow();
    }

    private static List<byte[]> probe(Request request, AtomicReference<Socket> openSocket)
            throws Exception {
        final long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(request.timeoutMs);
        Socket plainSocket = new Socket();
        openSocket.set(plainSocket);
        SSLSocket sslSocket = null;
        try {
            final boolean viaProxy = request.proxyHost != null;
            // DNS resolution is covered by the overall deadline as well.
            InetAddress address = InetAddress.getByName(viaProxy ? request.proxyHost : request.host);
            plainSocket.connect(new InetSocketAddress(address, viaProxy ? request.proxyPort : request.port),
                    remainingMs(deadline));
            plainSocket.setSoTimeout(remainingMs(deadline));

            if (viaProxy) {
                openTunnel(plainSocket, request, deadline);
            }

            ChainCaptor captor = new ChainCaptor();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{captor}, null);
            // createSocket(socket, host, ...) also sends the host name as SNI.
            sslSocket = (SSLSocket) sslContext.getSocketFactory()
                    .createSocket(plainSocket, request.host, request.port, true);
            openSocket.set(sslSocket);
            sslSocket.setSoTimeout(remainingMs(deadline));
            SSLException handshakeError = null;
            try {
                sslSocket.startHandshake();
            } catch (SSLException e) {
                // Expected when the chain was captured: the captor rejects it.
                handshakeError = e;
            }

            X509Certificate[] chain = captor.captured.get();
            if (chain == null || chain.length == 0) {
                if (handshakeError != null) {
                    throw new ProbeException("CONNECTION_FAILED", "TLS handshake failed ("
                            + handshakeError.getClass().getSimpleName() + ").");
                }
                throw new ProbeException("NO_CERTIFICATES", "Server returned no certificates.");
            }
            List<byte[]> encoded = new ArrayList<>(chain.length);
            for (X509Certificate certificate : chain) {
                try {
                    encoded.add(certificate.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new ProbeException("CERTIFICATE_ERROR",
                            "Failed to encode a certificate of the chain.");
                }
            }
            return encoded;
        } catch (GeneralSecurityException e) {
            throw new ProbeException("UNEXPECTED_ERROR",
                    "TLS is not available (" + e.getClass().getSimpleName() + ").");
        } finally {
            closeQuietly(sslSocket);
            closeQuietly(plainSocket);
        }
    }

    /** Opens an HTTP CONNECT tunnel to the target through the proxy. */
    private static void openTunnel(Socket socket, Request request, long deadline)
            throws IOException, ProbeException {
        String authority = (request.host.indexOf(':') >= 0 ? "[" + request.host + "]" : request.host)
                + ":" + request.port;
        StringBuilder connect = new StringBuilder()
                .append("CONNECT ").append(authority).append(" HTTP/1.1\r\n")
                .append("Host: ").append(authority).append("\r\n");
        if (request.proxyAuthorization != null) {
            connect.append("Proxy-Authorization: ").append(request.proxyAuthorization).append("\r\n");
        }
        connect.append("\r\n");
        OutputStream out = socket.getOutputStream();
        out.write(connect.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        // Read the response head byte by byte so that no TLS bytes are consumed.
        InputStream in = socket.getInputStream();
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        final byte[] terminator = {'\r', '\n', '\r', '\n'};
        int matched = 0;
        while (matched < terminator.length) {
            socket.setSoTimeout(remainingMs(deadline));
            int b = in.read();
            if (b == -1) {
                throw new ProbeException("CONNECTION_FAILED", "The proxy closed the connection.");
            }
            head.write(b);
            if (head.size() > MAX_PROXY_RESPONSE_BYTES) {
                throw new ProbeException("CONNECTION_FAILED", "The proxy response is too large.");
            }
            if (b == terminator[matched]) {
                matched++;
            } else {
                matched = (b == '\r') ? 1 : 0;
            }
        }
        String statusLine = new String(head.toByteArray(), StandardCharsets.ISO_8859_1).split("\r\n", 2)[0];
        String[] parts = statusLine.split(" ");
        if (parts.length < 2 || !parts[1].equals("200")) {
            throw new ProbeException("CONNECTION_FAILED",
                    "The proxy refused the tunnel (" + (parts.length > 1 ? parts[1] : "?") + ").");
        }
    }

    private static int remainingMs(long deadline) throws SocketTimeoutException {
        long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (remaining <= 0) {
            throw new SocketTimeoutException("deadline exceeded");
        }
        // 0 would mean "no timeout" for sockets.
        return (int) Math.max(1, Math.min(Integer.MAX_VALUE, remaining));
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (IOException ignored) {
            // Nothing to do.
        }
    }
}
