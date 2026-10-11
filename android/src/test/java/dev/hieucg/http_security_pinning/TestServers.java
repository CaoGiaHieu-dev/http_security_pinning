// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;

/**
 * Real local servers used by the native unit tests: every test performs a
 * genuine TCP connection and TLS handshake, without depending on the network.
 */
final class TestServers {

    static final char[] P12_PASSWORD = "changeit".toCharArray();

    private TestServers() {}

    static File fixture(String name) {
        String dir = System.getProperty("fixturesDir", "../test/fixtures");
        return new File(dir, name);
    }

    static List<Certificate> loadChain(String pemFile) throws Exception {
        try (InputStream in = new FileInputStream(fixture(pemFile))) {
            Collection<? extends Certificate> certs =
                    CertificateFactory.getInstance("X.509").generateCertificates(in);
            return new ArrayList<>(certs);
        }
    }

    /** Loads a PKCS#8 PEM private key (RSA or EC). */
    static PrivateKey loadKey(String pemFile) throws Exception {
        String pem = new String(Files.readAllBytes(fixture(pemFile).toPath()), StandardCharsets.US_ASCII)
                .replaceAll("-----[^-]+-----", "")
                .replaceAll("\\s", "");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (java.security.spec.InvalidKeySpecException notRsa) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    /** A key store holding the PEM [chainPem] and [keyPem]. */
    static KeyStore pemKeyStore(String chainPem, String keyPem) throws Exception {
        List<Certificate> chain = loadChain(chainPem);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", loadKey(keyPem), P12_PASSWORD, chain.toArray(new Certificate[0]));
        return keyStore;
    }

    /** A PKCS#12 key store fixture (password "changeit"). */
    static KeyStore p12KeyStore(String p12File) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(fixture(p12File))) {
            keyStore.load(in, P12_PASSWORD);
        }
        return keyStore;
    }

    /** The certificate chain stored in [keyStore], leaf first. */
    static List<byte[]> encodedChain(KeyStore keyStore) throws Exception {
        String alias = Collections.list(keyStore.aliases()).get(0);
        List<byte[]> encoded = new ArrayList<>();
        for (Certificate certificate : keyStore.getCertificateChain(alias)) {
            encoded.add(certificate.getEncoded());
        }
        return encoded;
    }

    /**
     * A TLS server that records completed handshakes, received application
     * bytes and the SNI names the clients sent.
     */
    static final class TlsServer implements AutoCloseable {
        final SSLServerSocket serverSocket;
        final AtomicInteger completedHandshakes = new AtomicInteger();
        final AtomicInteger applicationBytes = new AtomicInteger();
        final List<String> sniNames = new CopyOnWriteArrayList<>();
        final AtomicInteger connections = new AtomicInteger();

        TlsServer(String chainPem, String keyPem) throws Exception {
            this(pemKeyStore(chainPem, keyPem), null, false, InetAddress.getLoopbackAddress());
        }

        /**
         * @param protocols       TLS versions to enable (null: defaults).
         * @param needClientAuth  whether the server requires a client certificate.
         */
        TlsServer(KeyStore keyStore, String[] protocols, boolean needClientAuth, InetAddress address)
                throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, P12_PASSWORD);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 50, address);
            SSLParameters parameters = serverSocket.getSSLParameters();
            parameters.setSNIMatchers(Collections.<SNIMatcher>singletonList(
                    new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
                        @Override
                        public boolean matches(SNIServerName serverName) {
                            sniNames.add(new String(serverName.getEncoded(), StandardCharsets.US_ASCII));
                            return true;
                        }
                    }));
            if (protocols != null) parameters.setProtocols(protocols);
            parameters.setNeedClientAuth(needClientAuth);
            serverSocket.setSSLParameters(parameters);
            Thread thread = new Thread(this::serve, "test-tls-server");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        private void serve() {
            while (!serverSocket.isClosed()) {
                try {
                    final SSLSocket socket = (SSLSocket) serverSocket.accept();
                    connections.incrementAndGet();
                    Thread handler = new Thread(() -> handle(socket));
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handle(SSLSocket socket) {
            try (SSLSocket s = socket) {
                s.setSoTimeout(5000);
                s.startHandshake();
                completedHandshakes.incrementAndGet();
                int n = s.getInputStream().read(new byte[1024]);
                if (n > 0) applicationBytes.addAndGet(n);
            } catch (IOException expected) {
                // The probe aborts the handshake.
            }
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    /** How a {@link MisbehavingServer} treats each connection. */
    enum Misbehaviour {
        /** Accept and close at once (FIN). */
        CLOSE_IMMEDIATELY,
        /** Accept and reset the connection (RST). */
        RESET,
        /** Answer with an HTTP error instead of TLS. */
        PLAIN_HTTP,
    }

    /** A TCP server that never completes a TLS handshake. */
    static final class MisbehavingServer implements AutoCloseable {
        final ServerSocket serverSocket;

        MisbehavingServer(Misbehaviour misbehaviour) throws IOException {
            serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket socket = serverSocket.accept();
                        switch (misbehaviour) {
                            case CLOSE_IMMEDIATELY:
                                socket.close();
                                break;
                            case RESET:
                                socket.setSoLinger(true, 0);
                                socket.close();
                                break;
                            case PLAIN_HTTP:
                                socket.getOutputStream().write(
                                        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
                                                .getBytes(StandardCharsets.ISO_8859_1));
                                socket.getOutputStream().flush();
                                socket.close();
                                break;
                        }
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "test-misbehaving-server");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    /** A TCP server that trickles one byte at a time and never finishes TLS. */
    static final class SlowLorisServer implements AutoCloseable {
        final ServerSocket serverSocket;

        SlowLorisServer(long intervalMs) throws IOException {
            serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        final Socket socket = serverSocket.accept();
                        Thread writer = new Thread(() -> {
                            try (Socket s = socket) {
                                OutputStream out = s.getOutputStream();
                                // A TLS record header for a handshake message, one byte at a time.
                                byte[] bytes = {0x16, 0x03, 0x03, 0x40, 0x00};
                                for (int i = 0; ; i++) {
                                    out.write(bytes[i % bytes.length]);
                                    out.flush();
                                    Thread.sleep(intervalMs);
                                }
                            } catch (Exception ignored) {
                                // Client gave up.
                            }
                        });
                        writer.setDaemon(true);
                        writer.start();
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "test-slow-server");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    /** How a {@link ConnectProxy} answers a CONNECT request. */
    enum ProxyMode {
        /** Answer with the configured status line; tunnel on 200. */
        REPLY,
        /** Close the connection without answering. */
        CLOSE,
        /** Send a never-ending response head. */
        HUGE_HEAD,
    }

    /** A minimal HTTP CONNECT proxy that records the requests it receives. */
    static final class ConnectProxy implements AutoCloseable {
        final ServerSocket serverSocket;
        final List<String> requestHeads = new CopyOnWriteArrayList<>();
        private final String reply;
        private final ProxyMode mode;

        /** @param reply the status line to answer, e.g. "HTTP/1.1 200 OK". */
        ConnectProxy(String reply) throws IOException {
            this(reply, ProxyMode.REPLY);
        }

        ConnectProxy(String reply, ProxyMode mode) throws IOException {
            this.reply = reply;
            this.mode = mode;
            serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(this::serve, "test-proxy");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        private void serve() {
            while (!serverSocket.isClosed()) {
                try {
                    Socket client = serverSocket.accept();
                    Thread handler = new Thread(() -> handle(client));
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handle(Socket client) {
            try {
                InputStream in = client.getInputStream();
                ByteArrayOutputStream head = new ByteArrayOutputStream();
                while (!head.toString("ISO-8859-1").endsWith("\r\n\r\n")) {
                    int b = in.read();
                    if (b == -1) return;
                    head.write(b);
                }
                String text = head.toString("ISO-8859-1");
                requestHeads.add(text);
                OutputStream out = client.getOutputStream();
                if (mode == ProxyMode.CLOSE) {
                    client.close();
                    return;
                }
                if (mode == ProxyMode.HUGE_HEAD) {
                    out.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    byte[] filler = "X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                            .getBytes(StandardCharsets.ISO_8859_1);
                    for (int i = 0; i < 2000; i++) out.write(filler);
                    out.flush();
                    client.close();
                    return;
                }
                out.write((reply + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                if (!reply.contains(" 200 ")) {
                    client.close();
                    return;
                }
                String target = text.split(" ")[1];
                int port = Integer.parseInt(target.substring(target.lastIndexOf(':') + 1));
                Socket upstream = new Socket(InetAddress.getLoopbackAddress(), port);
                pipe(client.getInputStream(), upstream.getOutputStream(), upstream);
                pipe(upstream.getInputStream(), client.getOutputStream(), client);
            } catch (IOException ignored) {
                // Connection closed.
            }
        }

        private static void pipe(InputStream in, OutputStream out, Socket toClose) {
            Thread t = new Thread(() -> {
                byte[] buffer = new byte[4096];
                try {
                    int n;
                    while ((n = in.read(buffer)) != -1) {
                        out.write(buffer, 0, n);
                        out.flush();
                    }
                } catch (IOException ignored) {
                    // Closed.
                } finally {
                    try {
                        toClose.close();
                    } catch (IOException ignored) {
                        // Nothing to do.
                    }
                }
            });
            t.setDaemon(true);
            t.start();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }
}
