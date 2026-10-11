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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Local servers used by the native unit tests. */
final class TestServers {

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

    static PrivateKey loadKey(String pemFile) throws Exception {
        String pem = new String(Files.readAllBytes(fixture(pemFile).toPath()), StandardCharsets.US_ASCII)
                .replaceAll("-----[^-]+-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /**
     * A TLS server that records how many handshakes completed and how many
     * application bytes it received.
     */
    static final class TlsServer implements AutoCloseable {
        final SSLServerSocket serverSocket;
        final AtomicInteger completedHandshakes = new AtomicInteger();
        final AtomicInteger applicationBytes = new AtomicInteger();
        private final Thread thread;

        TlsServer(String chainPem, String keyPem) throws Exception {
            List<Certificate> chain = loadChain(chainPem);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("server", loadKey(keyPem), new char[0],
                    chain.toArray(new Certificate[0]));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            thread = new Thread(this::serve, "test-tls-server");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        private void serve() {
            while (!serverSocket.isClosed()) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.setSoTimeout(5000);
                    try {
                        socket.startHandshake();
                        completedHandshakes.incrementAndGet();
                        int n = socket.getInputStream().read(new byte[1024]);
                        if (n > 0) applicationBytes.addAndGet(n);
                    } catch (IOException expected) {
                        // The probe aborts the handshake.
                    }
                } catch (IOException e) {
                    return;
                }
            }
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

    /** A plain-text server that answers every connection with an HTTP error. */
    static final class PlainHttpServer implements AutoCloseable {
        final ServerSocket serverSocket;

        PlainHttpServer() throws IOException {
            serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try (Socket socket = serverSocket.accept()) {
                        socket.getOutputStream().write(
                                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
                                        .getBytes(StandardCharsets.ISO_8859_1));
                        socket.getOutputStream().flush();
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "test-plain-server");
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

    /** A minimal HTTP CONNECT proxy that records the requests it receives. */
    static final class ConnectProxy implements AutoCloseable {
        final ServerSocket serverSocket;
        final List<String> requestHeads = new CopyOnWriteArrayList<>();
        private final String reply;

        /** @param reply the status line to answer, e.g. "HTTP/1.1 200 OK". */
        ConnectProxy(String reply) throws IOException {
            this.reply = reply;
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
