// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * JVM unit tests of the Android certificate probe.
 *
 * <p>Run with {@code ./gradlew :http_security_pinning:testDebugUnitTest} from
 * {@code example/android}.
 */
public class CertificateProbeTest {

    private CertificateProbe probe;

    @Before
    public void setUp() {
        probe = new CertificateProbe();
    }

    @After
    public void tearDown() {
        probe.shutdown();
    }

    private static CertificateProbe.Request request(int port, int timeoutMs) throws Exception {
        return new CertificateProbe.Request("localhost", port, timeoutMs, null, -1, null);
    }

    private static String code(ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (CertificateProbe.ProbeException e) {
            return e.code;
        } catch (Exception e) {
            fail("Unexpected exception " + e);
        }
        fail("Expected a ProbeException");
        return null;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    @Test
    public void capturesTheChainAndAbortsTheHandshake() throws Exception {
        try (TestServers.TlsServer server =
                     new TestServers.TlsServer("server_a1_chain.pem", "server_a.key")) {
            List<byte[]> chain = probe.fetch(request(server.port(), 5000));

            List<Certificate> expected = TestServers.loadChain("server_a1_chain.pem");
            assertEquals(expected.size(), chain.size());
            for (int i = 0; i < chain.size(); i++) {
                assertArrayEquals(expected.get(i).getEncoded(), chain.get(i));
            }
            Thread.sleep(200);
            // The probe rejected the chain: no handshake completed, no data sent.
            assertEquals(0, server.completedHandshakes.get());
            assertEquals(0, server.applicationBytes.get());
        }
    }

    @Test
    public void theTrustManagerNeverTrustsAnything() throws Exception {
        CertificateProbe.ChainCaptor captor = new CertificateProbe.ChainCaptor();
        X509Certificate[] chain = TestServers.loadChain("server_a1_chain.pem")
                .toArray(new X509Certificate[0]);
        try {
            captor.checkServerTrusted(chain, "RSA");
            fail("checkServerTrusted must always throw");
        } catch (CertificateProbe.ChainCapturedException expected) {
            // Rejected after capturing.
        }
        assertNotNull(captor.captured.get());
        assertEquals(chain.length, captor.captured.get().length);
        try {
            captor.checkClientTrusted(chain, "RSA");
            fail("checkClientTrusted must always throw");
        } catch (java.security.cert.CertificateException expected) {
            // Rejected.
        }
        assertEquals(0, captor.getAcceptedIssuers().length);
    }

    @Test
    public void aSlowServerCannotExceedTheOverallDeadline() throws Exception {
        try (TestServers.SlowLorisServer server = new TestServers.SlowLorisServer(300)) {
            long start = System.nanoTime();
            assertEquals("TIMEOUT", code(() -> probe.fetch(request(server.port(), 1000))));
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            assertTrue("took " + elapsedMs + " ms", elapsedMs < 2500);
        }
    }

    @Test
    public void slowProbesDoNotBlockOtherProbes() throws Exception {
        try (TestServers.SlowLorisServer slow = new TestServers.SlowLorisServer(300);
             TestServers.TlsServer fast =
                     new TestServers.TlsServer("server_a1_chain.pem", "server_a.key")) {
            Thread blocker = new Thread(() -> {
                try {
                    probe.fetch(request(slow.port(), 3000));
                } catch (Exception ignored) {
                    // Times out.
                }
            });
            blocker.start();
            Thread.sleep(100);
            long start = System.nanoTime();
            assertEquals(2, probe.fetch(request(fast.port(), 3000)).size());
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            assertTrue("took " + elapsedMs + " ms", elapsedMs < 2000);
            blocker.join();
        }
    }

    @Test
    public void invalidArgumentsAreRejected() {
        assertEquals("INVALID_ARGS", code(() -> request(443, 0)));
        assertEquals("INVALID_ARGS", code(() -> request(443, -5)));
        assertEquals("INVALID_ARGS", code(() -> request(0, 1000)));
        assertEquals("INVALID_ARGS", code(() -> request(70000, 1000)));
        assertEquals("INVALID_ARGS",
                code(() -> new CertificateProbe.Request(" ", 443, 1000, null, -1, null)));
        assertEquals("INVALID_ARGS",
                code(() -> new CertificateProbe.Request("a.com", 443, 1000, "proxy", 0, null)));
        assertEquals("INVALID_ARGS", code(() -> new CertificateProbe.Request(
                "a.com", 443, 1000, "proxy", 8080, "Basic x\r\nX-Injected: 1")));
        // CR/LF or other non-host characters must never reach the CONNECT line.
        assertEquals("INVALID_ARGS", code(() -> new CertificateProbe.Request(
                "evil\r\nX-Injected: 1\r\n\r\nx.example.com", 443, 1000, "proxy", 8080, null)));
        assertEquals("INVALID_ARGS",
                code(() -> new CertificateProbe.Request("a.com/x", 443, 1000, null, -1, null)));
        assertEquals("INVALID_ARGS",
                code(() -> new CertificateProbe.Request("a.com", 443, 1000, "pro xy", 8080, null)));
        assertTrue(CertificateProbe.isValidHost("xn--bcher-kva.de"));
        assertTrue(CertificateProbe.isValidHost("::1"));
        assertTrue(CertificateProbe.isValidHost("127.0.0.1"));
    }

    @Test
    public void connectionFailuresAreReported() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closedPort = socket.getLocalPort();
        }
        final int port = closedPort;
        assertEquals("CONNECTION_FAILED", code(() -> probe.fetch(request(port, 3000))));
    }

    @Test
    public void aNonTlsServerIsAConnectionFailure() throws Exception {
        try (TestServers.PlainHttpServer notTls = new TestServers.PlainHttpServer()) {
            assertEquals("CONNECTION_FAILED", code(() -> probe.fetch(request(notTls.port(), 3000))));
        }
    }

    @Test
    public void probesThroughAnHttpConnectProxy() throws Exception {
        try (TestServers.TlsServer server =
                     new TestServers.TlsServer("server_a1_chain.pem", "server_a.key");
             TestServers.ConnectProxy proxy = new TestServers.ConnectProxy("HTTP/1.1 200 Connection established")) {
            String auth = "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes("UTF-8"));
            List<byte[]> chain = probe.fetch(new CertificateProbe.Request(
                    "localhost", server.port(), 5000, "127.0.0.1", proxy.port(), auth));
            assertEquals(2, chain.size());
            assertEquals(1, proxy.requestHeads.size());
            String head = proxy.requestHeads.get(0);
            assertTrue(head, head.startsWith("CONNECT localhost:" + server.port() + " HTTP/1.1\r\n"));
            assertTrue(head, head.contains("Proxy-Authorization: " + auth + "\r\n"));
            assertEquals(0, server.completedHandshakes.get());
        }
    }

    @Test
    public void aRefusedTunnelIsAConnectionFailure() throws Exception {
        try (TestServers.ConnectProxy proxy =
                     new TestServers.ConnectProxy("HTTP/1.1 407 Proxy Authentication Required")) {
            assertEquals("CONNECTION_FAILED", code(() -> probe.fetch(new CertificateProbe.Request(
                    "localhost", 443, 3000, "127.0.0.1", proxy.port(), null))));
        }
    }
}
