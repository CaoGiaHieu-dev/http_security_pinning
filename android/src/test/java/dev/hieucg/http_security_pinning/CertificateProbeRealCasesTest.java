// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Real-world cases for the Android certificate probe. Every test performs a
 * genuine TCP connection and TLS handshake against a local server, so the
 * probe code runs exactly as in an app, without depending on the Internet.
 *
 * <p>The probe must capture the presented chain in every case (it never
 * trusts anything itself; the Dart side compares the chain with the pins),
 * must never complete a handshake or send application data, and must map
 * every failure to the error code Dart expects.
 */
public class CertificateProbeRealCasesTest {

    private CertificateProbe probe;

    @Before
    public void setUp() {
        probe = new CertificateProbe();
    }

    @After
    public void tearDown() {
        probe.shutdown();
    }

    private static CertificateProbe.Request request(String host, int port) throws Exception {
        return new CertificateProbe.Request(host, port, 5000, null, -1, null);
    }

    private String errorCode(CertificateProbe.Request request) {
        try {
            probe.fetch(request);
        } catch (CertificateProbe.ProbeException e) {
            return e.code;
        }
        fail("Expected a ProbeException");
        return null;
    }

    private static void assertChain(List<byte[]> expected, List<byte[]> actual) {
        assertEquals(expected.size(), actual.size());
        for (int i = 0; i < expected.size(); i++) {
            assertArrayEquals("certificate " + i, expected.get(i), actual.get(i));
        }
    }

    /** Captures [keyStore]'s chain from a real server and checks no handshake completed. */
    private void assertCaptured(KeyStore keyStore, String[] protocols, boolean needClientAuth)
            throws Exception {
        try (TestServers.TlsServer server = new TestServers.TlsServer(
                keyStore, protocols, needClientAuth, InetAddress.getLoopbackAddress())) {
            List<byte[]> chain = probe.fetch(request("localhost", server.port()));
            assertChain(TestServers.encodedChain(keyStore), chain);
            Thread.sleep(100);
            assertEquals("handshake must be aborted", 0, server.completedHandshakes.get());
            assertEquals("no application data", 0, server.applicationBytes.get());
        }
    }

    // --- Certificates the system would reject: the chain is still captured. --

    @Test
    public void capturesTheChainOfAnExpiredCertificate() throws Exception {
        assertCaptured(TestServers.p12KeyStore("expired.p12"), null, false);
    }

    @Test
    public void capturesTheChainOfACertificateForAnotherHost() throws Exception {
        assertCaptured(TestServers.p12KeyStore("wrong_host.p12"), null, false);
    }

    @Test
    public void capturesASelfSignedEcCertificate() throws Exception {
        assertCaptured(TestServers.pemKeyStore("selfsigned.pem", "selfsigned.key"), null, false);
    }

    @Test
    public void capturesLeafAndIntermediateFromAnUntrustedCa() throws Exception {
        KeyStore keyStore = TestServers.pemKeyStore("server_a1_chain.pem", "server_a.key");
        assertEquals(2, TestServers.encodedChain(keyStore).size());
        assertCaptured(keyStore, null, false);
    }

    // --- Protocol variants. ---------------------------------------------

    @Test
    public void worksWithTls12Only() throws Exception {
        assertCaptured(TestServers.pemKeyStore("server_a1_chain.pem", "server_a.key"),
                new String[]{"TLSv1.2"}, false);
    }

    @Test
    public void worksWithTls13Only() throws Exception {
        String[] supported = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
        assumeTrue(java.util.Arrays.asList(supported).contains("TLSv1.3"));
        assertCaptured(TestServers.pemKeyStore("server_a1_chain.pem", "server_a.key"),
                new String[]{"TLSv1.3"}, false);
    }

    @Test
    public void worksWhenTheServerRequiresAClientCertificate() throws Exception {
        // The server certificate arrives before the client certificate is
        // requested, so the chain is captured and no certificate is sent.
        assertCaptured(TestServers.pemKeyStore("server_a1_chain.pem", "server_a.key"), null, true);
    }

    @Test
    public void sendsTheHostNameAsSni() throws Exception {
        // SNI carries fully qualified names only (RFC 6066): a single-label
        // name such as "localhost" is never sent. A local CONNECT proxy lets
        // the probe use a real FQDN without DNS.
        try (TestServers.TlsServer server = new TestServers.TlsServer(
                "server_a1_chain.pem", "server_a.key");
             TestServers.ConnectProxy proxy =
                     new TestServers.ConnectProxy("HTTP/1.1 200 Connection established")) {
            probe.fetch(new CertificateProbe.Request(
                    "service.example.test", server.port(), 5000, "127.0.0.1", proxy.port(), null));
            assertEquals(java.util.Collections.singletonList("service.example.test"), server.sniNames);
            assertTrue(proxy.requestHeads.get(0)
                    .startsWith("CONNECT service.example.test:" + server.port() + " HTTP/1.1\r\n"));
        }
    }

    @Test
    public void sendsNoSniForAnIpAddress() throws Exception {
        try (TestServers.TlsServer server = new TestServers.TlsServer(
                "server_a1_chain.pem", "server_a.key")) {
            assertEquals(2, probe.fetch(request("127.0.0.1", server.port())).size());
            assertTrue(server.sniNames.isEmpty());
        }
    }

    @Test
    public void worksOverIpv6Loopback() throws Exception {
        InetAddress ipv6 = InetAddress.getByName("::1");
        assumeTrue(ipv6 instanceof Inet6Address);
        TestServers.TlsServer server;
        try {
            server = new TestServers.TlsServer(
                    TestServers.pemKeyStore("server_a1_chain.pem", "server_a.key"), null, false, ipv6);
        } catch (java.net.SocketException noIpv6) {
            assumeTrue("IPv6 loopback unavailable", false);
            return;
        }
        try (TestServers.TlsServer s = server) {
            assertEquals(2, probe.fetch(request("::1", s.port())).size());
        }
    }

    // --- Servers that fail: each failure maps to a Dart error code. --------

    @Test
    public void aServerClosingImmediatelyIsAConnectionFailure() throws Exception {
        try (TestServers.MisbehavingServer server =
                     new TestServers.MisbehavingServer(TestServers.Misbehaviour.CLOSE_IMMEDIATELY)) {
            assertEquals("CONNECTION_FAILED", errorCode(request("localhost", server.port())));
        }
    }

    @Test
    public void aResetConnectionIsAConnectionFailure() throws Exception {
        try (TestServers.MisbehavingServer server =
                     new TestServers.MisbehavingServer(TestServers.Misbehaviour.RESET)) {
            assertEquals("CONNECTION_FAILED", errorCode(request("localhost", server.port())));
        }
    }

    @Test
    public void anUnresolvableHostIsAConnectionFailure() throws Exception {
        assertEquals("CONNECTION_FAILED",
                errorCode(request("does-not-exist.invalid", 443)));
    }

    @Test
    public void aServerNeverAnsweringTimesOut() throws Exception {
        // Accepts the TCP connection (backlog) but never speaks TLS.
        try (java.net.ServerSocket silent =
                     new java.net.ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            long start = System.nanoTime();
            assertEquals("TIMEOUT", errorCode(new CertificateProbe.Request(
                    "localhost", silent.getLocalPort(), 800, null, -1, null)));
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue("took " + elapsedMs + " ms", elapsedMs < 2500);
        }
    }

    // --- Proxies. ----------------------------------------------------------

    @Test
    public void aProxyClosingWithoutAnswerIsAConnectionFailure() throws Exception {
        try (TestServers.ConnectProxy proxy =
                     new TestServers.ConnectProxy(null, TestServers.ProxyMode.CLOSE)) {
            assertEquals("CONNECTION_FAILED", errorCode(new CertificateProbe.Request(
                    "localhost", 443, 3000, "127.0.0.1", proxy.port(), null)));
        }
    }

    @Test
    public void aHugeProxyResponseIsRejected() throws Exception {
        try (TestServers.ConnectProxy proxy =
                     new TestServers.ConnectProxy(null, TestServers.ProxyMode.HUGE_HEAD)) {
            assertEquals("CONNECTION_FAILED", errorCode(new CertificateProbe.Request(
                    "localhost", 443, 3000, "127.0.0.1", proxy.port(), null)));
        }
    }

    @Test
    public void aBadGatewayFromTheProxyIsAConnectionFailure() throws Exception {
        try (TestServers.ConnectProxy proxy = new TestServers.ConnectProxy("HTTP/1.1 502 Bad Gateway")) {
            assertEquals("CONNECTION_FAILED", errorCode(new CertificateProbe.Request(
                    "localhost", 443, 3000, "127.0.0.1", proxy.port(), null)));
        }
    }

    @Test
    public void capturesAnExpiredChainThroughAProxyWithCredentials() throws Exception {
        KeyStore keyStore = TestServers.p12KeyStore("expired.p12");
        try (TestServers.TlsServer server = new TestServers.TlsServer(
                keyStore, null, false, InetAddress.getLoopbackAddress());
             TestServers.ConnectProxy proxy =
                     new TestServers.ConnectProxy("HTTP/1.1 200 Connection established")) {
            String auth = "Basic " + Base64.getEncoder().encodeToString("u:p".getBytes("UTF-8"));
            List<byte[]> chain = probe.fetch(new CertificateProbe.Request(
                    "pinned.example.test", server.port(), 5000, "127.0.0.1", proxy.port(), auth));
            assertChain(TestServers.encodedChain(keyStore), chain);
            assertTrue(proxy.requestHeads.get(0).contains("Proxy-Authorization: " + auth + "\r\n"));
            assertEquals(java.util.Collections.singletonList("pinned.example.test"), server.sniNames);
            assertEquals(0, server.completedHandshakes.get());
        }
    }

    // --- Load. ----------------------------------------------------------------

    @Test
    public void manyConcurrentProbesAllSucceed() throws Exception {
        final int probes = CertificateProbe.MAX_THREADS + 8;
        try (TestServers.TlsServer server = new TestServers.TlsServer(
                "server_a1_chain.pem", "server_a.key")) {
            ExecutorService callers = Executors.newFixedThreadPool(probes);
            try {
                List<Future<List<byte[]>>> results = new ArrayList<>();
                for (int i = 0; i < probes; i++) {
                    results.add(callers.submit(new Callable<List<byte[]>>() {
                        @Override
                        public List<byte[]> call() throws Exception {
                            return probe.fetch(new CertificateProbe.Request(
                                    "localhost", server.port(), 10000, null, -1, null));
                        }
                    }));
                }
                for (Future<List<byte[]>> result : results) {
                    assertEquals(2, result.get(15, TimeUnit.SECONDS).size());
                }
                assertEquals(probes, server.connections.get());
                assertEquals(0, server.completedHandshakes.get());
            } finally {
                callers.shutdownNow();
            }
        }
    }

    @Test
    public void probesQueuedBehindStuckOnesStillRespectTheirDeadline() throws Exception {
        try (TestServers.SlowLorisServer slow = new TestServers.SlowLorisServer(300)) {
            ExecutorService callers = Executors.newFixedThreadPool(CertificateProbe.MAX_THREADS);
            try {
                // Occupy every probe thread for ~4 s.
                for (int i = 0; i < CertificateProbe.MAX_THREADS; i++) {
                    callers.submit(() -> {
                        try {
                            probe.fetch(new CertificateProbe.Request(
                                    "localhost", slow.port(), 4000, null, -1, null));
                        } catch (CertificateProbe.ProbeException ignored) {
                            // Times out.
                        }
                        return null;
                    });
                }
                Thread.sleep(300);
                long start = System.nanoTime();
                assertEquals("TIMEOUT", errorCode(new CertificateProbe.Request(
                        "localhost", slow.port(), 500, null, -1, null)));
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                assertTrue("took " + elapsedMs + " ms", elapsedMs < 1500);
            } finally {
                callers.shutdownNow();
            }
        }
    }

    @Test
    public void aProbeAfterShutdownFailsFast() throws Exception {
        probe.shutdown();
        try {
            probe.fetch(request("localhost", 443));
            fail("Expected a rejection after shutdown");
        } catch (java.util.concurrent.RejectedExecutionException expected) {
            // The plugin maps unexpected runtime errors to PLUGIN_ERROR.
        }
    }
}
