// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;

/** Tests of the method channel handling of the Android plugin. */
public class HttpSecurityPinningPluginTest {

    private CertificateProbe probe;

    @Before
    public void setUp() {
        probe = new CertificateProbe();
    }

    @After
    public void tearDown() {
        probe.shutdown();
    }

    private static MethodCall fetchCall(Object host, Object port, Object timeout) {
        Map<String, Object> args = new HashMap<>();
        args.put("url", "https://localhost/");
        args.put("host", host);
        args.put("port", port);
        args.put("timeout", timeout);
        return new MethodCall("fetchHostCertificates", args);
    }

    @Test
    public void unknownMethodsAreNotImplemented() {
        MethodChannel.Result result = mock(MethodChannel.Result.class);
        new HttpSecurityPinningPlugin().onMethodCall(new MethodCall("other", null), result);
        verify(result).notImplemented();
    }

    @Test
    public void missingOrInvalidArgumentsAreReported() {
        Object[][] cases = {
                {null, 443, 1000},
                {"localhost", null, 1000},
                {"localhost", 443, null},
                {"localhost", 443, 0},
        };
        for (Object[] c : cases) {
            MethodChannel.Result result = mock(MethodChannel.Result.class);
            HttpSecurityPinningPlugin.handleFetch(probe, fetchCall(c[0], c[1], c[2]), result);
            verify(result).error(eq("INVALID_ARGS"), anyString(), isNull());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void returnsTheChainAsByteArrays() throws Exception {
        try (TestServers.TlsServer server =
                     new TestServers.TlsServer("server_a1_chain.pem", "server_a.key")) {
            MethodChannel.Result result = mock(MethodChannel.Result.class);
            HttpSecurityPinningPlugin.handleFetch(probe, fetchCall("localhost", server.port(), 5000), result);
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(result).success(captor.capture());
            List<byte[]> chain = (List<byte[]>) captor.getValue();
            assertEquals(2, chain.size());
        }
    }

    @Test
    public void errorsDoNotLeakRawExceptionMessages() throws Exception {
        MethodChannel.Result result = mock(MethodChannel.Result.class);
        HttpSecurityPinningPlugin.handleFetch(probe,
                fetchCall("no-such-host.invalid", 443, 3000), result);
        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(result).error(anyString(), message.capture(), isNull());
        // Only an exception class name, never the raw message.
        assertEquals(false, message.getValue().contains("no-such-host.invalid"));
    }
}
