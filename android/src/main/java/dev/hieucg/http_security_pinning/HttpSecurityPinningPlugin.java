// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dev.hieucg.http_security_pinning;

import androidx.annotation.NonNull;

import java.util.List;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.StandardMethodCodec;

/**
 * Bridges the Dart {@code MethodChannelCertificateFetcher} to
 * {@link CertificateProbe}.
 */
public class HttpSecurityPinningPlugin implements FlutterPlugin, MethodCallHandler {

    static final String CHANNEL = "http_security_pinning";

    private MethodChannel channel;
    private CertificateProbe probe;

    @Override
    public void onAttachedToEngine(@NonNull FlutterPluginBinding flutterPluginBinding) {
        BinaryMessenger messenger = flutterPluginBinding.getBinaryMessenger();
        // Not serial: a slow host must not delay the probes of other hosts.
        BinaryMessenger.TaskQueue taskQueue = messenger.makeBackgroundTaskQueue(
                new BinaryMessenger.TaskQueueOptions().setIsSerial(false));
        probe = new CertificateProbe();
        channel = new MethodChannel(messenger, CHANNEL, StandardMethodCodec.INSTANCE, taskQueue);
        channel.setMethodCallHandler(this);
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull Result result) {
        if (!call.method.equals("fetchHostCertificates")) {
            result.notImplemented();
            return;
        }
        handleFetch(probe, call, result);
    }

    /** Handles {@code fetchHostCertificates}; package-private for tests. */
    static void handleFetch(CertificateProbe probe, MethodCall call, Result result) {
        try {
            final Integer port = call.argument("port");
            final Integer timeoutMs = call.argument("timeout");
            final Integer proxyPort = call.argument("proxyPort");
            CertificateProbe.Request request = new CertificateProbe.Request(
                    call.argument("host"),
                    port == null ? -1 : port,
                    timeoutMs == null ? -1 : timeoutMs,
                    call.argument("proxyHost"),
                    proxyPort == null ? -1 : proxyPort,
                    call.argument("proxyAuthorization"));
            List<byte[]> certificates = probe.fetch(request);
            result.success(certificates);
        } catch (CertificateProbe.ProbeException e) {
            result.error(e.code, e.getMessage(), null);
        } catch (RuntimeException e) {
            result.error("PLUGIN_ERROR",
                    "Unexpected plugin error (" + e.getClass().getSimpleName() + ").", null);
        }
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        if (channel != null) {
            channel.setMethodCallHandler(null);
            channel = null;
        }
        if (probe != null) {
            probe.shutdown();
            probe = null;
        }
    }
}
