package dev.hieucg.http_security_pinning;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

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

    /**
     * Custom exception for certificate fetching failures, used internally.
     */
    private static class CertificateFetchException extends Exception {
        final String code;

        CertificateFetchException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /**
     * Handles the logic of fetching certificate chains from a given URL.
     * This is a static inner class as it does not need access to the plugin instance state.
     */
    private static class HostCertificatesFetcher {
        public List<byte[]> fetch(@NonNull String urlString, int timeoutMs) throws CertificateFetchException {
            if (urlString.isEmpty()) {
                throw new CertificateFetchException("INVALID_URL", "URL is null or empty.");
            }

            HttpsURLConnection connection = null;
            try {
                URL url = new URL(urlString);
                connection = (HttpsURLConnection) url.openConnection();
                connection.setConnectTimeout(timeoutMs);
                connection.setInstanceFollowRedirects(true);
                connection.connect();

                Certificate[] certificates = connection.getServerCertificates();
                if (certificates == null || certificates.length == 0) {
                    throw new CertificateFetchException("NO_CERTIFICATES", "Server returned no certificates.");
                }

                final List<byte[]> hostCertificates = new ArrayList<>(certificates.length);
                for (Certificate certificate : certificates) {
                    hostCertificates.add(certificate.getEncoded());
                }
                return hostCertificates;
            } catch (MalformedURLException e) {
                throw new CertificateFetchException("INVALID_URL", "Malformed URL: " + e.getMessage());
            } catch (IOException e) {
                throw new CertificateFetchException("CONNECTION_FAILED", "Connection failed: " + e.getMessage());
            } catch (CertificateEncodingException e) {
                throw new CertificateFetchException("CERTIFICATE_ERROR", "Failed to encode certificate: " + e.getMessage());
            } catch (Exception e) {
                throw new CertificateFetchException("UNEXPECTED_ERROR", "An unexpected error occurred: " + e.getMessage());
            } finally {
                if (connection != null) {
                    connection.disconnect();
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

                if (timeoutMs == null) {
                    result.error("INVALID_ARGS", "Timeout argument is missing.", null);
                    return;
                }

                List<byte[]> certificates = hostCertificatesFetcher.fetch(urlString, timeoutMs);
                result.success(certificates);
            } catch (CertificateFetchException e) {
                result.error(e.code, e.getMessage(), null);
            } catch (Exception e) {
                // This is a final safeguard against any unexpected errors within the plugin logic itself.
                result.error("PLUGIN_ERROR", "An unexpected plugin error occurred: " + e.getMessage(), null);
            }
        } else {
            result.notImplemented();
        }
    }

    @Override
    public void onDetachedFromEngine(@NonNull FlutterPluginBinding binding) {
        channel.setMethodCallHandler(null);
    }
}