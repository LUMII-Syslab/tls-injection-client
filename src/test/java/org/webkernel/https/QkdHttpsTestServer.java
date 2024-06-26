package org.webkernel.https;


import lv.lumii.qkd.InjectableEtsiKEM;
import lv.lumii.tls.auth.FileToken;
import lv.lumii.tls.auth.Token;
import lv.lumii.tls.auth.TrustStore;
import nl.altindag.ssl.SSLFactory;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.Common;

import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;


public class QkdHttpsTestServer {

    private static final String MAIN_DIRECTORY = mainDirectory();

    private static String mainDirectory() {
        File f = new File(QkdHttpsTestServer.class.getProtectionDomain().getCodeSource().getLocation().getPath());
        String mainExecutable = f.getAbsolutePath();
        String mainDirectory = f.getParent();

        // Fix for debug purposes when launching from the IDE:
        if (mainExecutable.replace('\\', '/').endsWith("/build/classes/java/main")) {
            mainDirectory = mainExecutable.substring(0, mainExecutable.length() - "/build/classes/java/main".length());
            mainExecutable = "java";
        }
        if (mainExecutable.replace('\\', '/').endsWith("/build/classes/java/test")) {
            mainDirectory = mainExecutable.substring(0, mainExecutable.length() - "/build/classes/java/test".length());
            mainExecutable = "java";
        }
        return mainDirectory;
    }

    class MyHttpResponseHandler implements HttpClientResponseHandler {

        @Override
        public Object handleResponse(ClassicHttpResponse classicHttpResponse) throws HttpException, IOException {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {

        Common.loadNativeLibrary();

        injectQKD(() -> {
            Token saeToken = new FileToken(
                    new String[]{MAIN_DIRECTORY + File.separator + "sae-2.crt.pem"},
                    MAIN_DIRECTORY + File.separator + "sae-2.key.pem",
                    "");
            TrustManagerFactory trustMgrFact = new TrustStore(new String[]{MAIN_DIRECTORY + File.separator + "ca.crt.pem"}).trustManagerFactory();

            try {
                return SSLFactory.builder()
                        .withIdentityMaterial(saeToken.key(), saeToken.password(), saeToken.certificateChain())
                        .withNeedClientAuthentication()
                        .withWantClientAuthentication()
                        .withProtocols("TLSv1.3")
                        .withTrustMaterial(trustMgrFact)
                        .withSecureRandom(SecureRandom.getInstanceStrong())
                        .withCiphers("TLS_AES_256_GCM_SHA384")
                        .build();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        try {
            Token token = new FileToken(MAIN_DIRECTORY + File.separator + "server.pfx", "server-keystore-pass", "server");
            KeyStore trustStore = KeyStore.getInstance(new File(MAIN_DIRECTORY + File.separator + "ca.truststore"), "ca-truststore-pass".toCharArray());

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(trustStore);

            SSLFactory sslf2 = SSLFactory.builder()
                    .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                    .withNeedClientAuthentication()
                    .withWantClientAuthentication()
                    .withProtocols("TLSv1.3")
                    .withTrustMaterial(trustMgrFact)
                    .withSecureRandom(SecureRandom.getInstanceStrong())
                    .withCiphers("TLS_AES_256_GCM_SHA384")
                    .build();

            Optional<X509ExtendedTrustManager> tm = sslf2.getTrustManager();

            HttpServer server = new HttpServer(Optional.of(sslf2.getSslContext()), 1234,
                    (socket, requestBuilder) -> new HttpResponse<byte[]>() {
                        @Override
                        public int statusCode() {
                            return 200;
                        }

                        @Override
                        public HttpRequest request() {
                            return null;
                        }

                        @Override
                        public Optional<HttpResponse<byte[]>> previousResponse() {
                            return Optional.empty();
                        }

                        @Override
                        public HttpHeaders headers() {
                            return HttpHeaders.of(Map.of(), (k, v) -> true);
                        }

                        @Override
                        public byte[] body() {
                            return "THIS IS MY REPLY".getBytes(StandardCharsets.UTF_8);
                        }

                        @Override
                        public Optional<SSLSession> sslSession() {
                            return Optional.empty();
                        }

                        @Override
                        public URI uri() {
                            return null;
                        }

                        @Override
                        public HttpClient.Version version() {
                            return HttpClient.Version.HTTP_1_1;
                        }
                    });

            server.start();
        } catch (Exception e) {
            System.err.println("Some exception occurred.12345678");
            e.printStackTrace();
        }

    }

    private static void injectQKD(InjectableEtsiKEM.SSLFactoryFactory sslf1) {
        InjectionPoint injectionPoint = InjectionPoint.theInstance();
        final InjectableAlgorithms initialAlgs = new InjectableAlgorithms();
        injectionPoint.push(initialAlgs);

        final CompletableFuture<InjectableAlgorithms> algsWithEtsi = new CompletableFuture<>();

        algsWithEtsi.complete( // = assign the value, which can be used using algsWithEtsi.get()
                initialAlgs
                        .withoutDefaultKEMs()
                        .withKEM("QKD-ETSI",
                                0xFEFE, // from the reserved-for-private-use range, i.e., 0xFE00..0xFEFF for KEMs
                                () -> new InjectableEtsiKEM(
                                        sslf1,
                                        "localhost:8020",
                                        "25840139-0dd4-49ae-ba1e-b86731601803",
                                        () -> {
                                            try {
                                                injectionPoint.pop(algsWithEtsi.get());
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                throw new RuntimeException(e);
                                            }
                                        },
                                        () -> {
                                            try {
                                                injectionPoint.pushAfter(algsWithEtsi.get(), initialAlgs);
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                                throw new RuntimeException(e);
                                            }
                                        }
                                ),
                                InjectableKEMs.Ordering.BEFORE));
        try {
            injectionPoint.pushAfter(algsWithEtsi.get(), initialAlgs);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


}
