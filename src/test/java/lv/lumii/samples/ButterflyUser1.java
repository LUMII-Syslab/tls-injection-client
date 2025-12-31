package lv.lumii.samples;

import lv.lumii.butterfly.ButterflyKEM;
import lv.lumii.butterfly.ButterflyProperties;
import lv.lumii.pqc.InjectableFrodoKEM;
import lv.lumii.pqc.InjectableLiboqsKEM;
import lv.lumii.pqc.InjectableLiboqsSigAlg;
import lv.lumii.pqc.InjectableSphincsPlus;
import lv.lumii.tls.auth.FileToken;
import lv.lumii.tls.auth.Token;
import lv.lumii.tls.auth.TrustStore;
import nl.altindag.ssl.SSLFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tls.injection.InjectableAlgorithms;
import org.bouncycastle.tls.injection.InjectableKEMs;
import org.bouncycastle.tls.injection.InjectionPoint;
import org.openquantumsafe.Common;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * A TLS client that uses a key obtained from a QKD device to secure the TLS session.
 *
 * For testing purposes, you can use QKD KME simulator from here: https://github.com/next-door-key/py-qkd-kme-sim
 */
public class ButterflyUser1 {


    private static final String MAIN_DIRECTORY = mainDirectory();


    // >>>>> Our credentials + trust store to verify the server.
    private static final Token token = new FileToken(MAIN_DIRECTORY + File.separator + "ca-scripts" + File.separator+"user1"+File.separator+"client.pfx", "client-keystore-pass", "client");
    private static final TrustStore trustStore = new TrustStore(MAIN_DIRECTORY + File.separator + "ca-scripts" + File.separator+"ca"+File.separator+ "ca.truststore", "ca-truststore-pass");

    private static final ButterflyProperties butterflyProperties = new ButterflyProperties(MAIN_DIRECTORY);
    // <<<<<

    private static String mainDirectory() {
        File f = new File(QkdTlsTestClient.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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


    public static void main(String[] args) throws Exception {

        System.out.println("13dxxxdc3q");
        Common.loadNativeLibrary();


        injectButterfly();

        try {
            SSLFactory sslf2 = SSLFactory.builder()
                    .withIdentityMaterial(token.key(), token.password(), token.certificateChain())
                    .withNeedClientAuthentication()
                    .withWantClientAuthentication()
                    .withProtocols("TLSv1.3")
                    .withTrustMaterial(trustStore.trustManagerFactory()) // or just trustStore.asKeyStore()
                    .withSecureRandom(SecureRandom.getInstanceStrong())
                    .withCiphers("TLS_AES_256_GCM_SHA384")
                    .withHostnameVerifier((hostname, session) -> {
                        return true;
                    })
                    .build();

            long ms1 = System.currentTimeMillis();

            if (ButterflyUser2.USER2_TLS) {

                try (SSLSocket sslSocket = (SSLSocket) sslf2.getSslSocketFactory().createSocket(butterflyProperties.user2Uri().getHost(), butterflyProperties.user2Uri().getPort())) {
                    SSLParameters params = sslSocket.getSSLParameters();
                    params.setServerNames(
                            List.of(new SNIHostName("localhost"))
                    );
                    sslSocket.setSSLParameters(params);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                    PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true);

                    // Send message to the server
                    writer.println("Hello, server!");

                    // Read server response
                    String response = reader.readLine();

                    long ms2 = System.currentTimeMillis();

                    System.out.println("Server response (" + (ms2 - ms1) + "ms): " + response);

                }
            }
            else {
                // non-TLS mode
                try (Socket sslSocket = new Socket(butterflyProperties.user2Uri().getHost(), butterflyProperties.user2Uri().getPort())) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                    PrintWriter writer = new PrintWriter(sslSocket.getOutputStream(), true);

                    // Send message to the server
                    writer.println("Hello, server!");

                    // Read server response
                    String response = reader.readLine();

                    long ms2 = System.currentTimeMillis();

                    System.out.println("Server response (" + (ms2 - ms1) + "ms): " + response);

                }
            }

        } catch (Exception e) {
            System.err.println("Some exception occurred.");
            e.printStackTrace();
        }

    }

    private static void injectButterfly() {
        InjectionPoint injectionPoint = InjectionPoint.theInstance();
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(32768 * 32));

        InjectableSphincsPlus mySphincs = new InjectableSphincsPlus();

        String oqsName = "SPHINCS+-SHA2-128f-simple";
        List<String> oqsAliases = Arrays.asList(new String[] {"SPHINCS+-SHA2-128F", "SPHINCS+", "SPHINCSPLUS"});
        InjectableLiboqsSigAlg oqsSphincs = new InjectableLiboqsSigAlg(oqsName, oqsAliases, mySphincs.oid(), mySphincs.codePoint());

        String oqsDilithiumName = "Dilithium2";
        int oqsDilithiumCodePoint = 0xfea0;
        ASN1ObjectIdentifier oqsDilithiumOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.7.4").branch("4");
        Collection<String> oqsDilithiumAliases = Arrays.asList(new String[]{});
        InjectableLiboqsSigAlg oqsDilithium2 = new InjectableLiboqsSigAlg(oqsDilithiumName, oqsDilithiumAliases, oqsDilithiumOid, oqsDilithiumCodePoint);

        InjectableAlgorithms initialAlgs = new InjectableAlgorithms()
                .withoutDefaultKEMs()
                .withSigAlg(oqsSphincs.name(), oqsAliases, oqsSphincs.oid(), oqsSphincs.codePoint(), oqsSphincs)
                .withSigAlg(oqsDilithiumName, oqsDilithiumAliases, oqsDilithiumOid, oqsDilithiumCodePoint, oqsDilithium2)
                .withKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT,
                        ()->new InjectableLiboqsKEM(InjectableFrodoKEM.NAME, InjectableFrodoKEM.CODE_POINT), InjectableKEMs.Ordering.AFTER);

        injectionPoint.push(initialAlgs);

        new ButterflyKEM(
                butterflyProperties,
                injectionPoint,
                initialAlgs
        ).inject();
    }

}
