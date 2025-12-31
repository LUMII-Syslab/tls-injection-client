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
import org.openquantumsafe.KEMs;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import java.net.ServerSocket;
/**
 * A TLS server that uses QKD keys to secure TLS sessions.
 *
 * For testing purposes, you can use QKD KME simulator from here: https://github.com/next-door-key/py-qkd-kme-sim
 */
public class ButterflyUser2 {

    public static final boolean USER2_TLS = true;
    private static final String MAIN_DIRECTORY = mainDirectory();

    // >>>>> Our server credentials + trust store to verify the client.
    private static final Token token = new FileToken(MAIN_DIRECTORY + File.separator + "ca-scripts" + File.separator+"user2"+File.separator+"server.pfx", "server-keystore-pass", "server");
    private static final TrustStore trustStore = new TrustStore(MAIN_DIRECTORY + File.separator + "ca-scripts" + File.separator+"ca"+File.separator+ "ca.truststore", "ca-truststore-pass");

    private static final ButterflyProperties butterflyProperties = new ButterflyProperties(MAIN_DIRECTORY);
    // <<<<<


/*    // >>>>> Our server credentials + trust store to verify clients.
    //For PKCS12 (.pfx):
    //  private static final Token token = new FileToken(MAIN_DIRECTORY + File.separator + "server.pfx", "server-keystore-pass", "server");
    //For PEM cert+key:
    private static final Token token = new FileToken(
            new String[]{MAIN_DIRECTORY + File.separator + "server.crt"},
            MAIN_DIRECTORY + File.separator + "server.key",
            "");
    private static final TrustStore trustStore = new TrustStore(MAIN_DIRECTORY + File.separator + "ca.truststore", "ca-truststore-pass");
    // <<<<<
*/
    private static String mainDirectory() {
        File f = new File(QkdTlsTestServer.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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

        int PORT = butterflyProperties.user2Uri().getPort(); //8443;
        System.out.println("!");

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

            // Initialize SSLContext with the KeyManager
            SSLContext sslContext = sslf2.getSslContext();

            sslContext.init(sslf2.getKeyManagerFactory().get().getKeyManagers(), trustStore.trustManagerFactory().getTrustManagers(), SecureRandom.getInstanceStrong());

            // Create SSLServerSocketFactory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            if (USER2_TLS) {
                // Create SSLServerSocket
                SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT);
                sslServerSocket.setNeedClientAuth(true); // <<<<< this is very important line; otherwise, all clients are let in!
                sslServerSocket.setEnabledCipherSuites(sslServerSocket.getSupportedCipherSuites());

                System.out.println("TLS server started on port " + PORT);

                while (true) {
                    // Accept client connections
                    try {
                        Socket socket = sslServerSocket.accept();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

                        // Read client message
                        String message = reader.readLine();
                        System.out.println("Received: " + message);

                        // Send response to client
                        writer.println("Hello, client! Your message was: " + message);

                    } catch (Exception clientEx) {
                        clientEx.printStackTrace();
                    }
                }
            }
            else {
                // non-TLS socket
                ServerSocket serverSocket = new ServerSocket(PORT); // NON-TLS
                System.out.println("Non-TLS server listening on " + PORT);

                while (true) {
                    // Accept client connections
                    try {
                        Socket socket = serverSocket.accept();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

                        // Read client message
                        String message = reader.readLine();
                        System.out.println("Received: " + message);

                        // Send response to client
                        writer.println("Hello, client! Your message was: " + message);

                    } catch (Exception clientEx) {
                        clientEx.printStackTrace();
                    }
                }

            }

        } catch (Exception e) {
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
