import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

public class EchoHttpsServer {

    public static void main(String[] args) throws Exception {
        int port = 8443;

        // Load keystore
        char[] password = "111111".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream keystoreInputStream = EchoHttpsServer.class.getResourceAsStream("./keystore.jks")) {
            keyStore.load(keystoreInputStream, password);
        }

        // Initialize key manager factory
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, password);

        // Initialize SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // Create and configure the HTTPS server
        HttpsServer server = HttpsServer.create(new InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    System.out.println("Failed to create HTTPS server");
                }
            }
        });

        // Create a simple context for the root path "/"
        server.createContext("/", exchange -> {
            InputStream requestBody = exchange.getRequestBody();
            byte[] requestBodyBytes = requestBody.readAllBytes();
            // String requestBodyString = new String(requestBodyBytes);

            exchange.sendResponseHeaders(200, requestBodyBytes.length);
            OutputStream responseBody = exchange.getResponseBody();
            responseBody.write(requestBodyBytes);
            responseBody.close();
        });

        // Start the server
        server.start();

        System.out.println("Server started on port " + port);
    }
}

