package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.SslClientAuthMode;

import io.undertow.Undertow.Builder;
import io.undertow.Undertow.ListenerBuilder;
import io.undertow.Undertow.ListenerType;
import io.undertow.UndertowOptions;
import io.undertow.protocols.ssl.SNIContextMatcher;
import io.undertow.protocols.ssl.SNISSLContext;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import runwar.Server;
import runwar.options.ConfigParser.JSONOption;
import runwar.options.ServerOptions;
import runwar.security.SSLUtil;

public class ListenerManager {

    ListenerManager() {
    }

    public static void configureListeners(Builder serverBuilder, ServerOptions serverOptions) {
        JSONOption listeners = serverOptions.listeners();
        String cfengine = serverOptions.cfEngineName();

        LOG.info("Listeners:");

        if (listeners.hasOption("http")) {
            JSONOption HTTPListeners = listeners.g("http");
            for (String key : HTTPListeners.getKeys()) {
                JSONOption listener = HTTPListeners.g(key);
                LOG.info(
                        "  - Binding HTTP on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port"));
                OptionMap.Builder socketOptions = OptionMap.builder();

                if (listener.hasOption("HTTP2Enable")) {
                    LOG.debug("     Setting HTTP/2 enabled: " + listener.getOptionBoolean("HTTP2Enable"));
                    // Undertow ignores this :/
                    socketOptions.set(UndertowOptions.ENABLE_HTTP2, listener.getOptionBoolean("HTTP2Enable"));
                    // Only this server-wide setting appears to do anything. If it's not set, set
                    // it.
                    if (serverOptions.undertowOptions().getMap().get(UndertowOptions.ENABLE_HTTP2) == null) {
                        serverOptions.undertowOptions().set(UndertowOptions.ENABLE_HTTP2,
                                listener.getOptionBoolean("HTTP2Enable"));
                        // Otherwise, set it, favoring true
                    } else {
                        serverOptions.undertowOptions().set(UndertowOptions.ENABLE_HTTP2,
                                listener.getOptionBoolean("HTTP2Enable")
                                        || serverOptions.undertowOptions().getMap().get(UndertowOptions.ENABLE_HTTP2));
                    }
                }

                serverBuilder.addListener(
                        new ListenerBuilder()
                                .setType(ListenerType.HTTP)
                                .setPort(listener.getOptionInt("port"))
                                .setHost(listener.getOptionValue("IP"))
                                .setOverrideSocketOptions(socketOptions.getMap()));
            }
        }

        if (listeners.hasOption("ssl")) {
            JSONOption HTTPSListeners = listeners.g("ssl");
            for (String key : HTTPSListeners.getKeys()) {
                JSONOption listener = HTTPSListeners.g(key);
                LOG.info("  - Binding SSL on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port"));

                if (serverOptions.sslEccDisable() && cfengine.toLowerCase().equals("adobe")) {
                    LOG.debug("   Disabling com.sun.net.ssl.enableECC");
                    System.setProperty("com.sun.net.ssl.enableECC", "false");
                }

                try {
                    JSONOption clientCert = listener.g("clientCert");
                    String[] sslAddCACerts = null;
                    String sslTruststore = null;
                    String sslTruststorePass = null;

                    if (clientCert.hasOption("CATrustStoreFile")) {
                        sslTruststore = clientCert.getOptionValue("CATrustStoreFile");
                        if (clientCert.hasOption("CATrustStorePass")
                                && clientCert.getOptionValue("CATrustStorePass") != null) {
                            sslTruststorePass = clientCert.getOptionValue("CATrustStorePass");
                        } else {
                            sslTruststorePass = "";
                        }
                    }
                    // Even if there is a trust store provided above, any certs below will be added
                    // in along with the original contents.
                    if (clientCert.hasOption("CACertFiles")) {
                        sslAddCACerts = clientCert.getOptionArray("CACertFiles").stream().toArray(String[]::new);
                    }

                    JSONArray certs = listener.getOptionArray("certs");
                    SNIContextMatcher.Builder sniMatchBuilder = new SNIContextMatcher.Builder();
                    boolean first = true;

                    SSLContext sslContext = null;
                    if (certs.size() > 0) {

                        for (Object certObject : certs) {
                            JSONOption cert = new JSONOption((JSONObject) certObject);

                            File certFile = cert.getOptionFile("certFile");
                            File keyFile = cert.getOptionFile("keyFile");
                            char[] keypass;
                            if (cert.hasOption("keyPass") && cert.getOptionValue("keyPass") != null) {
                                keypass = cert.getOptionValue("keyPass").toCharArray();
                            } else {
                                keypass = "".toCharArray();
                            }

                            sslContext = SSLUtil.createSSLContext(certFile, keyFile, keypass, null, sslTruststore,
                                    sslTruststorePass, sslAddCACerts, sniMatchBuilder);
                            if (first) {
                                // The first SSL Context we come across becomes the default
                                // If the site allows in a hostname not matched by any of the certs, this
                                // context will get used.
                                sniMatchBuilder.setDefaultContext(sslContext);
                                first = false;
                            }
                            // Wipe out the password just so it's not laying around memory
                            if (keypass != null) {
                                Arrays.fill(keypass, '*');
                            }
                        }

                    } else {
                        sslContext = SSLUtil.createSSLContext(null, sslTruststore, sslTruststorePass, sslAddCACerts,
                                sniMatchBuilder);
                        sniMatchBuilder.setDefaultContext(sslContext);
                    }
                    // Only enable SNI if there was more than 1 cert
                    if (certs.size() > 1) {
                        LOG.debug("     Enabling SNI on SSLContext. (" + certs.size() + " certs)");
                        sslContext = new SNISSLContext(sniMatchBuilder.build());
                    }
                    OptionMap.Builder socketOptions = OptionMap.builder();

                    if (listener.hasOption("HTTP2Enable")) {
                        LOG.debug("     Setting HTTP/2 enabled: " + listener.getOptionBoolean("HTTP2Enable"));
                        // Undertow ignores this :/
                        socketOptions.set(UndertowOptions.ENABLE_HTTP2, listener.getOptionBoolean("HTTP2Enable"));
                        // Only this server-wide setting appears to do anything. If it's not set, set
                        // it.
                        if (serverOptions.undertowOptions().getMap().get(UndertowOptions.ENABLE_HTTP2) == null) {
                            serverOptions.undertowOptions().set(UndertowOptions.ENABLE_HTTP2,
                                    listener.getOptionBoolean("HTTP2Enable"));
                            // Otherwise, set it, favoring true
                        } else {
                            serverOptions.undertowOptions().set(UndertowOptions.ENABLE_HTTP2,
                                    listener.getOptionBoolean("HTTP2Enable") || serverOptions.undertowOptions().getMap()
                                            .get(UndertowOptions.ENABLE_HTTP2));
                        }
                    }

                    if (clientCert.hasOption("mode")) {
                        LOG.debug("     Client Cert Negotiation: " + clientCert.getOptionValue("mode"));
                        socketOptions.set(Options.SSL_CLIENT_AUTH_MODE,
                                SslClientAuthMode.valueOf(clientCert.getOptionValue("mode").toUpperCase()));
                    }

                    if (clientCert.hasOption("SSLRenegotiationEnable")
                            && clientCert.getOptionBoolean("SSLRenegotiationEnable")) {
                        LOG.warn("     SSL Client cert renegotiation is enabled.  Disabling HTTP/2 and TLS1.3");
                        socketOptions.set(UndertowOptions.ENABLE_HTTP2, false);
                        if (!socketOptions.getMap().contains(Options.SSL_ENABLED_PROTOCOLS)) {
                            socketOptions.setSequence(Options.SSL_ENABLED_PROTOCOLS, "TLSv1.1", "TLSv1.2");
                        }
                    }

                    serverBuilder.addListener(
                            new ListenerBuilder()
                                    .setType(ListenerType.HTTPS)
                                    .setPort(listener.getOptionInt("port"))
                                    .setHost(listener.getOptionValue("IP"))
                                    .setSslContext(sslContext)
                                    .setOverrideSocketOptions(socketOptions.getMap()));

                } catch (Exception e) {
                    throw new RuntimeException("Unable to start SSL", e);
                }
            }
        }

        if (listeners.hasOption("ajp")) {
            JSONOption AJPListeners = listeners.g("ajp");
            for (String key : AJPListeners.getKeys()) {
                JSONOption listener = AJPListeners.g(key);
                LOG.info("  - Binding AJP on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port"));
                OptionMap.Builder socketOptions = OptionMap.builder();
                if (serverOptions.undertowOptions().getMap().size() == 0) {
                    // if no options is set, default to the large packet size
                    socketOptions.set(UndertowOptions.MAX_AJP_PACKET_SIZE, 65536);
                }

                final String AJPPort = listener.getOptionValue("port");
                serverBuilder.addListener(
                        new ListenerBuilder()
                                .setType(ListenerType.AJP)
                                .setPort(listener.getOptionInt("port"))
                                .setHost(listener.getOptionValue("IP"))
                                .setOverrideSocketOptions(socketOptions.getMap())
                                .setRootHandler(new HttpHandler() {

                                    @Override
                                    public void handleRequest(final HttpServerExchange exchange) throws Exception {

                                        Map<String, String> attrs = exchange
                                                .getAttachment(HttpServerExchange.REQUEST_ATTRIBUTES);
                                        if (attrs == null) {
                                            exchange.putAttachment(HttpServerExchange.REQUEST_ATTRIBUTES,
                                                    attrs = new HashMap<>());
                                        }

                                        // Mark this request as coming from this AJP port as Undertow doesn't seem to
                                        // provide any way to get this info from the exchange later.
                                        attrs.put("__ajp_port", AJPPort);
                                        Server.getRootHandler().handleRequest(exchange);
                                    }

                                    @Override
                                    public String toString() {
                                        return "AJP Identifying Handler";
                                    }

                                }));
            }
        }

    }

}
