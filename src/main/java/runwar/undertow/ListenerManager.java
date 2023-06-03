package runwar;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.Undertow.ListenerBuilder;
import io.undertow.Undertow.ListenerType;
import io.undertow.client.ClientConnection;
import io.undertow.UndertowOptions;
import io.undertow.predicate.Predicates;
import io.undertow.predicate.Predicate;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.ProxyPeerAddressHandler;
import io.undertow.server.handlers.SSLHeaderHandler;
import io.undertow.server.handlers.accesslog.AccessLogHandler;
import io.undertow.server.handlers.accesslog.DefaultAccessLogReceiver;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
import io.undertow.server.handlers.cache.DirectBufferCache;
import io.undertow.server.handlers.encoding.ContentEncodingRepository;
import io.undertow.server.handlers.encoding.EncodingHandler;
import io.undertow.server.handlers.encoding.GzipEncodingProvider;
import io.undertow.server.handlers.resource.CachingResourceManager;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.server.handlers.resource.ResourceHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletSessionConfig;
import io.undertow.util.CanonicalPathUtils;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderValues;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.MimeMappings;
import io.undertow.io.Sender;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import io.undertow.protocols.ssl.SNIContextMatcher;
import io.undertow.protocols.ssl.SNISSLContext;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import runwar.options.ConfigParser.JSONOption;
import org.xnio.*;
import org.xnio.OptionMap;
import org.xnio.Options;
import runwar.logging.LoggerFactory;
import runwar.logging.LoggerPrintStream;
import runwar.logging.RunwarAccessLogReceiver;
import runwar.mariadb4j.MariaDB4jManager;
import runwar.options.ServerOptions;
import runwar.security.SSLUtil;
import runwar.security.SecurityManager;
import runwar.tray.Tray;
import runwar.undertow.MappedResourceManager;
import runwar.undertow.HostResourceManager;
import runwar.undertow.RequestDebugHandler;
import runwar.undertow.SSLClientCertHeaderHandler;
import runwar.undertow.LifecyleHandler;
import runwar.undertow.WelcomeFileHandler;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;
import runwar.util.ClassLoaderUtils;
import runwar.util.RequestDumper;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.io.*;
import java.util.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.server.HandlerWrapper;
import static runwar.logging.RunwarLogger.LOG;

public class ListenerManager {

    ListenerManager(){
    }

    public static void configureListeners(Builder serverBuilder, ServerOptions serverOptions ) {
        JSONOption listeners = serverOptions.listeners();
        String cfengine = serverOptions.cfEngineName();

        if( listeners.hasOption( "http" ) ) {
            JSONOption HTTPListeners = listeners.g( "http" );
            for( String key : HTTPListeners.getKeys() ) {
                JSONOption listener = HTTPListeners.g( key );
                LOG.info("Binding HTTP on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port") );
                OptionMap.Builder socketOptions = OptionMap.builder();

                if (listener.hasOption("HTTP2Enable" ) ) {
                    LOG.info("Setting HTTP/2 enabled: " + listener.getOptionBoolean("HTTP2Enable" ) );
                    socketOptions.set(UndertowOptions.ENABLE_HTTP2, listener.getOptionBoolean("HTTP2Enable" ) );
                }

                serverBuilder.addListener(
                    new ListenerBuilder()
                    .setType( ListenerType.HTTP )
                    .setPort( listener.getOptionInt("port") )
                    .setHost( listener.getOptionValue("IP") )
                    .setOverrideSocketOptions( socketOptions.getMap() )
                );
            }
        }

        if( listeners.hasOption( "ssl" ) ) {
            JSONOption HTTPSListeners = listeners.g( "ssl" );
            for( String key : HTTPSListeners.getKeys() ) {
                JSONOption listener = HTTPSListeners.g( key );
                LOG.info("Binding SSL on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port") );

                if (serverOptions.sslEccDisable() && cfengine.toLowerCase().equals("adobe")) {
                    LOG.debug("disabling com.sun.net.ssl.enableECC");
                    System.setProperty("com.sun.net.ssl.enableECC", "false");
                }

                try {
                    SSLContext sslContext=null;
                    String[] sslAddCerts=null;
                    String[] sslAddCACerts=null;
                    String sslTruststore=null;
                    String sslTruststorePass=null;
                    JSONArray certs = listener.getOptionArray( "certs" );
                    SNIContextMatcher.Builder sniMatchBuilder = new SNIContextMatcher.Builder();
                    boolean first = true;

                    if( certs.size() > 0 ) {

                        for( Object certObject : certs ) {
                            JSONOption cert = new JSONOption( (JSONObject)certObject );

                            File certFile = cert.getOptionFile( "certFile" );
                            File keyFile = cert.getOptionFile( "keyFile" );
                            char[] keypass;
                            if( cert.hasOption( "keyPass" ) && cert.getOptionValue( "keyPass" ) != null ) {
                                keypass = cert.getOptionValue( "keyPass" ).toCharArray();
                            } else {
                                keypass = "".toCharArray();
                            }

                            sslContext = SSLUtil.createSSLContext(certFile, keyFile, keypass, sslAddCerts, sslTruststore, sslTruststorePass, sslAddCACerts, sniMatchBuilder);
                            if( first ) {
                                // The first cert is the default
                                sniMatchBuilder.setDefaultContext(sslContext);
                                first = false;
                            }
                            if (keypass != null) {
                                Arrays.fill(keypass, '*');
                            }
                        }

                    } else {
                        sslContext = SSLUtil.createSSLContext( sslAddCerts, sslTruststore, sslTruststorePass, sslAddCACerts, sniMatchBuilder );
                        sniMatchBuilder.setDefaultContext(sslContext);
                    }
                    // Only enable SNI if there was more than 1 cert
                    if( certs.size() > 1 ) {
                        LOG.info("Enabling SNI on SSLContext. (" + certs.size() + " certs)");
                        sslContext = new SNISSLContext( sniMatchBuilder.build() );
                    }
                    OptionMap.Builder socketOptions = OptionMap.builder();

                    JSONOption clientCert = listener.g( "clientCert" );
                    if ( clientCert.hasOption( "mode" ) ) {
                        LOG.debug("Client Cert Negotiation: " + clientCert.getOptionValue( "mode" ) );
                        socketOptions.set(Options.SSL_CLIENT_AUTH_MODE, SslClientAuthMode.valueOf( clientCert.getOptionValue( "mode" ) ) );
                    }

                    if( clientCert.hasOption( "SSLRenegotiationEnable" ) ) {
                        LOG.info("SSL Client cert renegotiation is enabled.  Disabling HTTP/2 and TLS1.3");
                        socketOptions.set(UndertowOptions.ENABLE_HTTP2, false );
                        if( !socketOptions.getMap().contains( Options.SSL_ENABLED_PROTOCOLS ) ) {
                            socketOptions.setSequence( Options.SSL_ENABLED_PROTOCOLS, "TLSv1.1", "TLSv1.2" );
                        }
                    }

                    serverBuilder.addListener(
                        new ListenerBuilder()
                        .setType( ListenerType.HTTPS )
                        .setPort( listener.getOptionInt("port") )
                        .setHost( listener.getOptionValue("IP") )
                        .setSslContext( sslContext )
                        .setOverrideSocketOptions( socketOptions.getMap() )
                    );

                } catch (Exception e) {
                    throw new RuntimeException( "Unable to start SSL", e );
                }
            }
        }


        if( listeners.hasOption( "ajp" ) ) {
            JSONOption AJPListeners = listeners.g( "ajp" );
            for( String key : AJPListeners.getKeys() ) {
                JSONOption listener = AJPListeners.g( key );
                LOG.info("Binding AJP on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port") );
                OptionMap.Builder socketOptions = OptionMap.builder();
                if (serverOptions.undertowOptions().getMap().size() == 0) {
                    // if no options is set, default to the large packet size
                    socketOptions.set(UndertowOptions.MAX_AJP_PACKET_SIZE, 65536);
                }

                serverBuilder.addListener(
                    new ListenerBuilder()
                    .setType( ListenerType.AJP )
                    .setPort( listener.getOptionInt("port") )
                    .setHost( listener.getOptionValue("IP") )
                    .setOverrideSocketOptions( socketOptions.getMap() )
                );
            }
        }

    }

}
