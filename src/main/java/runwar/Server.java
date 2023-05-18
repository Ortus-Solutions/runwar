package runwar;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
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
import io.undertow.servlet.api.ThreadSetupAction;
import io.undertow.servlet.api.ThreadSetupAction.Handle;
import io.undertow.util.CanonicalPathUtils;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderValues;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.MimeMappings;
import io.undertow.io.Sender;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.xnio.*;
import runwar.logging.LoggerFactory;
import runwar.logging.LoggerPrintStream;
import runwar.logging.RunwarAccessLogReceiver;
import runwar.mariadb4j.MariaDB4jManager;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import runwar.options.ConfigParser.JSONOption;
import runwar.security.SSLUtil;
import runwar.security.SecurityManager;
import runwar.tray.Tray;
import runwar.undertow.MappedResourceManager;
import runwar.undertow.HostResourceManager;
import runwar.undertow.RequestDebugHandler;
import runwar.undertow.SSLClientCertHeaderHandler;
import runwar.util.ClassLoaderUtils;
import runwar.util.PortRequisitioner;
import runwar.util.RequestDumper;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletRequest;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.server.HandlerWrapper;

import static runwar.logging.RunwarLogger.CONTEXT_LOG;
import static runwar.logging.RunwarLogger.LOG;
import static runwar.logging.RunwarLogger.MAPPER_LOG;

import runwar.util.Utils;

@SuppressWarnings( "deprecation" )
public class Server {

    public static String processName = "Starting Server...";
    public static final AttachmentKey<String> DEPLOYMENT_KEY = AttachmentKey.create(String.class);
    public static final AttachmentKey<SiteDeployment> SITE_DEPLOYMENT_KEY = AttachmentKey.create(SiteDeployment.class);

    private static final ThreadLocal<HttpServerExchange> currentExchange= new ThreadLocal<HttpServerExchange>();
    private volatile static ServerOptions serverOptions;
    private volatile static SiteOptions siteOptions;
    private static MariaDB4jManager mariadb4jManager;
    private ConcurrentHashMap<String,SiteDeployment> deployments = new ConcurrentHashMap<String,SiteDeployment>();
    private SiteDeployment adobeDefaultDeployment=null;
	private HashSet<String> deploymentKeyWarnings = new HashSet<String>();
    private Undertow undertow;
    private MonitorThread monitor;

    private String PID;
    private static volatile String serverState = ServerState.STOPPED;
    private static final String filePathSeparator = System.getProperty("path.separator");

    private static ClassLoader _classLoader;

    private String serverName = "default";
    private File statusFile = null;
    public static final String bar = "******************************************************************************";
    private SSLContext sslContext;
    private Thread shutDownThread;
    private SecurityManager securityManager;
    private String serverMode;
    private PrintStream originalSystemOut;
    private PrintStream originalSystemErr;

    private static final Thread mainThread = Thread.currentThread();

    private static XnioWorker worker, logWorker;
    //private volatile static runwar.util.PortRequisitioner ports;
    private Tray tray;
    //private FusionReactor fusionReactor;

    public Server() {
    }

    // for openBrowser
    public Server(int seconds) {
        Timer timer = new Timer();
        timer.schedule(this.new OpenBrowserTask(), seconds * 1000);
    }

    private void initClassLoader(List<URL> _classpath) {
        if (_classLoader == null) {
            int paths = _classpath.size();
            LOG.debug("Initializing classloader with " + _classpath.size() + " jar(s)");
            if (paths > 0) {
                LOG.tracef("classpath: %s", _classpath);
                _classLoader = new URLClassLoader(_classpath.toArray(new URL[paths]));
            } else {
                _classLoader = Thread.currentThread().getContextClassLoader();
            }
        }
    }

    public void setClassLoader(URLClassLoader classLoader) {
        _classLoader = classLoader;
    }

    public static ClassLoader getClassLoader() {
        return _classLoader;
    }

    public synchronized void startServer(String[] args, URLClassLoader classLoader) throws Exception {
        setClassLoader(classLoader);
        startServer(args);
    }

    public static void ensureJavaVersion() {
        Class<?> nio;
        LOG.debug("Checking that we're running on > java7");
        try {
            nio = Server.class.getClassLoader().loadClass("java.nio.charset.StandardCharsets");
            nio.getClass().getName();
        } catch (java.lang.ClassNotFoundException e) {
            throw new RuntimeException("Could not load NIO!  Are we running on Java 7 or greater?  Sorry, exiting...");
        }
    }

    public synchronized void startServer(final String[] args) throws Exception {
        throw new RuntimeException( "Is this used?" );
        //startServer(CommandLineHandler.parseArguments(args));
    }

    public synchronized void restartServer() throws Exception {
        restartServer(getServerOptions());
    }

    public synchronized void restartServer(final ServerOptions options) throws Exception {
        LaunchUtil.displayMessage(serverOptions.processName(), "Info", "Restarting server...");
        LOG.info(bar);
        LOG.info("***  Restarting server");
        LOG.info(bar);
        stopServer();
        LaunchUtil.restartApplication(() -> {
            LOG.debug("About to restart... ");
            stopServer();
            serverWentDown();
        });
    }

    private synchronized void requisitionPorts() {
        /*
        LOG.debug("HOST to be bound:" + serverOptions.host());
        ports = new PortRequisitioner(serverOptions.host());
        ports.add("http", serverOptions.httpPort(), serverOptions.httpEnable());
        ports.add("stop", serverOptions.stopPort());
        ports.add("ajp", serverOptions.ajpPort(), serverOptions.ajpEnable());
        ports.add("https", serverOptions.sslPort(), serverOptions.sslEnable());

        ports.requisition();
        serverOptions.httpPort(ports.get("http").socket);
        serverOptions.stopPort(ports.get("stop").socket);
        serverOptions.ajpPort(ports.get("ajp").socket);
        serverOptions.sslPort(ports.get("https").socket);
*/
    }

    public synchronized void startServer(final ServerOptions options) throws Exception {
        serverOptions = options;
        // One site for now-- this becomes a loop!
        siteOptions = serverOptions.getSites().get(0);
        //LoggerFactory.configure(serverOptions);
        // redirect out and err to context logger
        hookSystemStreams();

        serverState = ServerState.STARTING;
        if (serverOptions.action().equals("stop")) {
            Stop.stopServer(serverOptions, true);
        }
        serverName = serverOptions.serverName();
        String host = serverOptions.host(), cfengine = serverOptions.cfEngineName(), processName = serverOptions.processName();
        String realHost = getRealHost( host );
        String contextPath = serverOptions.contextPath();
        File warFile = serverOptions.warFile();
        if (warFile == null) {
            throw new RuntimeException("-war argument is required!");
        }
        if (serverOptions.statusFile() != null) {
            statusFile = serverOptions.statusFile();
        }
        String warPath = serverOptions.warUriString();
        char[] stoppassword = serverOptions.stopPassword();
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        processName = serverOptions.processName();

        // general configuration methods
        RunwarConfigurer configurer = new RunwarConfigurer(this);

        LOG.info(bar);
        LOG.info("Starting RunWAR " + getVersion());
        //requisitionPorts();

        Builder serverBuilder = Undertow.builder();
        setUndertowOptions(serverBuilder);
        JSONOption listeners = serverOptions.listeners();

        if( listeners.hasOption( "http" ) ) {
            JSONOption HTTPListeners = listeners.g( "http" );
            for( String key : HTTPListeners.getKeys() ) {
                JSONOption listener = HTTPListeners.g( key );
                LOG.info("Binding HTTP on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port") );
                serverBuilder.addHttpListener(listener.getOptionInt("port"), listener.getOptionValue("IP"));

                // TODO: set socket-specific XNIO Options so each binding can have a different setting
                if (listener.hasOption("HTTP2Enable" ) ) {
                    LOG.info("Setting HTTP/2 enabled: " + listener.getOptionBoolean("HTTP2Enable" ) );
                    serverBuilder.setServerOption(UndertowOptions.ENABLE_HTTP2, listener.getOptionBoolean("HTTP2Enable" ));
                }

            }
        }

        // TODO: This needs to be done on a per listener basis
    	if( siteOptions.clientCertRenegotiation() ) {
            LOG.info("SSL Client cert renegotiation is enabled.  Disabling HTTP/2 and TLS1.3");
            siteOptions.http2Enable(false);
            if( !serverOptions.xnioOptions().getMap().contains( Options.SSL_ENABLED_PROTOCOLS ) ) {
                serverOptions.xnioOptions().setSequence( Options.SSL_ENABLED_PROTOCOLS, "TLSv1.1", "TLSv1.2" );
            }
    	}


        if( listeners.hasOption( "ssl" ) ) {
            JSONOption HTTPSListeners = listeners.g( "ssl" );
            for( String key : HTTPSListeners.getKeys() ) {

                // TODO: Why is this set by default for SSL?
                serverOptions.directBuffers(true);

                JSONOption listener = HTTPSListeners.g( key );
                LOG.info("Binding SSL on " + listener.getOptionValue("IP") + ":" + listener.getOptionValue("port") );


                if (serverOptions.sslEccDisable() && cfengine.toLowerCase().equals("adobe")) {
                    LOG.debug("disabling com.sun.net.ssl.enableECC");
                    System.setProperty("com.sun.net.ssl.enableECC", "false");
                }

                try {
                    String[] sslAddCerts=null;
                    String[] sslAddCACerts=null;
                    String sslTruststore=null;
                    String sslTruststorePass=null;
                    JSONArray certs = listener.getOptionArray( "certs" );

                    if( certs.size() > 0 ) {
                        // TODO: Loop over all certs and build SNI matcing SSL context
                        JSONOption cert = new JSONOption( (JSONObject)certs.get(0) );

                        File certFile = cert.getOptionFile( "certFile" );
                        File keyFile = cert.getOptionFile( "keyFile" );
                        char[] keypass;
                        if( cert.hasOption( "keyPass" ) && cert.getOptionValue( "keyPass" ) != null ) {
                            keypass = cert.getOptionValue( "keyPass" ).toCharArray();
                        } else {
                            keypass = "".toCharArray();
                        }

                        sslContext = SSLUtil.createSSLContext(certFile, keyFile, keypass, sslAddCerts, sslTruststore, sslTruststorePass, sslAddCACerts, new String[]{listener.getOptionValue("IP")});
                        if (keypass != null) {
                            Arrays.fill(keypass, '*');
                        }
                    } else {
                        sslContext = SSLUtil.createSSLContext( sslAddCerts, sslTruststore, sslTruststorePass, sslAddCACerts );
                    }
                    serverBuilder.addHttpsListener(listener.getOptionInt("port"), listener.getOptionValue("IP"), sslContext);
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
                serverBuilder.addAjpListener(listener.getOptionInt("port"), listener.getOptionValue("IP"));
                if (serverOptions.undertowOptions().getMap().size() == 0) {
                    // if no options is set, default to the large packet size
                    serverBuilder.setServerOption(UndertowOptions.MAX_AJP_PACKET_SIZE, 65536);
                }
            }
        }

        securityManager = new SecurityManager();

    	LOG.debug("WAR root:" + warFile.getAbsolutePath());
        if (!warFile.exists()) {
            throw new RuntimeException("war does not exist: " + warFile.getAbsolutePath());
        }
/*
        if (serverOptions.background()) {
            setServerState(ServerState.STARTING_BACKGROUND);
            // this will eventually system.exit();
            LaunchUtil.relaunchAsBackgroundProcess(serverOptions.background(false), true);
            setServerState(ServerState.STARTED_BACKGROUND);
            // just in case
            Thread.sleep(200);
            System.exit(0);
        } else {
        	LOG.debug("background:" + serverOptions.background());
        }
*/
        File webinf = serverOptions.webInfDir();
        File webXmlFile = serverOptions.webXmlFile();

        String libDirs = serverOptions.libDirs();
        URL jarURL = serverOptions.jarURL();
        // If this folder is a proper war, add its WEB-INF/lib folder to the passed libDirs
        if (warFile.isDirectory() && webXmlFile != null && webXmlFile.exists()) {
            if (libDirs == null) {
                libDirs = "";
            } else if (libDirs.length() > 0) {
                libDirs = libDirs + ",";
            }
            libDirs = libDirs + webinf.getAbsolutePath() + "/lib";
            LOG.debug("Adding additional lib dir of: " + webinf.getAbsolutePath() + "/lib");
            serverOptions.libDirs(libDirs);
        }

        List<URL> cp = new ArrayList<>();
//        cp.add(Server.class.getProtectionDomain().getCodeSource().getLocation());
        if (libDirs != null) {
            cp.addAll(getJarList(libDirs));
        }
        if (jarURL != null) {
            cp.add(jarURL);
        }

        if (serverOptions.mariaDB4jImportSQLFile() != null) {
        	LOG.debug("Importing sql file: " + serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
            cp.add(serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
        }
        cp.addAll(getClassesList(new File(webinf, "/classes")));
        initClassLoader(cp);

        serverMode = Mode.WAR;
        if (!webinf.exists()) {
            serverMode = Mode.DEFAULT;
            if (getCFMLServletClass(cfengine) != null) {
                serverMode = Mode.SERVLET;
            }
        }
        LOG.debugf("Server Mode: %s", serverMode);

        // redirect out and err to context logger
        //hookSystemStreams();
        String osName = System.getProperties().getProperty("os.name");
        String iconPNG = System.getProperty("cfml.server.trayicon");
        if (iconPNG != null && iconPNG.length() > 0) {
            serverOptions.iconImage(iconPNG);
        }
        String dockIconPath = System.getProperty("cfml.server.dockicon");
        if (dockIconPath == null || dockIconPath.length() == 0) {
            dockIconPath = serverOptions.iconImage();
        }

        if (osName != null && osName.startsWith("Mac OS X")) {
            if (serverOptions.dockEnable()) {
                Image dockIcon = Tray.getIconImage(dockIconPath);
                System.setProperty("com.apple.mrj.application.apple.menu.about.name", processName);
                System.setProperty("com.apple.mrj.application.growbox.intrudes", "false");
                System.setProperty("apple.laf.useScreenMenuBar", "true");
                System.setProperty("-Xdock:name", processName);
                try {
                    Class<?> appClass = Class.forName("com.apple.eawt.Application");
                    Method getAppMethod = appClass.getMethod("getApplication");
                    Object appInstance = getAppMethod.invoke(null);
                    Method dockMethod = appInstance.getClass().getMethod("setDockIconImage", java.awt.Image.class);
                    dockMethod.invoke(appInstance, dockIcon);
                } catch (Exception e) {
                    LOG.warn("error setting dock icon image", e);
                }
            } else {
                System.setProperty("apple.awt.UIElement", "true");
            }
        }
        LOG.info("Servlet Context: " + contextPath );
        LOG.info("Log Directory: " + serverOptions.logDir().getAbsolutePath());
        LOG.info(bar);
        addShutDownHook();

        //LOG.debug("Transfer Min Size: " + siteOptions.transferMinSize());

        // configure NIO options and worker
        Xnio xnio = Xnio.getInstance("nio", Server.class.getClassLoader());
        OptionMap.Builder serverXnioOptions = serverOptions.xnioOptions();

        // TODO: Set this on listener level
        if (siteOptions.clientCertNegotiation() != null) {
	    	LOG.debug("Client Cert Negotiation: " + siteOptions.clientCertNegotiation() );
	        serverXnioOptions.set(Options.SSL_CLIENT_AUTH_MODE, SslClientAuthMode.valueOf( siteOptions.clientCertNegotiation() ) );
        }

        logXnioOptions(serverXnioOptions,serverBuilder);

        if (serverOptions.ioThreads() != 0) {
        	LOG.debug("IO Threads: " + serverOptions.ioThreads());
            serverBuilder.setIoThreads(serverOptions.ioThreads()); // posterity: ignored when managing worker
            serverXnioOptions.set(Options.WORKER_IO_THREADS, serverOptions.ioThreads());
        }
        if (serverOptions.workerThreads() != 0) {
        	LOG.debug("Worker threads: " + serverOptions.workerThreads());
            serverBuilder.setWorkerThreads(serverOptions.workerThreads()); // posterity: ignored when managing worker
            serverXnioOptions.set(Options.WORKER_TASK_CORE_THREADS, serverOptions.workerThreads())
                    .set(Options.WORKER_TASK_MAX_THREADS, serverOptions.workerThreads());
        }
        worker = xnio.createWorker(serverXnioOptions.getMap());

        // separate log worker to prevent logging-caused bottleneck
        logWorker = xnio.createWorker(OptionMap.builder()
                .set(Options.WORKER_IO_THREADS, 2)
                .set(Options.CONNECTION_HIGH_WATER, 1000000)
                .set(Options.CONNECTION_LOW_WATER, 1000000)
                .set(Options.WORKER_TASK_CORE_THREADS, 2)
                .set(Options.WORKER_TASK_MAX_THREADS, 2)
                .set(Options.TCP_NODELAY, true)
                .set(Options.CORK, true)
                .getMap());

        ServletSessionConfig servletSessionConfig = new ServletSessionConfig();
        servletSessionConfig.setHttpOnly(serverOptions.cookieHttpOnly());
        servletSessionConfig.setSecure(serverOptions.cookieSecure());

        // hack to prevent . being picked up as the system path (jacob.x.dll)
        final String jarPath = getThisJarLocation().getPath();
        String javaLibraryPath = System.getProperty("java.library.path");
        if (javaLibraryPath == null) {
            if (webXmlFile != null) {
                javaLibraryPath = jarPath + ':' + new File(webXmlFile.getParentFile(), "lib").getPath();
            } else {
                javaLibraryPath = jarPath + ':' + new File(warFile, "/WEB-INF/lib/").getPath();
            }
        } else {
            javaLibraryPath = jarPath + filePathSeparator + javaLibraryPath;
        }
        System.setProperty("java.library.path", javaLibraryPath);
        LOG.trace("java.library.path:" + System.getProperty("java.library.path"));

        final DeploymentInfo servletBuilder = deployment()
                .setContextPath(contextPath.equals("/") ? "" : contextPath)
                .setTempDir(new File(System.getProperty("java.io.tmpdir")))
                .setDeploymentName("site1")
                .setServletSessionConfig(servletSessionConfig)
                .setDisplayName(serverName)
                .setServerName("WildFly / Undertow")
                .addThreadSetupAction( new ThreadSetupAction() {

                        public Handle setup(final HttpServerExchange exchange) {

                            // This allows the exchange to be available to the task thread.
                        	currentExchange.set(exchange);
                            return new Handle() {

                                @Override
                                public void tearDown() {
                                	currentExchange.remove();
                                }
                            };
                        }
                })
                // This handler is run after the security handlers, just before the request is dispatched to deployment code.
                // I need this "inside" the servlet so it can access the HttpServletRequest
                .addInnerHandlerChainWrapper(new HandlerWrapper() {
                    @Override
                    public HttpHandler wrap(HttpHandler next) {
                        // Set SSL_CLIENT_ headers if client certs are present
                        return new SSLClientCertHeaderHandler( next, siteOptions, serverOptions.cfEngineName().toLowerCase().contains( "lucee" ) );

                    }
                });

        configurer.configureServlet(servletBuilder);

        configurer.configureServerResourceHandler(servletBuilder);

        configurer.configureRestMappings(servletBuilder);

        // TODO: probably best to create a new worker for websockets, if we want fastness, but for now we share
        // TODO: add buffer pool size (maybe-- direct is best at 16k), enable/disable be good I reckon tho
        servletBuilder.addServletContextAttribute(WebSocketDeploymentInfo.ATTRIBUTE_NAME,
                new WebSocketDeploymentInfo().setBuffers(new DefaultByteBufferPool(true, 1024 * 16)).setWorker(worker));
        LOG.debug("Added websocket context");

        if ( siteOptions.basicAuthEnable() || siteOptions.clientCertEnable() ) {
            securityManager.configureAuth( serverBuilder, siteOptions, servletBuilder);
        }

        if( serverOptions.getSites().size() == 1 ) {
            // Create default context
            createSiteDeployment( servletBuilder, serverOptions.getSites().get(0).webroot(), configurer, SiteDeployment.DEFAULT, null, serverOptions.getSites().get(0) );
        } else {
            for( SiteOptions siteOptions : serverOptions.getSites() ) {
                createSiteDeployment( servletBuilder, siteOptions.webroot(), configurer, siteOptions.siteName(), null, siteOptions );
            }
        }

        HttpHandler hostHandler = new HttpHandler() {

            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
            	SiteDeployment deployment;
                String deploymentKey;

                if( serverOptions.getSites().size() > 1 ) {
                    JSONObject bindings = serverOptions.bindings();
                    String IP = exchange.getConnection().getLocalAddress( InetSocketAddress.class ).getAddress().getHostAddress().toLowerCase();
                    String port = String.valueOf( exchange.getConnection().getLocalAddress( InetSocketAddress.class ).getPort() );
                    String hostName = exchange.getHostName().toLowerCase();
                    JSONObject match;

                    // TODO: See about caching these lookups.

                    // Try exact IP and hostname match
                    String bindingKey = IP + ":" + port + ":" + hostName;
                    LOG.trace( "Trying binding key: " + bindingKey );
                    match = (JSONObject)bindings.get( bindingKey );

                    if( match == null ) {
                        // Try exact hostmame on any IP
                        bindingKey = "0.0.0.0:" + port + ":" + hostName;
                        LOG.trace( "Trying binding key: " + bindingKey );
                        match = (JSONObject)bindings.get( bindingKey );

                        if( match == null ) {
                            // Try wildcard hostmame on exact IP
                            bindingKey = IP + ":" + port + ":*" ;
                            LOG.trace( "Trying binding key: " + bindingKey );
                            match = (JSONObject)bindings.get( bindingKey );
                        }

                        if( match == null ) {
                            // Try wildcard hostmame on any IP
                            bindingKey = "0.0.0.0:" + port + ":*" ;
                            LOG.trace( "Trying binding key: " + bindingKey );
                            match = (JSONObject)bindings.get( bindingKey );
                        }

                        if( match == null ) {
                            // Look for a default site
                            bindingKey = "default" ;
                            LOG.trace( "Trying binding key: " + bindingKey );
                            match = (JSONObject)bindings.get( bindingKey );
                        }

                        if( match == null ) {
                            String message = "Can't find a matching binding for IP [" + IP + "], port [" + port + "], and hostname [" + hostName + "]";
                            LOG.debug( message );

                            // TODO: How to customize this
                            final String errorPage = "<html><head><title>Site Not Found</title></head><body><h1>Site Not Found</h1>" + message.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;") + "</body></html>";
                            exchange.setStatusCode(404);
                            exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, "" + errorPage.length());
                            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                            Sender sender = exchange.getResponseSender();
                            sender.send(errorPage);
                            return;
                        }
                    }

                    deploymentKey = (String)match.get( "site" );
                    LOG.trace( "Binding is for site: " + deploymentKey );
                	exchange.putAttachment(DEPLOYMENT_KEY, deploymentKey);
            		deployment = deployments.get( deploymentKey );
                }

            	// If we're not auto-creating contexts, then just pass to our default servlet deployment
            	else if( !serverOptions.autoCreateContexts() ) {
            		deployment = deployments.get( SiteDeployment.DEFAULT );

            	// Otherwise, see if a deployment already exists
            	} else {

            		if( !isHeaderSafe( exchange, "", "X-Webserver-Context" ) ) return;

                	deploymentKey = exchange.getRequestHeaders().getFirst( "X-Webserver-Context" );
                	if( deploymentKey == null ){
                		deploymentKey = exchange.getHostName().toLowerCase();
                	}
                	// Save into the exchange for later in the thread
                	exchange.putAttachment(DEPLOYMENT_KEY, deploymentKey);

            		deployment = deployments.get( deploymentKey );
            		if( deployment == null ) {

                		if( !isHeaderSafe( exchange, deploymentKey, "X-Tomcat-DocRoot" ) ) return;
                    	String docRoot = exchange.getRequestHeaders().getFirst( "X-Tomcat-DocRoot" );

                    	if( docRoot != null && !docRoot.isEmpty() ) {
                    		File docRootFile = new File( docRoot );
                    		if( docRootFile.exists() && docRootFile.isDirectory() ) {

                    			// Enforce X-ModCFML-SharedKey
                        		if( !isHeaderSafe( exchange, deploymentKey, "X-ModCFML-SharedKey" ) ) return;
                            	String modCFMLSharedKey = exchange.getRequestHeaders().getFirst( "X-ModCFML-SharedKey" );
                            	if( modCFMLSharedKey == null ) {
                            		modCFMLSharedKey = "";
                            	}

                            	// If a secret was provided, enforce it
                            	if( !serverOptions.autoCreateContextsSecret().equals( "" ) && !serverOptions.autoCreateContextsSecret().equals( modCFMLSharedKey ) ) {
									exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
									exchange.setStatusCode(403);
									exchange.getResponseSender().send( "The web server's X-ModCFML-SharedKey was not supplied or doesn't match the configured secret." );
									logOnce( deploymentKey, "SharedKeyNotMatch", "debug", "The web server's X-ModCFML-SharedKey [" + modCFMLSharedKey + "] was not supplied or doesn't match the auto-create-contexts-secret setting [" + ( serverOptions.autoCreateContextsSecret() == null ? "" : serverOptions.autoCreateContextsSecret() ) + "] for deploymentKey [" + deploymentKey + "]." );
									return;
                            	}
                            	String vDirs = null;
                            	if( serverOptions.autoCreateContextsVDirs() ) {
                            		if( !isHeaderSafe( exchange, deploymentKey, "x-vdirs" ) ) return;
                                	vDirs = exchange.getRequestHeaders().getFirst( "x-vdirs" );
                                    if( vDirs != null && !vDirs.isEmpty() ) {
                                    	// Ensure we can trust the x-vdirs header.  Only use it if the x-vdirs-sharedkey header is also supplied with the shared key
                                		if( !isHeaderSafe( exchange, deploymentKey, "x-vdirs-sharedkey" ) ) return;
                                    	String vDirsSharedKey = exchange.getRequestHeaders().getFirst( "x-vdirs-sharedkey" );
                                    	if( vDirsSharedKey == null || vDirsSharedKey.isEmpty() ) {
                                    		vDirs = null;
        									logOnce( deploymentKey, "NovDirsSharedKey", "warn", "The x-vdirs header was provided, but it is being igonred because no x-vdirs-sharedkey header is present." );
                                    	} else {
                                        	// If a secret was provided, enforce it
                                        	if( !serverOptions.autoCreateContextsSecret().equals( "" ) && !serverOptions.autoCreateContextsSecret().equals( vDirsSharedKey ) ) {
                                        		vDirs = null;
            									logOnce( deploymentKey, "VDirsSharedKeyNotMatch", "warn", "The x-vdirs header was provided, but it is being igonred because the x-vdirs-sharedkey header [" + vDirsSharedKey + "] doesn't match the auto-create-contexts-secret setting [" + ( serverOptions.autoCreateContextsSecret() == null ? "" : serverOptions.autoCreateContextsSecret() ) + "] for deploymentKey [" + deploymentKey + "]." );
                                        	}
                                    	}
                                    }
                            	}
                            	try {
                            		deployment = createSiteDeployment( servletBuilder, docRootFile, configurer, deploymentKey, vDirs, serverOptions.getSites().get(0) );
                            	} catch ( MaxContextsException e ) {

									exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
									exchange.setStatusCode(500);
									exchange.getResponseSender().send( e.getMessage() );

									logOnce( deploymentKey, "MaxContextsException", "error", e.getMessage() + "  The requested deploymentKey was [" + deploymentKey + "]" );
                       	        	return;
                            	}
                    		} else {
                    	        LOG.warn( "X-Tomcat-DocRoot of [" + docRoot + "] does not exist or is not directory.  Using default context." );
                        		deployment = deployments.get( SiteDeployment.DEFAULT );
                    		}
                    	} else {
                    		logOnce( deploymentKey, "NoDocRootHeader", "warn", "X-Tomcat-DocRoot is null or empty.  Using default context for deploymentKey [" + deploymentKey + "]." );
                    		deployment = deployments.get( SiteDeployment.DEFAULT );
                    	}

            		}
            	}

                // Save into the exchange for later in the thread
                exchange.putAttachment(SITE_DEPLOYMENT_KEY, deployment);
                deployment.processRequest( exchange );

            }

            @Override
            public String toString() {
                return "Runwar HostHandler";
            }
        };

        LOG.debug("started servlet deployment manager");

        if (serverOptions.bufferSize() != 0) {
            LOG.debug("Buffer Size: " + serverOptions.bufferSize());
            serverBuilder.setBufferSize(serverOptions.bufferSize());
        }
        LOG.debug("Direct Buffers: " + serverOptions.directBuffers());
        serverBuilder.setDirectBuffers(serverOptions.directBuffers());

        serverBuilder.setHandler(hostHandler);
        try {
            PID = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
            String pidFile = serverOptions.pidFile();
            if (pidFile != null && pidFile.length() > 0) {
                File file = new File(pidFile);
                file.deleteOnExit();
                try (PrintWriter writer = new PrintWriter(file)) {
                    writer.print(PID);
                }
            }
        } catch (Exception e) {
            LOG.error("Unable to get PID:" + e.getMessage());
        }

        serverBuilder.setWorker(worker);
        undertow = serverBuilder.build();

        // start the stop monitor thread
        assert monitor == null;
        monitor = new MonitorThread(stoppassword);
        monitor.start();
        LOG.debug("started stop monitor");
        tray = new Tray();

        if (serverOptions.trayEnable()) {
            try {
                tray.hookTray(this);
                LOG.debug("hooked system tray");
            } catch (Throwable e) {
                LOG.error("system tray hook failed", e);
            }
        } else {
            LOG.debug("System tray integration disabled");
        }

        if (serverOptions.openbrowser()) {
            LOG.debug("Starting open browser action");
            new Server(3);
        }

        String msg = "Server is up - stop-port:" + serverOptions.stopPort() + " PID:" + PID + " version " + getVersion();
        LOG.info(msg);
        // if the status line output would be suppressed due to logging levels, send it to sysout
        if (serverOptions.logLevel().equalsIgnoreCase("WARN") || serverOptions.logLevel().equalsIgnoreCase("ERROR")) {
            System.out.println(msg);
        }
        if (serverOptions.trayEnable()) {
            LaunchUtil.displayMessage(serverOptions.processName(), "info", msg);
        }
        setServerState(ServerState.STARTED);
        if (serverOptions.mariaDB4jEnable()) {
        	LOG.debug("MariaDB support enable");
            mariadb4jManager = new MariaDB4jManager(_classLoader);
            try {
                mariadb4jManager.start(serverOptions.mariaDB4jPort(), serverOptions.mariaDB4jBaseDir(),
                        serverOptions.mariaDB4jDataDir(), serverOptions.mariaDB4jImportSQLFile());
            } catch (Exception dbStartException) {
                LOG.error("Could not start MariaDB4j", dbStartException);
            }
        } else {
            LOG.trace("MariaDB support is disabled");
        }
        try {

            undertow.start();

        } catch (Exception any) {
            if (any.getCause() instanceof java.net.SocketException && any.getCause().getMessage().equals("Permission denied")) {
                System.err.println("You need to be root or Administrator to bind to a port below 1024!");
            } else {
                any.printStackTrace();
            }
            LOG.error(any);
            System.exit(1);
        }
    }

    @SuppressWarnings("unchecked")
    private void setUndertowOptions(Builder serverBuilder) {
		OptionMap undertowOptionsMap = serverOptions.undertowOptions().getMap();
        for (Option option : undertowOptionsMap) {
        	LOG.debug("UndertowOption " + option.getName() + ':' + undertowOptionsMap.get(option));
            serverBuilder.setServerOption(option, undertowOptionsMap.get(option));
            serverBuilder.setSocketOption(UndertowOptions.IDLE_TIMEOUT, 999999999);
            serverBuilder.setSocketOption(option, undertowOptionsMap.get(option));
        }
    }

    @SuppressWarnings("unchecked")
    private void logXnioOptions(OptionMap.Builder xnioOptions, Builder serverBuilder) {
        OptionMap serverXnioOptionsMap = xnioOptions.getMap();
        for (Option option : serverXnioOptionsMap) {
        	LOG.debug("XNIO-Option " + option.getName() + ':' + serverXnioOptionsMap.get(option));
            serverBuilder.setSocketOption(option, serverXnioOptionsMap.get(option));
        }
    }
/*
    PortRequisitioner getPorts() {
        return ports;
    }*/

    static String fullExchangePath(HttpServerExchange exchange) {
        return exchange.getRequestURL() + (exchange.getQueryString().length() > 0 ? "?" + exchange.getQueryString() : "");
    }

    private synchronized void hookSystemStreams() {
        LOG.trace("Piping system streams to logger");
        if (System.out instanceof LoggerPrintStream) {
            LOG.trace("streams already piped");
        } else {
            originalSystemOut = System.out;
            originalSystemErr = System.err;
            System.setOut(new LoggerPrintStream(CONTEXT_LOG, org.jboss.logging.Logger.Level.INFO));
            System.setErr(new LoggerPrintStream(CONTEXT_LOG, org.jboss.logging.Logger.Level.ERROR, "^SLF4J:.*"));
        }
    }

    private void unhookSystemStreams() {
        LOG.trace("Unhooking system streams logger");
        if (originalSystemOut != null) {
            System.setOut(originalSystemOut);
            System.setErr(originalSystemErr);
        } else {
            LOG.trace("Original System streams were null, probably never piped to logger.");
        }
    }

    private void addShutDownHook() {
        if (shutDownThread == null) {
            shutDownThread = new Thread() {
                public void run() {
                    LOG.debug("Running shutdown hook");
                    try {
                        if (!getServerState().equals(ServerState.STOPPING) && !getServerState().equals(ServerState.STOPPED)) {
                            LOG.debug("shutdown hook:stopServer()");
                            stopServer();
                        }
//                    if(tempWarDir != null) {
//                        LaunchUtil.deleteRecursive(tempWarDir);
//                    }
                        if (mainThread.isAlive()) {
                            LOG.debug("shutdown hook joining main thread");
                            mainThread.interrupt();
                            mainThread.join(3000);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    LOG.debug("Shutdown hook finished");
                }
            };
            Runtime.getRuntime().addShutdownHook(shutDownThread);
            LOG.debug("Added shutdown hook");
        }
    }

    public void stopServer() {
        int exitCode = 0;
        if (shutDownThread != null && Thread.currentThread() != shutDownThread) {
            LOG.debug("Removed shutdown hook");
            Runtime.getRuntime().removeShutdownHook(shutDownThread);
        }
        switch (getServerState()) {
            case ServerState.STOPPING:
                LOG.warn("Stop server called, however the server is already stopping.");
                break;
            case ServerState.STOPPED:
                LOG.warn("Stop server called, however the server has already stopped.");
                break;
            default:
                try {
                    setServerState(ServerState.STOPPING);
                    LOG.info(bar);
                    String port = Integer.toString(serverOptions.stopPort());
                    String serverName = serverOptions.serverName() != null ? serverOptions.serverName() : "null";
                    LOG.infof("*** stopping server '%s' (socket %s)", serverName, port);
                    LOG.info(bar);
                    if (serverOptions.mariaDB4jEnable()) {
                        mariadb4jManager.stop();
                    }
                    if (deployments != null) {
                        try {
                        	 for ( Map.Entry<String,SiteDeployment> deployment : deployments.entrySet() ) {
                        		 DeploymentManager manager = deployment.getValue().getDeploymentManager();
                                 switch (manager.getState()) {
                                     case UNDEPLOYED:
                                         break;
                                     default:
                                         manager.stop();
                                         manager.undeploy();
                                 }

                        	 }

                            if (undertow != null) {
                                undertow.stop();
                            }
                            if (worker != null) {
                                worker.shutdown();
                                logWorker.shutdown();
                            }
                            //                Thread.sleep(1000);
                        } catch (Exception notRunning) {
                            LOG.error("*** server did not appear to be running", notRunning);
                            LOG.info(bar);
                        }
                    }
                    setServerState(ServerState.STOPPED);
                    LOG.debug("All deployments undeployed and underlying Undertow servers stopped");

                } catch (Exception e) {
                    e.printStackTrace();
                    setServerState(ServerState.UNKNOWN);
                    LOG.error("*** unknown server error", e);
                    exitCode = 1;
                }

                tray.unhookTray();
                if (System.getProperty("runwar.listloggers") != null && Boolean.parseBoolean(System.getProperty("runwar.listloggers"))) {
                    LoggerFactory.listLoggers();
                }
                unhookSystemStreams();

                if (System.getProperty("runwar.classlist") != null && Boolean.parseBoolean(System.getProperty("runwar.classlist"))) {
                    ClassLoaderUtils.listAllClasses(serverOptions.logDir() + "/classlist.txt");
                }

                if (monitor != null) {
                    LOG.debug("Stopping server monitor");
                    MonitorThread monitorThread = monitor;
                    monitor = null;
                    monitorThread.stopListening(false);
                    monitorThread.interrupt();
                }

                if (exitCode != 0) {
                    System.exit(exitCode);
                }
                LOG.debug("Stopped server");

                break;
        }

    }

    public ResourceManager getResourceManager(File warFile, Long transferMinSize, Map<String, Path> aliases, File internalCFMLServerRoot) {
    	Boolean cached = !siteOptions.directoryListingRefreshEnable() && siteOptions.cacheServletPaths();

        LOG.debugf("Initialized " + ( cached ? "CACHED " : "" ) + "MappedResourceManager - base: %s, web-inf: %s, aliases: %s", warFile.getAbsolutePath(), internalCFMLServerRoot.getAbsolutePath(), aliases);

        MappedResourceManager mappedResourceManager = new MappedResourceManager(warFile, transferMinSize, aliases, internalCFMLServerRoot, siteOptions);
        if ( !cached ) {
            return mappedResourceManager;
        }

        LOG.debugf("ResourceManager Cache total size: %s MB", siteOptions.fileCacheTotalSizeMB() );
        LOG.debugf("ResourceManager Cache max file size: %s KB", siteOptions.fileCacheMaxFileSizeKB() );

        // 8 hours in in milliseconds-- used for both the path metadata cache AND the file contents cache
        // Setting to -1 will never expire items from the cache, which is tempting-- but having some sort of expiration will keep errant entries from clogging the cache forever
        int METADATA_MAX_AGE = 8 * 60 * 60 * 1000;
        /* DirectBufferCache.sliceSize: internally DirectBufferCache has a buffer pool. This pool is responsible for allocating byte buffers to store the data that is in the cache,
         * the size of those buffers will be sliceSize * slicesPerPage. Each byte buffer region that is allocated in the memory is split into slicesPerPage, and then each buffer
         *  will have sliceSize. To give you an example, if you have 50 slicesPerPage and each one is 10,000 bytes long (this would be sliceSize), each time a buffer is needed,
         *  it allocates a region whose size is 500,000 bytes. That region is split into 50 byte buffers of length 10,000 (in bytes).
         *  If those buffers are all used at some point and not reclaimed, when the pool needs more buffers, it will allocate another 500,000 bytes long chunk, and so on, but there is a limit to it,
         *  which is maxMemory
         */
        // Max file size to cache directly in memory-- measured in bytes.
        final long maxFileSize = siteOptions.fileCacheMaxFileSizeKB() * 1024; // Convert KB to B
        /* DirectBufferCache.maxMemory: this is the maximum number of bytes that can be allocated by the pool. So, in the example above, supposed that slicesPerPage is 50, and sliceSize is 10,000 bytes,
         * if you have a maxMemory of 1,000,000 bytes, it means that the buffer pool can only allocate two chunks of 500,000 bytes each, because that's the number of 500,000 bytes long
         * regions that fit into 1,000,000. If none of those buffers are reclaimed at some point, and more buffers are needed, the buffer pool will refuse to do more allocations.
         * The cache will remove the oldest entry from usage pov because it is LRU. This cache is used by CachingResourceManager to store contents of files in direct memory. */
        int maxMemory = siteOptions.fileCacheTotalSizeMB() * 1024 * 1024; // Convert MB to B
        // Number of paths to cache. i.e. /foo.txt maps to C:/webroot/foo.txt
        // I assume the memory overhead of the meta is nearly zero since it's just a single POJO instance per path
        final int metadataCacheSize = 10000;
        if( maxMemory > 0 && maxFileSize > 0 ) {
            int sliceSize = 1024 * 1024; // 1 KB per slice
            // DirectBufferCache slicesPerPage: the explanation is right above.
            int slicesPerPage = 10; // 10 slices per page means 10 KB per buffer
            final DirectBufferCache dataCache = new DirectBufferCache(sliceSize, slicesPerPage, maxMemory, BufferAllocator.DIRECT_BYTE_BUFFER_ALLOCATOR, METADATA_MAX_AGE);

            return new CachingResourceManager(metadataCacheSize, maxFileSize, dataCache, mappedResourceManager, METADATA_MAX_AGE);
        } else {
        	LOG.debug("ResourceManager file cache disabled since size is zero. Path lookups will still be cached." );
            return new CachingResourceManager(metadataCacheSize, maxFileSize, null, mappedResourceManager, METADATA_MAX_AGE);
        }
    }

    public static File getThisJarLocation() {
        return LaunchUtil.getJarDir(Server.class);
    }

    public String getPID() {
        return PID;
    }

    private int getPortOrErrorOut(int portNumber, String host) {
        try (ServerSocket nextAvail = new ServerSocket(portNumber, 1, getInetAddress(host))) {
            portNumber = nextAvail.getLocalPort();
            nextAvail.close();
            return portNumber;
        } catch (java.net.BindException e) {
            throw new RuntimeException("Error getting port " + portNumber + "!  Cannot start:  " + e.getMessage());
        } catch (UnknownHostException e) {
            throw new RuntimeException("Unknown host (" + host + ")");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getRealHost(String host) {
    	return getInetAddress(host).getHostAddress();
    }

    public static InetAddress getInetAddress(String host) {
        try {
            return InetAddress.getByName(host);
        } catch (UnknownHostException e) {
        	if( host.toLowerCase().endsWith( ".localhost" ) ) {
    			// It's possible to have "fake" hosts such as mytest.localhost which aren't in DNS
    			// or your hosts file.  Browsers will resolve them to localhost, but the call above
    			// will fail with a UnknownHostException since they aren't real
                try {
                	return InetAddress.getByName( "127.0.0.1" );
                } catch (UnknownHostException e2) {
                	throw new RuntimeException("Error getting inet address for " + host);
                }
        	}
            throw new RuntimeException("Error getting inet address for " + host);
        }
    }

    private List<URL> getJarList(String libDirs) throws IOException {
        return RunwarConfigurer.getJarList(libDirs);
    }

    @SuppressWarnings("unchecked")
    private static Class<Servlet> getCFMLServletClass(String cfengine) {
        Class<Servlet> cfmlServlet = null;
        try {
            cfmlServlet = (Class<Servlet>) _classLoader.loadClass(cfengine + ".loader.servlet.CFMLServlet");
            LOG.debug("dynamically loaded CFML servlet from runwar child classloader");
        } catch (java.lang.ClassNotFoundException devnul) {
            try {
                cfmlServlet = (Class<Servlet>) Server.class.getClassLoader().loadClass(cfengine + ".loader.servlet.CFMLServlet");
                LOG.debug("dynamically loaded CFML servlet from runwar classloader");
            } catch (java.lang.ClassNotFoundException e) {
                LOG.trace("No CFML servlet found in class loader hierarchy");
            }
        }
        return cfmlServlet;
    }

    @SuppressWarnings("unchecked")
    private static Class<Servlet> getRestServletClass(String cfengine) {
        Class<Servlet> restServletClass = null;
        try {
            restServletClass = (Class<Servlet>) _classLoader.loadClass(cfengine + ".loader.servlet.RestServlet");
        } catch (java.lang.ClassNotFoundException e) {
            try {
                restServletClass = (Class<Servlet>) Server.class.getClassLoader().loadClass(cfengine + ".loader.servlet.RestServlet");
            } catch (ClassNotFoundException e1) {
                e1.printStackTrace();
            }
        }
        return restServletClass;
    }

    private List<URL> getClassesList(File classesDir) throws IOException {
        List<URL> classpath = new ArrayList<>();
        if (classesDir == null) {
            return classpath;
        }
        if (classesDir.exists() && classesDir.isDirectory()) {
            URL url = classesDir.toURI().toURL();
            classpath.add(url);
            for (File item : Objects.requireNonNull(classesDir.listFiles())) {
                if (item.isDirectory()) {
                    classpath.addAll(getClassesList(item));
                }
            }
        } else {
            LOG.debug("WEB-INF classes directory (" + classesDir.getAbsolutePath() + ") does not exist");
        }
        return classpath;
    }

    public static void printVersion() {
        System.out.println(LaunchUtil.getResourceAsString("runwar/version.properties"));
        System.out.println(LaunchUtil.getResourceAsString("io/undertow/version.properties"));
    }

    public static String getVersion() {
        String versionProp = LaunchUtil.getResourceAsString("runwar/version.properties");
        if (versionProp == null) {
            return "unknown";
        }
        String[] version = versionProp.split("=");
        return version[version.length - 1].trim();
    }
/*
    public int getHttpPort() {
        return ports.get("http").socket;
    }

    public int getSslPort() {
        return ports.get("https").socket;
    }

    public int getStopPort() {
        return ports.get("stop").socket;
    }
    */

    public boolean serverWentDown() {
        return serverWentDown(serverOptions.launchTimeout(), 3000, getInetAddress(siteOptions.host()), siteOptions.httpPort());
    }

    public static boolean serverWentDown(int timeout, long sleepTime, InetAddress server, int port) {
        long start = System.currentTimeMillis();
        long elapsed = (System.currentTimeMillis() - start);
        while (elapsed < timeout) {
            try {
                if (checkServerIsUp(server, port)) {
                    try {
                        Thread.sleep(sleepTime);
                        elapsed = (System.currentTimeMillis() - start);
                    } catch (InterruptedException e) {
                        // expected
                    }
                } else {
                    return true;
                }
            } catch (ConnectException e) {
                // expexted
                e.printStackTrace();
                LOG.error(e);
                return true;
            }
        }
        return false;
    }

    public static boolean serverCameUp(int timeout, long sleepTime, InetAddress server, int port) {
        long start = System.currentTimeMillis();
        while ((System.currentTimeMillis() - start) < timeout) {
            try {
                if (!checkServerIsUp(server, port)) {
                    try {
                        Thread.sleep(sleepTime);
                    } catch (InterruptedException e) {
                        return false;
                    }
                } else {
                    return true;
                }
            } catch (ConnectException e) {
                e.printStackTrace();
                LOG.debug("Error while connecting: " + server.getHostAddress() + ":" + port + " - " + e.getMessage());
            }
        }
        return false;
    }

    public static boolean checkServerIsUp(InetAddress server, int port) throws ConnectException {
        Socket sock = null;
        try {
            sock = new Socket();
            InetSocketAddress sa = new InetSocketAddress(server, port);
            sock.connect(sa, 500);
            return true;
        } catch (ConnectException e) {
            LOG.debug("Error while connecting. " + e.getMessage());
        } catch (SocketTimeoutException e) {
            LOG.debug("Socket Timeout: " + server.getHostAddress() + ":" + port + " - " + e.getMessage() + ".");
        } catch (SocketException e) {
            LOG.debug("Socket Exception: " + server.getHostAddress() + ":" + port + " - " + e.getMessage() + ".");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (sock != null) {
                try {
                    sock.close();
                } catch (IOException e) {
                    // don't care
                }
            }
        }
        return false;
    }

    class OpenBrowserTask extends TimerTask {

        public void run() {
            int portNumber = siteOptions.httpPort();
            String protocol = "http";
            String host = siteOptions.host();
            String openbrowserURL = serverOptions.openbrowserURL();
            int timeout = serverOptions.launchTimeout();
            if (openbrowserURL == null || openbrowserURL.length() == 0) {
                openbrowserURL = "http://" + host + ":" + portNumber;
            }
            if (siteOptions.sslEnable()) {
                portNumber = siteOptions.sslPort();
                protocol = "https";
                if (openbrowserURL.startsWith("http:")) {
                    openbrowserURL = openbrowserURL.replaceFirst("http:", "https:");
                }
            }
            if (!openbrowserURL.startsWith("http")) {
                openbrowserURL = (!openbrowserURL.startsWith("/")) ? "/" + openbrowserURL : openbrowserURL;
                openbrowserURL = protocol + "://" + host + ":" + portNumber + openbrowserURL;
            }
            // if binding to all IPs, swap out with localhost.
            openbrowserURL = Utils.replaceHost(openbrowserURL, "0.0.0.0", "127.0.0.1");

            LOG.info("Waiting up to " + (timeout / 1000) + " seconds for " + host + ":" + portNumber + "...");
            try {
                if (serverCameUp(timeout, 3000, getInetAddress(host), portNumber)) {
                    LOG.infof("Opening browser to url: %s", openbrowserURL);
                    BrowserOpener.openURL(openbrowserURL.trim(), serverOptions.browser());
                } else {
                    LOG.errorf("Timeout of %s reached, could not open browser to url: %s", timeout, openbrowserURL);
                }
            } catch (Exception e) {
                LOG.error(e.getMessage());
            }
            return;
        }
    }

    public ServerOptions getServerOptions() {
        return serverOptions;
    }

    private void setServerState(String state) {
        serverState = state;
    }

    public static String getProcessName() {
        return processName;
    }

    public String getServerState() {
        return serverState;
    }

    public synchronized SiteDeployment createSiteDeployment( DeploymentInfo servletBuilder, File webroot, RunwarConfigurer configurer, String deploymentKey, String vDirs, SiteOptions siteOptions ) throws Exception {
    	SiteDeployment deployment;

    	// If another thread already created this deployment
    	if( ( deployment = deployments.get( deploymentKey ) ) != null ) {
    		return deployment;
    	}

    	if( deployments.size() > serverOptions.autoCreateContextsMax() ) {
    		throw new MaxContextsException( "Cannot create new servlet deployment.  The configured max is [" + serverOptions.autoCreateContextsMax() + "]." );
    	}

        LOG.info("Creating deployment [" + deploymentKey + "] in " + webroot.toString() );

    	File webInfDir = serverOptions.webInfDir();
        Long transferMinSize= siteOptions.transferMinSize();
        Map<String,Path> aliases = new HashMap<>();
        siteOptions.aliases().forEach((s, s2) -> aliases.put(s,Paths.get(s2)));

        // Add any web server VDirs to Undertow. They come in this format:
        // /foo,C:\path\to\foo;/bar,C:\path\to\bar
        if( vDirs != null && !vDirs.isEmpty() ) {
        	// Parsing logic borrowed from mod_cfml source:
        	// https://github.com/paulklinkenberg/mod_cfml/blob/32e1fd868d7698f91ad12cffcaeb17258b4071d8/java/mod_cfml-valve/src/mod_cfml/core.java#L409-L420
			String[] aVDirs = vDirs.split(";");
			for (int i=0; i<aVDirs.length; i++) {
				String[] dirParts = aVDirs[i].split(",");
				if (dirParts.length == 2 && dirParts[0].length() > 1 && dirParts[1].length() > 1) {
					// windows paths to forward slash
					dirParts[1] = dirParts[1].replace("\\", "/");
					if( !aliases.containsKey( dirParts[0] ) ) {
						aliases.put( dirParts[0], Paths.get( dirParts[1] ) );
					}
				}
			}
        }

        ResourceManager resourceManager = getResourceManager(webroot, transferMinSize, aliases, webInfDir);


        // For non=Adobe (Lucee), create actual servlet context
        if( serverOptions.cfEngineName().toLowerCase().indexOf("adobe") == -1 ) {
            servletBuilder.setResourceManager(resourceManager);
        	DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
        	manager.deploy();

        	deployment = new SiteDeployment( manager.start(), manager, siteOptions );
            LOG.debug("New servlet context created for [" + deploymentKey + "]" );
        // For Adobe
        } else {
        	// For first deployment, create initial resource manager and deploy
        	if( deployments.size() == 0 ) {

                servletBuilder.setResourceManager( new HostResourceManager( resourceManager ) );
            	DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
            	manager.deploy();
            	deployment = new SiteDeployment( manager.start(), manager, siteOptions );
                this.adobeDefaultDeployment = deployment;
                LOG.debug("Initial servlet context created for [" + deploymentKey + "]" );

           	// For all subsequent deploys, reuse default deployment and simply add new resource manager
        	} else {

        		((HostResourceManager)servletBuilder.getResourceManager()).addResourceManager( deploymentKey, resourceManager );
                // Create a new deployment and site handler chain that calls the same servlet initial handler
            	deployment = new SiteDeployment( this.adobeDefaultDeployment.getServletInitialHandler(), this.adobeDefaultDeployment.getDeploymentManager(), siteOptions );
                LOG.debug("Cloned servlet context added for deployment [" + deploymentKey + "]" );

        	}

        }

    	deployments.put(deploymentKey, deployment);

    	return deployment;
    }

    private void logOnce( String deploymentKey, String type, String severity, String message ) {
    	String logKey = deploymentKey + type;
    	severity = severity.toLowerCase();
		if( !deploymentKeyWarnings.contains( logKey ) ) {
			deploymentKeyWarnings.add( logKey );
			switch (severity) {
			case "trace":
				LOG.trace( message );
				break;
			case "debug":
				LOG.debug( message );
				break;
			case "info":
				LOG.info( message );
				break;
			case "warn":
				LOG.warn( message );
				break;
			case "error":
				LOG.error( message );
				break;
			case "fatal":
				LOG.fatal( message );
				break;
			default:
				LOG.info( message );
			}

		}
    }

    private Boolean isHeaderSafe( HttpServerExchange exchange, String deploymentKey, String headerName ) {
    	HeaderValues headerValues = exchange.getRequestHeaders().get( headerName );
    	if( headerValues != null && headerValues.size() > 1 ) {
        	exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
        	exchange.setStatusCode(403);
        	exchange.getResponseSender().send( "The request header [" + headerName + "] was supplied " + headerValues.size() + " times which is likely a configuration error.  CommandBox won't serve requests with fishy ModCFML headers for security." );
        	logOnce( deploymentKey, "SharedKeyNotMatch", "debug", "The request header [" + headerName + "] was supplied " + headerValues.size() + " times which is likely a configuration error. The values are " + headerValues.toString() + ""
        			+ ".  CommandBox won't serve requests with fishy ModCFML headers for security." );
        	return false;
    	}
    	return true;
    }

    public static HttpServerExchange getCurrentExchange() {
    	return currentExchange.get();
    }

    public static void setCurrentExchange( HttpServerExchange exchange ) {
    	currentExchange.set( exchange );
    }

    public static class ServerState {

        public static final String STARTING = "STARTING";
        public static final String STARTED = "STARTED";
        public static final String STARTING_BACKGROUND = "STARTING_BACKGROUND";
        public static final String STARTED_BACKGROUND = "STARTED_BACKGROUND";
        public static final String STOPPING = "STOPPING";
        public static final String STOPPED = "STOPPED";
        public static final String UNKNOWN = "UNKNOWN";
    }

    public static class Mode {

        public static final String WAR = "war";
        public static final String SERVLET = "servlet";
        public static final String DEFAULT = "default";
    }

    private class MonitorThread extends Thread {

        private char[] stoppassword;
        private volatile boolean listening = false;
        private volatile boolean systemExitOnStop = true;
        private ServerSocket serverSocket;

        public MonitorThread(char[] stoppassword) {
            this.stoppassword = stoppassword;
            setDaemon(true);
            setName("StopMonitor");
        }

        @Override
        public void run() {
            // Executor exe = Executors.newCachedThreadPool();
            int exitCode = 0;
            serverSocket = null;
            try {
                serverSocket = new ServerSocket(serverOptions.stopPort(), 1, getInetAddress(siteOptions.host()));
                listening = true;
                LOG.info(bar);
                LOG.info("*** starting 'stop' listener thread - Host: " + siteOptions.host()
                        + " - Socket: " + serverOptions.stopPort());
                LOG.info(bar);
                while (listening) {
                    LOG.debug("StopMonitor listening for password");
                    if (serverState == ServerState.STOPPED || serverState == ServerState.STOPPING) {
                        listening = false;
                    }
                    final Socket clientSocket = serverSocket.accept();
                    int r, i = 0;
                    BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    try {
                        while (listening && (r = reader.read()) != -1) {
                            char ch = (char) r;
                            if (stoppassword.length > i && ch == stoppassword[i]) {
                                i++;
                            } else {
                                i = 0; // prevent prefix only matches
                            }
                        }
                        if (i == stoppassword.length) {
                            listening = false;
                        } else {
                            if (listening) {
                                LOG.warn("Incorrect password used when trying to stop server.");
                            } else {
                                LOG.debug("stopped listening for stop password.");
                            }

                        }
                    } catch (java.net.SocketException e) {
                        // reset
                    }
                    try {
                        clientSocket.close();
                    } catch (IOException e) {
                        LOG.error(e);
                    }
                }
            } catch (Exception e) {
                LOG.error(e);
                exitCode = 1;
                e.printStackTrace();
            } finally {
                LOG.debug("Closing server socket");
                try {
                    serverSocket.close();
                    serverSocket = null;
                } catch (IOException e) {
                    LOG.error(e);
                    e.printStackTrace();
                }
                try {
                    if (mainThread.isAlive()) {
                        LOG.debug("monitor joining main thread");
                        mainThread.interrupt();
                        try {
                            mainThread.join();
                        } catch (InterruptedException ie) {
                            // expected
                        }
                    }
                } catch (Exception e) {
                    LOG.error(e);
                    e.printStackTrace();
                }
            }
            if (systemExitOnStop) {
                System.exit(exitCode); // this will call our shutdown hook
            }
            return;
        }

        public void stopListening(boolean systemExitOnStop) {
            this.systemExitOnStop = systemExitOnStop;
            listening = false;
            // send a char to the reader so it will stop waiting
            Socket s;
            try {
                s = new Socket(getInetAddress(siteOptions.host()), serverOptions.stopPort());
                OutputStream out = s.getOutputStream();
                out.write('s');
                out.flush();
                out.close();
                s.close();
            } catch (IOException e) {
                // expected if already stopping
            }

        }

    }

	public class SiteDeployment {

	    private final HttpHandler siteInitialHandler;
	    private final HttpHandler servletInitialHandler;
	    private final DeploymentManager deploymentManager;
	    public final static String DEFAULT = "default";

	    public SiteDeployment(HttpHandler servletInitialHandler, DeploymentManager deploymentManager, SiteOptions siteOptions ) throws Exception {
	        this.deploymentManager = deploymentManager;
            this.servletInitialHandler = servletInitialHandler;
	        this.siteInitialHandler = buildSiteHandlerChain( servletInitialHandler, siteOptions );
	    }

        private HttpHandler buildSiteHandlerChain( HttpHandler servletInitialHandler, SiteOptions siteOptions ) throws Exception {

            final PathHandler pathHandler = new PathHandler(Handlers.redirect(serverOptions.contextPath())) {
                private final HttpString HTTPONLY = new HttpString("HttpOnly");
                private final HttpString SECURE = new HttpString("Secure");
                private final boolean addHttpOnlyHeader = serverOptions.cookieHttpOnly();
                private final boolean addSecureHeader = serverOptions.cookieHttpOnly();

                @Override
                public void handleRequest(final HttpServerExchange exchange) throws Exception {

                    if (!exchange.getResponseHeaders().contains(HTTPONLY) && addHttpOnlyHeader) {
                        exchange.getResponseHeaders().add(HTTPONLY, "true");
                    }
                    if (!exchange.getResponseHeaders().contains("Secure") && addSecureHeader) {
                        exchange.getResponseHeaders().add(SECURE, "true");
                    }

                    if (exchange.getRequestPath().endsWith(".svgz")) {
                        exchange.getResponseHeaders().put(Headers.CONTENT_ENCODING, "gzip");
                    }
                    // clear any welcome-file info cached after initial request *NOT THREAD SAFE*
                    if (siteOptions.directoryListingRefreshEnable() && exchange.getRequestPath().endsWith("/")) {
                        CONTEXT_LOG.trace("*** Resetting servlet path info");
                        //manager.getDeployment().getServletPaths().invalidate();
                    }

                    if (serverOptions.debug() && serverOptions.testing() && exchange.getRequestPath().endsWith("/dumprunwarrequest")) {
                        new RequestDumper().handleRequest(exchange);
                    } else {
                        String requestPath = exchange.getRequestPath();
                        while( !requestPath.isEmpty() && ( requestPath.startsWith( "/" ) || requestPath.startsWith( "\\" ) ) ) {
                            requestPath = requestPath.substring( 1 );
                        }
                        requestPath = requestPath.toUpperCase();
                        // Undertow has checks for this, but a more careful check is required with a case insensitive resource manager
                        if( !requestPath.isEmpty() && ( requestPath.startsWith( "WEB-INF/" ) || requestPath.startsWith( "WEB-INF\\" ) ) ) {
                            CONTEXT_LOG.trace("Blocking suspicious access to : " + exchange.getRequestPath() );
                            // Not ending the exchange here so the servlet can still send any custom error page.
                            exchange.setStatusCode( 404 );
                        }

                        // Then ensures any error status codes set in our predicate/server rules don't go any further
                        // The default response listener on the exchange will render the appropriate error page for us.
                        if( exchange.getStatusCode() > 399 ) {
                             //&& !exchange.isResponseStarted()
                             exchange.endExchange();
                             return;
                        }
                        super.handleRequest(exchange);
                    }
                }

                @Override
                public String toString() {
                    return "Runwar PathHandler";
                }
            };

            MimeMappings.Builder mimeMappings = MimeMappings.builder();
            siteOptions.mimeTypes().forEach((ext, contentType) -> {
                LOG.debugf("Adding Mime type %s = '%s'", ext, contentType);
                mimeMappings.addMapping(ext, contentType);
            });
            // Only needed until this is complete: https://issues.redhat.com/browse/UNDERTOW-2218
            mimeMappings.addMapping("webp", "image/webp");

            ResourceManager resourceManager = this.deploymentManager.getDeployment().getDeploymentInfo().getResourceManager();

            // TODO: Enforce allowed extensions
            final HttpHandler resourceHandler = new ResourceHandler( resourceManager )
                    .setDirectoryListingEnabled( siteOptions.directoryListingEnable() )
                    // TODO: default to welcome files from web.xml
                    // Can't enforce welcome files in resourcehandler since we need the index.cfm added PRIOR to our predicate below
                    //.setWelcomeFiles( siteOptions.welcomeFiles() )
                    .setMimeMappings( mimeMappings.build() );


        // Default list of what the default servlet will serve
        String allowedExt = "3gp,3gpp,7z,ai,aif,aiff,asf,asx,atom,au,avi,bin,bmp,btm,cco,crt,css,csv,deb,der,dmg,doc,docx,eot,eps,flv,font,gif,hqx,htc,htm,html,ico,img,ini,iso,jad,jng,jnlp,jpeg,jpg,js,json,kar,kml,kmz,m3u8,m4a,m4v,map,mid,midi,mml,mng,mov,mp3,mp4,mpeg,mpeg4,mpg,msi,msm,msp,ogg,otf,pdb,pdf,pem,pl,pm,png,ppt,pptx,prc,ps,psd,ra,rar,rpm,rss,rtf,run,sea,shtml,sit,svg,svgz,swf,tar,tcl,tif,tiff,tk,ts,ttf,txt,wav,wbmp,webm,webp,wmf,wml,wmlc,wmv,woff,woff2,xhtml,xls,xlsx,xml,xpi,xspf,zip,aifc,aac,apk,bak,bk,bz2,cdr,cmx,dat,dtd,eml,fla,gz,gzip,ipa,ia,indd,hey,lz,maf,markdown,md,mkv,mp1,mp2,mpe,odt,ott,odg,odf,ots,pps,pot,pmd,pub,raw,sdd,tsv,xcf,yml,yaml,handlebars,hbs";        // Add any custom additions by our users
        if( siteOptions.defaultServletAllowedExt().length() > 0 ) {
        	allowedExt += "," + siteOptions.defaultServletAllowedExt();
        }

        LOG.debug("Extensions allowed by the resource handler for static files: " + allowedExt);

        final String[] extArray = allowedExt.toLowerCase().split(",");

            HttpHandler allowedExtensions = new HttpHandler() {

                @Override
                public void handleRequest(final HttpServerExchange exchange) throws Exception {

                    Resource resource = resourceManager.getResource(CanonicalPathUtils.canonicalize(exchange.getRelativePath()));
                    if( resource != null && !resource.isDirectory() ) {
                        String ext = resource.getFile().getName().toLowerCase();
                        if( ext.contains(".") ) {
                            ext = ext.substring(ext.lastIndexOf(".") + 1);
                        }
                        Boolean found = false;
                        for( String allowedExt : extArray ) {
                            if( ext.equals( allowedExt ) ) {
                                found = true;
                                break;
                            }
                        }
                        if( !found ) {
                            LOG.debug( "Blocking access to [" + exchange.getRelativePath() + "] based on allowed extensions." );
                            exchange.setStatusCode( 403 );
                            return;
                        }
                    }
                    resourceHandler.handleRequest( exchange );
                }

                @Override
                public String toString() {
                    return "Default status code Handler";
                }
            };

            // In the event we are rendering a custom error page and the servlet is NOT processing it, then put the original
            // status code back before the resource handler closes the reponse channel
            HttpHandler defaultStatusCodeHandler = new HttpHandler() {
                @Override
                public void handleRequest(final HttpServerExchange exchange) throws Exception {
                    Map<String, String> requestAttrs = exchange.getAttachment( exchange.REQUEST_ATTRIBUTES );
                    if( requestAttrs != null && requestAttrs.containsKey( "default-response-handler" ) ) {
                        exchange.setStatusCode( Integer.parseInt( requestAttrs.get( "default-response-handler" ) ) );
                    }
                    allowedExtensions.handleRequest( exchange );
                }

                @Override
                public String toString() {
                    return "Default status code Handler";
                }
            };

            HttpHandler CFOrStaticHandler = Handlers.predicate(
                Predicates.parse( siteOptions.servletPassPredicate() ),
                servletInitialHandler,
                defaultStatusCodeHandler
            );

            HttpHandler welcomeFileHandler = new WelcomeFileHandler(CFOrStaticHandler, resourceManager, Arrays.asList(siteOptions.welcomeFiles()) );

            pathHandler.addPrefixPath(serverOptions.contextPath(), welcomeFileHandler);
            HttpHandler httpHandler = pathHandler;

            if (siteOptions.predicateText() != null && siteOptions.predicateText().length() > 0 ) {
                LOG.debug("Adding predicates");

                List<PredicatedHandler> ph = PredicatedHandlersParser.parse(siteOptions.predicateText(), _classLoader);
                LOG.trace(siteOptions.predicateText());

                httpHandler = Handlers.predicates(ph, httpHandler);
            }

            if (siteOptions.gzipEnable()) {
                //the default packet size on the internet is 1500 bytes so
                //any file less than 1.5k can be sent in a single packet
                if (siteOptions.gzipPredicate() != null) {
                    LOG.debug("Setting GZIP predicate to = " + siteOptions.gzipPredicate());
                }
                // The max-content-size predicate was replaced with request-larger-than
                httpHandler = new EncodingHandler(new ContentEncodingRepository().addEncodingHandler(
                        "gzip", new GzipEncodingProvider(), 50, Predicates.parse(siteOptions.gzipPredicate()))).setNext(httpHandler);
            }

            if (siteOptions.logAccessEnable()) {
                RunwarAccessLogReceiver accessLogReceiver = RunwarAccessLogReceiver.builder().setLogWriteExecutor(logWorker)
                        .setRotate(true)
                        .setOutputDirectory(siteOptions.logAccessDir().toPath())
                        .setLogBaseName(siteOptions.logAccessBaseFileName())
                        .setLogNameSuffix(serverOptions.logSuffix())
                        .build();
                LOG.debug("Logging combined access to " + siteOptions.logAccessDir() + " base name of '" + siteOptions.logAccessBaseFileName() + "." + serverOptions.logSuffix() + ", rotated daily'");
                httpHandler = new AccessLogHandler(httpHandler, accessLogReceiver, "combined", Server.class.getClassLoader());
            }

            if (siteOptions.proxyPeerAddressEnable()) {
                LOG.debug("Enabling Proxy Peer Address handling");
                httpHandler = new ProxyPeerAddressHandler(httpHandler);
            }

            if (siteOptions.clientCertTrustHeaders()) {
                LOG.debug("Checking for upstream client cert HTTP headers");
                httpHandler = new SSLHeaderHandler(httpHandler);
            }

            return new LifecyleHandler(httpHandler, serverOptions, siteOptions);

        }

	    public HttpHandler getServletInitialHandler() {
	        return servletInitialHandler;
	    }

	    public HttpHandler getSiteInitialHandler() {
	        return siteInitialHandler;
	    }

	    public DeploymentManager getDeploymentManager() {
	        return deploymentManager;
	    }

	    public void processRequest( HttpServerExchange exchange ) throws Exception {
	        siteInitialHandler.handleRequest(exchange);
	    }
	}

	private class MaxContextsException extends Exception {

		public MaxContextsException( String message ) {
			super( message );
		}

	}


}


