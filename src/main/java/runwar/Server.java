package runwar;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.UndertowOptions;
import io.undertow.predicate.Predicates;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.ProxyPeerAddressHandler;
import io.undertow.server.handlers.SSLHeaderHandler;
import io.undertow.server.handlers.accesslog.AccessLogHandler;
import io.undertow.server.handlers.accesslog.DefaultAccessLogReceiver;
import io.undertow.server.handlers.cache.DirectBufferCache;
import io.undertow.server.handlers.encoding.ContentEncodingRepository;
import io.undertow.server.handlers.encoding.EncodingHandler;
import io.undertow.server.handlers.encoding.GzipEncodingProvider;
import io.undertow.server.handlers.resource.CachingResourceManager;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletSessionConfig;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import javashim.JavaShimClassLoader;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.xnio.*;
import runwar.logging.LoggerFactory;
import runwar.logging.LoggerPrintStream;
import runwar.logging.RunwarAccessLogReceiver;
import runwar.mariadb4j.MariaDB4jManager;
import runwar.options.CommandLineHandler;
import runwar.options.ServerOptions;
import runwar.options.ServerOptionsImpl;
import runwar.security.SSLUtil;
import runwar.security.SecurityManager;
import runwar.tray.Tray;
import runwar.undertow.MappedResourceManager;
import runwar.undertow.RequestDebugHandler;
import runwar.util.ClassLoaderUtils;
import runwar.util.FusionReactor;
import runwar.util.PortRequisitioner;
import runwar.util.RequestDumper;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Path;
import java.util.List;
import java.util.*;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import static runwar.logging.RunwarLogger.CONTEXT_LOG;
import static runwar.logging.RunwarLogger.LOG;

public class Server {

    public static volatile String processName = "RunWAR";
    private ServerOptionsImpl serverOptions;
    private static MariaDB4jManager mariadb4jManager;
    private DeploymentManager manager;
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
    private SecurityManager securityManager;
    private String serverMode;
    private PrintStream originalSystemOut;
    private PrintStream originalSystemErr;

    private static final int METADATA_MAX_AGE = 2000;

    private static XnioWorker worker, logWorker;
    private runwar.util.PortRequisitioner ports;
    private static HTTP2Proxy http2proxy;
    private Tray tray;
    private FusionReactor fusionReactor;

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
            LOG.debug("Initializing classloader with "+ _classpath.size() + " libraries");
            Thread.currentThread().setContextClassLoader(new JavaShimClassLoader(Thread.currentThread().getContextClassLoader()));
//            LOG.debug("Booted:" + VM.isBooted());
            if( paths > 0) {
                LOG.tracef("classpath: %s",_classpath);
                _classLoader = new JavaShimClassLoader(new URLClassLoader(_classpath.toArray(new URL[paths]), Thread.currentThread().getContextClassLoader()));
//                _classLoader = new CustomClassLoader(new URLClassLoader(_classpath.toArray(new URL[paths])));
    //          _classLoader = new URLClassLoader(_classpath.toArray(new URL[_classpath.size()]),Thread.currentThread().getContextClassLoader());
    //          _classLoader = new URLClassLoader(_classpath.toArray(new URL[_classpath.size()]),ClassLoader.getSystemClassLoader());
    //          _classLoader = new XercesFriendlyURLClassLoader(_classpath.toArray(new URL[_classpath.size()]),ClassLoader.getSystemClassLoader());
              //Thread.currentThread().setContextClassLoader(_classLoader);
//                try {
//                    Class<?> yourMainClass = Class.forName("sun.misc.VM", true, _classLoader);
//                } catch (ClassNotFoundException e) {
//                    e.printStackTrace();
//                }

            } else {
                _classLoader = Thread.currentThread().getContextClassLoader();
            }
        }
    }

    public void setClassLoader(URLClassLoader classLoader){
        _classLoader = classLoader;
    }

    public static ClassLoader getClassLoader(){
        return _classLoader;
    }

    public synchronized void startServer(String[] args, URLClassLoader classLoader) throws Exception {
        setClassLoader(classLoader);
        startServer(args);
    }

    public synchronized void startServer(final String[] args) throws Exception {
        startServer(CommandLineHandler.parseArguments(args));
    }

    public synchronized void restartServer() throws Exception {
        restartServer(getServerOptions());
    }
    public synchronized void restartServer(final ServerOptions options) throws Exception {
        LaunchUtil.displayMessage(options.processName(), "Info", "Restarting server...");
        LOG.info(bar);
        LOG.info("***  Restarting server");
        LOG.info(bar);
        LaunchUtil.restartApplication(() -> {
            LOG.debug("About to restart... (but probably we'll just die here-- this is neigh impossible.)");
                stopServer();
                serverWentDown();
        });
    }

    private synchronized void requisitionPorts(){
        ports = new PortRequisitioner(serverOptions.host());
        ports.add("http", serverOptions.httpPort());
        ports.add("stop", serverOptions.stopPort());
        ports.add("ajp", serverOptions.ajpPort(), serverOptions.ajpEnable());
        ports.add("https", serverOptions.sslPort(), serverOptions.sslEnable());
        ports.add("http2", serverOptions.http2ProxySSLPort(), serverOptions.http2Enable());
        if(serverOptions.http2Enable()) {
            ports.add("https", serverOptions.http2ProxySSLPort(),true);
            ports.add("http2", serverOptions.sslPort());
        }

        ports.requisition();
        serverOptions.httpPort(ports.get("http").socket);
        serverOptions.stopPort(ports.get("stop").socket);
        serverOptions.ajpPort(ports.get("ajp").socket);
        serverOptions.sslPort(ports.get("https").socket);
        serverOptions.http2ProxySSLPort(ports.get("http2").socket);

    }
    
    public synchronized void startServer(final ServerOptions options) throws Exception {
        serverOptions = (ServerOptionsImpl) options;
        LoggerFactory.configure(serverOptions);
        // redirect out and err to context logger
        hookSystemStreams();
        serverState = ServerState.STARTING;
        if(serverOptions.action().equals("stop")){
            Stop.stopServer(serverOptions,true);
        }
        serverName = serverOptions.serverName();
        String host = serverOptions.host(), cfengine = serverOptions.cfEngineName(), processName = serverOptions.processName();
        String contextPath = serverOptions.contextPath();
        File warFile = serverOptions.warFile();
        if (warFile == null) {
            throw new RuntimeException("-war argument is required!");
        }
        if (serverOptions.statusFile() != null) {
            statusFile = serverOptions.statusFile();
        }
        String warPath = serverOptions.warUriString();
        char[] stopPassword = serverOptions.stopPassword();
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        processName = serverOptions.processName();

        // general configuration methods
        RunwarConfigurer configurer = new RunwarConfigurer(this);
        if(serverOptions.sslSelfSign()){
            configurer.generateSelfSignedCertificate();
        }
        if(serverOptions.service()){
            new Service(serverOptions).generateServiceScripts();
            System.exit(0);
        }

        LOG.info("Starting RunWAR " + getVersion());
        LaunchUtil.assertMinimumJavaVersion("1.8");
        requisitionPorts();

        Builder serverBuilder = Undertow.builder();
        setUndertowOptions(serverBuilder);

        if(serverOptions.http2Enable()) {
            LOG.info("Enabling HTTP2 protocol");
            if(!serverOptions.sslEnable()) {
                LOG.warn("SSL is required for HTTP2.  Enabling default SSL server.");
                serverOptions.sslEnable(true);
            }
            serverBuilder.setServerOption(UndertowOptions.ENABLE_HTTP2, true);
            //serverBuilder.setSocketOption(Options.REUSE_ADDRESSES, true);
        }

        if (serverOptions.sslEnable()) {
            int sslPort = ports.get("https").socket;
            serverOptions.directBuffers(true);
            LOG.info("Enabling SSL protocol on port " + sslPort);
            if(serverOptions.sslEccDisable()) {
                LOG.debug("disabling com.sun.net.ssl.enableECC");
                System.setProperty("com.sun.net.ssl.enableECC", "false");
            } else {
                LOG.debug("NOT disabling com.sun.net.ssl.enableECC");
            }
            try {
                if (serverOptions.sslCertificate() != null) {
                    File certFile = serverOptions.sslCertificate();
                    File keyFile = serverOptions.sslKey();
                    char[] keypass = serverOptions.sslKeyPass();
                    String[] sslAddCerts = serverOptions.sslAddCerts();
                    sslContext = SSLUtil.createSSLContext(certFile, keyFile, keypass, sslAddCerts, new String[]{serverName});
                    if(keypass != null)
                        Arrays.fill(keypass, '*');
                } else {
                    sslContext = SSLUtil.createSSLContext();
                }
                serverBuilder.addHttpsListener(sslPort, host, sslContext);
            } catch (Exception e) {
                LOG.error("Unable to start SSL:" + e.getMessage());
                e.printStackTrace();
                System.exit(1);
            }
        }

        if (serverOptions.ajpEnable()) {
            LOG.info("Enabling AJP protocol on port " + serverOptions.ajpPort());
            serverBuilder.addAjpListener(serverOptions.ajpPort(), host);
        }

        securityManager = new SecurityManager();

        // if the war is archived, unpack it to system temp
        if(warFile.exists() && !warFile.isDirectory()) {
            URL zipResource = warFile.toURI().toURL();
            String warDir = warFile.getName().toLowerCase().replace(".war", "");
            warFile = new File(warFile.getParentFile(), warDir);
            if(!warFile.exists()) {
                if(!warFile.mkdir()){
                    LOG.error("Unable to explode WAR to " + warFile.getAbsolutePath());
                } else {
                    LOG.debug("Exploding compressed WAR to " + warFile.getAbsolutePath());
                    LaunchUtil.unzipResource(zipResource, warFile, false);
                }
            } else {
                LOG.debug("Using already exploded WAR in " + warFile.getAbsolutePath());
            }
            warPath = warFile.getAbsolutePath();
            if(serverOptions.warFile().getAbsolutePath().equals(serverOptions.contentDirs())) {
                serverOptions.contentDirs(warFile.getAbsolutePath());
            }
            serverOptions.warFile(warFile);
        }
        if (!warFile.exists()) {
            throw new RuntimeException("war does not exist: " + warFile.getAbsolutePath());
        }

        if (serverOptions.background()) {
            setServerState(ServerState.STARTING_BACKGROUND);
            // this will eventually system.exit();
            LaunchUtil.relaunchAsBackgroundProcess(serverOptions.background(false),true);
            setServerState(ServerState.STARTED_BACKGROUND);
            // just in case
            Thread.sleep(200);
            System.exit(0);
        }

        File webinf = serverOptions.webInfDir();
        File webXmlFile = serverOptions.webXmlFile();

        String libDirs = serverOptions.libDirs();
        URL jarURL = serverOptions.jarURL();
        // If this folder is a proper war, add its WEB-INF/lib folder to the passed libDirs
        if (warFile.isDirectory() && webXmlFile != null && webXmlFile.exists()) {
            if (libDirs == null) {
                libDirs = "";
            } else if( libDirs.length() > 0 ) {
                libDirs = libDirs + ","; 
            }
            libDirs = libDirs + webinf.getAbsolutePath() + "/lib";
            LOG.info("Adding additional lib dir of: " + webinf.getAbsolutePath() + "/lib");
            if(LaunchUtil.versionGreaterThanOrEqualTo(System.getProperty("java.version"),"1.9")){
                File cfusiondir = new File(webinf,"cfusion");
                if(cfusiondir.exists()){
                    LOG.debug("Adding cfusion/lib dir by hand becuase java9+" + cfusiondir.getAbsolutePath());
                    libDirs += "," + cfusiondir.getAbsolutePath() + "/lib";
                }
            }
            serverOptions.libDirs(libDirs);
        }

        List<URL> cp = new ArrayList<>();
//        cp.add(Server.class.getProtectionDomain().getCodeSource().getLocation());
        if (libDirs != null)
            cp.addAll(getJarList(libDirs));
        if (jarURL != null)
            cp.add(jarURL);
        
        if(serverOptions.mariaDB4jImportSQLFile() != null){
            LOG.info("Importing sql file: "+serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
            cp.add(serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
        }
        cp.addAll(getClassesList(new File(webinf, "/classes")));
//        cp.addAll(getClassesList(new File(webinf, "/cfclasses")));
        initClassLoader(cp);

        fusionReactor = new FusionReactor(_classLoader);

        // redirect out and err to context logger
        //hookSystemStreams();

        String osName = System.getProperties().getProperty("os.name");
        String iconPNG = System.getProperty("cfml.server.trayicon");
        if( iconPNG != null && iconPNG.length() > 0) {
            serverOptions.iconImage(iconPNG);
        }
        String dockIconPath = System.getProperty("cfml.server.dockicon");
        if( dockIconPath == null || dockIconPath.length() == 0) {
            dockIconPath = serverOptions.iconImage();
        }

        if (osName != null && osName.startsWith("Mac OS X")) {
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
                LOG.warn("error setting dock icon image",e);
            }
        }
        LOG.info(bar);
        LOG.info("Starting - port:" + ports.get("http") + " stop-port:" + ports.get("stop") + " warpath:" + warPath);
        LOG.info("context: " + contextPath + "  -  version: " + getVersion());
        if (serverOptions.contentDirectories().size() > 0) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(serverOptions.contentDirectories());
            LOG.info("web-dirs: " + jsonArray.toJSONString());
        } else {
            LOG.debug("no content directories configured");
        }
        if (serverOptions.aliases().size() > 0) {
            LOG.info("aliases: " + new JSONObject(serverOptions.aliases()).toJSONString() );
        } else {
            LOG.debug("no aliases configured");
        }
        LOG.info("Log Directory: " + serverOptions.logDir().getAbsolutePath());
        LOG.info(bar);

        LOG.debug("Transfer Min Size: " + serverOptions.transferMinSize());

        Xnio xnio = Xnio.getInstance("nio", Server.class.getClassLoader());

        worker = xnio.createWorker(serverOptions.xnioOptions().getMap());

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

        final DeploymentInfo servletBuilder = deployment()
                .setContextPath(contextPath.equals("/") ? "" : contextPath)
                .setTempDir(new File(System.getProperty("java.io.tmpdir")))
                .setDeploymentName(warPath)
                .setServletSessionConfig(servletSessionConfig)
                .setDisplayName(serverName)
                .setServerName( "WildFly / Undertow" );

        // hack to prevent . being picked up as the system path (jacob.x.dll)
        final String jarPath = getThisJarLocation().getPath();
        String javaLibraryPath = System.getProperty("java.library.path");
        if (javaLibraryPath == null) {
            if (webXmlFile != null) {
                javaLibraryPath =  jarPath + ':' + new File(webXmlFile.getParentFile(), "lib").getPath();
            } else {
                javaLibraryPath = jarPath  + ':' + new File(warFile, "/WEB-INF/lib/").getPath();
            }
        } else {
            javaLibraryPath = jarPath + filePathSeparator + javaLibraryPath;
        }
        System.setProperty("java.library.path", javaLibraryPath);
        LOG.trace("java.library.path:" + System.getProperty("java.library.path"));

        configurer.configureServerResourceHandler(servletBuilder);
        if(serverOptions.basicAuthEnable()) {
            securityManager.configureAuth(servletBuilder, serverOptions);
        }

        configurer.configureServlet(servletBuilder);

        // TODO: probably best to create a new worker for websockets, if we want fastness, but for now we share
        // TODO: add buffer pool size (maybe-- direct is best at 16k), enable/disable be good I reckon tho
        servletBuilder.addServletContextAttribute(WebSocketDeploymentInfo.ATTRIBUTE_NAME,
                new WebSocketDeploymentInfo().setBuffers(new DefaultByteBufferPool(true, 1024 * 16)).setWorker(worker));

        LOG.debug("Added websocket context");

        manager = defaultContainer().addDeployment(servletBuilder);

        // stupid hack for older adobe versions
        String originalJavaVersion = System.getProperty("java.version","");
        if(serverOptions.cfEngineName().equalsIgnoreCase("adobe") && !servletBuilder.getDisplayName().contains("2018")) {
            if(LaunchUtil.versionGreaterThanOrEqualTo(originalJavaVersion,"1.9")){
                LOG.debug("Setting java version from " + originalJavaVersion + " to 1.8 temporarily because we're running " + servletBuilder.getDisplayName());
                System.setProperty("java.version","1.8");
            }
        }

        manager.deploy();
        HttpHandler servletHandler = manager.start();
        LOG.debug("started servlet deployment manager");

        if (!System.getProperty("java.version", "").equalsIgnoreCase(originalJavaVersion)) {
            System.setProperty("java.version", originalJavaVersion);
        }

        /*
        List welcomePages =  manager.getDeployment().getDeploymentInfo().getWelcomePages();
        CFMLResourceHandler resourceHandler = new CFMLResourceHandler(servletBuilder.getResourceManager(), servletHandler, welcomePages);
        resourceHandler.directoryListingEnable(directoryListingEnable);
        PathHandler pathHandler = Handlers.path(Handlers.redirect(contextPath))
                .addPrefixPath(contextPath, resourceHandler);
        HttpHandler errPageHandler = new SimpleErrorPageHandler(pathHandler);
        Builder serverBuilder = Undertow.builder().addHttpListener(portNumber, host).setHandler(errPageHandler);
*/

        if(serverOptions.httpEnable()) {
            serverBuilder.addHttpListener(ports.get("http").socket, host);
        }

        if(serverOptions.bufferSize() != 0) {
            LOG.info("Buffer Size: " + serverOptions.bufferSize());
            serverBuilder.setBufferSize(serverOptions.bufferSize());
        }
        if(serverOptions.ioThreads() != 0) {
            LOG.info("IO Threads: " + serverOptions.ioThreads());
            serverBuilder.setIoThreads(serverOptions.ioThreads());
        }
        if(serverOptions.workerThreads() != 0) {
            LOG.info("Worker threads: " + serverOptions.workerThreads());
            serverBuilder.setWorkerThreads(serverOptions.workerThreads());
        }
        LOG.info("Direct Buffers: " + serverOptions.directBuffers());
        serverBuilder.setDirectBuffers(serverOptions.directBuffers());

        final PathHandler pathHandler = new PathHandler(Handlers.redirect(contextPath)) {
            private final HttpString HTTPONLY = new HttpString("HttpOnly");
            private final HttpString SECURE = new HttpString("Secure");
            private final boolean addHttpOnlyHeader = serverOptions.cookieHttpOnly();
            private final boolean addSecureHeader = serverOptions.cookieHttpOnly();

            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
/*
                final SessionManager sessionManager = exchange.getAttachment(SessionManager.ATTACHMENT_KEY);
                final SessionConfig sessionconfig = exchange.getAttachment(SessionConfig.ATTACHMENT_KEY);
                Session session = sessionManager.getSession(exchange, sessionconfig);
                if (session == null) {
                    LOG.error("SESSION WAS NULL");
                    session = sessionManager.createSession(exchange, sessionconfig);
                }
*/
                if(!exchange.getResponseHeaders().contains(HTTPONLY) && addHttpOnlyHeader){
                    exchange.getResponseHeaders().add(HTTPONLY, "true");
                }
                if(!exchange.getResponseHeaders().contains("Secure") && addSecureHeader){
                    exchange.getResponseHeaders().add(SECURE, "true");
                }

                if(fusionReactor.hasFusionReactor()){
                    fusionReactor.setFusionReactorInfo("myTransaction","myTransacitonApplication");
                }


                CONTEXT_LOG.debug("requested: '" + fullExchangePath(exchange) + "'" );
                // sessionConfig.setSessionId(exchange, ""); // TODO: see if this suppresses jsessionid
                if (exchange.getRequestPath().endsWith(".svgz")) {
                    exchange.getResponseHeaders().put(Headers.CONTENT_ENCODING, "gzip");
                }
                // clear any welcome-file info cached after initial request *NOT THREAD SAFE*
                if (serverOptions.directoryListingRefreshEnable() && exchange.getRequestPath().endsWith("/")) {
                    CONTEXT_LOG.trace("*** Resetting servlet path info");
                    manager.getDeployment().getServletPaths().invalidate();
                }
                if(serverOptions.debug()){
                    // output something if in debug mode and response is other than OK
                    exchange.addExchangeCompleteListener((httpServerExchange, nextListener) -> {
                        if(httpServerExchange.getStatusCode() > 399) {
                            CONTEXT_LOG.warnf("responded: Status Code %s (%s)", httpServerExchange.getStatusCode(), fullExchangePath(httpServerExchange));
                        }
                        nextListener.proceed();
                    });
                }

                if(serverOptions.debug() && exchange.getRequestPath().endsWith("/dumprunwarrequest")) {
                    new RequestDumper().handleRequest(exchange);
                } else {
                    super.handleRequest(exchange);
                }
            }
        };
        pathHandler.addPrefixPath(contextPath, servletHandler);

        HttpHandler httpHandler;

        if (serverOptions.gzipEnable()) {
            final EncodingHandler handler = new EncodingHandler(new ContentEncodingRepository().addEncodingHandler(
                    "gzip", new GzipEncodingProvider(), 50, Predicates.parse("max-content-size[5]")))
                    .setNext(pathHandler);
            httpHandler = new ErrorHandler(handler);
        } else {
            httpHandler = new ErrorHandler(pathHandler);
        }

/*
        // if we do some kind of nifty single-sign-on deal we need this but just overhead otherwise
        SessionCookieConfig sessionConfig = new SessionCookieConfig();
        sessionConfig.setHttpOnly(serverOptions.cookieHttpOnly());
        sessionConfig.setSecure(serverOptions.cookieSecure());
        httpHandler = new SessionAttachmentHandler(httpHandler, new InMemorySessionManager("", 1, true), sessionConfig);
*/


        if (serverOptions.logAccessEnable()) {
//            final String PATTERN = "cs-uri cs(test-header) x-O(aa) x-H(secure)";
            RunwarAccessLogReceiver accessLogReceiver = RunwarAccessLogReceiver.builder().setLogWriteExecutor(logWorker)
                .setRotate(true)
                .setOutputDirectory(serverOptions.logAccessDir().toPath())
                .setLogBaseName(serverOptions.logAccessBaseFileName())
                .setLogNameSuffix(serverOptions.logSuffix())
//                .setLogFileHeaderGenerator(new ExtendedAccessLogParser.ExtendedAccessLogHeaderGenerator(PATTERN))
                .build();
            LOG.info("Logging combined access to " + serverOptions.logAccessDir() + " base name of '" + serverOptions.logAccessBaseFileName() + "." + serverOptions.logSuffix() + ", rotated daily'");
//            errPageHandler = new AccessLogHandler(errPageHandler, logReceiver, PATTERN, new ExtendedAccessLogParser( Server.class.getClassLoader()).parse(PATTERN));
//            errPageHandler = new AccessLogHandler(errPageHandler, logReceiver,"common", Server.class.getClassLoader());
            httpHandler = new AccessLogHandler(httpHandler, accessLogReceiver,"combined", Server.class.getClassLoader());
        }


        if (serverOptions.logRequestsEnable()) {
            LOG.debug("Enabling request dumper");
            DefaultAccessLogReceiver requestsLogReceiver = DefaultAccessLogReceiver.builder().setLogWriteExecutor(logWorker)
                    .setRotate(true)
                    .setOutputDirectory(options.logRequestsDir().toPath())
                    .setLogBaseName(options.logRequestsBaseFileName())
                    .setLogNameSuffix(options.logSuffix())
                    .build();
            httpHandler = new RequestDebugHandler(httpHandler, requestsLogReceiver);
        }

        if (serverOptions.proxyPeerAddressEnable()) {
            LOG.debug("Enabling Proxy Peer Address handling");
            httpHandler = new SSLHeaderHandler(new ProxyPeerAddressHandler(httpHandler));
        }

        if (serverOptions.http2Enable()) {
            http2proxy = new HTTP2Proxy(ports, xnio);
            httpHandler = http2proxy.proxyHandler(httpHandler);
        }

        if(serverOptions.basicAuthEnable()) {
            securityManager.configureAuth(httpHandler, serverBuilder, options);
        } else {
            serverBuilder.setHandler(httpHandler);
        }

        try {
            PID = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
            String pidFile = serverOptions.pidFile();
            if (pidFile != null && pidFile.length() > 0) {
                File file = new File(pidFile);
                file.deleteOnExit();
                try(PrintWriter writer = new PrintWriter(file)){
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
        monitor = new MonitorThread(this);
        monitor.start();
        LOG.debug("started stop monitor");
        tray = new Tray();

        if(serverOptions.trayEnable()) {
            try {
                tray.hookTray(this);
                LOG.debug("hooked system tray");	
            } catch( Throwable e ) {
                LOG.error( "system tray hook failed", e );
            }
        } else {
            LOG.debug("System tray integration disabled");
        }

        if (serverOptions.openbrowser()) {
            LOG.debug("Starting open browser action");
            new Server(3);
        }
        
        // if this println changes be sure to update the LaunchUtil so it will know success
        String sslInfo = serverOptions.sslEnable() ? " https-port:" + ports.get("https") : "";
        String msg = "Server is up - http-port:" + ports.get("http") + sslInfo + " stop-port:" + ports.get("stop") +" PID:" + PID + " version " + getVersion();
        LOG.info(msg);
        // if the status line output would be suppressed due to logging levels, send it to sysout
        if(serverOptions.logLevel().equalsIgnoreCase("WARN") || serverOptions.logLevel().equalsIgnoreCase("ERROR")) {
            System.out.println(msg);
        }
        if(serverOptions.trayEnable()) {
            LaunchUtil.displayMessage(serverOptions.processName(), "info", msg);
        }
        setServerState(ServerState.STARTED);
//        ConfigWebAdmin admin = new ConfigWebAdmin(lucee.runtime.engine.ThreadLocalPageContext.getConfig(), null);
//        admin._updateMapping(virtual, physical, archive, primary, inspect, toplevel);
//        admin._store();

//        Class<?> appClass = _classLoader.loadClass("lucee.loader.engine.CFMLEngineFactory");
//        Method getAppMethod = appClass.getMethod("getInstance");
//        Object appInstance = getAppMethod.invoke(null);
//        Object webs = appInstance.getClass().getMethod("getCFMLEngineFactory").invoke(appInstance, null);
//        Object ef = webs.getClass().getMethod("getInstance").invoke(webs, null);
//
//        System.out.println(appInstance.toString());

        if (serverOptions.mariaDB4jEnable()) {
            LOG.info("MariaDB support enable");
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
        try{

            undertow.start();

            if (serverOptions.http2Enable() && http2proxy != null && sslContext != null) {
                LOG.debug("Starting HTTP2 proxy");
                http2proxy.start(sslContext);
            }

            // two times to test system tray issue
            System.gc();
            System.gc();

        }
        catch (Exception any) {
            if(any.getCause() instanceof java.net.SocketException && any.getCause().getMessage().equals("Permission denied") ) {
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
            LOG.info("UndertowOption " + option.getName() + ':' + undertowOptionsMap.get(option));
            serverBuilder.setServerOption(option, undertowOptionsMap.get(option));
        }
    }

    PortRequisitioner getPorts() {
        return ports;
    }

    private static String fullExchangePath(HttpServerExchange exchange) {
        return exchange.getRequestPath() + (exchange.getQueryString().length() > 0 ? "?" + exchange.getQueryString() : "");
    }

    private synchronized void hookSystemStreams() {
        LOG.trace("Piping system streams to logger");
        if (System.out instanceof LoggerPrintStream) {
            LOG.trace("streams already piped");
        } else {
            originalSystemOut = System.out;
            originalSystemErr = System.err;
            System.setOut(new LoggerPrintStream(CONTEXT_LOG, org.jboss.logging.Logger.Level.INFO));
            // filter out SLF4j binding errors (yeah yeah)
            System.setErr(new LoggerPrintStream(CONTEXT_LOG, org.jboss.logging.Logger.Level.ERROR, "^SLF4J:.*"));
        }
    }

    private synchronized void unhookSystemStreams() {
        LOG.trace("Unhooking system streams logger");
        if(originalSystemOut != null) {
            System.setOut(originalSystemOut);
            System.setErr(originalSystemErr);
        } else {
            LOG.trace("Original System streams were null, probably never piped to logger.");
        }
    }

    public synchronized void stopServer() {
        int exitCode = 0;
        if(monitor != null) {
            monitor.removeShutDownHook();
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
                    String port = getPorts() != null ? getPorts().get("stop").toString() : "null";
                    String serverName = serverOptions.serverName() != null ? serverOptions.serverName() : "null";
                    LOG.infof("*** stopping server '%s' (socket %s)", serverName, port);
                    LOG.info(bar);
                    if (serverOptions.mariaDB4jEnable()) {
                        mariadb4jManager.stop();
                    }
                    if(manager != null){
                        try {
                            switch (manager.getState()) {
                                case UNDEPLOYED:
                                    break;
                                default:
                                    manager.stop();
                                    manager.undeploy();
                            }
                            if(http2proxy != null){
                                http2proxy.stop();
                            }
                            undertow.stop();
                            if(worker != null) {
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
                unhookSystemStreams();

                if (System.getProperty("runwar.classlist") != null && Boolean.parseBoolean(System.getProperty("runwar.classlist"))) {
                    ClassLoaderUtils.listAllClasses(serverOptions.logDir() + "/classlist.txt");
                }
                if (System.getProperty("runwar.listloggers") != null && Boolean.parseBoolean(System.getProperty("runwar.listloggers"))) {
                    LoggerFactory.listLoggers();
                }

                LOG.debug("Stopping server monitor");
                if (monitor != null) {
                    MonitorThread monitorThread = monitor;
                    monitorThread.stopListening();
                    monitor = null;
                } else{
                    LOG.error("server monitor was null!");
                }

                if (exitCode != 0) {
                    System.exit(exitCode);
                }
                LOG.debug("Stopped server");

                break;
        }

    }

    ResourceManager getResourceManager(File warFile, Long transferMinSize, Set<Path> contentDirs, Map<String,Path> aliases, File internalCFMLServerRoot) {
        MappedResourceManager mappedResourceManager = new MappedResourceManager(warFile, transferMinSize, contentDirs, aliases, internalCFMLServerRoot);
        if(serverOptions.directoryListingRefreshEnable() || !serverOptions.bufferEnable()) {
            return mappedResourceManager;
        }
        final DirectBufferCache dataCache = new DirectBufferCache(1000, 10, 1000 * 10 * 1000, BufferAllocator.DIRECT_BYTE_BUFFER_ALLOCATOR, METADATA_MAX_AGE);
        final int metadataCacheSize = 100;
        final long maxFileSize = 10000;
        return new CachingResourceManager(metadataCacheSize,maxFileSize, dataCache, mappedResourceManager, METADATA_MAX_AGE);
    }

    public static File getThisJarLocation() {
        return LaunchUtil.getJarDir(Server.class);
    }

    public String getPID() {
        return PID;
    }

    private List<URL> getJarList(String libDirs) throws IOException {
        return RunwarConfigurer.getJarList(libDirs);
    }

    private List<URL> getClassesList(File classesDir) throws IOException {
        List<URL> classpath = new ArrayList<>();
        if (classesDir == null)
            return classpath;
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
        if(versionProp == null)
            return "unknown";
        String[] version = versionProp.split("=");
        return version[version.length - 1].trim();
    }

    public int getHttpPort() {
        return ports.get("http").socket;
    }

    public int getSslPort() {
        return ports.get("https").socket;
    }

    public int getStopPort() {
        return ports.get("stop").socket;
    }

    public boolean serverWentDown() {
        try {
            return serverWentDown(serverOptions.launchTimeout(), 3000, InetAddress.getByName(serverOptions.host()), ports.get("http").socket);
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
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
                LOG.debug("Error while connecting: " + server.getHostAddress() + ":" + port + " - " + e.getMessage());
            }
        }
        return false;
    }

    public static boolean checkServerIsUp(InetAddress server, int port) throws ConnectException {
        try(Socket sock = new Socket()) {
            InetSocketAddress sa = new InetSocketAddress(server, port);
            sock.connect(sa, 500);
            return true;
        } catch (ConnectException e) {
            throw e;
        } catch (SocketTimeoutException e) {
            LOG.debug("Socket Timeout: " + server.getHostAddress() + ":" + port + " - " + e.getMessage() + ".");
        } catch (SocketException e) {
            LOG.debug("Socket Exception: " + server.getHostAddress() + ":" + port + " - " + e.getMessage() + ".");
        } catch (IOException e) {
            LOG.warn("IO Exception: " + server.getHostAddress() + ":" + port + " - " + e.getMessage() + ".");
        }
        return false;
    }

    class OpenBrowserTask extends TimerTask {
        public void run() {
            int portNumber = ports.get("http").socket;
            String protocol = "http";
            String host = serverOptions.host();
            String openbrowserURL = serverOptions.openbrowserURL();
            int timeout = serverOptions.launchTimeout();
            if (openbrowserURL == null || openbrowserURL.length() == 0) {
                openbrowserURL = "http://" + host + ":" + portNumber;
            }
            if(serverOptions.sslEnable()) {
                portNumber = serverOptions.sslPort();
                protocol = "https";
                openbrowserURL = openbrowserURL.replace("http:", "https:");
            }
            if (!openbrowserURL.startsWith("http")) {
                openbrowserURL = (!openbrowserURL.startsWith("/")) ? "/" + openbrowserURL : openbrowserURL;
                openbrowserURL = protocol + "://" + host + ":" + portNumber + openbrowserURL;
            }
            LOG.info("Waiting up to " + (timeout/1000) + " seconds for " + host + ":" + portNumber + "...");
            try {
                if (serverCameUp(timeout, 3000, InetAddress.getByName(host), portNumber)) {
                    LOG.infof("Opening browser to url: %s", openbrowserURL);
                    BrowserOpener.openURL(openbrowserURL.trim());
                } else {
                    LOG.errorf("Timeout of %s reached, could not open browser to url: %s", timeout, openbrowserURL);
                }
            } catch (Exception e) {
                LOG.error(e.getMessage());
            }
        }
    }

    public ServerOptions getServerOptions() {
        return serverOptions;
    }

    private synchronized void setServerState(String state) {
        serverState = state;
        if (statusFile != null) {
            try(PrintWriter writer = new PrintWriter(statusFile)) {
                writer.print(state);
            } catch (FileNotFoundException e) {
                LOG.error(e.getMessage());
            }
        }
    }

    public static String getProcessName() {
        return processName;
    }

    public String getServerState() {
        return serverState;
    }

    public DeploymentManager getManager() {
        return manager;
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

}
