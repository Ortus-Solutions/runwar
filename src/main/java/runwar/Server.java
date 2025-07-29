package runwar;

import static io.undertow.servlet.Servlets.deployment;
import static runwar.logging.RunwarLogger.CONTEXT_LOG;
import static runwar.logging.RunwarLogger.LOG;

import java.awt.Image;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Pattern;

import javax.servlet.Servlet;

import org.xnio.Option;
import org.xnio.OptionMap;

import io.undertow.Undertow;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ServletSessionConfig;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import runwar.logging.LoggerFactory;
import runwar.logging.LoggerPrintStream;
import runwar.mariadb4j.MariaDB4jManager;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import runwar.tray.Tray;
import runwar.undertow.BindingMatcherHandler;
import runwar.undertow.ListenerManager;
import runwar.undertow.SSLCertHeaderHandler;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;
import runwar.undertow.handler.WarmUpServer;
import runwar.util.ClassLoaderUtils;
import runwar.util.Utils;

@SuppressWarnings("deprecation")
public class Server {

    public static String processName = "Starting Server...";
    /**
     * used to track if Undertow actually started or not. Calling server.stop() can
     * hang otherwise
     */
    public static volatile boolean undertowStarted = false;

    private static final ThreadLocal<HttpServerExchange> currentExchange = new ThreadLocal<HttpServerExchange>();
    private static final ThreadLocal<String> currentDeploymentKey = new ThreadLocal<String>();
    private static HttpHandler rootHandler;
    private volatile static ServerOptions serverOptions;
    private volatile static SiteDeploymentManager siteDeploymentManager;
    private static MariaDB4jManager mariadb4jManager;
    private Undertow undertow;
    private StopMonitor monitor;

    private String PID;
    private static volatile String serverState = ServerState.STOPPED;
    private static final String filePathSeparator = System.getProperty("path.separator");

    private static ClassLoader _classLoader;

    private String serverName = "default";
    public static final String bar = "******************************************************************************";
    private Thread shutDownThread;
    private PrintStream originalSystemOut;
    private PrintStream originalSystemErr;

    private static final Thread mainThread = Thread.currentThread();

    private Tray tray;
    // private FusionReactor fusionReactor;

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
            LOG.debug("  Initializing classloader with " + _classpath.size() + " jar(s)");
            if (paths > 0) {
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
        throw new RuntimeException("Is this used?");
        // startServer(CommandLineHandler.parseArguments(args));
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

    public synchronized void startServer(final ServerOptions options) throws Exception {
        serverOptions = options;
        // LoggerFactory.configure(serverOptions);
        // redirect out and err to context logger
        hookSystemStreams();

        serverState = ServerState.STARTING;
        serverName = serverOptions.serverName();
        String cfengine = serverOptions.cfEngineName(), processName = serverOptions.processName();
        String contextPath = serverOptions.contextPath();
        File warFile = serverOptions.warFile();
        String warPath = serverOptions.warUriString();
        char[] stoppassword = serverOptions.stopPassword();
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        processName = serverOptions.processName();

        // general configuration methods
        RunwarConfigurer configurer = new RunwarConfigurer(this);

        LOG.info(bar);
        LOG.info("Starting Runwar");
        LOG.info("  - Runwar Version: " + getVersion());
        LOG.info("  - Java Version: "
                + System.getProperty("java.vm.version", System.getProperty("java.version", "Unknown")) + " ("
                + System.getProperty("java.vendor", "Unknown") + ")");
        LOG.info("  - Java Home: " + System.getProperty("java.home", "Unknown"));
        LOG.info(bar);

        Undertow.Builder serverBuilder = Undertow.builder();

        // Add all HTTP/SSL/AJP listeners
        ListenerManager.configureListeners(serverBuilder, serverOptions);
        LOG.debug(bar);
        LOG.debug("Undertow Server:");

        // Compile and regex hostname patterns
        if (serverOptions.getSites().size() > 1) {
            JSONObject bindings = serverOptions.bindings();
            for (String key : bindings.keySet()) {
                if (key.endsWith(":regex:")) {
                    for (Object binding : (JSONArray) bindings.get(key)) {
                        JSONObject bindingInfo = (JSONObject) binding;
                        bindingInfo.put("pattern",
                                Pattern.compile(((String) bindingInfo.get("regexMatch")).toLowerCase()));
                    }
                }
            }
        }

        if (!warFile.exists()) {
            throw new RuntimeException("WAR does not exist: " + warFile.getAbsolutePath());
        }

        File webinf = serverOptions.webInfDir();
        File webXmlFile = serverOptions.webXmlFile();

        String libDirs = serverOptions.libDirs();
        // If this folder is a proper war, add its WEB-INF/lib folder to the passed
        // libDirs
        if (warFile.isDirectory() && webXmlFile != null && webXmlFile.exists()) {
            if (libDirs == null) {
                libDirs = "";
            } else if (libDirs.length() > 0) {
                libDirs = libDirs + ",";
            }
            libDirs = libDirs + webinf.getAbsolutePath() + "/lib";
            serverOptions.libDirs(libDirs);
        }

        List<URL> cp = new ArrayList<>();
        if (libDirs != null) {
            cp.addAll(getJarList(libDirs));
        }

        if (serverOptions.mariaDB4jImportSQLFile() != null) {
            LOG.debug("  Importing sql file: " + serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
            cp.add(serverOptions.mariaDB4jImportSQLFile().toURI().toURL());
        }
        cp.addAll(getClassesList(new File(webinf, "/classes")));
        initClassLoader(cp);

        // redirect out and err to context logger
        // hookSystemStreams();
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
                    LOG.warn("  Error setting dock icon image", e);
                }
            } else {
                System.setProperty("apple.awt.UIElement", "true");
            }
        }
        LOG.debug("  WAR root:" + warFile.getAbsolutePath());
        LOG.debug("  Servlet Context: " + contextPath);
        LOG.debug("  Log Directory: " + serverOptions.logDir().getAbsolutePath());
        if (serverOptions.directBuffers() != null) {
            LOG.debug("  Direct Buffers: " + serverOptions.directBuffers());
            serverBuilder.setDirectBuffers(serverOptions.directBuffers());
        }
        if (serverOptions.bufferSize() != 0) {
            LOG.debug("  Buffer Size: " + serverOptions.bufferSize());
            serverBuilder.setBufferSize(serverOptions.bufferSize());
        }
        addShutDownHook();

        if (serverOptions.workerThreads() != 0) {
            LOG.debug("  Worker threads (Max requests): " + serverOptions.workerThreads());
            serverBuilder.setWorkerThreads(serverOptions.workerThreads());
        }

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

        final DeploymentInfo servletBuilder = deployment()
                .setContextPath(contextPath.equals("/") ? "" : contextPath)
                .setTempDir(new File(System.getProperty("java.io.tmpdir")))
                .setDeploymentName("CommandBox-Servlet-Deployment")
                .setServletSessionConfig(servletSessionConfig)
                .setDisplayName(serverName)
                .setServerName("WildFly / Undertow")
                // I need this "inside" the servlet so it can access the HttpServletRequest
                .addInnerHandlerChainWrapper(new HandlerWrapper() {
                    @Override
                    public HttpHandler wrap(HttpHandler next) {
                        // Set SSL_CLIENT_ headers if client certs are present
                        return new SSLCertHeaderHandler(next,
                                serverOptions.cfEngineName().toLowerCase().contains("lucee"));

                    }
                });

        LOG.info(bar);
        LOG.info("Configuring Servlet");

        configurer.configureServlet(servletBuilder);

        configurer.configureServerResourceHandler(servletBuilder);

        configurer.configureRestMappings(servletBuilder);

        servletBuilder.addServletContextAttribute(WebSocketDeploymentInfo.ATTRIBUTE_NAME,
                new WebSocketDeploymentInfo().setBuffers(new DefaultByteBufferPool(true, 1024 * 16)));

        try {
            PID = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
            String pidFile = serverOptions.pidFile();
            if (pidFile != null && pidFile.length() > 0) {
                File file = new File(pidFile);
                file.deleteOnExit();
                LOG.debug("  PID file: " + file.toString());
                try (PrintWriter writer = new PrintWriter(file)) {
                    writer.print(PID);
                }
            }
        } catch (Exception e) {
            LOG.error("Unable to get PID:" + e.getMessage());
        }

        LOG.info(bar);
        siteDeploymentManager = new SiteDeploymentManager(serverOptions);
        if (serverOptions.getSites().size() == 1) {
            // Create default context
            siteDeploymentManager.createSiteDeployment(servletBuilder, serverOptions.getSites().get(0).webroot(),
                    configurer, SiteDeployment.DEFAULT, null, serverOptions.getSites().get(0));
            LOG.debug(bar);
        } else {
            for (SiteOptions siteOptions : serverOptions.getSites()) {
                siteDeploymentManager.createSiteDeployment(servletBuilder, siteOptions.webroot(), configurer,
                        siteOptions.siteName(), null, siteOptions);
                LOG.debug(bar);
            }
        }
        if (!serverOptions.debug()) {
            LOG.info(bar);
        }

        rootHandler = new BindingMatcherHandler(serverOptions, siteDeploymentManager, configurer, servletBuilder);
        serverBuilder.setHandler(rootHandler);

        setUndertowOptions(serverBuilder);
        setXnioOptions(serverBuilder);

        undertow = serverBuilder.build();

        // start the stop monitor thread
        assert monitor == null;
        monitor = new StopMonitor(stoppassword, serverOptions);
        monitor.start();
        tray = new Tray();

        if (serverOptions.trayEnable()) {
            try {
                tray.hookTray(this);
            } catch (Throwable e) {
                LOG.error("System tray hook failed", e);
            }
        } else {
            LOG.debug("System tray integration disabled");
        }

        if (serverOptions.openbrowser()) {
            LOG.debug("Starting open browser action");
            new Server(3);
        }

        String msg = "Server is up - stop-port:" + serverOptions.stopPort() + " PID:" + PID + " version "
                + getVersion();
        LOG.info(msg);
        // if the status line output would be suppressed due to logging levels, send it
        // to sysout
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
            undertowStarted = true;

            LOG.trace("Firing any warmup handlers");
            WarmUpServer.triggerWarmups();

        } catch (Exception any) {
            if (any.getCause() instanceof java.net.SocketException
                    && any.getCause().getMessage().equals("Permission denied")) {
                System.err.println("You need to be root or Administrator to bind to a port below 1024!");
            } else {
                any.printStackTrace();
            }
            LOG.error(any);
            System.exit(1);
        }
    }

    @SuppressWarnings("unchecked")
    private void setUndertowOptions(Undertow.Builder serverBuilder) {
        OptionMap undertowOptionsMap = serverOptions.undertowOptions().getMap();
        if (undertowOptionsMap.size() > 0) {
            LOG.debug("Undertow Options:");
        }
        for (Option option : undertowOptionsMap) {
            LOG.debug("  - " + option.getName() + " = " + undertowOptionsMap.get(option));
            serverBuilder.setServerOption(option, undertowOptionsMap.get(option));
            serverBuilder.setSocketOption(option, undertowOptionsMap.get(option));
        }
        if (undertowOptionsMap.size() > 0) {
            LOG.debug(bar);
        }
    }

    @SuppressWarnings("unchecked")
    private void setXnioOptions(Undertow.Builder serverBuilder) {
        OptionMap serverXnioOptionsMap = serverOptions.xnioOptions().getMap();
        if (serverXnioOptionsMap.size() > 0) {
            LOG.debug("XNIO Options:");
        }
        for (Option option : serverXnioOptionsMap) {
            LOG.debug("  - " + option.getName() + " = " + serverXnioOptionsMap.get(option));
            serverBuilder.setSocketOption(option, serverXnioOptionsMap.get(option));
        }
        if (serverXnioOptionsMap.size() > 0) {
            LOG.debug(bar);
        }
    }

    public static String fullExchangePath(HttpServerExchange exchange) {
        return exchange.getRequestURL()
                + (exchange.getQueryString().length() > 0 ? "?" + exchange.getQueryString() : "");
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
                    LOG.trace("Running shutdown hook");
                    try {
                        if (!getServerState().equals(ServerState.STOPPING)
                                && !getServerState().equals(ServerState.STOPPED)) {
                            stopServer(false);
                        }
                        if (mainThread.isAlive()) {
                            LOG.trace("Shutdown hook joining main thread");
                            mainThread.interrupt();
                            mainThread.join(3000);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            };
            Runtime.getRuntime().addShutdownHook(shutDownThread);
            LOG.debug("  Added shutdown hook");
        }
    }

    public void stopServer() {
        stopServer(true);
    }

    public void stopServer(boolean exit) {
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
                    String port = Integer.toString(serverOptions.stopPort());
                    String serverName = serverOptions.serverName() != null ? serverOptions.serverName() : "null";
                    LOG.infof("Stopping server '%s'", serverName);
                    if (serverOptions.mariaDB4jEnable()) {
                        mariadb4jManager.stop();
                    }
                    if (undertowStarted) {
                        if (siteDeploymentManager.getDeployments() != null) {
                            try {
                                for (Map.Entry<String, SiteDeployment> deployment : siteDeploymentManager
                                        .getDeployments()
                                        .entrySet()) {
                                    deployment.getValue().stop();
                                }

                                if (undertow != null) {
                                    undertow.stop();
                                }
                                // Thread.sleep(1000);
                            } catch (Exception notRunning) {
                                LOG.error("*** server did not appear to be running", notRunning);
                                LOG.info(bar);
                            }
                        }
                        LOG.debug("All deployments undeployed and underlying Undertow servers stopped");
                    } else {
                        LOG.debug("Undertow never fully started, marking as stopped.");
                    }
                    setServerState(ServerState.STOPPED);

                } catch (Exception e) {
                    e.printStackTrace();
                    setServerState(ServerState.UNKNOWN);
                    LOG.error("*** unknown server error", e);
                    exitCode = 1;
                }

                tray.unhookTray();
                if (System.getProperty("runwar.listloggers") != null
                        && Boolean.parseBoolean(System.getProperty("runwar.listloggers"))) {
                    LoggerFactory.listLoggers();
                }
                unhookSystemStreams();

                if (System.getProperty("runwar.classlist") != null
                        && Boolean.parseBoolean(System.getProperty("runwar.classlist"))) {
                    ClassLoaderUtils.listAllClasses(serverOptions.logDir() + "/classlist.txt");
                }

                if (monitor != null) {
                    LOG.trace("Stopping server monitor");
                    StopMonitor stopMonitor = monitor;
                    monitor = null;
                    stopMonitor.stopListening(false);
                    stopMonitor.interrupt();
                }

                if (exit && exitCode != 0) {
                    System.exit(exitCode);
                }
                LOG.info("Stopped server");

                break;
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
            if (host.toLowerCase().endsWith(".localhost")) {
                // It's possible to have "fake" hosts such as mytest.localhost which aren't in
                // DNS
                // or your hosts file. Browsers will resolve them to localhost, but the call
                // above
                // will fail with a UnknownHostException since they aren't real
                try {
                    return InetAddress.getByName("127.0.0.1");
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
                cfmlServlet = (Class<Servlet>) Server.class.getClassLoader()
                        .loadClass(cfengine + ".loader.servlet.CFMLServlet");
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
                restServletClass = (Class<Servlet>) Server.class.getClassLoader()
                        .loadClass(cfengine + ".loader.servlet.RestServlet");
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

    public boolean serverWentDown() {
        return serverWentDown(serverOptions.launchTimeout(), 3000, getInetAddress("127.0.0.1"),
                serverOptions.stopPort());
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
            int portNumber = serverOptions.stopPort();
            String protocol = "http";
            String host = "127.0.0.1";
            String openbrowserURL = serverOptions.openbrowserURL();
            if (openbrowserURL == null) {
                LOG.warn("Open Browser URL is empty, ignoring...");
                return;
            }
            int timeout = serverOptions.launchTimeout();

            // if binding to all IPs, swap out with localhost.
            openbrowserURL = Utils.replaceHost(openbrowserURL, "0.0.0.0", "127.0.0.1");

            LOG.info("Waiting up to " + (timeout / 1000) + " seconds for stop port " + host + ":" + portNumber + "...");
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

    public static String getServerState() {
        return serverState;
    }

    public static Thread getMainThread() {
        return mainThread;
    }

    public static HttpHandler getRootHandler() {
        return rootHandler;
    }

    public static HttpServerExchange getCurrentExchange() {
        return currentExchange.get();
    }

    public static void setCurrentExchange(HttpServerExchange exchange) {
        currentExchange.set(exchange);
    }

    public static String getCurrentDeploymentKey() {
        return currentDeploymentKey.get();
    }

    public static void setCurrentDeploymentKey(String deploymentKey) {
        currentDeploymentKey.set(deploymentKey);
    }

    public static SiteDeploymentManager getSiteDeploymentManager() {
        return siteDeploymentManager;
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
