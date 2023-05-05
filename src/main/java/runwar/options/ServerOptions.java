package runwar.options;

import io.undertow.UndertowOptions;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.xnio.OptionMap;
import org.xnio.Options;
import runwar.Server;
import runwar.Server.Mode;
import runwar.options.SiteOptions;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

import static runwar.util.Reflection.setOptionMapValue;

public class ServerOptions {

    private String[] servletWelcomeFiles;

    private String serverName = null, processName = "RunWAR", logLevel = "INFO", contextPath = "/";

    private boolean debug = false, isBackground = true, logRequestsEnable = false, openbrowser = false, startedFromCommandline = false, enableURLRewrite = false;

    private String pidFile, openbrowserURL,  logFileBaseName="server", logRequestBaseFileName="requests", logSuffix="txt", libDirs = null;

                                // 50 secs
    private int launchTimeout = 50 * 1000, socketNumber = 8779;

    private URL jarURL = null;

    private File workingDir, warFile, webInfDir, webXmlFile, webXmlOverrideFile, logDir, logRequestsDir, urlRewriteFile, urlRewriteLog, trayConfig, statusFile = null;

    private String iconImage = null;

    private String urlRewriteCheckInterval = null, urlRewriteStatusPath = null;

    private String cfmlServletConfigWebDir = null, cfmlServletConfigServerDir = null;

    private String defaultShell = "";

    private boolean trayEnable = true;

    private boolean webXmlOverrideForce = false;

    private boolean dockEnable = true; // for mac users

    private File configFile;

    private char[] stopPassword = "klaatuBaradaNikto".toCharArray();

    private String action = "start";

    private String browser = "";

    private String cfengineName = "";

    private boolean customHTTPStatusEnable = true;

    private boolean mariadb4jEnable = false;

    private int mariadb4jPort = 13306;

    private File mariadb4jBaseDir, mariadb4jDataDir, mariadb4jImportSQLFile = null;

    private List<String> jvmArgs = null;

    private boolean servletRestEnable = false;

    private String[] servletRestMappings = {};

    private boolean filterPathInfoEnable = true;

    private String[] cmdlineArgs = null;

    private String[] loadBalance = null;

    private boolean directBuffers = true;

    int bufferSize, ioThreads, workerThreads = 0;

    private boolean secureCookies = false, cookieHttpOnly = false, cookieSecure = false;

    private JSONArray trayConfigJSON;

    private boolean sslEccDisable = true;

    private boolean sslSelfSign = false;

    private boolean service = false;

    public String logPattern = "[%-5p] %c: %m%n";

    private Boolean autoCreateContexts= false;

    private String autoCreateContextsSecret="";

    private Integer autoCreateContextsMax=200;

    private Boolean autoCreateContextsVDirs=false;

    private String consoleLayout="PatternLayout";

    private Map<String, Object> consoleLayoutOptions = new HashMap<String, Object>();

    private List<SiteOptions> sites = new ArrayList<SiteOptions>();

    public String getLogPattern() {
        return logPattern;
    }

    private OptionMap.Builder serverXnioOptions = OptionMap.builder()
            .set(Options.WORKER_IO_THREADS, 8)
            .set(Options.CONNECTION_HIGH_WATER, 1000000)
            .set(Options.CONNECTION_LOW_WATER, 1000000)
            .set(Options.WORKER_TASK_CORE_THREADS, 30)
            .set(Options.WORKER_TASK_MAX_THREADS, 30)
            .set(Options.TCP_NODELAY, true)
            .set(Options.CORK, true);

    private boolean testing = false;
    private OptionMap.Builder undertowOptions = OptionMap.builder();

    public String toJson(Set<String> set){
        JSONArray jsonArray = new JSONArray();
        jsonArray.addAll(set);
        return jsonArray.toJSONString();
    }

    public String toJson(Map<?,?> map){
        final Map<String,String> finalMap = new HashMap<>();
        map.forEach((o, o2) -> {
            if(o instanceof Integer){
                finalMap.put(Integer.toString((Integer) o),(String)o2);
            } else {
                finalMap.put((String)o,(String)o2);
            }
        });
        return new JSONObject(finalMap).toJSONString();
    }

    public List<SiteOptions> getSites() {
        return this.sites;
    }

    public ServerOptions addSite( SiteOptions site ) {
        site.setServerOptions( this );
        this.sites.add( site );
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#commandLineArgs(java.lang.String[])
     */
    public ServerOptions commandLineArgs(String[] args) {
        this.cmdlineArgs = args;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#commandLineArgs()
     */
    public String[] commandLineArgs() {
        // TODO: totally refactor argument handling so we can serialize and not
        // muck around like this.
        List<String> argarray = new ArrayList<String>();

        return argarray.toArray(new String[0]);
/*
        if (cmdlineArgs == null) {
            cmdlineArgs = "".split("");
            argarray.add("-war");
            argarray.add(warFile() != null ? warFile().getAbsolutePath() : new File(".").getAbsolutePath());
        }
        Boolean skipNext = false;
        for (String arg : cmdlineArgs) {
            arg = arg.trim();
            if (arg.equals("--background") || arg.equals("--port") || arg.equals("--stop-port") || arg.equals("--host") ) {
                skipNext = true;
            } else {
                if(skipNext) {
                    skipNext = false;
                } else if( !arg.equals("--background=true") ) {
                    argarray.add(arg);
                }
            }
        }
        argarray.add("--host");
        argarray.add(String.valueOf(host()));
        argarray.add("--background");
        argarray.add(Boolean.toString(background()));
        argarray.add("--port");
        argarray.add(Integer.toString(httpPort()));
        argarray.add("--stop-port");
        argarray.add(Integer.toString(stopPort()));
        return argarray.toArray(new String[argarray.size()]);
        */
    }

    /**
     * @see runwar.options.ServerOptions#serverName()
     */
    public String serverName() {
        if(serverName == null){
            serverName = Paths.get(".").toFile().getAbsoluteFile().getParentFile().getName();
            assert serverName.length() > 3;
        }
        return serverName;
    }

    /**
     * @see runwar.options.ServerOptions#serverName(java.lang.String)
     */
    public ServerOptions serverName(String serverName) {
        this.serverName = serverName;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logLevel()
     */
    public String logLevel() {
        return logLevel;
    }

    /**
     * @see runwar.options.ServerOptions#logLevel(java.lang.String)
     */
    public ServerOptions logLevel(String level) {
        this.logLevel = level.toUpperCase();
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#contextPath()
     */
    public String contextPath() {
        return contextPath;
    }

    /**
     * @see runwar.options.ServerOptions#configFile()
     */
    public File configFile() {
        return configFile;
    }

    /**
     * @see runwar.options.ServerOptions#configFile(java.io.File)
     */
    public ServerOptions configFile(File file) {
        this.configFile = file;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#contextPath(java.lang.String)
     */
    public ServerOptions contextPath(String contextPath) {
        this.contextPath = contextPath;
        return this;
    }

    public String[] servletWelcomeFiles() {
        return servletWelcomeFiles;
    }

    public ServerOptions servletWelcomeFiles(String[] servletWelcomeFiles) {
        this.servletWelcomeFiles = servletWelcomeFiles;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteApacheFormat()
     */
    public boolean urlRewriteApacheFormat() {
        return urlRewriteFile() == null ? false : urlRewriteFile().getPath().endsWith(".htaccess") || urlRewriteFile().getPath().endsWith(".conf");
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteEnable()
     */
    public boolean urlRewriteEnable() {
        return enableURLRewrite;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteEnable(boolean)
     */
    public ServerOptions urlRewriteEnable(boolean bool) {
        this.enableURLRewrite = bool;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteFile(java.io.File)
     */
    public ServerOptions urlRewriteFile(File file) {
        this.urlRewriteFile = file;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteFile()
     */
    public File urlRewriteFile() {
        return this.urlRewriteFile;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteLog(java.io.File)
     */
    public ServerOptions urlRewriteLog(File file) {
        this.urlRewriteLog = file;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteLog()
     */
    public File urlRewriteLog() {
        return this.urlRewriteLog;
    }

    /**
     * @see
     * runwar.options.ServerOptions#urlRewriteCheckInterval(java.lang.String)
     */
    public ServerOptions urlRewriteCheckInterval(String interval) {
        this.urlRewriteCheckInterval = interval;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteCheckInterval()
     */
    public String urlRewriteCheckInterval() {
        return this.urlRewriteCheckInterval;
    }

    /**
     * @see
     * runwar.options.ServerOptions#urlRewriteStatusPath(java.lang.String)
     */
    public ServerOptions urlRewriteStatusPath(String path) {
        if (!path.startsWith("/")) {
            path = '/' + path;
        }
        this.urlRewriteStatusPath = path;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#urlRewriteStatusPath()
     */
    public String urlRewriteStatusPath() {
        return this.urlRewriteStatusPath;
    }

    /**
     * @see runwar.options.ServerOptions#stopPort()
     */
    public int stopPort() {
        return socketNumber;
    }

    /**
     * @see runwar.options.ServerOptions#stopPort(int)
     */
    public ServerOptions stopPort(int socketNumber) {
        this.socketNumber = socketNumber;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logPattern(java.lang.String)
     */
    public ServerOptions logPattern(String pattern) {
        if (pattern != null && pattern.length() > 0)
            logPattern = pattern;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logPattern()
     */
    public String logPattern() {
        return logPattern;
    }

    /**
     * @see runwar.options.ServerOptions#hasLogDir()
     */
    public boolean hasLogDir() {
        return logDir != null;
    }

    /**
     * @see runwar.options.ServerOptions#logDir()
     */
    public File logDir() {
        if (logDir == null) {
            String defaultLogDir = new File(Server.getThisJarLocation().getParentFile(), "./.logs/")
                    .getAbsolutePath();
            logDir = new File(defaultLogDir);
            if (warFile() != null) {
                File warFile = warFile();
                if (warFile.isDirectory() && new File(warFile, "WEB-INF").exists()) {
                    defaultLogDir = warFile.getPath() + "/WEB-INF/logs/";
                } else if (cfEngineName().length() != 0) {
                    String serverConfigDir = cfmlServletConfigServerDir();
                    if (serverConfigDir != null) {
                        defaultLogDir = new File(serverConfigDir, "log/").getAbsolutePath();
                    }
                }
                logDir = new File(defaultLogDir);
            }
        }
        assert logDir != null;
        return logDir;
    }

    /**
     * @see runwar.options.ServerOptions#logDir(java.lang.String)
     */
    public ServerOptions logDir(String logDir) {
        if (logDir != null && logDir.length() > 0)
            this.logDir = new File(logDir);
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logDir(java.io.File)
     */
    public ServerOptions logDir(File logDir) {
        this.logDir = logDir;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logFileName(java.lang.String)
     */
    public ServerOptions logFileName(String name) {
        this.logFileBaseName = name;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logFileName()
     */
    public String logFileName() {
        this.logFileBaseName = (this.logFileBaseName == null) ? "server." : this.logFileBaseName;
        return this.logFileBaseName;
    }

    /**
     * @see runwar.options.ServerOptions#logFileName(java.lang.String)
     */
    public ServerOptions logSuffix(String suffix) {
        this.logSuffix = suffix;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#logFileName()
     */
    public String logSuffix() {
        return this.logSuffix;
    }

    /**
     * @see runwar.options.ServerOptions#openbrowser()
     */
    public boolean openbrowser() {
        return openbrowser;
    }

    /**
     * @see runwar.options.ServerOptions#openbrowser(boolean)
     */
    public ServerOptions openbrowser(boolean openbrowser) {
        this.openbrowser = openbrowser;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#openbrowserURL()
     */
    public String openbrowserURL() {
        return openbrowserURL;
    }

    /**
     * @see runwar.options.ServerOptions#openbrowserURL(java.lang.String)
     */
    public ServerOptions openbrowserURL(String openbrowserURL) {
        this.openbrowserURL = openbrowserURL;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#pidFile()
     */
    public String pidFile() {
        return pidFile;
    }

    /**
     * @see runwar.options.ServerOptions#pidFile(java.lang.String)
     */
    public ServerOptions pidFile(String pidFile) {
        this.pidFile = pidFile;
        return this;
    }


    /**
     * @see runwar.options.ServerOptions#launchTimeout()
     */
    public int launchTimeout() {
        return launchTimeout;
    }

    /**
     * @see runwar.options.ServerOptions#launchTimeout(int)
     */
    public ServerOptions launchTimeout(int launchTimeout) {
        this.launchTimeout = launchTimeout;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#processName()
     */
    public String processName() {
        return processName;
    }

    /**
     * @see runwar.options.ServerOptions#processName(java.lang.String)
     */
    public ServerOptions processName(String processName) {
        this.processName = processName;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#libDirs()
     */
    public String libDirs() {
        return libDirs;
    }

    /**
     * @see runwar.options.ServerOptions#libDirs(java.lang.String)
     */
    public ServerOptions libDirs(String libDirs) {
        this.libDirs = libDirs;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#debug()
     */
    public boolean debug() {
        return debug;
    }

    /**
     * @see runwar.options.ServerOptions#debug(boolean)
     */
    public ServerOptions debug(boolean debug) {
        this.debug = debug;
        if (debug && logLevel == "WARN") {
            logLevel = "DEBUG";
        }
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#workingDir()
     */
    public File workingDir() {
        return workingDir != null ? workingDir: Paths.get(".").toFile().getAbsoluteFile();
    }

    /**
     * @see runwar.options.ServerOptions#workingDir(java.io.File)
     */
    public ServerOptions workingDir(File workingDir) {
        this.workingDir = workingDir;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#warFile()
     */
    public File warFile() {
        return warFile;
    }

    /**
     * @see runwar.options.ServerOptions#warFile(java.io.File)
     */
    public ServerOptions warFile(File warFile) {
        this.warFile = warFile;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#webInfDir()
     */
    public File webInfDir() {
        if(webInfDir == null) {
            if (webXmlFile != null && (webXmlFile.getParentFile().getName().equalsIgnoreCase("WEB-INF") || new File(webXmlFile.getParentFile(), "lib").exists())) {
                webInfDir = webXmlFile.getParentFile();
            } else if(warFile() != null && warFile.exists() && warFile.isDirectory()) {
                webInfDir = new File(warFile, "WEB-INF");
            }
        }
        return webInfDir;
    }

    /**
     * @see runwar.options.ServerOptions#webInfDir(java.io.File)
     */
    public ServerOptions webInfDir(File webInfDir) {
        this.webInfDir = webInfDir;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlFile()
     */
    public File webXmlFile() {
        if(webXmlFile == null && webInfDir() != null) {
            webXmlFile(new File(webInfDir(),"web.xml"));
        }
        return webXmlFile;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlPath()
     */
    public String webXmlPath() throws MalformedURLException {
        return webXmlFile.toURI().toURL().toString();
    }

    /**
     * @see runwar.options.ServerOptions#webXmlOverrideFile()
     */
    public File webXmlOverrideFile(){
        return webXmlOverrideFile;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlOverrideFile(java.io.File)
     */
    public ServerOptions webXmlOverrideFile(File webXmlOverrideFile) {
        this.webXmlOverrideFile = webXmlOverrideFile;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlOverrideForce()
     */
    public boolean webXmlOverrideForce() {
        return webXmlOverrideForce;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlOverrideForce(boolean)
     */
    public ServerOptions webXmlOverrideForce(boolean enable) {
        this.webXmlOverrideForce = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#webXmlFile(java.io.File)
     */
    public ServerOptions webXmlFile(File webXmlFile) {
        this.webXmlFile = webXmlFile;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#iconImage()
     */
    public String iconImage() {
        return iconImage;
    }

    /**
     * @see runwar.options.ServerOptions#iconImage(java.lang.String)
     */
    public ServerOptions iconImage(String iconImage) {
        this.iconImage = iconImage;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#trayConfig()
     */
    public File trayConfig() {
        return trayConfig;
    }

    /**
     * @see runwar.options.ServerOptions#trayConfig(java.io.File)
     */
    public ServerOptions trayConfig(File trayConfig) {
        this.trayConfig = trayConfig;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#trayConfigJSON()
     */
    public JSONArray trayConfigJSON() {
        return trayConfigJSON;
    }

    /**
     * @see
     * runwar.options.ServerOptions#trayConfig(net.minidev.json.JSONArray)
     */
    public ServerOptions trayConfig(JSONArray trayConfig) {
        this.trayConfigJSON = trayConfig;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#trayEnable()
     */
    public boolean trayEnable() {
        return trayEnable;
    }

    /**
     * @see runwar.options.ServerOptions#trayEnable(boolean)
     */
    public ServerOptions trayEnable(boolean enable) {
        this.trayEnable = enable;
        return this;
    }

    public String defaultShell() {
        return defaultShell;
    }

    public String browser() {
        return browser;
    }

    public ServerOptions browser(String browser){
        this.browser = browser;
        return this;
    }

    public ServerOptions defaultShell(String defaultShell) {
        this.defaultShell = defaultShell;
        return this;
    }

     /**
     * @see runwar.options.ServerOptions#dockEnable()
     */
    public boolean dockEnable() {
        return dockEnable;
    }

    /**
     * @see runwar.options.ServerOptions#dockEnable(boolean)
     */
    public ServerOptions dockEnable(boolean enable) {
        this.dockEnable = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#cfmlServletConfigWebDir()
     */
    public String cfmlServletConfigWebDir() {
        return cfmlServletConfigWebDir;
    }

    /**
     * @see
     * runwar.options.ServerOptions#cfmlServletConfigWebDir(java.lang.String)
     */
    public ServerOptions cfmlServletConfigWebDir(String cfmlServletConfigWebDir) {
        this.cfmlServletConfigWebDir = cfmlServletConfigWebDir;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#cfmlServletConfigServerDir()
     */
    public String cfmlServletConfigServerDir() {
        if (cfmlServletConfigServerDir == null)
            cfmlServletConfigServerDir = System.getProperty("cfml.server.config.dir");
        return cfmlServletConfigServerDir;
    }

    /**
     * @see
     * runwar.options.ServerOptions#cfmlServletConfigServerDir(java.lang.String)
     */
    public ServerOptions cfmlServletConfigServerDir(String cfmlServletConfigServerDir) {
        this.cfmlServletConfigServerDir = cfmlServletConfigServerDir;
        return this;
    }


    /**
     * @see runwar.options.ServerOptions#warUriString()
     */
    public String warUriString() {
        if(warFile() == null)
            return "";
        try {
            return warFile().toURI().toURL().toString();
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * @see runwar.options.ServerOptions#stopPassword(char[])
     */
    public ServerOptions stopPassword(char[] password) {
        this.stopPassword = password;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#stopPassword()
     */
    public char[] stopPassword() {
        return this.stopPassword;
    }

    /**
     * @see runwar.options.ServerOptions#cfEngineName(java.lang.String)
     */
    public ServerOptions cfEngineName(String cfengineName) {
        if (cfengineName.toLowerCase().equals("lucee") || cfengineName.toLowerCase().equals("adobe")
                || cfengineName.toLowerCase().equals("railo") || cfengineName.toLowerCase().equals("")) {
            this.cfengineName = cfengineName.toLowerCase();
        } else {
            throw new RuntimeException(
                    "Unknown engine type: " + cfengineName + ", must be one of: lucee, adobe, railo");
        }
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#cfEngineName()
     */
    public String cfEngineName() {
        if(cfengineName.isEmpty() && webInfDir() != null && webInfDir().exists() && new File(webInfDir(),"cfusion").exists()) {
            cfengineName = "adobe";
        } else if(cfengineName.isEmpty() && webInfDir() != null && webInfDir().exists() && new File(webInfDir(),"lucee").exists()) {
            cfengineName = "lucee";
        }
        return cfengineName;
    }

    /**
     * @see runwar.options.ServerOptions#customHTTPStatusEnable(boolean)
     */
    public ServerOptions customHTTPStatusEnable(boolean enable) {
        this.customHTTPStatusEnable = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#customHTTPStatusEnable()
     */
    public boolean customHTTPStatusEnable() {
        return this.customHTTPStatusEnable;
    }

    /**
     * @see runwar.options.ServerOptions#sendfileEnable(boolean)
     */
    public ServerOptions sendfileEnable(boolean enable) {
        //if (!enable) {
//            this.transferMinSize = Long.MAX_VALUE;
        //}
        return this;
    }
    /**
     * @see runwar.options.ServerOptions#jvmArgs(java.util.List)
     */
    public ServerOptions jvmArgs(List<String> args) {
        this.jvmArgs = args;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#jvmArgs()
     */
    public List<String> jvmArgs() {
        return this.jvmArgs;
    }

    /**
     * @see runwar.options.ServerOptions#servletRestEnable(boolean)
     */
    public ServerOptions servletRestEnable(boolean enable) {
        this.servletRestEnable = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#servletRestEnable()
     */
    public boolean servletRestEnable() {
        return this.servletRestEnable;
    }

    /**
     * @see
     * runwar.options.ServerOptions#servletRestMappings(java.lang.String)
     */
    public ServerOptions servletRestMappings(String mappings) {
        return servletRestMappings(mappings.split(","));
    }

    /**
     * @see
     * runwar.options.ServerOptions#servletRestMappings(java.lang.String[])
     */
    public ServerOptions servletRestMappings(String[] mappings) {
        this.servletRestMappings = mappings;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#servletRestMappings()
     */
    public String[] servletRestMappings() {
        return this.servletRestMappings;
    }

    /**
     * @see runwar.options.ServerOptions#filterPathInfoEnable(boolean)
     */
    public ServerOptions filterPathInfoEnable(boolean enable) {
        this.filterPathInfoEnable = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#filterPathInfoEnable()
     */
    public boolean filterPathInfoEnable() {
        return this.filterPathInfoEnable;
    }

    /**
     * @see runwar.options.ServerOptions#ioThreads()
     */
    public int ioThreads() {
        return ioThreads;
    }

    /**
     * @see runwar.options.ServerOptions#ioThreads(int)
     */
    public ServerOptions ioThreads(int ioThreads) {
        this.ioThreads = ioThreads;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#workerThreads()
     */
    public int workerThreads() {
        return workerThreads;
    }

    /**
     * @see runwar.options.ServerOptions#workerThreads(int)
     */
    public ServerOptions workerThreads(int workerThreads) {
        this.workerThreads = workerThreads;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#directBuffers(boolean)
     */
    public ServerOptions directBuffers(boolean enable) {
        this.directBuffers = enable;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#directBuffers()
     */
    public boolean directBuffers() {
        return this.directBuffers;
    }

    /**
     * @see runwar.options.ServerOptions#secureCookies(boolean)
     */
    public ServerOptions secureCookies(boolean enable) {
        this.secureCookies = enable;
        this.cookieHttpOnly = enable;
        this.cookieSecure = enable;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#secureCookies()
     */
    public boolean secureCookies() {
        return this.secureCookies;
    }

    /**
     * @see runwar.options.ServerOptions#cookieHttpOnly(boolean)
     */
    public ServerOptions cookieHttpOnly(boolean enable) {
        this.cookieHttpOnly= enable;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#cookieHttpOnly()
     */
    public boolean cookieHttpOnly() {
        return this.cookieHttpOnly;
    }

    /**
     * @see runwar.options.ServerOptions#cookieSecure(boolean)
     */
    public ServerOptions cookieSecure(boolean enable) {
        this.cookieSecure = enable;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#cookieSecure()
     */
    public boolean cookieSecure() {
        return this.cookieSecure;
    }

    /*
     * @see runwar.options.ServerOptions#SSLECCDISABLE(boolean)
     */
    public ServerOptions sslEccDisable(boolean enable) {
        this.sslEccDisable = enable;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#SSLECCDISABLE()
     */
    public boolean sslEccDisable() {
        return this.sslEccDisable;
    }

    /*
     * @see runwar.options.ServerOptions#ignoreWebXmlWelcomePages()
     */
    public boolean ignoreWebXmlWelcomePages() {
        return getSites().get(0).welcomeFiles() != null && getSites().get(0).welcomeFiles().length > 0;
    }

    /*
     * @see runwar.options.ServerOptions#ignoreWebXmlWelcomePages()
     */
    public boolean ignoreWebXmlRestMappings() {
        return servletRestMappings() != null && servletRestMappings().length > 0;
    }



    /*
     * @see runwar.options.ServerOptions#autoCreateContexts()
     */
    public Boolean autoCreateContexts() {
        return autoCreateContexts;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContexts(boolean)
     */
    public ServerOptions autoCreateContexts(Boolean autoCreateContexts) {
    	this.autoCreateContexts = autoCreateContexts;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContextsSecret()
     */
    public String autoCreateContextsSecret() {
        return autoCreateContextsSecret;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContextsSecret(String)
     */
    public ServerOptions autoCreateContextsSecret(String autoCreateContextsSecret) {
    	this.autoCreateContextsSecret = autoCreateContextsSecret;
        return this;
    }


    /*
     * @see runwar.options.ServerOptions#autoCreateContextsVDirs()
     */
    public Boolean autoCreateContextsVDirs() {
        return autoCreateContextsVDirs;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContextsVDirs(boolean)
     */
    public ServerOptions autoCreateContextsVDirs(Boolean autoCreateContextsVDirs) {
    	this.autoCreateContextsVDirs = autoCreateContextsVDirs;
        return this;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContextsMax()
     */
    public Integer autoCreateContextsMax() {
        return autoCreateContextsMax;
    }

    /*
     * @see runwar.options.ServerOptions#autoCreateContextsMax(Integer)
     */
    public ServerOptions autoCreateContextsMax(Integer autoCreateContextsMax) {
    	this.autoCreateContextsMax = autoCreateContextsMax;
        return this;
    }


    /**
     * @see runwar.options.ServerOptions#xnioOptions(java.lang.String)
     */
    public ServerOptions xnioOptions(String options) {
        String[] optionList = options.split(";");
        for (int x = 0; x < optionList.length; x++) {
            String[] splitted = optionList[x].split("=");
            if( splitted.length != 2 ) {
            	throw new IllegalArgumentException("XNIO Option is malformed. Expected [" + optionList[x] + "] to be in the form of [OPTION_NAME=value].");
            }
            setOptionMapValue(serverXnioOptions, Options.class, splitted[0].trim(), splitted[1].trim());
        }
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#xnioOptions(OptionMap.Builder)
     */
    public ServerOptions xnioOptions(OptionMap.Builder options) {
        this.serverXnioOptions = options;
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#xnioOptions()
     */
    public OptionMap.Builder xnioOptions() {
        return this.serverXnioOptions;
    }


    /**
     * @see runwar.options.ServerOptions#xnioOptions(java.lang.String)
     */
    public ServerOptions undertowOptions(String options) {
        String[] optionList = options.split(",");
        for (int x = 0; x < optionList.length; x++) {
            String[] splitted = optionList[x].split("=");
            String optionName = splitted[0].trim().toUpperCase();
            String optionValue = splitted[1].trim();
            setOptionMapValue(undertowOptions, UndertowOptions.class, optionName, optionValue);
        }
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#undertowOptions(OptionMap.Builder)
     */
    public ServerOptions undertowOptions(OptionMap.Builder options) {
        this.undertowOptions = options;
        return this;
    }

    public String consoleLayout() {
        return this.consoleLayout;
    }

    public ServerOptions consoleLayout(String consoleLayout) {
        this.consoleLayout = consoleLayout;
        return this;
    }

    public Map<String, Object> consoleLayoutOptions() {
        if( consoleLayout().equals( "PatternLayout" ) && !this.consoleLayoutOptions.containsKey( "pattern" ) ) {
            this.consoleLayoutOptions.put( "pattern", getLogPattern() );
        }
        return this.consoleLayoutOptions;
    }

    public ServerOptions consoleLayoutOptions(String consoleLayoutOptions) {
    	try {
          this.consoleLayoutOptions = (JSONObject)(new JSONParser().parse( consoleLayoutOptions ));
    	} catch( Exception e ) {
    		throw new RuntimeException( e );
    	}
        return this;
    }

    /**
     * @see runwar.options.ServerOptions#xnioOptions()
     */
    public OptionMap.Builder undertowOptions() {
        return this.undertowOptions;
    }

    ///////////////////// DEPRECATE /////////////////////

    // backwards compat workaround to get stuff running
    public String host() {
        System.out.println( "serverOptions.host() FIX ME!" );
        return getSites().get(0).host();
    }


    public boolean testing() {
        return testing;
    }

    public boolean service() {
        return service;
    }

    public ServerOptions service(boolean enable) {
        service = enable;
        return this;
    }

    public ServerOptions sslSelfSign(boolean enable) {
        this.sslSelfSign = enable;
        return this;
    }

    public boolean sslSelfSign() { return this.sslSelfSign; }

    public String serverMode() {
        if(webInfDir() != null && webInfDir().exists()) {
            return Mode.WAR;
        } else if( new File(warFile(), "WEB-INF").exists()) {
            return Mode.WAR;
        }
        return Mode.DEFAULT;
    }

    public ServerOptions startedFromCommandLine(boolean enable) {
        this.startedFromCommandline = enable;
        return this;
    }

    public boolean startedFromCommandLine() {
        return this.startedFromCommandline;
    }

    public ServerOptions loadBalance(String hosts) {
        return loadBalance(hosts.split("(?<!\\\\),"));
    }

    public ServerOptions loadBalance(String[] hosts) {
        this.loadBalance = hosts;
        return this;
    }

    public String[] loadBalance() {
        return this.loadBalance;
    }

    public int bufferSize() {
        return bufferSize;
    }

    public ServerOptions bufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
        return this;
    }

    public ServerOptions mariaDB4jEnable(boolean enable) {
        this.mariadb4jEnable = enable;
        return this;
    }

    public boolean mariaDB4jEnable() {
        return this.mariadb4jEnable;
    }

    public ServerOptions mariaDB4jPort(int port) {
        this.mariadb4jPort = port;
        return this;
    }

    public int mariaDB4jPort() {
        return this.mariadb4jPort;
    }

    public ServerOptions mariaDB4jBaseDir(File dir) {
        this.mariadb4jBaseDir = dir;
        return this;
    }

    public File mariaDB4jBaseDir() {
        return this.mariadb4jBaseDir;
    }

    public ServerOptions mariaDB4jDataDir(File dir) {
        this.mariadb4jDataDir = dir;
        return this;
    }

    public File mariaDB4jDataDir() {
        return this.mariadb4jDataDir;
    }

    public ServerOptions mariaDB4jImportSQLFile(File file) {
        this.mariadb4jImportSQLFile = file;
        return this;
    }

    public File mariaDB4jImportSQLFile() {
        return this.mariadb4jImportSQLFile;
    }

    public ServerOptions action(String action) {
        this.action = action;
        return this;
    }

    public String action() {
        return this.action;
    }

    public File statusFile() {
        return statusFile;
    }

    public ServerOptions statusFile(File statusFile) {
        this.statusFile = statusFile;
        return this;
    }

    public ServerOptions testing(boolean testing) {
        this.testing = testing;
        if (testing && logLevel == "WARN") {
            logLevel = "DEBUG";
        }
        return this;
    }

    public URL jarURL() {
        return jarURL;
    }

    public ServerOptions jarURL(URL jarURL) {
        this.jarURL = jarURL;
        return this;
    }

    public boolean background() {
        return isBackground;
    }

    public ServerOptions background(boolean isBackground) {
        this.isBackground = isBackground;
        return this;
    }

    public boolean logRequestsEnable() {
        return logRequestsEnable;
    }

    public ServerOptions logRequestsEnable(boolean enable) {
        this.logRequestsEnable = enable;
        return this;
    }

    public ServerOptions logRequestsDir(File logDir) {
        this.logRequestsDir = logDir;
        return this;
    }

    public ServerOptions logRequestsDir(String logDir) {
        this.logRequestsDir = new File(logDir);
        return this;
    }

    public File logRequestsDir() {
        if(this.logRequestsDir == null)
            return logDir();
        return this.logRequestsDir;
    }

    public ServerOptions logRequestsBaseFileName(String name) {
        this.logRequestBaseFileName= name;
        return this;
    }

    public String logRequestsBaseFileName() {
        return this.logRequestBaseFileName;
    }


}