package runwar.options;

import io.undertow.UndertowOptions;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.xnio.OptionMap;
import org.xnio.Options;
import runwar.Server;
import runwar.Server.Mode;
import runwar.options.ServerOptions;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

import static runwar.util.Reflection.setOptionMapValue;

public class SiteOptions {

    private ServerOptions serverOptions;

    private String host = "127.0.0.1", logAccessBaseFileName="access", cfmlDirs, siteName="default";

    private Set<String> contentDirectories = new HashSet<>();

    private int portNumber = 8088, ajpPort = 8009, sslPort = 1443;

    private boolean enableAJP = false, enableSSL = false, enableHTTP = true;

    private boolean directoryListingEnable = true, logAccessEnable = false;

    private boolean directoryListingRefreshEnable = false;

    private String[] welcomeFiles;

    private boolean cacheEnable = false;

    private File sslCertificate, sslKey, logAccessDir, webroot;

    private String clientCertNegotiation;

    private char[] sslKeyPass = null;

    private String predicateText, securityRealm = "";

    private Boolean clientCertEnable = false;

    private String defaultServletAllowedExt = "";

    private Boolean clientCertTrustHeaders = false;

    private JSONArray clientCertSubjectDNs = new JSONArray();

    private JSONArray clientCertIssuerDNs = new JSONArray();

    private boolean gzipEnable = false;

    private String gzipPredicate = "request-larger-than(1500)";

    private Long transferMinSize = (long) 1024 * 1024 * 10; // 10 MB

    private Map<Integer, String> errorPages = null;

    private String[] sslAddCerts = null;

    private String[] sslAddCACerts = null;

    private String sslTruststore = null;

    private String sslTruststorePass = "";

    private Boolean clientCertRenegotiation = false;

    private static Map<String, String> userPasswordList;

    private boolean enableBasicAuth = false;

    private String authPredicate = null;

    private boolean proxyPeerAddressEnable = false;

    private boolean http2enable = false;

    private Boolean caseSensitiveWebServer= null;

    private Boolean resourceManagerLogging= false;

    private Boolean resourceManagerFileSystemWatcher= false;

    private Boolean cacheServletPaths= false;

    private Integer fileCacheTotalSizeMB = 50; // 50MB cache (up to 10 buffers)

    private Integer fileCacheMaxFileSizeKB = 50; // cache files up to 50KB in size;

    private final Map<String, String> aliases = new HashMap<String, String>();

    private final Map<String, String> mimeTypes = new HashMap<String, String>();


    public ServerOptions  erverOptions() {
        return serverOptions;
    }

    public SiteOptions setServerOptions(ServerOptions serverOptions) {
        this.serverOptions = serverOptions;
        return this;
    }

    public String siteName() {
        return siteName;
    }

    public SiteOptions siteName(String siteName) {
        this.siteName = siteName;
        return this;
    }

    public File webroot() {
        return webroot;
    }

    public SiteOptions webroot(File webroot) {
        this.webroot = webroot;
        return this;
    }

    public String host() {
        return host;
    }

    public SiteOptions host(String host) {
        this.host = host;
        return this;
    }

    public int httpPort() {
        return portNumber;
    }

    public SiteOptions httpPort(int portNumber) {
        this.portNumber = portNumber;
        return this;
    }

    public int ajpPort() {
        return ajpPort;
    }

    public SiteOptions ajpPort(int ajpPort) {
        this.ajpPort = ajpPort;
        return this;
    }

    public int sslPort() {
        return sslPort;
    }

    public SiteOptions sslPort(int sslPort) {
        this.sslPort = sslPort;
        return this;
    }

    public boolean sslEnable() {
        return enableSSL;
    }

    public SiteOptions sslEnable(boolean enableSSL) {
        this.enableSSL = enableSSL;
        return this;
    }

    public boolean httpEnable() {
        return enableHTTP;
    }

    public SiteOptions httpEnable(boolean bool) {
        this.enableHTTP = bool;
        return this;
    }

    public String contentDirs() {
        if (cfmlDirs == null && serverOptions.warFile() != null) {
            contentDirs(serverOptions.warFile().getAbsolutePath());
        }
        return cfmlDirs;
    }

    public Set<String> contentDirectories() {
        if(contentDirs() != null){
            Stream.of(contentDirs().split(",")).forEach(aDirList -> {
                String dir;
                String[] directoryAndAliasList = aDirList.trim().split("=");
                if (directoryAndAliasList.length == 1) {
                    dir = directoryAndAliasList[0].trim();
                    if(dir.length() > 0)
                        contentDirectories.add(dir);
                }
            });
        }
        return contentDirectories;
    }

    public SiteOptions contentDirectories(List<String> dirs) {
        contentDirectories.addAll(dirs);  // a set so we can always safely add
        return this;
    }

    public SiteOptions contentDirectories(Set<String> dirs) {
        contentDirectories = dirs;
        return this;
    }

    public SiteOptions contentDirs(String dirs) {
        this.cfmlDirs = dirs;
        return this;
    }

    public Map<String,String> aliases() {
        if(contentDirs() == null && aliases.size() == 0){
            return new HashMap<>();
        }
        Stream.of(contentDirs().split(",")).forEach(aDirList -> {
            Path path;
            String dir = "";
            String virtual = "";
            String[] directoryAndAliasList = aDirList.trim().split("=");
            if (directoryAndAliasList.length == 1) {
                dir = directoryAndAliasList[0].trim();
              //  if(dir.length() > 0)
                //    contentDirectories.add(dir); // a set so we can always safely add
            } else {
                dir = directoryAndAliasList[1].trim();
                virtual = directoryAndAliasList[0].trim();
            }
            dir = dir.endsWith("/") ? dir : dir + '/';
            path = Paths.get(dir).normalize().toAbsolutePath();
            if(virtual.length() != 0){
                virtual = virtual.startsWith("/") ? virtual : "/" + virtual;
                virtual = virtual.endsWith("/") ? virtual.substring(0, virtual.length() - 1) : virtual;
                aliases.put(virtual.toLowerCase(), path.toString());
            }
        });
        return aliases;
    }

    public SiteOptions aliases(Map<String,String> aliases) {
        this.aliases.putAll(aliases);
        return this;
    }

    public SiteOptions mimeTypes(String mimeTypes) {
        Stream.of(mimeTypes.split(",")).forEach(mimeType -> {
            String[] mimePair = mimeType.trim().split(";");
            if (mimePair.length == 2) {
                this.mimeTypes.put( mimePair[0], mimePair[1] );
            }
        });
        return this;
    }

    public SiteOptions mimeTypes(Map<String,String> mimeTypes) {
        this.mimeTypes.putAll(aliases);
        return this;
    }

    public Map<String,String> mimeTypes() {
        return this.mimeTypes;
    }

    public boolean logAccessEnable() {
        return logAccessEnable;
    }

    public SiteOptions logAccessEnable(boolean enable) {
        this.logAccessEnable = enable;
        return this;
    }

    public SiteOptions logAccessDir(File logDir) {
        this.logAccessDir = logDir;
        return this;
    }

    public SiteOptions logAccessDir(String logDir) {
        this.logAccessDir = new File(logDir);
        return this;
    }

    public File logAccessDir() {
        if(this.logAccessDir == null)
            return serverOptions.logDir();
        return this.logAccessDir;
    }

    public SiteOptions logAccessBaseFileName(String name) {
        this.logAccessBaseFileName = name;
        return this;
    }

    public String logAccessBaseFileName() {
        return this.logAccessBaseFileName;
    }

    public boolean ajpEnable() {
        return enableAJP;
    }

    public SiteOptions ajpEnable(boolean enableAJP) {
        this.enableAJP = enableAJP;
        return this;
    }

    public String predicateText() {
        return predicateText;
    }

    public SiteOptions predicateText(String predicateText) {
        this.predicateText = predicateText;
        return this;
    }

    public boolean cacheEnable() {
        return cacheEnable;
    }

    public SiteOptions cacheEnable(boolean cacheEnable) {
        this.cacheEnable = cacheEnable;
        return this;
    }

    public boolean directoryListingEnable() {
        return directoryListingEnable;
    }

    public SiteOptions directoryListingEnable(boolean directoryListingEnable) {
        this.directoryListingEnable = directoryListingEnable;
        return this;
    }

    public boolean directoryListingRefreshEnable() {
        return directoryListingRefreshEnable;
    }

    public SiteOptions directoryListingRefreshEnable(boolean directoryListingRefreshEnable) {
        this.directoryListingRefreshEnable = directoryListingRefreshEnable;
        return this;
    }

    public String[] welcomeFiles() {
        // Default to the server-wide welcome files found in the web.xml
        if( welcomeFiles == null || welcomeFiles.length == 0 ) {
            return serverOptions.servletWelcomeFiles();
        }
        return welcomeFiles;
    }

    public SiteOptions welcomeFiles(String[] welcomeFiles) {
        this.welcomeFiles = welcomeFiles;
        return this;
    }

    public SiteOptions sslCertificate(File file) {
        this.sslCertificate = file;
        return this;
    }

    public File sslCertificate() {
        if(sslCertificate != null && !sslCertificate.exists() ){
            throw new IllegalArgumentException("Certificate file does not exist: " + sslCertificate.getAbsolutePath());
        }
        return this.sslCertificate;
    }

    public SiteOptions clientCertNegotiation(String clientCertNegotiation) {
        this.clientCertNegotiation = clientCertNegotiation.toUpperCase();
        return this;
    }

    public String clientCertNegotiation() {
        return this.clientCertNegotiation;
    }

    public SiteOptions securityRealm(String securityRealm){
        this.securityRealm = securityRealm;
        return this;
    }

    public String securityRealm(){
        return this.securityRealm;
    }

    public SiteOptions clientCertEnable(Boolean clientCertEnable){
        this.clientCertEnable = clientCertEnable;
        return this;
    }

    public Boolean clientCertEnable(){
        return this.clientCertEnable;
    }

    public SiteOptions clientCertTrustHeaders(Boolean clientCertTrustHeaders){
        this.clientCertTrustHeaders = clientCertTrustHeaders;
        return this;
    }

    public Boolean clientCertTrustHeaders(){
        return this.clientCertTrustHeaders;
    }

    public SiteOptions clientCertSubjectDNs(String clientCertSubjectDNs){
    	try {
    		System.out.println( "clientCertSubjectDNs: " + clientCertSubjectDNs );
    		this.clientCertSubjectDNs = (JSONArray)(new JSONParser().parse( clientCertSubjectDNs ));
		} catch( Exception e ) {
			throw new RuntimeException( e );
		}
        return this;
    }

    public JSONArray clientCertSubjectDNs(){
        return this.clientCertSubjectDNs;
    }

    public SiteOptions clientCertIssuerDNs(String clientCertIssuerDNs){
    	try {
    		this.clientCertIssuerDNs = (JSONArray)(new JSONParser().parse( clientCertIssuerDNs ));
    	} catch( Exception e ) {
    		throw new RuntimeException( e );
    	}
        return this;
    }

    public JSONArray clientCertIssuerDNs(){
        return this.clientCertIssuerDNs;
    }

    public SiteOptions sslKey(File file) {
        this.sslKey = file;
        return this;
    }

    public File sslKey() {
        return this.sslKey;
    }

    public SiteOptions sslKeyPass(char[] pass) {
        this.sslKeyPass = pass;
        return this;
    }

    public char[] sslKeyPass() {
        return this.sslKeyPass;
    }

    public SiteOptions transferMinSize(Long minSize) {
        this.transferMinSize = minSize;
        return this;
    }

    public Long transferMinSize() {
        return this.transferMinSize;
    }

    public SiteOptions gzipEnable(boolean enable) {
        this.gzipEnable = enable;
        return this;
    }

    public boolean gzipEnable() {
        return this.gzipEnable;
    }

    public SiteOptions gzipPredicate(String predicate) {
        this.gzipPredicate = predicate;
        return this;
    }

    public String gzipPredicate() {
        return this.gzipPredicate;
    }

    public SiteOptions errorPages(String errorpages) {
        this.errorPages = new HashMap<Integer, String>();
        String[] pageList = errorpages.split(",");
        for (int x = 0; x < pageList.length; x++) {
            String[] splitted = pageList[x].split("=");
            String location = "";
            int errorCode = 1;
            if (splitted.length == 1) {
                location = pageList[x].trim();
            } else {
                errorCode = Integer.parseInt(splitted[0].trim());
                location = splitted[1].trim();
            }
            // TODO: verify we don't need to do anything different if the WAR
            // context is something other than "/".
            location = location.startsWith("/") ? location : "/" + location;
            errorPages.put(errorCode, location);
        }
        return this;
    }

    public SiteOptions errorPages(Map<Integer, String> errorpages) {
        this.errorPages = errorpages;
        return this;
    }

    public Map<Integer, String> errorPages() {
        return this.errorPages;
    }

    public SiteOptions basicAuthEnable(boolean enable) {
        this.enableBasicAuth = enable;
        return this;
    }

    public boolean basicAuthEnable() {
        return this.enableBasicAuth;
    }

    public SiteOptions authPredicate(String predicate) {
        this.authPredicate = predicate;
        return this;
    }

    public String authPredicate() {
        return this.authPredicate;
    }

    public SiteOptions basicAuth(String userPasswordList) {
        HashMap<String, String> ups = new HashMap<String, String>();
        try {
            for (String up : userPasswordList.split("(?<!\\\\),")) {
                up = up.replace("\\,", ",");
                String u = up.split("(?<!\\\\)=")[0].replace("\\=", "=");
                String p = up.split("(?<!\\\\)=")[1].replace("\\=", "=");
                ups.put(u, p);
            }
        } catch (Exception e) {
            throw new RuntimeException("Incorrect 'users' format (user=pass,user2=pass2) : " + userPasswordList);
        }
        return basicAuth(ups);
    }

    public SiteOptions basicAuth(Map<String, String> userPassList) {
        userPasswordList = userPassList;
        return this;
    }

    public Map<String, String> basicAuth() {
        return userPasswordList;
    }

    public SiteOptions sslAddCerts(String sslCerts) {
        return sslAddCerts(sslCerts.split("(?<!\\\\),"));
    }

    public SiteOptions sslAddCerts(String[] sslCerts) {
        this.sslAddCerts = sslCerts;
        return this;
    }

    public String[] sslAddCerts() {
        return this.sslAddCerts;
    }

    public SiteOptions sslAddCACerts(String sslCerts) {
        return sslAddCACerts(sslCerts.split("(?<!\\\\),"));
    }

    public SiteOptions sslAddCACerts(String[] sslCerts) {
        this.sslAddCACerts = sslCerts;
        return this;
    }

    public String[] sslAddCACerts() {
        return this.sslAddCACerts;
    }

    public SiteOptions sslTruststore(String sslTruststore) {
        this.sslTruststore = sslTruststore;
        return this;
    }

    public String sslTruststore() {
        return this.sslTruststore;
    }

    public SiteOptions sslTruststorePass(String sslTruststorePass) {
        this.sslTruststorePass = sslTruststorePass;
        return this;
    }

    public Boolean clientCertRenegotiation() {
        return this.clientCertRenegotiation;
    }

    public SiteOptions clientCertRenegotiation(Boolean clientCertRenegotiation) {
        this.clientCertRenegotiation = clientCertRenegotiation;
        return this;
    }

    public String sslTruststorePass() {
        return this.sslTruststorePass;
    }

    public SiteOptions proxyPeerAddressEnable(boolean enable) {
        this.proxyPeerAddressEnable = enable;
        return this;
    }

    public boolean proxyPeerAddressEnable() {
        return this.proxyPeerAddressEnable;
    }

    public SiteOptions http2Enable(boolean enable) {
        this.http2enable = enable;
        return this;
    }

    public boolean http2Enable() {
        return this.http2enable;
    }

    public String defaultServletAllowedExt() {
        return defaultServletAllowedExt;
    }

    public SiteOptions defaultServletAllowedExt(String defaultServletAllowedExt) {
    	this.defaultServletAllowedExt = defaultServletAllowedExt;
        return this;
    }

    public Boolean resourceManagerLogging() {
        return resourceManagerLogging;
    }

    public SiteOptions resourceManagerLogging(Boolean resourceManagerLogging) {
    	this.resourceManagerLogging = resourceManagerLogging;
        return this;
    }

    public Boolean resourceManagerFileSystemWatcher() {
        return resourceManagerFileSystemWatcher;
    }

    public SiteOptions resourceManagerFileSystemWatcher(Boolean resourceManagerFileSystemWatcher) {
    	this.resourceManagerFileSystemWatcher = resourceManagerFileSystemWatcher;
        return this;
    }

    public Boolean cacheServletPaths() {
        return cacheServletPaths;
    }

    public SiteOptions cacheServletPaths(Boolean cacheServletPaths) {
    	this.cacheServletPaths = cacheServletPaths;
        return this;
    }

    public Integer fileCacheTotalSizeMB() {
        return fileCacheTotalSizeMB;
    }

    public SiteOptions fileCacheTotalSizeMB(Integer fileCacheTotalSizeMB) {
    	this.fileCacheTotalSizeMB = fileCacheTotalSizeMB;
        return this;
    }

    public Integer fileCacheMaxFileSizeKB() {
        return fileCacheMaxFileSizeKB;
    }

    public SiteOptions fileCacheMaxFileSizeKB(Integer fileCacheMaxFileSizeKB) {
    	this.fileCacheMaxFileSizeKB = fileCacheMaxFileSizeKB;
        return this;
    }

    public Boolean caseSensitiveWebServer() {
        return caseSensitiveWebServer;
    }

    public SiteOptions caseSensitiveWebServer(Boolean caseSensitiveWebServer) {
    	this.caseSensitiveWebServer = caseSensitiveWebServer;
        return this;
    }





}