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

    private int portNumber = 8088, ajpPort = 8009, sslPort = 1443;

    private boolean enableAJP = false, enableSSL = false, enableHTTP = true;

    private boolean directoryListingEnable = true, logAccessEnable = false;

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

    private String[] sslAddCACerts = null;

    private String sslTruststore = null;

    private String sslTruststorePass = "";

    private Boolean clientCertRenegotiation = false;

    private Map<String, String> userPasswordList;

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

    private String servletPassPredicate = "regex( '^/(.+?\\.cf[cm])(/.*)?$' )";


    public ServerOptions getServerOptions() {
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

    public Map<String,String> aliases() {
        return aliases;
    }

    public SiteOptions aliases(JSONObject aliases) {
        for( String virtual : aliases.keySet() ) {
            String path = aliases.get( virtual ).toString();
            path = Paths.get( path.endsWith("/") ? path : path + '/' ).normalize().toAbsolutePath().toString();
            virtual = virtual.startsWith("/") ? virtual : "/" + virtual;
            virtual = virtual.endsWith("/") ? virtual.substring(0, virtual.length() - 1) : virtual;
            this.aliases.put( virtual.toLowerCase(), path );
        }
        return this;
    }

    public SiteOptions mimeTypes(JSONObject mimeTypes) {
        HashMap<String, String> mimes = new HashMap<String, String>();

        for( String key : mimeTypes.keySet() ) {
            mimes.put( key, mimeTypes.get( key ).toString() );
        }

        return mimeTypes(mimes);
    }

    public SiteOptions mimeTypes(Map<String,String> mimeTypes) {
        this.mimeTypes.putAll(mimeTypes);
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

    public SiteOptions clientCertSubjectDNs(JSONArray clientCertSubjectDNs){
        this.clientCertSubjectDNs = clientCertSubjectDNs;
        return this;
    }

    public JSONArray clientCertSubjectDNs(){
        return this.clientCertSubjectDNs;
    }

    public SiteOptions clientCertIssuerDNs(JSONArray clientCertIssuerDNs){
    	this.clientCertIssuerDNs = clientCertIssuerDNs;
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
        if( minSize == -1L ) {
            // Effectivley turns it off
            this.transferMinSize = Long.MAX_VALUE;
        }
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

    public String gzipPredicate() {
        return this.gzipPredicate;
    }


    public SiteOptions gzipPredicate(String gzipPredicate) {
        this.gzipPredicate = gzipPredicate;
        return this;
    }

    public String servletPassPredicate() {
        return this.servletPassPredicate;
    }

    public SiteOptions servletPassPredicate(String servletPassPredicate) {
        this.servletPassPredicate = servletPassPredicate;
        return this;
    }
    public SiteOptions errorPages(JSONObject errorpages) {
        this.errorPages = new HashMap<Integer, String>();

        for( String key : errorpages.keySet() ) {
            String strCode = key.toString().trim();
            Integer code = strCode.toLowerCase() == "default" ? 1 : Integer.parseInt( strCode );
            String location = errorpages.get( key ).toString();
            location = location.startsWith("/") ? location : "/" + location;
            this.errorPages.put( code, location );
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

    public SiteOptions basicAuth(JSONObject userPasswordList) {
        HashMap<String, String> ups = new HashMap<String, String>();

        for( String key : userPasswordList.keySet() ) {
            ups.put( key, userPasswordList.get( key ).toString() );
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

    public SiteOptions sslAddCACerts(JSONArray sslAddCACerts) {
        return sslAddCACerts(sslAddCACerts.toArray(new String[0]));
    }

    public SiteOptions sslAddCACerts(String[] sslAddCACerts) {
        this.sslAddCACerts = sslAddCACerts;
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