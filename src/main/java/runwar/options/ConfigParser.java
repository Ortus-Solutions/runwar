package runwar.options;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.ParseException;
import runwar.LaunchUtil;
import runwar.Server;
import runwar.logging.RunwarLogger;
import runwar.logging.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;
import java.util.stream.Collectors;

import static runwar.logging.RunwarLogger.CONF_LOG;
import static runwar.logging.RunwarLogger.CONTEXT_LOG;

public class ConfigParser {

    private ServerOptions serverOptions;
    private File configFile;

    public ConfigParser(File config){
        if(!config.exists()) {
            String message = "Configuration file does not exist: " + config.getAbsolutePath();
            CONF_LOG.error(message);
            throw new RuntimeException(message);
        }
        serverOptions = new ServerOptions();
        serverOptions.configFile(config);
        configFile = config;
        parseOptions();
    }


    public ServerOptions getServerOptions(){
        return serverOptions;
    }

    private void parseOptions() {
        JSONObject jsonConfig;
        String configFilePath = "unknown";
        try {
            configFilePath = configFile.getCanonicalPath();
            jsonConfig = (JSONObject) JSONValue.parseWithException(LaunchUtil.readFile(configFile));
        } catch (ParseException | IOException e1) {
            System.out.println("Could not load " + configFilePath + " : " + e1.getMessage());
            throw new RuntimeException("Could not load " + configFilePath + " : " + e1.getMessage());
        }

        JSONOption serverConfig = new JSONOption(jsonConfig);


        if (serverConfig.hasOption("debug")) {
            boolean debug = serverConfig.getOptionBoolean("debug");
            serverOptions.debug(debug);
            if (debug) {
                serverOptions.logLevel("debug");
            }
        }

        if (serverConfig.hasOption("trace") && serverConfig.getOptionBoolean("trace") ) {
            serverOptions.logLevel("trace");
        }

        if (serverConfig.hasOption("RunwarAppenderLayout") ) {
            serverOptions.consoleLayout(serverConfig.getOptionValue("RunwarAppenderLayout"));
        }

        if (serverConfig.hasOption("RunwarAppenderLayoutOptions")) {
            serverOptions.consoleLayoutOptions(serverConfig.getOptionObject("RunwarAppenderLayoutOptions"));
        }

        /*
        CommandBox never passes this, always defaults
        if (serverConfig.hasOption(line, Keys.LOGBASENAME)) {
            serverOptions.logFileName(line.getOptionValue(Keys.LOGBASENAME));
        }
        */

        if (serverConfig.hasOption("logDir")) {
            serverOptions.logDir(serverConfig.getOptionValue("logDir"));
        } else {
            serverOptions.logDir();
        }

        if (serverConfig.hasOption("rewritesLogPath")) {
            serverOptions.urlRewriteLog(new File(serverConfig.getOptionValue("rewritesLogPath")));
        }

        LoggerFactory.configure(serverOptions);

        if (serverConfig.hasOption("listeners") ) {
            serverOptions.listeners(serverConfig.g("listeners"));
        }

        if (serverConfig.hasOption("bindings") ) {
            serverOptions.bindings(serverConfig.getOptionObject("bindings"));
        }

        if (serverConfig.hasOption("appFileSystemPath")) {
            serverOptions.warFile(getFile(serverConfig.getOptionValue("appFileSystemPath")));
        }

        if (serverConfig.hasOption("name")) {
            serverOptions.serverName(serverConfig.getOptionValue("name"));
        }

        if (serverConfig.hasOption("startTimeout")) {
            serverOptions.launchTimeout(((Number) serverConfig.getParsedOptionValue("startTimeout")).intValue() * 1000);
        }
        /*
        CommandBox never passes this
        if (serverConfig.hasOption(Keys.PASSWORD)) {
            serverOptions.stopPassword(serverConfig.getOptionValue(Keys.PASSWORD).toCharArray());
        }
        */
        if (serverConfig.hasOption("stopsocket")) {
            serverOptions.stopPort(((Number) serverConfig.getParsedOptionValue("stopsocket")).intValue());
        }

        if (serverConfig.hasOption("webXml")) {
            String webXmlPath = serverConfig.getOptionValue("webXml");
            File webXmlFile = new File(webXmlPath);
            if (webXmlFile.exists()) {
                serverOptions.webXmlFile(webXmlFile);
            } else {
                throw new RuntimeException("Could not find web.xml! " + webXmlPath);
            }
        }

        if (serverConfig.hasOption("webXMLOverride")) {
            String webXmlOverridePath = serverConfig.getOptionValue("webXMLOverride");
            File webXmlOverrideFile = new File(webXmlOverridePath);
            if (webXmlOverrideFile.exists()) {
                serverOptions.webXmlOverrideFile(webXmlOverrideFile);
            } else {
                throw new RuntimeException("Could not find web.xml override! " + webXmlOverridePath);
            }
        }
        if (serverConfig.hasOption("webXMLOverrideForce")) {
            serverOptions.webXmlOverrideForce(serverConfig.getOptionBoolean("webXMLOverrideForce"));
        }
        /*
        CommandBox has no setting for this
        if (serverConfig.hasOption("CONTEXT")) {
            serverOptions.contextPath(serverConfig.getOptionValue("CONTEXT"));
        }
        */


        if (!serverConfig.hasOption("rewritesEnable")) {
            serverOptions.urlRewriteEnable(serverConfig.getOptionBoolean("rewritesEnable"));
        }
        if (serverConfig.hasOption("rewritesConfig")) {
            serverOptions.urlRewriteFile(getFile(serverConfig.getOptionValue("rewritesConfig")));
        }
        if (serverConfig.hasOption("rewritesConfigReloadSeconds")) {
            serverOptions.urlRewriteCheckInterval(serverConfig.getOptionValue("rewritesConfigReloadSeconds"));
        }
        if (serverConfig.hasOption("rewritesStatusPath")) {
            serverOptions.urlRewriteStatusPath(serverConfig.getOptionValue("rewritesStatusPath"));
        }

        if (serverConfig.hasOption("openBrowser")) {
            serverOptions.openbrowser(serverConfig.getOptionBoolean("openBrowser"));
        }

        if (serverConfig.hasOption("ModCFMLenable")) {
            serverOptions.autoCreateContexts(serverConfig.getOptionBoolean("ModCFMLenable"));
        }

        if (serverConfig.hasOption("ModCFMLSharedKey")) {
            serverOptions.autoCreateContextsSecret(serverConfig.getOptionValue("ModCFMLSharedKey"));
        }

        if (serverConfig.hasOption("ModCFMLMaxContexts")) {
            serverOptions.autoCreateContextsMax(Integer.valueOf(serverConfig.getOptionValue("ModCFMLMaxContexts")));
        }

        if (serverConfig.hasOption("ModCFMLcreateVDirs")) {
            serverOptions.autoCreateContextsVDirs(serverConfig.getOptionBoolean("ModCFMLcreateVDirs"));
        }

        if (serverConfig.hasOption("openbrowserURL")) {
            serverOptions.openbrowserURL(serverConfig.getOptionValue("openbrowserURL"));
        }

        if (serverConfig.hasOption("pidfile")) {
            serverOptions.pidFile(serverConfig.getOptionValue("pidfile"));
        }

        if (serverConfig.hasOption("processName")) {
            serverOptions.processName(serverConfig.getOptionValue("processName"));
        }

        if (serverConfig.hasOption("trayEnable")) {
            serverOptions.trayEnable(serverConfig.getOptionBoolean("trayEnable"));
        }

        if (serverConfig.hasOption("dockEnable")) {
            serverOptions.dockEnable(serverConfig.getOptionBoolean("dockEnable"));
        }

        if (serverConfig.hasOption("trayicon")) {
            serverOptions.iconImage(serverConfig.getOptionValue("trayicon"));
        }
        // TODO: use JSONd irectly as "trayOptions"
        if (serverConfig.hasOption("trayOptionsFile")) {
            serverOptions.trayConfig(getFile(serverConfig.getOptionValue("trayOptionsFile")));
        }

        if (serverConfig.hasOption("engineName")) {
            serverOptions.cfEngineName(serverConfig.getOptionValue("engineName"));
        }

        if (serverConfig.hasOption("customHTTPStatusEnable")) {
            serverOptions.customHTTPStatusEnable(serverConfig.getOptionBoolean("customHTTPStatusEnable"));
        }

        // TODO: Is anyone using this???
        if (serverConfig.hasOption("MARIADB4J")) {
            serverOptions.mariaDB4jEnable(serverConfig.getOptionBoolean("MARIADB4J"));
        }
        if (serverConfig.hasOption("MARIADB4JPORT")) {
            serverOptions.mariaDB4jPort(Integer.valueOf(serverConfig.getOptionValue("MARIADB4JPORT")));
        }
        if (serverConfig.hasOption("MARIADB4JBASEDIR")) {
            serverOptions.mariaDB4jBaseDir(new File(serverConfig.getOptionValue("MARIADB4JBASEDIR")));
        }
        if (serverConfig.hasOption("MARIADB4JDATADIR")) {
            serverOptions.mariaDB4jDataDir(new File(serverConfig.getOptionValue("MARIADB4JDATADIR")));
        }
        if (serverConfig.hasOption("MARIADB4JIMPORT")) {
            serverOptions.mariaDB4jImportSQLFile(new File(serverConfig.getOptionValue("MARIADB4JIMPORT")));
        }
        // TODO: Is anyone using this???


        if (serverConfig.hasOption("restMappings")) {
            serverOptions.servletRestMappings(serverConfig.getOptionValue("restMappings"));
            // No setting for this
            //if (!serverConfig.hasOption("SERVLETREST")) {
                serverOptions.servletRestEnable(true);
           // }
        }

        // TODO: No setting exists for this
        if (serverConfig.hasOption("FILTERPATHINFO")) {
            serverOptions.filterPathInfoEnable(serverConfig.getOptionBoolean("FILTERPATHINFO"));
        }
        // TODO: No setting for this
        if (serverConfig.hasOption("BUFFERSIZE")) {
            serverOptions.bufferSize(Integer.valueOf(serverConfig.getOptionValue("BUFFERSIZE")));
        }
        // TODO: No setting for this
        if (serverConfig.hasOption("IOTHREADS")) {
            serverOptions.ioThreads(Integer.valueOf(serverConfig.getOptionValue("IOTHREADS")));
        }
        if (serverConfig.hasOption("maxRequests")) {
            serverOptions.workerThreads(Integer.valueOf(serverConfig.getOptionValue("maxRequests")));
        }
        // TODO: No setting for this
        if (serverConfig.hasOption("DIRECTBUFFERS")) {
            serverOptions.directBuffers(serverConfig.getOptionBoolean("DIRECTBUFFERS"));
        }

        if (serverConfig.hasOption("sessionCookieHTTPOnly")) {
            serverOptions.cookieHttpOnly(serverConfig.getOptionBoolean("sessionCookieHTTPOnly"));
        }

        if (serverConfig.hasOption("sessionCookieSecure")) {
            serverOptions.cookieSecure(serverConfig.getOptionBoolean("sessionCookieSecure"));
        }

        // TODO: No setting for this
        if (serverConfig.hasOption("SSLECCDISABLE")) {
            serverOptions.sslEccDisable(serverConfig.getOptionBoolean("SSLECCDISABLE"));
        }

        if (serverConfig.hasOption("preferredBrowser")) {
            serverOptions.browser(serverConfig.getOptionValue("preferredBrowser"));
        }

        if (serverConfig.hasOption("runwarXNIOOptions")) {
            serverOptions.xnioOptions(serverConfig.getOptionObject("runwarXNIOOptions"));
        }

        if (serverConfig.hasOption("runwarUndertowOptions")) {
           serverOptions.undertowOptions(serverConfig.getOptionObject("runwarUndertowOptions"));
        }



        ///////////////////////////////////////////////////////////////////////////////////////////
        //                              SITE SPECIFIC SETTING                                    //
        ///////////////////////////////////////////////////////////////////////////////////////////

        JSONObject sites = serverConfig.getOptionObject( "sites" );
        for ( Map.Entry<String, Object> entry : sites.entrySet() ) {

            String siteName = entry.getKey();
            JSONOption siteConfig = new JSONOption( (JSONObject)entry.getValue() );

            SiteOptions site = new SiteOptions().siteName( siteName );

            CONF_LOG.info("Loading config for site [" + siteName + "].");

            site.webroot(getFile( siteConfig.getOptionValue("webroot")));



            if (siteConfig.hasOption("servletPassPredicate")) {
                site.servletPassPredicate(siteConfig.getOptionValue("servletPassPredicate"));
            }

            if (siteConfig.hasOption("directoryBrowsing")) {
                site.directoryListingEnable(siteConfig.getOptionBoolean("directoryBrowsing"));
            }

            if (siteConfig.hasOption("welcomeFiles")) {
                site.welcomeFiles(siteConfig.getOptionValue("welcomeFiles").split(","));
            }

            if (siteConfig.hasOption("resourceManagerLogging")) {
                site.resourceManagerLogging(siteConfig.getOptionBoolean("resourceManagerLogging"));
            }
            if (siteConfig.hasOption("host")) {
                site.host(siteConfig.getOptionValue("host"));
            }

            if (siteConfig.hasOption("HTTPEnable")) {
                site.httpEnable(siteConfig.getOptionBoolean("HTTPEnable"));
            }
            if (siteConfig.hasOption("port")) {
                site.httpPort(((Number) siteConfig.getParsedOptionValue("port")).intValue());
            }
            if (siteConfig.hasOption("HTTP2Enable")) {
                site.http2Enable(siteConfig.getOptionBoolean("HTTP2Enable"));
            }
            if (siteConfig.hasOption("AJPEnable")) {
                site.ajpEnable(siteConfig.getOptionBoolean("AJPEnable"));
            }
            if (siteConfig.hasOption("AJPPort")) {
                site.ajpPort(((Number) siteConfig.getParsedOptionValue("AJPPort")).intValue());
            }
            if (siteConfig.hasOption("SSLEnable")) {
                site.sslEnable(siteConfig.getOptionBoolean("SSLEnable"));
                if (!siteConfig.hasOption("sessionCookieSecure")) {
                    // TODO: This isn't being used!
                    CONF_LOG.trace("SSL enabled and secure cookies not explicitly disabled; enabling secure cookies");
                    serverOptions.secureCookies(true);
                }
            }
            if (siteConfig.hasOption("SSLPort")) {
                site.sslPort(((Number) siteConfig.getParsedOptionValue("SSLPort")).intValue());
            }

            if (siteConfig.hasOption("SSLCertFile")) {
                File certFile = getFile(siteConfig.getOptionValue("SSLCertFile"));
                site.sslCertificate(certFile);
            }
            if (siteConfig.hasOption("SSLKeyFile")) {
                File keyFile = getFile(siteConfig.getOptionValue("SSLKeyFile"));
                site.sslKey(keyFile);
            }
            if (siteConfig.hasOption("SSLKeyPass")) {
                site.sslKeyPass(siteConfig.getOptionValue("SSLKeyPass").toCharArray());
            }

            if (siteConfig.hasOption("clientCertMode")) {
                site.clientCertNegotiation(siteConfig.getOptionValue("clientCertMode"));
            }
            if (siteConfig.hasOption("clientCertSSLRenegotiationEnable")) {
                site.clientCertRenegotiation(siteConfig.getOptionBoolean("clientCertSSLRenegotiationEnable"));
            }
            if (siteConfig.hasOption("securityRealm")) {
                site.securityRealm(siteConfig.getOptionValue("securityRealm"));
            }
            if (siteConfig.hasOption("clientCertEnable")) {
                site.clientCertEnable(siteConfig.getOptionBoolean("clientCertEnable"));

                if( site.clientCertEnable() ) {
                    if (siteConfig.hasOption("clientCertSubjectDNs")) {
                       site.clientCertSubjectDNs(siteConfig.getOptionArray("clientCertSubjectDNs"));
                    }
                    if (siteConfig.hasOption("clientCertIssuerDNs")) {
                     site.clientCertIssuerDNs(siteConfig.getOptionArray("clientCertIssuerDNs"));
                    }
                }
            }

            if (siteConfig.hasOption("clientCertTrustUpstreamHeaders")) {
                site.clientCertTrustHeaders(siteConfig.getOptionBoolean("clientCertTrustUpstreamHeaders"));
            }


            // TODO: This setting doesn't exist
            if (siteConfig.hasOption("SSLADDCERTS")) {
                site.sslAddCerts(siteConfig.getOptionValue("SSLADDCERTS"));
            }
            if (siteConfig.hasOption("clientCertCACertFiles")) {
                site.sslAddCACerts(siteConfig.getOptionArray("clientCertCACertFiles"));
            }
            if (siteConfig.hasOption("clientCertCATrustStoreFile")) {
                site.sslTruststore(siteConfig.getOptionValue("clientCertCATrustStoreFile"));
            }
            if (siteConfig.hasOption("clientCertCATrustStorePass")) {
                site.sslTruststorePass(siteConfig.getOptionValue("clientCertCATrustStorePass"));
            }
            if (siteConfig.hasOption("basicAuthEnable")) {
                site.basicAuthEnable(siteConfig.getOptionBoolean("basicAuthEnable"));
            }

            if (siteConfig.hasOption("webRulesText")) {
                site.predicateText(siteConfig.getOptionValue("webRulesText"));
            }

            if (siteConfig.hasOption("authPredicate")) {
                site.authPredicate(siteConfig.getOptionValue("authPredicate"));
            }

            if (siteConfig.hasOption("basicAuthUsers")) {
                site.basicAuth(siteConfig.getOptionObject("basicAuthUsers"));
            }

            if (siteConfig.hasOption("mimeTypes")) {
             site.mimeTypes(siteConfig.getOptionObject("mimeTypes"));
            }

            if (siteConfig.hasOption("aliases")) {
             site.aliases(siteConfig.getOptionObject("aliases"));
            }

            if (siteConfig.hasOption("allowedExt")) {
                site.defaultServletAllowedExt(siteConfig.getOptionValue("allowedExt"));
            }

            if (siteConfig.hasOption("caseSensitivePaths")) {
                site.caseSensitiveWebServer(siteConfig.getOptionBoolean("caseSensitivePaths"));
            }

            if (siteConfig.hasOption("fileCacheEnable")) {
                // causing issues...
                //site.cacheServletPaths(siteConfig.getOptionBoolean("fileCacheEnable"));
            }
            /* Commmand has no setting for this
            if (siteConfig.hasOption("RESOURCEMANAGERFILESYSTEMWATCHER")) {
                site.resourceManagerFileSystemWatcher(siteConfig.getOptionBoolean("RESOURCEMANAGERFILESYSTEMWATCHER"));
            }
            */
            if (siteConfig.hasOption("fileCacheTotalSizeMB")) {
                site.fileCacheTotalSizeMB(Integer.valueOf(siteConfig.getOptionValue("fileCacheTotalSizeMB")));
            }

            if (siteConfig.hasOption("fileCacheMaxFileSizeKB")) {
                site.fileCacheMaxFileSizeKB(Integer.valueOf(siteConfig.getOptionValue("fileCacheMaxFileSizeKB")));
            }

            if (siteConfig.hasOption("accessLogBaseName")) {
                site.logAccessBaseFileName(siteConfig.getOptionValue("accessLogBaseName"));
            }
            if (siteConfig.hasOption("accessLogBaseDir")) {
                site.logAccessDir(getFile(siteConfig.getOptionValue("accessLogBaseDir")));
            }
            if (siteConfig.hasOption("accessLogEnable")) {
                site.logAccessEnable(siteConfig.getOptionBoolean("accessLogEnable"));
            }
            /* TODO: No CommandBox setting for these
            if (siteConfig.hasOption("TRANSFERMINSIZE")) {
                site.transferMinSize(Long.valueOf(siteConfig.getOptionValue("TRANSFERMINSIZE")));
            }

            if (siteConfig.hasOption("SENDFILE")) {
                site.sendfileEnable(siteConfig.getOptionBoolean("SENDFILE"));
            }
            */

            if (siteConfig.hasOption("GZipEnable")) {
                site.gzipEnable(siteConfig.getOptionBoolean("GZipEnable"));
            }
            if (siteConfig.hasOption("GZipPredicate")) {
                site.gzipPredicate(siteConfig.getOptionValue("GZipPredicate"));
            }

            if (siteConfig.hasOption("errorPages")) {
                site.errorPages(siteConfig.getOptionObject("errorPages"));
            }

            // TODO: No CommandBox setting for this
            if (siteConfig.hasOption("DIRECTORYREFRESH")) {
                site.directoryListingRefreshEnable(siteConfig.getOptionBoolean("DIRECTORYREFRESH"));
            }

            if (siteConfig.hasOption("useProxyForwardedIP")) {
                site.proxyPeerAddressEnable(siteConfig.getOptionBoolean("useProxyForwardedIP"));
            }

            serverOptions.addSite( site );
        }



    }


    static File getFile(String path) {
        File file = new File(path);
        if (!file.exists() || file == null) {
            throw new RuntimeException("File not found: " + path + " (" + file.getAbsolutePath() + ")");
        }
        return file;
    }

    public static class JSONOption {
        private JSONObject jsonConfig;

        public JSONOption(JSONObject jsonConfig) {
            this.jsonConfig = jsonConfig;
        }

        public Number getParsedOptionValue(String string) {
            return Integer.parseInt(getOptionValue(string));
        }

        public ArrayList<String> getOptions() {
            Iterator<String> keys = jsonConfig.keySet().iterator();
            ArrayList<String> options = new ArrayList<String>();
            while(keys.hasNext()) {
                String key = keys.next();
                options.add(key+"="+jsonConfig.get(key).toString());
            }
            return options;
        }

        public Set<String> getKeys() {
            return jsonConfig.keySet();
        }

        public String getOptionValue(String key) {
            key = getKeyNoCase(key);
            if(hasOption(key)){
              return jsonConfig.get(key).toString();
            }
            return null;
        }

        public Boolean getOptionBoolean(String key) {
            key = getKeyNoCase(key);
            if(hasOption(key)){
              return Boolean.valueOf( jsonConfig.get(key).toString() );
            }
            return null;
        }

        public Integer getOptionInt(String key) {
            key = getKeyNoCase(key);
            if(hasOption(key)){
              return Integer.valueOf( jsonConfig.get(key).toString() );
            }
            return null;
        }

        public File getOptionFile(String key) {
            key = getKeyNoCase(key);
            if(hasOption(key)){
              return getFile( jsonConfig.get(key).toString() );
            }
            return null;
        }

        public JSONOption g(String key) {
            key = getKeyNoCase(key);
          return new JSONOption((JSONObject) jsonConfig.get(key));
        }

        public JSONObject get(String key) {
            key = getKeyNoCase(key);
            return (JSONObject) jsonConfig.get(key);
        }

        public JSONObject getOptionObject(String key) {
            return get(key);
        }

        public void put(String key, String value) {
            jsonConfig.put(key,value);
        }

        public JSONArray getOptionArray(String key) {
            key = getKeyNoCase(key);
            return (JSONArray) jsonConfig.get(key);
        }

        public String getKeyNoCase(String dirtyKey) {
            if(dirtyKey == null)
                return dirtyKey;

            if( jsonConfig.containsKey( dirtyKey ) )
                return dirtyKey;

            String result = jsonConfig.keySet().stream()
                    .filter(map -> dirtyKey.toLowerCase().equals(map.toLowerCase()))
                    .map(map->map)
                    .collect(Collectors.joining());
            return result.length() > 0 ? result : dirtyKey;
        }

        public boolean hasOption(String key) {
            key = getKeyNoCase(key);
            if(key == null)
                return false;
            return jsonConfig.containsKey(key) && jsonConfig.get(key).toString().length() > 0;
        }
    }

}
