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
            boolean debug = Boolean.valueOf(serverConfig.getOptionValue("debug"));
            serverOptions.debug(debug);
            if (debug) {
                serverOptions.logLevel("debug");
            }
        }

        if (serverConfig.hasOption("trace") && Boolean.valueOf(serverConfig.getOptionValue("trace")) ) {
            serverOptions.logLevel("trace");
        }

        if (serverConfig.hasOption("RunwarAppenderLayout") ) {
            serverOptions.consoleLayout(serverConfig.getOptionValue("RunwarAppenderLayout"));
        }

        /* if (serverConfig.hasOption(line, Keys.CONSOLELAYOUTOPTIONS)) {
            serverOptions.consoleLayoutOptions(line.getOptionValue(Keys.CONSOLELAYOUTOPTIONS));
        }
        */
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
/*
        if (serverConfig.hasOption(line, Keys.RESOURCEMANAGERLOGGING)) {
            No CommandBox setting for this
            serverOptions.resourceManagerLogging(Boolean.valueOf(serverConfig.getOptionValue(Keys.RESOURCEMANAGERLOGGING)));
        }
*/
        if (serverConfig.hasOption("rewritesLogPath")) {
            serverOptions.urlRewriteLog(new File(serverConfig.getOptionValue("rewritesLogPath")));
        }

        LoggerFactory.configure(serverOptions);

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
            serverOptions.webXmlOverrideForce(Boolean.valueOf(serverConfig.getOptionValue("webXMLOverrideForce")));
        }
        /*
        CommandBox has no setting for this
        if (serverConfig.hasOption("CONTEXT")) {
            serverOptions.contextPath(serverConfig.getOptionValue("CONTEXT"));
        }
        */


        if (!serverConfig.hasOption("rewritesEnable")) {
            serverOptions.urlRewriteEnable(Boolean.valueOf(serverConfig.getOptionValue("rewritesEnable")));
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
        /*
        TODO: DO we use these??
        if (serverConfig.hasOption("DIRS")) {
            serverOptions.contentDirs(serverConfig.getOptionValue("DIRS"));
        }
        */
       /*
        Not using
        if (serverConfig.hasOption("LOGREQUESTSBASENAME")) {
            serverOptions.logRequestsEnable(true);
            serverOptions.logRequestsBaseFileName(serverConfig.getOptionValue("LOGREQUESTSBASENAME"));
        }
        if (serverConfig.hasOption("LOGREQUESTSDIR")) {
            serverOptions.logRequestsEnable(true);
            serverOptions.logRequestsDir(getFile(serverConfig.getOptionValue("LOGREQUESTSDIR")));
        }
        if (serverConfig.hasOption("LOGREQUESTS")) {
            serverOptions.logRequestsEnable(Boolean.valueOf(serverConfig.getOptionValue("LOGREQUESTS")));
        }
        */

        if (serverConfig.hasOption("openBrowser")) {
            serverOptions.openbrowser(Boolean.valueOf(serverConfig.getOptionValue("openBrowser")));
        }

        if (serverConfig.hasOption("ModCFMLenable")) {
            serverOptions.autoCreateContexts(Boolean.valueOf(serverConfig.getOptionValue("ModCFMLenable")));
        }

        if (serverConfig.hasOption("ModCFMLSharedKey")) {
            serverOptions.autoCreateContextsSecret(serverConfig.getOptionValue("ModCFMLSharedKey"));
        }

        if (serverConfig.hasOption("ModCFMLMaxContexts")) {
            serverOptions.autoCreateContextsMax(Integer.valueOf(serverConfig.getOptionValue("ModCFMLMaxContexts")));
        }

        if (serverConfig.hasOption("ModCFMLcreateVDirs")) {
            serverOptions.autoCreateContextsVDirs(Boolean.valueOf(serverConfig.getOptionValue("ModCFMLcreateVDirs")));
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
            serverOptions.trayEnable(Boolean.valueOf(serverConfig.getOptionValue("trayEnable")));
        }

        if (serverConfig.hasOption("dockEnable")) {
            serverOptions.dockEnable(Boolean.valueOf(serverConfig.getOptionValue("dockEnable")));
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
            serverOptions.customHTTPStatusEnable(Boolean.valueOf(serverConfig.getOptionValue("customHTTPStatusEnable")));
        }

        // TODO: Is anyone using this???
        if (serverConfig.hasOption("MARIADB4J")) {
            serverOptions.mariaDB4jEnable(Boolean.valueOf(serverConfig.getOptionValue("MARIADB4J")));
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
            serverOptions.filterPathInfoEnable(Boolean.valueOf(serverConfig.getOptionValue("FILTERPATHINFO")));
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
            serverOptions.directBuffers(Boolean.valueOf(serverConfig.getOptionValue("DIRECTBUFFERS")));
        }

        if (serverConfig.hasOption("sessionCookieHTTPOnly")) {
            serverOptions.cookieHttpOnly(Boolean.valueOf(serverConfig.getOptionValue("sessionCookieHTTPOnly")));
        }

        if (serverConfig.hasOption("sessionCookieSecure")) {
            serverOptions.cookieSecure(Boolean.valueOf(serverConfig.getOptionValue("sessionCookieSecure")));
        }

        // TODO: No setting for this
        if (serverConfig.hasOption("SSLECCDISABLE")) {
            serverOptions.sslEccDisable(Boolean.valueOf(serverConfig.getOptionValue("SSLECCDISABLE")));
        }

        if (serverConfig.hasOption("preferredBrowser")) {
            serverOptions.browser(serverConfig.getOptionValue("preferredBrowser"));
        }

        if (serverConfig.hasOption("runwarXNIOOptions")) {
            // TODO: Transform
            //serverOptions.xnioOptions(serverConfig.getOptionObject("runwarXNIOOptions"));
        }

        if (serverConfig.hasOption("runwarUndertowOptions")) {
            // TODO: Transform
           // serverOptions.undertowOptions(serverConfig.getOptionObject("runwarUndertowOptions"));
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

            if (siteConfig.hasOption("directoryBrowsing")) {
                site.directoryListingEnable(Boolean.valueOf(siteConfig.getOptionValue("directoryBrowsing")));
            }

            if (siteConfig.hasOption("welcomeFiles")) {
                site.welcomeFiles(siteConfig.getOptionValue("welcomeFiles").split(","));
            }
            if (siteConfig.hasOption("host")) {
                site.host(siteConfig.getOptionValue("host"));
            }

            if (siteConfig.hasOption("HTTPEnable")) {
                site.httpEnable(Boolean.valueOf(siteConfig.getOptionValue("HTTPEnable")));
            }
            if (siteConfig.hasOption("port")) {
                site.httpPort(((Number) siteConfig.getParsedOptionValue("port")).intValue());
            }
            if (siteConfig.hasOption("HTTP2Enable")) {
                site.http2Enable(Boolean.valueOf(siteConfig.getOptionValue("HTTP2Enable")));
            }
            if (siteConfig.hasOption("AJPEnable")) {
                site.ajpEnable(Boolean.valueOf(siteConfig.getOptionValue("AJPEnable")));
            }
            if (siteConfig.hasOption("AJPPort")) {
                site.ajpPort(((Number) siteConfig.getParsedOptionValue("AJPPort")).intValue());
            }
            if (siteConfig.hasOption("SSLEnable")) {
                site.sslEnable(Boolean.valueOf(siteConfig.getOptionValue("SSLEnable")));
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
                site.clientCertRenegotiation(Boolean.valueOf(siteConfig.getOptionValue("clientCertSSLRenegotiationEnable")));
            }
            if (siteConfig.hasOption("securityRealm")) {
                site.securityRealm(siteConfig.getOptionValue("securityRealm"));
            }
            if (siteConfig.hasOption("clientCertEnable")) {
                site.clientCertEnable(Boolean.valueOf(siteConfig.getOptionValue("clientCertEnable")));

                if( site.clientCertEnable() ) {
                    if (siteConfig.hasOption("clientCertSubjectDNs")) {
                        // TODO: test this
                //       site.clientCertSubjectDNs(siteConfig.getOptionObject("clientCertSubjectDNs"));
                    }
                    if (siteConfig.hasOption("clientCertIssuerDNs")) {
                        // TODO: test this
                //     site.clientCertIssuerDNs(siteConfig.getOptionObject("clientCertIssuerDNs"));
                    }
                }
            }

            if (siteConfig.hasOption("clientCertTrustUpstreamHeaders")) {
                site.clientCertTrustHeaders(Boolean.valueOf(siteConfig.getOptionValue("clientCertTrustUpstreamHeaders")));
            }


            // TODO: This setting doesn't exist
            if (siteConfig.hasOption("SSLADDCERTS")) {
                site.sslAddCerts(siteConfig.getOptionValue("SSLADDCERTS"));
            }
            if (siteConfig.hasOption("clientCertCACertFiles")) {
                // TODO: convert list/array
                //site.sslAddCACerts(siteConfig.getOptions("clientCertCACertFiles"));
            }
            if (siteConfig.hasOption("clientCertCATrustStoreFile")) {
                site.sslTruststore(siteConfig.getOptionValue("clientCertCATrustStoreFile"));
            }
            if (siteConfig.hasOption("clientCertCATrustStorePass")) {
                site.sslTruststorePass(siteConfig.getOptionValue("clientCertCATrustStorePass"));
            }
            if (siteConfig.hasOption("basicAuthEnable")) {
                site.basicAuthEnable(Boolean.valueOf(siteConfig.getOptionValue("basicAuthEnable")));
            }

            if (siteConfig.hasOption("authPredicate")) {
                site.authPredicate(siteConfig.getOptionValue("authPredicate"));
            }

            if (siteConfig.hasOption("basicAuthUsers")) {
                // TODO: Convert object type
                //site.basicAuth(siteConfig.getOptionObject("basicAuthUsers"));
            }


            if (siteConfig.hasOption("mimeTypes")) {
                // TODO massage type
            // site.mimeTypes(siteConfig.getOptionValue("mimeTypes"));
            }

            if (siteConfig.hasOption("allowedExt")) {
                site.defaultServletAllowedExt(siteConfig.getOptionValue("allowedExt"));
            }

            if (siteConfig.hasOption("caseSensitivePaths")) {
                site.caseSensitiveWebServer(Boolean.valueOf(siteConfig.getOptionValue("caseSensitivePaths")));
            }

            if (siteConfig.hasOption("fileCacheEnable")) {
                site.cacheServletPaths(Boolean.valueOf(siteConfig.getOptionValue("fileCacheEnable")));
            }
            /* Commmand has no setting for this
            if (siteConfig.hasOption("RESOURCEMANAGERFILESYSTEMWATCHER")) {
                site.resourceManagerFileSystemWatcher(Boolean.valueOf(siteConfig.getOptionValue("RESOURCEMANAGERFILESYSTEMWATCHER")));
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
                site.logAccessEnable(Boolean.valueOf(siteConfig.getOptionValue("accessLogEnable")));
            }
            /* TODO: No CommandBox setting for these
            if (siteConfig.hasOption("TRANSFERMINSIZE")) {
                site.transferMinSize(Long.valueOf(siteConfig.getOptionValue("TRANSFERMINSIZE")));
            }

            if (siteConfig.hasOption("SENDFILE")) {
                site.sendfileEnable(Boolean.valueOf(siteConfig.getOptionValue("SENDFILE")));
            }
            */

            if (siteConfig.hasOption("GZipEnable")) {
                site.gzipEnable(Boolean.valueOf(siteConfig.getOptionValue("GZipEnable")));
            }
            if (siteConfig.hasOption("GZipPredicate")) {
                site.gzipPredicate(siteConfig.getOptionValue("GZipPredicate"));
            }

            if (siteConfig.hasOption("errorPages")) {
                // TODO: transform this
                //site.errorPages(siteConfig.getOptionValue("errorPages"));
            }

            // TODO: No CommandBox setting for these
            if (siteConfig.hasOption("DIRECTORYREFRESH")) {
                site.directoryListingRefreshEnable(Boolean.valueOf(siteConfig.getOptionValue("DIRECTORYREFRESH")));
            }
            if (siteConfig.hasOption("useProxyForwardedIP")) {
                site.proxyPeerAddressEnable(Boolean.valueOf(siteConfig.getOptionValue("useProxyForwardedIP")));
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

    private class JSONOption {
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

        public String getOptionValue(String key) {
            key = getKeyNoCase(key);
            if(hasOption(key)){
              return jsonConfig.get(key).toString();
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
