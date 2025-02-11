package runwar;

import static io.undertow.Handlers.predicate;
import static runwar.logging.RunwarLogger.LOG;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Arrays;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;

import io.undertow.predicate.Predicates;
import io.undertow.server.handlers.cache.CacheHandler;
import io.undertow.server.handlers.cache.DirectBufferCache;
import io.undertow.server.handlers.resource.ResourceHandler;
import io.undertow.servlet.api.*;
import io.undertow.servlet.handlers.DefaultServlet;
import io.undertow.util.MimeMappings;
import runwar.options.ServerOptions;
import runwar.undertow.WebXMLParser;
import runwar.servlet.RegexPathInfoFilter;

public class RunwarConfigurer {

    private static ServerOptions serverOptions;
    private final Server server;
    private String[] defaultWelcomeFiles = new String[] { "index.cfm", "index.cfml", "default.cfm", "index.html",
            "index.htm",
            "default.html", "default.htm" };

    private static ClassLoader getClassLoader() {
        return Server.getClassLoader();

    }

    RunwarConfigurer(final Server server) {
        this.server = server;
        serverOptions = server.getServerOptions();
    }

    void configureServerResourceHandler(DeploymentInfo servletBuilder) {
        File warFile = serverOptions.warFile();
        File webInfDir = serverOptions.webInfDir();
        String cfengine = serverOptions.cfEngineName();
        String cfusionDir = new File(webInfDir, "cfusion").getAbsolutePath().replace('\\', '/');

        if (cfengine.equals("adobe") || cfengine.equals("") && new File(cfusionDir).exists()) {
            String cfformDir = new File(webInfDir, "cfform").getAbsolutePath().replace('\\', '/');

            final String cfClasspath = "%s/lib/updates,%s/lib/,%s/lib/axis2,%s/gateway/lib/,%s/../cfform/jars,%s/../flex/jars,%s/lib/oosdk/lib,%s/lib/oosdk/classes"
                    .replaceAll("%s", cfusionDir);
            final HashMap<String, String> cfprops = new HashMap<>();

            cfprops.put("coldfusion.home", cfusionDir);
            cfprops.put("coldfusion.rootDir", cfusionDir);
            cfprops.put("coldfusion.libPath", cfusionDir + "/lib");
            cfprops.put("flex.dir", cfformDir);
            cfprops.put("coldfusion.jsafe.defaultalgo", "FIPS186Random");
            cfprops.put("coldfusion.classPath", cfClasspath);

            cfprops.put("java.security.policy", cfusionDir + "/lib/coldfusion.policy");
            cfprops.put("java.security.auth.policy", cfusionDir + "/lib/neo_jaas.policy");
            cfprops.put("java.nixlibrary.path", cfusionDir + "/lib");
            cfprops.put("java.library.path", cfusionDir + "/lib");

            LOG.debug("Setting coldfusion.home: '" + cfusionDir + "'");
            LOG.debug("Setting coldfusion.classpath: '" + cfClasspath + "'");
            LOG.debug("Setting flex.dir (cfform): '" + cfformDir + "'");
            if (System.getProperty("coldfusion.home") == null) {
                cfprops.forEach((k, v) -> {
                    System.setProperty(k, v);
                    LOG.tracef("Setting %s = '%s'", k, v);
                });
            }

            // Hide error messages about MediaLib stuff
            System.setProperty("com.sun.media.jai.disableMediaLib", "true");
            cfengine = "adobe";
        }

        configureServerWar(servletBuilder);
        if (cfengine.equals("adobe")) {
            String cfCompilerOutput = (String) servletBuilder.getServletContextAttributes()
                    .get("coldfusion.compiler.outputDir");
            if (cfCompilerOutput == null || cfCompilerOutput.matches("^.?WEB-INF.*?")) {
                // I don't know why, but Adobe needs the absolute path, vs. /WEB-INF/cfclasses
                // CF will throw errors otherwise.
                File cfCompilerOutputDir = new File(webInfDir, "/cfclasses").getAbsoluteFile();
                try {
                    cfCompilerOutputDir = new File(webInfDir, "/cfclasses").getAbsoluteFile().getCanonicalFile();
                } catch (IOException e) {
                    LOG.error(e);
                }
                LOG.debug("  Setting coldfusion.compiler.outputDir: '" + cfCompilerOutputDir.getPath() + "'");
                if (!cfCompilerOutputDir.exists()) {
                    if (!cfCompilerOutputDir.mkdir()) {
                        LOG.error("  Unable to create cfclasses dir: '" + cfCompilerOutputDir.getPath() + "'");
                    }
                }
                servletBuilder.addServletContextAttribute("coldfusion.compiler.outputDir",
                        cfCompilerOutputDir.getPath());
            }
        }

        serverOptions.getSites().get(0).mimeTypes().forEach((ext, contentType) -> {
            servletBuilder.addMimeMapping(new MimeMapping(ext, contentType));
        });
        // Only needed until this is complete:
        // https://issues.redhat.com/browse/UNDERTOW-2218
        servletBuilder.addMimeMapping(new MimeMapping("webp", "image/webp"));
    }

    private void configureServerWar(DeploymentInfo servletBuilder) {
        File warFile = serverOptions.warFile();
        File webInfDir = serverOptions.webInfDir();
        LOG.info("  Found WEB-INF: '" + webInfDir.getAbsolutePath() + "'");
        if (getClassLoader() == null) {
            throw new RuntimeException("FATAL: Could not load any libs for war: " + warFile.getAbsolutePath());
        }
        servletBuilder.setClassLoader(getClassLoader());

        WebXMLParser.parseWebXml(serverOptions.webXmlFile(), servletBuilder, serverOptions.ignoreWebXmlRestMappings(),
                false, serverOptions.servletRestEnable(), serverOptions);
        File webXMLOverrideFile = serverOptions.webXmlOverrideFile();
        if (webXMLOverrideFile != null) {
            LOG.debug("  Using webxml override: '" + webXMLOverrideFile.getAbsolutePath() + "'");
            WebXMLParser.parseWebXml(webXMLOverrideFile, servletBuilder, serverOptions.ignoreWebXmlRestMappings(),
                    serverOptions.webXmlOverrideForce(), serverOptions.servletRestEnable(), serverOptions);
        }
    }

    @SuppressWarnings("unchecked")
    private void configureURLRewrite(DeploymentInfo servletBuilder, File webInfDir) throws ClassNotFoundException {
        if (serverOptions.urlRewriteEnable()) {
            LOG.debug("  Enabling Tuckey URL rewriting");
            Class<Filter> rewriteFilter;
            String urlRewriteFile = "runwar/urlrewrite.xml";
            if (new File(webInfDir, "urlrewrite.xml").exists() && serverOptions.urlRewriteFile() == null) {
                serverOptions.urlRewriteFile(new File(webInfDir, "urlrewrite.xml"));
            }
            try {
                rewriteFilter = (Class<Filter>) getClassLoader().loadClass("runwar.util.UrlRewriteFilter");
            } catch (java.lang.ClassNotFoundException e) {
                rewriteFilter = (Class<Filter>) Server.class.getClassLoader().loadClass("runwar.util.UrlRewriteFilter");
            }
            if (serverOptions.urlRewriteFile() != null) {
                if (!serverOptions.urlRewriteFile().isFile()) {
                    String message = "The URL rewrite file " + urlRewriteFile + " does not exist!";
                    LOG.error(message);
                    throw new RuntimeException(message);
                } else {
                    urlRewriteFile = serverOptions.urlRewriteFile().getAbsolutePath();
                }
            }

            String rewriteFormat = serverOptions.urlRewriteApacheFormat() ? "modRewrite-style" : "XML";
            LOG.debug("    " + rewriteFormat + " rewrite config file: " + urlRewriteFile);
            FilterInfo rewriteFilterInfo = new FilterInfo("UrlRewriteFilter", rewriteFilter)
                    .addInitParam("confPath", urlRewriteFile)
                    .addInitParam("statusEnabled", Boolean.toString(serverOptions.debug()))
                    .addInitParam("modRewriteConf", Boolean.toString(serverOptions.urlRewriteApacheFormat()));
            if (serverOptions.urlRewriteCheckInterval() != null) {
                rewriteFilterInfo.addInitParam("confReloadCheckInterval", serverOptions.urlRewriteCheckInterval());
            }
            if (serverOptions.urlRewriteStatusPath() != null && serverOptions.urlRewriteStatusPath().length() != 0) {
                rewriteFilterInfo.addInitParam("statusPath", serverOptions.urlRewriteStatusPath());
            }
            rewriteFilterInfo.addInitParam("logLevel", "SLF4J");
            servletBuilder.addFilter(rewriteFilterInfo);
            servletBuilder.addFilterUrlMapping("UrlRewriteFilter", "/*", DispatcherType.REQUEST);
        }
    }

    @SuppressWarnings({ "unchecked" })
    private void configurePathInfoFilter(DeploymentInfo servletBuilder) throws ClassNotFoundException {
        if (serverOptions.filterPathInfoEnable()) {
            FilterInfo filterInfo = new FilterInfo("RegexPathInfoFilter", runwar.servlet.RegexPathInfoFilter.class);
            filterInfo.addInitParam("regex", "^(/.+?\\.cf[cm]|/.+?\\.bx[sm])(/.*)");
            servletBuilder.addFilter(filterInfo);
            servletBuilder.addFilterUrlMapping("RegexPathInfoFilter", "/*", DispatcherType.REQUEST);
            servletBuilder.addFilterUrlMapping("RegexPathInfoFilter", "/*", DispatcherType.FORWARD);
        }
    }

    static List<URL> getJarList(String libDirs) throws IOException {
        List<URL> classpath = new ArrayList<>();
        String[] list = libDirs.split(",");
        for (String path : list) {
            if (".".equals(path) || "..".equals(path)) {
                continue;
            }

            File file = new File(path);
            if (file.exists() && file.isDirectory()) {
                File fileList[] = file.listFiles();
                for (File item : fileList) {
                    String directoryName = item.getAbsolutePath();
                    classpath.addAll(getJarList(directoryName));
                }
            } else if (file.exists() && file.isFile()) {
                String fileName = file.getAbsolutePath().toLowerCase();
                if (fileName.endsWith(".jar") || fileName.endsWith(".zip")) {
                    URL url = file.toURI().toURL();
                    classpath.add(url);
                    LOG.trace("  Lib: " + file.getAbsolutePath());
                }
            }
        }
        return classpath;
    }

    private void addCacheHandler(final DeploymentInfo servletBuilder) {
        // this handles mime types and adds a simple cache for static files
        servletBuilder.addInitialHandlerChainWrapper(handler -> {
            final ResourceHandler resourceHandler = new ResourceHandler(servletBuilder.getResourceManager());
            MimeMappings.Builder mimes = MimeMappings.builder();
            // add font mime types not included by default
            mimes.addMapping("eot", "application/vnd.ms-fontobject");
            mimes.addMapping("otf", "font/opentype");
            mimes.addMapping("ttf", "application/x-font-ttf");
            mimes.addMapping("woff", "application/x-font-woff");
            List<String> suffixList = new ArrayList<>(Arrays.asList(".eot", ".otf", ".ttf", ".woff"));
            // add the default types and any added in web.xml files
            for (MimeMapping mime : servletBuilder.getMimeMappings()) {
                LOG.debug("Adding mime-name: " + mime.getExtension() + " - " + mime.getMimeType());
                mimes.addMapping(mime.getExtension(), mime.getMimeType());
                suffixList.add("." + mime.getExtension());
            }
            resourceHandler.setMimeMappings(mimes.build());
            String[] suffixes = new String[suffixList.size()];
            suffixes = suffixList.toArray(suffixes);
            // simple cacheHandler, someday maybe make this configurable
            final CacheHandler cacheHandler = new CacheHandler(new DirectBufferCache(1024, 10, 10480), resourceHandler);
            return predicate(Predicates.suffixes(suffixes), cacheHandler, handler);
        });
    }

    void configureServlet(final DeploymentInfo servletBuilder) throws ClassNotFoundException {
        File webInfDir = serverOptions.webInfDir();
        configureURLRewrite(servletBuilder, webInfDir);
        configurePathInfoFilter(servletBuilder);

        if (serverOptions.getSites().get(0).cacheEnable()) {
            addCacheHandler(servletBuilder);
        } else {
            LOG.debug("  File cache is disabled");
        }

        if (serverOptions.customHTTPStatusEnable()) {
            servletBuilder.setSendCustomReasonPhraseOnError(true);
        }

        if (serverOptions.getSites().get(0).errorPages() != null) {
            for (Integer errorCode : serverOptions.getSites().get(0).errorPages().keySet()) {
                String location = serverOptions.getSites().get(0).errorPages().get(errorCode);
                if (errorCode == 1) {
                    servletBuilder.addErrorPage(new ErrorPage(location));
                } else {
                    servletBuilder.addErrorPage(new ErrorPage(location, errorCode));
                }
            }
        }

        // Default list of what the default servlet will serve
        // Add any custom additions by our users
        String allowedExt = "3gp,3gpp,7z,ai,aif,aiff,asf,asx,atom,au,avi,bin,bmp,btm,cco,crt,css,csv,deb,der,dmg,doc,docx,eot,eps,flv,font,gif,hqx,htc,htm,html,ico,img,ini,iso,jad,jng,jnlp,jpeg,jpg,js,json,kar,kml,kmz,m3u8,m4a,m4v,map,mid,midi,mml,mng,mov,mp3,mp4,mpeg,mpeg4,mpg,msi,msm,msp,ogg,otf,pdb,pdf,pem,pl,pm,png,ppt,pptx,prc,ps,psd,ra,rar,rpm,rss,rtf,run,sea,shtml,sit,svg,svgz,swf,tar,tcl,tif,tiff,tk,ts,ttf,txt,wav,wbmp,webm,webp,wmf,wml,wmlc,wmv,woff,woff2,xhtml,xls,xlsx,xml,xpi,xspf,zip,aifc,aac,apk,bak,bk,bz2,cdr,cmx,dat,dtd,eml,fla,gz,gzip,ipa,ia,indd,hey,lz,maf,markdown,md,mkv,mp1,mp2,mpe,odt,ott,odg,odf,ots,pps,pot,pmd,pub,raw,sdd,tsv,xcf,yml,yaml,handlebars,hbs";
        if (serverOptions.getSites().get(0).defaultServletAllowedExt().length() > 0) {
            allowedExt += "," + serverOptions.getSites().get(0).defaultServletAllowedExt();
        }

        allowedExt = allowedExt.toLowerCase();
        StringBuilder allowedExtBuilder = new StringBuilder();
        for (String ext : allowedExt.split(",")) {
            expandExtension(ext, allowedExtBuilder);
        }
        allowedExt = allowedExtBuilder.toString();
        if (allowedExt.endsWith(",")) {
            allowedExt = allowedExt.substring(0, allowedExt.length() - 1);
        }

        // this prevents us from having to use our own ResourceHandler (directory
        // listing, welcome files, see below) and error handler for now
        servletBuilder.addServlet(new ServletInfo(io.undertow.servlet.handlers.ServletPathMatches.DEFAULT_SERVLET_NAME,
                DefaultServlet.class)
                .addInitParam("directory-listing",
                        Boolean.toString(serverOptions.getSites().get(0).directoryListingEnable()))
                .addInitParam("default-allowed", "false")
                .addInitParam("allowed-extensions", allowedExt)
                .addInitParam("allow-post", "true"));

        List<?> welcomePages = servletBuilder.getWelcomePages();
        if (serverOptions.ignoreWebXmlWelcomePages()) {
            LOG.debug("  Ignoring web.xml welcome file, so adding server options welcome files to deployment manager.");
            servletBuilder.addWelcomePages(serverOptions.getSites().get(0).welcomeFiles());
        } else if (welcomePages.size() == 0) {
            servletBuilder.addWelcomePages(defaultWelcomeFiles);
        }

    }

    void configureRestMappings(final DeploymentInfo servletBuilder) {

        if (serverOptions.ignoreWebXmlRestMappings() && serverOptions.servletRestEnable()) {
            LOG.debug(
                    "  Overriding web.xml rest mappings with " + Arrays.toString(serverOptions.servletRestMappings()));
            for (Map.Entry<String, ServletInfo> stringServletInfoEntry : servletBuilder.getServlets().entrySet()) {
                ServletInfo restServlet = stringServletInfoEntry.getValue();
                // LOG.trace("Checking servlet named: " + restServlet.getName() + " to see if
                // it's a REST servlet.");
                if (restServlet.getName().toLowerCase().equals("restservlet")
                        || restServlet.getName().toLowerCase().equals("cfrestservlet")) {
                    for (String path : serverOptions.servletRestMappings()) {
                        restServlet.addMapping(path);
                        LOG.debug("  Added rest mapping: " + path + " to " + restServlet.getName());
                    }
                }
            }
        } else if (!serverOptions.servletRestEnable()) {
            LOG.trace("  REST servlets disabled");
        }

    }

    void expandExtension(String input, StringBuilder allowedExtBuilder) {
        char[] currentCombo = input.toCharArray();

        // Create a bit vector the same length as the input, and set all of the bits to
        // 1
        BitSet bv = new BitSet(input.length());
        bv.set(0, currentCombo.length);

        // While the bit vector still has some bits set
        while (!bv.isEmpty()) {
            // Loop through the array of characters and set each one to uppercase or
            // lowercase,
            // depending on whether its corresponding bit is set
            for (int i = 0; i < currentCombo.length; ++i) {
                if (bv.get(i)) // If the bit is set
                    currentCombo[i] = Character.toUpperCase(currentCombo[i]);
                else
                    currentCombo[i] = Character.toLowerCase(currentCombo[i]);
            }

            // append the current combination
            allowedExtBuilder.append(currentCombo);
            allowedExtBuilder.append(",");

            // Decrement the bit vector
            DecrementBitVector(bv, currentCombo.length);
        }

        // Now the bit vector contains all zeroes, which corresponds to all of the
        // letters being lowercase.
        // Simply append the input as lowercase for the final combination
        allowedExtBuilder.append(input.toLowerCase());
        allowedExtBuilder.append(",");
    }

    public void DecrementBitVector(BitSet bv, int numberOfBits) {
        int currentBit = numberOfBits - 1;
        while (currentBit >= 0) {
            bv.flip(currentBit);

            // If the bit became a 0 when we flipped it, then we're done.
            // Otherwise we have to continue flipping bits
            if (!bv.get(currentBit))
                break;
            currentBit--;
        }
    }

}
