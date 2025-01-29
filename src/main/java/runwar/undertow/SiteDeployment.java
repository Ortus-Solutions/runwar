package runwar.undertow;

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
import io.undertow.util.CanonicalPathUtils;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderValues;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.util.Headers;
import io.undertow.server.HttpHandler;
import io.undertow.util.HttpString;
import io.undertow.util.MimeMappings;
import io.undertow.io.Sender;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import io.undertow.server.handlers.MetricsHandler;
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
import runwar.undertow.SSLCertHeaderHandler;
import runwar.undertow.LifecyleHandler;
import runwar.undertow.WelcomeFileHandler;
import runwar.undertow.handler.WarmUpServer;
import runwar.util.ClassLoaderUtils;
import runwar.util.RequestDumper;
import runwar.Server;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;
import java.util.List;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.server.HandlerWrapper;

import static runwar.logging.RunwarLogger.LOG;
import static runwar.logging.RunwarLogger.MAPPER_LOG;

@SuppressWarnings("deprecation")
public class SiteDeployment {

    private final HttpHandler siteInitialHandler;
    private final HttpHandler servletInitialHandler;
    private WebsocketHandler websocketHandler;
    private MetricsHandler siteMetricsHandler;
    private final DeploymentManager deploymentManager;
    private SecurityManager securityManager;
    private final ResourceManager resourceManager;
    private final SiteOptions siteOptions;
    // Will be null if access logging is off for this site
    private XnioWorker logWorker;
    // Provides a context for this site deployment to store items, such as rewrite
    // maps
    private volatile Map<String, Object> deploymentContext = new ConcurrentHashMap<String, Object>();

    public final static String DEFAULT = "default";

    public SiteDeployment(HttpHandler servletInitialHandler, DeploymentManager deploymentManager,
            SiteOptions siteOptions, ServerOptions serverOptions, ResourceManager resourceManager) throws Exception {
        this.deploymentManager = deploymentManager;
        this.servletInitialHandler = servletInitialHandler;
        this.resourceManager = resourceManager;
        this.siteOptions = siteOptions;
        this.siteInitialHandler = buildSiteHandlerChain(servletInitialHandler, serverOptions);
    }

    private HttpHandler buildSiteHandlerChain(HttpHandler servletInitialHandler, ServerOptions serverOptions)
            throws Exception {

        // Used to provide a hint to each warmup handler instance what site name it is
        // part of
        WarmUpServer.currentSite = siteOptions;

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

                String requestPath = exchange.getRequestPath();
                while (!requestPath.isEmpty() && (requestPath.startsWith("/") || requestPath.startsWith("\\"))) {
                    requestPath = requestPath.substring(1);
                }
                requestPath = requestPath.toUpperCase();
                // Undertow has checks for this, but a more careful check is required with a
                // case insensitive resource manager
                if (!requestPath.isEmpty()
                        && (requestPath.startsWith("WEB-INF/") || requestPath.startsWith("WEB-INF\\"))) {
                    LOG.trace("Blocking suspicious access to : " + exchange.getRequestPath());
                    // Not ending the exchange here so the servlet can still send any custom error
                    // page.
                    exchange.setStatusCode(404);
                }

                // Then ensures any error status codes set in our predicate/server rules don't
                // go any further
                // The default response listener on the exchange will render the appropriate
                // error page for us.
                if (exchange.getStatusCode() > 399) {
                    exchange.endExchange();
                    return;
                }
                super.handleRequest(exchange);
            }

            @Override
            public String toString() {
                return "Runwar PathHandler";
            }
        };

        MimeMappings.Builder mimeMappings = MimeMappings.builder();
        if (siteOptions.mimeTypes().size() > 0) {
            LOG.debugf("  Adding Mime types");
        }
        siteOptions.mimeTypes().forEach((ext, contentType) -> {
            LOG.tracef("  - %s = '%s'", ext, contentType);
            mimeMappings.addMapping(ext, contentType);
        });
        // Only needed until this is complete:
        // https://issues.redhat.com/browse/UNDERTOW-2218
        mimeMappings.addMapping("webp", "image/webp");

        ResourceManager resourceManager = getResourceManager();

        final HttpHandler resourceHandler = new ResourceHandler(resourceManager)
                .setDirectoryListingEnabled(siteOptions.directoryListingEnable())
                .setMimeMappings(mimeMappings.build());

        // Default list of what the default servlet will serve
        String allowedExt = "3gp,3gpp,7z,ai,aif,aiff,asf,asx,atom,au,avi,bin,bmp,btm,cco,crt,css,csv,deb,der,dmg,doc,docx,eot,eps,flv,font,gif,hqx,htc,htm,html,ico,img,ini,iso,jad,jng,jnlp,jpeg,jpg,js,json,kar,kml,kmz,m3u8,m4a,m4v,map,mid,midi,mml,mng,mov,mp3,mp4,mpeg,mpeg4,mpg,msi,msm,msp,ogg,otf,pdb,pdf,pem,pl,pm,png,ppt,pptx,prc,ps,psd,ra,rar,rpm,rss,rtf,run,sea,shtml,sit,svg,svgz,swf,tar,tcl,tif,tiff,tk,ts,ttf,txt,wav,wbmp,webm,webp,wmf,wml,wmlc,wmv,woff,woff2,xhtml,xls,xlsx,xml,xpi,xspf,zip,aifc,aac,apk,bak,bk,bz2,cdr,cmx,dat,dtd,eml,fla,gz,gzip,ipa,ia,indd,hey,lz,maf,markdown,md,mkv,mp1,mp2,mpe,odt,ott,odg,odf,ots,pps,pot,pmd,pub,raw,sdd,tsv,xcf,yml,yaml,handlebars,hbs"; // Add
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // any
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // custom
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // additions
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // by
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // our
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              // users
        if (siteOptions.defaultServletAllowedExt().length() > 0) {
            allowedExt += "," + siteOptions.defaultServletAllowedExt();
            LOG.trace("  Additional extensions allowed by the resource handler for static files: "
                    + siteOptions.defaultServletAllowedExt());
        }

        // Put allowed extensions for faster lookup
        Set<String> extSet = new HashSet<String>();
        Collections.addAll(extSet, allowedExt.toLowerCase().split(","));

        HttpHandler allowedExtensions = new HttpHandler() {

            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                String CononicalURI = CanonicalPathUtils.canonicalize(exchange.getRelativePath());
                Resource resource = resourceManager
                        .getResource(CononicalURI);
                if (resource != null && !resource.isDirectory()) {
                    String ext = resource.getFile().getName().toLowerCase();
                    if (ext.contains(".")) {
                        ext = ext.substring(ext.lastIndexOf(".") + 1);
                    }

                    // Whitelist the /.well-known/ directory
                    if (!CononicalURI.startsWith("/.well-known/") && !extSet.contains(ext)) {
                        LOG.debug(
                                "Blocking access to [" + exchange.getRelativePath() + "] based on allowed extensions.");
                        exchange.setStatusCode(403);
                        return;
                    }
                }
                resourceHandler.handleRequest(exchange);
            }

            @Override
            public String toString() {
                return "Default status code Handler";
            }
        };

        // In the event we are rendering a custom error page and the servlet is NOT
        // processing it, then put the original
        // status code back before the resource handler closes the response channel
        HttpHandler defaultStatusCodeHandler = new HttpHandler() {
            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                Map<String, String> requestAttrs = exchange.getAttachment(exchange.REQUEST_ATTRIBUTES);
                if (requestAttrs != null && requestAttrs.containsKey("default-response-handler")) {
                    exchange.setStatusCode(Integer.parseInt(requestAttrs.get("default-response-handler")));
                }
                allowedExtensions.handleRequest(exchange);
            }

            @Override
            public String toString() {
                return "Default status code Handler";
            }
        };

        HttpHandler CFOrStaticHandler = Handlers.predicate(
                Predicates.parse(siteOptions.servletPassPredicate()),
                servletInitialHandler,
                defaultStatusCodeHandler);

        HttpHandler welcomeFileHandler = new WelcomeFileHandler(CFOrStaticHandler, resourceManager,
                Arrays.asList(siteOptions.welcomeFiles()));

        pathHandler.addPrefixPath(serverOptions.contextPath(), welcomeFileHandler);
        HttpHandler httpHandler = pathHandler;

        if (siteOptions.predicateText() != null && siteOptions.predicateText().length() > 0) {
            LOG.debug("  Adding Server Rules");
            LOG.trace(siteOptions.predicateText());

            List<PredicatedHandler> ph = PredicatedHandlersParser.parse(siteOptions.predicateText(),
                    Server.getClassLoader());

            httpHandler = Handlers.predicates(ph, httpHandler);
        }

        if (siteOptions.gzipEnable()) {
            // the default packet size on the internet is 1500 bytes so
            // any file less than 1.5k can be sent in a single packet
            if (siteOptions.gzipPredicate() != null) {
                LOG.debug("  Setting GZIP predicate to = " + siteOptions.gzipPredicate());
            }
            // The max-content-size predicate was replaced with request-larger-than
            httpHandler = new EncodingHandler(new ContentEncodingRepository().addEncodingHandler(
                    "gzip", new GzipEncodingProvider(), 50, Predicates.parse(siteOptions.gzipPredicate())))
                    .setNext(httpHandler);
        }

        if (siteOptions.logAccessEnable()) {

            // separate log worker to prevent logging-caused bottleneck
            Xnio xnio = Xnio.getInstance("nio", Server.class.getClassLoader());
            XnioWorker logWorker = xnio.createWorker(OptionMap.builder()
                    .set(Options.WORKER_IO_THREADS, 2)
                    .set(Options.CONNECTION_HIGH_WATER, 1000000)
                    .set(Options.CONNECTION_LOW_WATER, 1000000)
                    .set(Options.WORKER_TASK_CORE_THREADS, 2)
                    .set(Options.WORKER_TASK_MAX_THREADS, 2)
                    .set(Options.TCP_NODELAY, true)
                    .set(Options.CORK, true)
                    .getMap());

            RunwarAccessLogReceiver accessLogReceiver = RunwarAccessLogReceiver.builder().setLogWriteExecutor(logWorker)
                    .setRotate(true)
                    .setOutputDirectory(siteOptions.logAccessDir().toPath())
                    .setLogBaseName(siteOptions.logAccessBaseFileName())
                    .setLogNameSuffix(serverOptions.logSuffix())
                    .build();
            LOG.debug("  Logging combined access to " + siteOptions.logAccessDir() + " base name of '"
                    + siteOptions.logAccessBaseFileName() + "." + serverOptions.logSuffix() + ", rotated daily'");
            httpHandler = new AccessLogHandler(httpHandler, accessLogReceiver, "combined",
                    Server.class.getClassLoader());
        }

        if (siteOptions.proxyPeerAddressEnable()) {
            LOG.debug("  Enabling Proxy Peer Address handling");
            httpHandler = new ProxyPeerAddressHandler(httpHandler);
        }

        if (siteOptions.clientCertTrustHeaders()) {
            LOG.debug("  Checking for upstream client cert HTTP headers");
            httpHandler = new SSLHeaderHandler(httpHandler);
        }

        if (siteOptions.basicAuthEnable() || siteOptions.clientCertEnable()) {
            this.securityManager = new SecurityManager();
            httpHandler = this.securityManager.configureAuth(siteOptions, httpHandler);
        }

        if (siteOptions.metricsEnable()) {
            this.siteMetricsHandler = new MetricsHandler(httpHandler);
            httpHandler = this.siteMetricsHandler;
        }

        httpHandler = new LifecyleHandler(httpHandler, serverOptions, siteOptions);

        if (siteOptions.webSocketEnable()) {
            LOG.info("  WebSocket Server started");
            httpHandler = new WebsocketHandler(httpHandler, serverOptions, siteOptions);
            this.websocketHandler = (WebsocketHandler) httpHandler;
        }

        return httpHandler;
    }

    public void processRequest(HttpServerExchange exchange) throws Exception {
        HttpHandler exchangeSetter = new HttpHandler() {
            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                try {
                    // This allows the exchange to be available to the thread.
                    Server.setCurrentExchange(exchange);
                    siteInitialHandler.handleRequest(exchange);
                } finally {
                    // Clean up after
                    Server.setCurrentExchange(null);
                }
            }

            @Override
            public String toString() {
                return "Exchange Setter Handler";
            }
        };
        if (exchange.isInIoThread()) {
            exchange.dispatch(exchangeSetter);
        } else {
            exchangeSetter.handleRequest(exchange);
        }
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

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public ResourceManager getResourceManager() {
        return resourceManager;
    }

    public Map<String, Object> getDeploymentContext() {
        return deploymentContext;
    }

    public SiteOptions getSiteOptions() {
        return siteOptions;
    }

    public MetricsHandler getSiteMetricsHandler() {
        return siteMetricsHandler;
    }

    public WebsocketHandler getWebsocketHandler() {
        return websocketHandler;
    }

    public void stop() {
        try {
            switch (deploymentManager.getState()) {
                case UNDEPLOYED:
                    break;
                default:
                    deploymentManager.stop();
                    deploymentManager.undeploy();
            }
            if (logWorker != null) {
                logWorker.shutdown();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}