package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;

import java.io.File;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import io.undertow.io.Sender;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.util.HeaderValues;
import io.undertow.util.Headers;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import runwar.LaunchUtil;
import runwar.RunwarConfigurer;
import runwar.options.ServerOptions;
import runwar.util.MaxContextsException;

@SuppressWarnings("deprecation")
public class BindingMatcherHandler implements HttpHandler {

    private ServerOptions serverOptions;
    private JSONObject bindings;
    private HashSet<String> deploymentKeyWarnings = new HashSet<String>();
    private SiteDeploymentManager siteDeploymentManager;
    private RunwarConfigurer configurer;
    private DeploymentInfo servletBuilder;
    private Map<String, Optional<JSONObject>> bindingSiteCache = new ConcurrentHashMap<String, Optional<JSONObject>>();
    private final String error404Site;

    public BindingMatcherHandler(ServerOptions serverOptions, SiteDeploymentManager siteDeploymentManager,
            RunwarConfigurer configurer, DeploymentInfo servletBuilder) {
        this.serverOptions = serverOptions;
        this.bindings = serverOptions.bindings();
        this.siteDeploymentManager = siteDeploymentManager;
        this.configurer = configurer;
        this.servletBuilder = servletBuilder;
        this.error404Site = LaunchUtil.getResourceAsString("runwar/error-404-site.html");
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        SiteDeployment deployment;
        String deploymentKey;
        ConcurrentHashMap<String, SiteDeployment> deployments = siteDeploymentManager.getDeployments();

        if (serverOptions.getSites().size() > 1) {
            String IP = exchange.getConnection().getLocalAddress(InetSocketAddress.class).getAddress().getHostAddress()
                    .toLowerCase();
            String port = String.valueOf(exchange.getConnection().getLocalAddress(InetSocketAddress.class).getPort());
            String hostName = exchange.getHostName().toLowerCase();
            JSONObject match;

            match = findBindingCached(IP, port, hostName);

            if (match == null) {
                String message = "Can't find a matching binding for IP [" + IP + "], port [" + port
                        + "], and hostname [" + hostName + "]";
                LOG.debug(message);
                final String errorPage = this.error404Site.replace("@@message@@", escapeHTML(message));
                exchange.setStatusCode(404);
                exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, "" + errorPage.length());
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                Sender sender = exchange.getResponseSender();
                sender.send(errorPage);
                return;
            }

            deploymentKey = (String) match.get("site");
            LOG.trace("Binding is for site: " + deploymentKey);
            exchange.putAttachment(SiteDeploymentManager.DEPLOYMENT_KEY, deploymentKey);
            deployment = deployments.get(deploymentKey);
        }

        // If we're not auto-creating contexts, then just pass to our default servlet
        // deployment
        else if (!serverOptions.autoCreateContexts()) {
            deployment = deployments.get(SiteDeployment.DEFAULT);

            // Otherwise, see if a deployment already exists
        } else {

            if (!isHeaderSafe(exchange, "", "X-Webserver-Context"))
                return;

            deploymentKey = exchange.getRequestHeaders().getFirst("X-Webserver-Context");
            if (deploymentKey == null) {
                deploymentKey = exchange.getHostName().toLowerCase();
            }
            // Save into the exchange for later in the thread
            exchange.putAttachment(SiteDeploymentManager.DEPLOYMENT_KEY, deploymentKey);

            deployment = deployments.get(deploymentKey);
            if (deployment == null) {

                if (!isHeaderSafe(exchange, deploymentKey, "X-Tomcat-DocRoot"))
                    return;
                String docRoot = exchange.getRequestHeaders().getFirst("X-Tomcat-DocRoot");

                if (docRoot != null && !docRoot.isEmpty()) {
                    File docRootFile = new File(docRoot);
                    if (docRootFile.exists() && docRootFile.isDirectory()) {

                        // Enforce X-ModCFML-SharedKey
                        if (!isHeaderSafe(exchange, deploymentKey, "X-ModCFML-SharedKey"))
                            return;
                        String modCFMLSharedKey = exchange.getRequestHeaders().getFirst("X-ModCFML-SharedKey");
                        if (modCFMLSharedKey == null) {
                            modCFMLSharedKey = "";
                        }

                        // If a secret was provided, enforce it
                        if (!serverOptions.autoCreateContextsSecret().equals("")
                                && !serverOptions.autoCreateContextsSecret().equals(modCFMLSharedKey)) {
                            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                            exchange.setStatusCode(403);
                            exchange.getResponseSender().send(
                                    "The web server's X-ModCFML-SharedKey was not supplied or doesn't match the configured secret.");
                            logOnce(deploymentKey, "SharedKeyNotMatch", "debug",
                                    "The web server's X-ModCFML-SharedKey [" + modCFMLSharedKey
                                            + "] was not supplied or doesn't match the auto-create-contexts-secret setting ["
                                            + (serverOptions.autoCreateContextsSecret() == null ? ""
                                                    : serverOptions.autoCreateContextsSecret())
                                            + "] for deploymentKey [" + deploymentKey + "].");
                            return;
                        }
                        String vDirs = null;
                        if (serverOptions.autoCreateContextsVDirs()) {
                            if (!isHeaderSafe(exchange, deploymentKey, "x-vdirs"))
                                return;
                            vDirs = exchange.getRequestHeaders().getFirst("x-vdirs");
                            if (vDirs != null && !vDirs.isEmpty()) {
                                // Ensure we can trust the x-vdirs header. Only use it if the x-vdirs-sharedkey
                                // header is also supplied with the shared key
                                if (!isHeaderSafe(exchange, deploymentKey, "x-vdirs-sharedkey"))
                                    return;
                                String vDirsSharedKey = exchange.getRequestHeaders().getFirst("x-vdirs-sharedkey");
                                if (vDirsSharedKey == null || vDirsSharedKey.isEmpty()) {
                                    vDirs = null;
                                    logOnce(deploymentKey, "NovDirsSharedKey", "warn",
                                            "The x-vdirs header was provided, but it is being ignored because no x-vdirs-sharedkey header is present.");
                                } else {
                                    // If a secret was provided, enforce it
                                    if (!serverOptions.autoCreateContextsSecret().equals("")
                                            && !serverOptions.autoCreateContextsSecret().equals(vDirsSharedKey)) {
                                        vDirs = null;
                                        logOnce(deploymentKey, "VDirsSharedKeyNotMatch", "warn",
                                                "The x-vdirs header was provided, but it is being ignored because the x-vdirs-sharedkey header ["
                                                        + vDirsSharedKey
                                                        + "] doesn't match the auto-create-contexts-secret setting ["
                                                        + (serverOptions.autoCreateContextsSecret() == null ? ""
                                                                : serverOptions.autoCreateContextsSecret())
                                                        + "] for deploymentKey [" + deploymentKey + "].");
                                    }
                                }
                            }
                        }
                        try {
                            deployment = siteDeploymentManager.createSiteDeployment(servletBuilder, docRootFile,
                                    configurer, deploymentKey, vDirs, serverOptions.getSites().get(0));
                        } catch (MaxContextsException e) {

                            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                            exchange.setStatusCode(500);
                            exchange.getResponseSender().send(e.getMessage());

                            logOnce(deploymentKey, "MaxContextsException", "error",
                                    e.getMessage() + "  The requested deploymentKey was [" + deploymentKey + "]");
                            return;
                        }
                    } else {
                        LOG.warn("X-Tomcat-DocRoot of [" + docRoot
                                + "] does not exist or is not directory.  Using default context.");
                        deployment = deployments.get(SiteDeployment.DEFAULT);
                    }
                } else {
                    logOnce(deploymentKey, "NoDocRootHeader", "warn",
                            "X-Tomcat-DocRoot is null or empty.  Using default context for deploymentKey ["
                                    + deploymentKey + "].");
                    deployment = deployments.get(SiteDeployment.DEFAULT);
                }

            }
        }

        // Save into the exchange for later in the thread
        exchange.putAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY, deployment);
        deployment.processRequest(exchange);

    }

    /**
     * Caches found bindings in a HashMap. This serves as a simple cache, but it is
     * possible to send a huge amount of
     * requests with random hostnames to the server and "fill up" the Map as there
     * is reaping mechanism. As such,
     * we'll only cache the first 10,000 IP/port/hostname combinations we see.
     */
    private JSONObject findBindingCached(String IP, String port, String hostName) {
        String cacheBindingKey = IP + ":" + port + ":" + hostName;
        if (bindingSiteCache.containsKey(cacheBindingKey)) {
            Optional<JSONObject> match = bindingSiteCache.get(cacheBindingKey);
            if (match.isPresent()) {
                return match.get();
            } else {
                return null;
            }
        }
        // May be null, but we still want to cache even that
        Optional<JSONObject> match = Optional.ofNullable(findBinding(IP, port, hostName));
        // A little protection to prevent an unlimited number of incoming hostname
        // variations from eating up crazy memory
        if (bindingSiteCache.size() < 10000) {
            bindingSiteCache.put(cacheBindingKey, match);
        }
        if (match.isPresent()) {
            return match.get();
        } else {
            return null;
        }
    }

    /**
     * Binding lookup order is as follows (in order):
     * - Exact IP and hostname match
     * - Exact IP and hostname ends with match
     * - Exact IP and hostname starts with match
     * - Exact IP and hostname regex match
     * - Any IP and hostname exact match
     * - Any IP and hostname ends with match
     * - Any IP and hostname starts with match
     * - Any IP and hostname regex match
     * - Exact IP and any hostname
     * - Any IP and any hostname
     * - Default site
     *
     * Note, the port always must match, unless there is a default site, then we
     * don't care.
     */
    private JSONObject findBinding(String IP, String port, String hostName) {
        JSONObject match;

        // 1. Try exact IP and hostname match
        String bindingKey = IP + ":" + port + ":" + hostName;
        LOG.trace("Trying binding key: " + bindingKey);
        match = (JSONObject) bindings.get(bindingKey);
        if (match != null)
            return match;

        // 2. Try exact IP and hostname ends with match
        match = findHostWildcardEndsWith(hostName, bindings, IP + ":" + port + "::endswith:");
        if (match != null)
            return match;

        // 3. Try exact IP and hostname starts with match
        match = findHostWildcardStartsWith(hostName, bindings, IP + ":" + port + "::startswith:");
        if (match != null)
            return match;

        // 4. Try exact IP and hostname regex match
        match = findHostWildcardRegex(hostName, bindings, IP + ":" + port + "::regex:");
        if (match != null)
            return match;

        // 5. Try Any IP and hostname exact match
        bindingKey = "0.0.0.0:" + port + ":" + hostName;
        LOG.trace("Trying binding key: " + bindingKey);
        match = (JSONObject) bindings.get(bindingKey);
        if (match != null)
            return match;

        // 6. Try any IP and hostname ends with match
        match = findHostWildcardEndsWith(hostName, bindings, "0.0.0.0:" + port + "::endswith:");
        if (match != null)
            return match;

        // 7. Try any IP and hostname starts with match
        match = findHostWildcardStartsWith(hostName, bindings, "0.0.0.0:" + port + "::startswith:");
        if (match != null)
            return match;

        // 8. Try Any IP and hostname regex match
        match = findHostWildcardRegex(hostName, bindings, "0.0.0.0:" + port + "::regex:");
        if (match != null)
            return match;

        // 9. Try Exact IP and any hostname
        bindingKey = IP + ":" + port + ":*";
        LOG.trace("Trying binding key: " + bindingKey);
        match = (JSONObject) bindings.get(bindingKey);
        if (match != null)
            return match;

        // 10. Try Any IP and any hostname
        bindingKey = "0.0.0.0:" + port + ":*";
        LOG.trace("Trying binding key: " + bindingKey);
        match = (JSONObject) bindings.get(bindingKey);
        if (match != null)
            return match;

        // 11. Look for a default site
        bindingKey = "default";
        LOG.trace("Trying binding key: " + bindingKey);
        match = (JSONObject) bindings.get(bindingKey);

        // Match can still be null if there was no default site
        return match;
    }

    private JSONObject findHostWildcardEndsWith(String hostName, JSONObject bindings, String bindingKey) {
        JSONArray options = (JSONArray) bindings.get(bindingKey);
        if (options == null) {
            return null;
        }
        for (Object option : options) {
            JSONObject binding = (JSONObject) option;
            String thisOptionMatch = (String) (binding.get("endsWithMatch"));
            LOG.trace("Checking if [" + hostName + "] ends with [" + thisOptionMatch + "] for binding [" + bindingKey
                    + "]");
            if (hostName.endsWith(thisOptionMatch)) {
                return binding;
            }
        }
        return null;
    }

    private JSONObject findHostWildcardStartsWith(String hostName, JSONObject bindings, String bindingKey) {
        JSONArray options = (JSONArray) bindings.get(bindingKey);
        if (options == null) {
            return null;
        }
        for (Object option : options) {
            JSONObject binding = (JSONObject) option;
            String thisOptionMatch = (String) (binding.get("startsWithMatch"));
            LOG.trace("Checking if [" + hostName + "] starts with [" + thisOptionMatch + "] for binding [" + bindingKey
                    + "]");
            if (hostName.startsWith(thisOptionMatch)) {
                return binding;
            }
        }
        return null;
    }

    private JSONObject findHostWildcardRegex(String hostName, JSONObject bindings, String bindingKey) {
        JSONArray options = (JSONArray) bindings.get(bindingKey);
        if (options == null) {
            return null;
        }
        for (Object option : options) {
            JSONObject binding = (JSONObject) option;
            Pattern thisOptionMatch = (Pattern) binding.get("pattern");
            String thisOptionStr = (String) (binding.get("regexMatch"));
            LOG.trace("Checking if [" + hostName + "] matches the regex [" + thisOptionStr + "] for binding ["
                    + bindingKey + "]");
            if (thisOptionMatch.matcher(hostName).matches()) {
                return binding;
            }
        }
        return null;
    }

    private void logOnce(String deploymentKey, String type, String severity, String message) {
        String logKey = deploymentKey + type;
        severity = severity.toLowerCase();
        if (!deploymentKeyWarnings.contains(logKey)) {
            deploymentKeyWarnings.add(logKey);
            switch (severity) {
                case "trace":
                    LOG.trace(message);
                    break;
                case "debug":
                    LOG.debug(message);
                    break;
                case "info":
                    LOG.info(message);
                    break;
                case "warn":
                    LOG.warn(message);
                    break;
                case "error":
                    LOG.error(message);
                    break;
                case "fatal":
                    LOG.fatal(message);
                    break;
                default:
                    LOG.info(message);
            }

        }
    }

    private Boolean isHeaderSafe(HttpServerExchange exchange, String deploymentKey, String headerName) {
        HeaderValues headerValues = exchange.getRequestHeaders().get(headerName);
        if (headerValues != null && headerValues.size() > 1) {
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
            exchange.setStatusCode(403);
            exchange.getResponseSender().send("The request header [" + headerName + "] was supplied "
                    + headerValues.size()
                    + " times which is likely a configuration error.  CommandBox won't serve requests with fishy ModCFML headers for security.");
            logOnce(deploymentKey, "SharedKeyNotMatch", "debug",
                    "The request header [" + headerName + "] was supplied " + headerValues.size()
                            + " times which is likely a configuration error. The values are " + headerValues.toString()
                            + ""
                            + ".  CommandBox won't serve requests with fishy ModCFML headers for security.");
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "Runwar HostHandler";
    }

    private String escapeHTML(String text) {
        return text
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("&", "&amp;");
    }
}
