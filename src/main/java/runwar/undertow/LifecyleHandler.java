package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;

import io.undertow.io.Sender;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.server.DefaultResponseListener;
import runwar.logging.RunwarLogger;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import runwar.Server;
import runwar.LaunchUtil;
import java.util.Map;
import java.util.HashMap;
import jakarta.servlet.RequestDispatcher;

public class LifecyleHandler implements HttpHandler {

    private final HttpHandler next;
    private final ServerOptions serverOptions;
    private final SiteOptions siteOptions;
    private final Map<Integer, String> errorPages;
    private final String error401;
    private final String error403;
    private final String error404;
    private final String error500;
    private final String errorDefault;

    LifecyleHandler(final HttpHandler next, ServerOptions serverOptions, SiteOptions siteOptions) {
        this.next = next;
        this.serverOptions = serverOptions;
        this.siteOptions = siteOptions;
        this.errorPages = siteOptions.errorPages();
        this.error401 = LaunchUtil.getResourceAsString("runwar/error-401.html");
        this.error403 = LaunchUtil.getResourceAsString("runwar/error-403.html");
        this.error404 = LaunchUtil.getResourceAsString("runwar/error-404.html");
        this.error500 = LaunchUtil.getResourceAsString("runwar/error-500.html");
        this.errorDefault = LaunchUtil.getResourceAsString("runwar/error-default.html");
    }

    @Override
    public void handleRequest(final HttpServerExchange inExchange) throws Exception {

        Map<String, String> requestAttrs = inExchange.getAttachment(inExchange.REQUEST_ATTRIBUTES);
        if (requestAttrs == null) {
            inExchange.putAttachment(HttpServerExchange.REQUEST_ATTRIBUTES, requestAttrs = new HashMap<>());
        }
        final Map<String, String> attrs = requestAttrs;

        if (!attrs.containsKey("default-response-handler")) {
            inExchange.addExchangeCompleteListener((httpServerExchange, nextListener) -> {
                if (serverOptions.debug() && httpServerExchange.getStatusCode() > 399) {
                    LOG.warnf("responded: Status Code %s (%s)", httpServerExchange.getStatusCode(),
                            Server.fullExchangePath(httpServerExchange));
                }
                nextListener.proceed();
            });
        }

        // This only fires if there is no response returned from the exchange
        // An example would be using the response-code handler which simply ends the
        // exchange
        inExchange.addDefaultResponseListener(exchange -> {

            if (!exchange.isResponseChannelAvailable()) {
                return false;
            }

            if (exchange.getStatusCode() > 399) {
                final String customErrorPage = errorPages.containsKey(exchange.getStatusCode())
                        ? errorPages.get(exchange.getStatusCode())
                        : errorPages.get(1);

                // If the custom error page errors, then prevent endless looping by rendering a
                // fail-safe error page
                // Also do this if there is no custom error page
                if (attrs.containsKey("default-response-handler") || customErrorPage == null) {
                    if (attrs.containsKey("default-response-handler")) {
                        exchange.setStatusCode(Integer.parseInt(attrs.get("default-response-handler")));
                    }
                    LOG.debug("Dispatching default error page " + exchange.getStatusCode());

                    final String errorPage = getDefaultErrorPage(exchange.getStatusCode());
                    exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, "" + errorPage.length());
                    exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                    Sender sender = exchange.getResponseSender();
                    sender.send(errorPage);
                    return true;
                }

                LOG.debug("Dispatching custom " + exchange.getStatusCode() + " error page: [" + customErrorPage + "]");
                attrs.put("default-response-handler", String.valueOf(exchange.getStatusCode()));

                try {
                    int originalStatusCode = exchange.getStatusCode();

                    // Mimic servlet request attribute behavior
                    if (attrs.get(RequestDispatcher.FORWARD_REQUEST_URI) == null) {
                        attrs.put(RequestDispatcher.FORWARD_REQUEST_URI, exchange.getRequestURI());
                        attrs.put(RequestDispatcher.FORWARD_CONTEXT_PATH, "");
                        attrs.put(RequestDispatcher.FORWARD_SERVLET_PATH, "");
                        attrs.put(RequestDispatcher.FORWARD_PATH_INFO, "");
                        attrs.put(RequestDispatcher.FORWARD_QUERY_STRING,
                                exchange.getQueryString().isEmpty() ? "" : "?" + exchange.getQueryString());
                    }
                    attrs.put(RequestDispatcher.ERROR_REQUEST_URI, exchange.getRequestURI());
                    attrs.put(RequestDispatcher.ERROR_SERVLET_NAME, "");

                    Throwable exception = exchange.getAttachment(DefaultResponseListener.EXCEPTION);
                    if (exception != null) {
                        // attrs.put(RequestDispatcher.ERROR_EXCEPTION, exception);
                        // attrs.put(RequestDispatcher.ERROR_EXCEPTION_TYPE, exception.getClass());
                        // The lines above won't work because undertow doesn't allow anything but
                        // strings
                        // in request attributes in the exchange, even though the servlet allows
                        // anything.
                        // I'll use these string representations for now.
                        attrs.put(RequestDispatcher.ERROR_EXCEPTION, exception.toString());
                        attrs.put(RequestDispatcher.ERROR_EXCEPTION_TYPE, exception.getClass().getName());
                        attrs.put(RequestDispatcher.ERROR_MESSAGE, exception.getMessage());
                    } else {
                        attrs.put(RequestDispatcher.ERROR_MESSAGE, StatusCodes.getReason(exchange.getStatusCode()));
                    }
                    attrs.put(RequestDispatcher.ERROR_STATUS_CODE, String.valueOf(exchange.getStatusCode()));

                    // If we keep the error status and our error handler is a .cfm, the servlet will
                    // reject request
                    // It's up to any CFML custom error handlers to set their own status code
                    exchange.setStatusCode(200);
                    ExchangeAttributes.relativePath().writeAttribute(exchange, customErrorPage);
                    exchange.getAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY).processRequest(exchange);

                    exchange.endExchange();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                return true;
            }

            return false;
        });

        LOG.debug("requested: '" + Server.fullExchangePath(inExchange) + "'");
        next.handleRequest(inExchange);
    }

    private String getDefaultErrorPage(int statusCode) {
        if (statusCode == 401) {
            return this.error401;
        } else if (statusCode == 403) {
            return this.error403;
        } else if (statusCode == 404) {
            return this.error404;
        } else if (statusCode == 500) {
            return this.error500;
        } else {
            return this.errorDefault
                    .replace("@@statusCode@@", String.valueOf(statusCode))
                    .replace("@@statusText@@", escapeHTML(StatusCodes.getReason(statusCode)));

        }
    }

    private String escapeHTML(String text) {
        return text
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("&", "&amp;");
    }
}