package runwar.undertow.handler;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

import io.undertow.UndertowLogger;
import io.undertow.server.Connectors;
import io.undertow.server.ExchangeCompletionListener;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.ResponseCodeHandler;
import io.undertow.server.handlers.builder.HandlerBuilder;
import io.undertow.util.SameThreadExecutor;

/**
 * A {@link HttpHandler} that warms the server up by hitting 1 or more URLs.
 * Options to reject (503) or queue traffic in the mean time
 *
 * @author Brad Wood
 */
public final class WarmUpServer implements HttpHandler {

    public static enum RequestStrategy {
        QUEUE,
        ALLOW,
        BLOCK;

        public static RequestStrategy fromString(String strategy) {
            for (RequestStrategy s : RequestStrategy.values()) {
                if (s.name().equalsIgnoreCase(strategy)) {
                    return s;
                }
            }
            throw new IllegalArgumentException("Invalid request strategy: " + strategy);
        }
    }

    /**
     * I track all the warmup handlers which need triggered when the server is ready
     */
    private static List<WarmUpServer> warmUpServers = new ArrayList<>();

    /**
     * * The current site name, used on bootstrap to know what site we belong to
     */
    public static String currentSiteName = "default";

    /**
     * If true, requests will be blocked until the server is warm.
     */
    private volatile boolean block = true;

    /**
     * The handler that will be invoked if the queue is full.
     */
    private volatile HttpHandler failureHandler = new ResponseCodeHandler(503);

    /**
     * The queue of requests that are waiting to be dispatched.
     * Hardcoded limit of 10000 queued requests for now
     */
    private final Queue<SuspendedRequest> queuedRequests = new LinkedBlockingQueue<>(10000);

    /**
     * The next handler in the chain
     */
    private HttpHandler next;

    /**
     * The URLs to hit to warm up the server
     */
    private String[] urls;

    /**
     * If true, requests will be queued until the server is warm as opposed to
     * blocked with a 503.
     */
    private RequestStrategy requestStrategy;

    /**
     * If true, the URLs will be hit asynchronously. If false, they will be hit
     * synchronously.
     */
    private Boolean async;

    /**
     * The timeout in milliseconds for each URL hit
     */
    private Long timeoutMS;

    /**
     * The name of the site this handler is warming up
     */
    private String thisSiteName = currentSiteName;

    /**
     * The listener that will be attached to each request to check if queued
     * requests can be dispatched
     */
    private final ExchangeCompletionListener COMPLETION_LISTENER = new ExchangeCompletionListener() {

        @Override
        public void exchangeEvent(final HttpServerExchange exchange, final NextListener nextListener) {
            SuspendedRequest req = null;

            while ((req = queuedRequests.poll()) != null) {
                try {
                    req.exchange.addExchangeCompleteListener(COMPLETION_LISTENER);
                    req.exchange.dispatch(req.next);
                    break;
                } catch (Throwable e) {
                    UndertowLogger.PREDICATE_LOGGER.error("Suspended request was skipped", e);
                }
            }

            nextListener.proceed();
        }
    };

    public WarmUpServer(final HttpHandler next, String[] urls, RequestStrategy requestStrategy,
            Boolean async,
            Integer timeoutSeconds) {
        this.next = next;
        this.urls = urls;
        this.requestStrategy = requestStrategy;
        this.async = async;
        this.timeoutMS = timeoutSeconds.longValue() * 1000L;

        // Register this server for warmup
        warmUpServers.add(this);
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // Just process like normal if we're not blocking requests, or this is a warmup
        // request
        boolean isWarmupRequest = isWarmupRequest(exchange);
        if (requestStrategy.equals(RequestStrategy.ALLOW) || isWarmupRequest) {
            next.handleRequest(exchange);
            return;
        }

        // If we're not warm, and we're blocking requests, then end it here
        if (block && requestStrategy.equals(RequestStrategy.BLOCK)) {
            UndertowLogger.PREDICATE_LOGGER.debug(
                    "Site [" + thisSiteName + "] Blocking request [" + exchange.getRequestURL()
                            + "] because site is still warming up");
            // Send a 503 and quit.
            Connectors.executeRootHandler(failureHandler, exchange);
            return;
        }

        // If we're queuing, then we have more work to do
        if (block) {
            // If this is a warmup request, it will run, but tack on a complete listener so
            // it can start emptying the queue when it's done
            if (isWarmupRequest) {
                exchange.addExchangeCompleteListener(COMPLETION_LISTENER);
            } else {

                exchange.dispatch(SameThreadExecutor.INSTANCE, new Runnable() {
                    @Override
                    public void run() {
                        // we have to try again in the sync block
                        // we need to have already dispatched for thread safety reasons
                        synchronized (WarmUpServer.this) {
                            if (block) {
                                UndertowLogger.PREDICATE_LOGGER.debug(
                                        "Site [" + thisSiteName + "] queuing request ["
                                                + exchange.getRequestURL()
                                                + "] because site is still warming up");
                                if (!queuedRequests.offer(new SuspendedRequest(exchange, next))) {

                                    UndertowLogger.PREDICATE_LOGGER.warn("Site [" + thisSiteName
                                            + "] warmup queue is full, rejecting request ["
                                            + exchange.getRequestURL() + "]");
                                    Connectors.executeRootHandler(failureHandler, exchange);
                                }
                                return;
                            }
                            exchange.dispatch(next);
                        }
                    }
                });
                return;

            }

        }

        if (!block && queuedRequests.size() > 0) {
            exchange.addExchangeCompleteListener(COMPLETION_LISTENER);
        }
        next.handleRequest(exchange);
    }

    private boolean isWarmupRequest(HttpServerExchange exchange) {
        return exchange.getRequestHeaders().contains("__site__warmup__");
    }

    public HttpHandler getFailureHandler() {
        return failureHandler;
    }

    public void setFailureHandler(HttpHandler failureHandler) {
        this.failureHandler = failureHandler;
    }

    public void triggerWarmup() {
        Runnable task = new Runnable() {
            @Override
            public void run() {
                try {
                    UndertowLogger.PREDICATE_LOGGER.info("Site [" + thisSiteName + "] warming up with "
                            + urls.length
                            + " URL(s) "
                            + (async ? "asynchronously" : "synchronously") + " with a timeout of " + timeoutMS + " ms");
                    long theTimeoutMS = timeoutMS;
                    Thread[] threads = new Thread[urls.length];
                    for (int i = 0; i < urls.length; i++) {
                        threads[i] = hitURL(urls[i]);
                        // If hitting the URL synchronously, wait for each one to finish before moving
                        // on
                        if (!async) {
                            // The timeout ms here is additive. 5 URLs at 20 seconds each could take up to
                            // 100 seconds total
                            threads[i].join(theTimeoutMS);
                            if (threads[i].isAlive()) {
                                UndertowLogger.PREDICATE_LOGGER
                                        .warn("Site [" + thisSiteName + "] timeout for URL [" + urls[i]
                                                + "] reached.  The request will continue to run in the background.");
                            }
                        }
                    }
                    // If we're async, fire all the threads above at once, and then wait for them to
                    // finish
                    if (async) {
                        long startMS = System.currentTimeMillis();
                        for (int i = 0; i < urls.length; i++) {
                            threads[i].join(timeoutMS);

                            if (threads[i].isAlive()) {
                                UndertowLogger.PREDICATE_LOGGER
                                        .warn("Site [" + thisSiteName + "] timeout for URL [" + urls[i]
                                                + "] reached.  The request will continue to run in the background.");
                            }

                            // Subtract the time we've already waited since all URLs are currently running.
                            // So no matter how many threads we fire, we'll never wait more than the
                            // original timeout
                            timeoutMS -= (System.currentTimeMillis() - startMS);
                            if (timeoutMS <= 0 && i < urls.length - 1) {
                                UndertowLogger.PREDICATE_LOGGER.warn(
                                        "Site [" + thisSiteName + "] total warmup timeout reached, stopping warmup");
                                break;
                            }
                        }
                    }

                    if (requestStrategy.equals(RequestStrategy.ALLOW)) {
                        UndertowLogger.PREDICATE_LOGGER.info("Site [" + thisSiteName + "] is warm.");
                    } else {
                        UndertowLogger.PREDICATE_LOGGER
                                .info("Site [" + thisSiteName + "] is warm, opening the flood gates");
                    }

                    // Requests can now flow through
                    block = false;

                } catch (Exception e) {
                    UndertowLogger.PREDICATE_LOGGER.error("Site [" + thisSiteName + "] error warming up server",
                            e);
                }

                // Now let's clear the queue
                if (requestStrategy.equals(RequestStrategy.QUEUE)) {
                    SuspendedRequest req = null;
                    while ((req = queuedRequests.poll()) != null) {
                        try {
                            req.exchange.addExchangeCompleteListener(COMPLETION_LISTENER);
                            req.exchange.dispatch(req.next);
                            break;
                        } catch (Throwable e) {
                            UndertowLogger.PREDICATE_LOGGER.error("Suspended request was skipped", e);
                        }
                    }
                }
            }
        };
        new Thread(task).start();
    }

    private Thread hitURL(String urlString) {

        Runnable task = new Runnable() {
            @Override
            public void run() {

                UndertowLogger.PREDICATE_LOGGER
                        .info("Site [" + thisSiteName + "] hitting warmup URL [" + urlString + "]");
                HttpURLConnection connection = null;
                try {
                    URL url = new URL(urlString);
                    long startMS = System.currentTimeMillis();
                    connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("GET");

                    connection.setRequestProperty("__site__warmup__", "true");

                    int responseCode = connection.getResponseCode();
                    String contentType = connection.getContentType();
                    String responseMessage = connection.getResponseMessage();
                    long contentLength = connection.getContentLengthLong();
                    long elapsedMS = System.currentTimeMillis() - startMS;

                    UndertowLogger.PREDICATE_LOGGER
                            .info("Site [" + thisSiteName + "] warmup URL [" + urlString + "] returned response code: ["
                                    + responseCode + " "
                                    + responseMessage
                                    + "] in " + elapsedMS + " ms Content-Type: [" + contentType + "] Content-Length: ["
                                    + contentLength + "]");

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    // We're not fetching the response body, just disconnect
                    if (connection != null) {
                        connection.disconnect();
                    }
                }
            }
        };

        Thread t = new Thread(task);
        t.start();
        return t;
    }

    public static void triggerWarmups() {
        for (WarmUpServer warmUpServer : warmUpServers) {
            // It's up to each handler to fire async
            warmUpServer.triggerWarmup();
        }
    }

    private static final class SuspendedRequest {
        final HttpServerExchange exchange;
        final HttpHandler next;

        private SuspendedRequest(HttpServerExchange exchange, HttpHandler next) {
            this.exchange = exchange;
            this.next = next;
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("warm-up-server( urls={");
        for (String url : urls) {
            sb.append(url).append(",");
        }
        sb.deleteCharAt(sb.length() - 1); // remove trailing comma
        sb.append("}, requestStrategy=")
                .append(requestStrategy)
                .append(", async=")
                .append(async)
                .append(", timeoutMS=")
                .append(timeoutMS)
                .append(")");
        return sb.toString();
    }

    public static class Builder implements HandlerBuilder {

        @Override
        public String name() {
            return "warm-up-server";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            Map<String, Class<?>> params = new HashMap<>();
            params.put("urls", String[].class);
            params.put("requestStrategy", String.class);
            params.put("async", Boolean.class);
            params.put("timeoutSeconds", Integer.class);
            return params;
        }

        @Override
        public Set<String> requiredParameters() {
            return Set.of("urls");
        }

        @Override
        public String defaultParameter() {
            return "urls";
        }

        @Override
        public HandlerWrapper build(Map<String, Object> config) {
            String requestStrategyStr = (String) config.get("requestStrategy");
            RequestStrategy requestStrategy;
            if (requestStrategyStr != null) {
                requestStrategy = RequestStrategy.fromString(requestStrategyStr);
            } else {
                requestStrategy = RequestStrategy.ALLOW;
            }

            Boolean async = (Boolean) config.get("async");
            if (async == null) {
                async = true;
            }
            Integer timeoutSeconds = (Integer) config.get("timeoutSeconds");
            if (timeoutSeconds == null) {
                timeoutSeconds = 60;
            }

            return new Wrapper((String[]) config.get("urls"), requestStrategy, async, timeoutSeconds);
        }

    }

    private static class Wrapper implements HandlerWrapper {
        private final String[] urls;
        private final RequestStrategy requestStrategy;
        private final Boolean async;
        private final Integer timeoutSeconds;

        private Wrapper(String[] urls, RequestStrategy requestStrategy, Boolean async,
                Integer timeoutSeconds) {
            this.urls = urls;
            this.requestStrategy = requestStrategy;
            this.async = async;
            this.timeoutSeconds = timeoutSeconds;
        }

        @Override
        public HttpHandler wrap(HttpHandler next) {
            return new WarmUpServer(next, urls, requestStrategy, async, timeoutSeconds);
        }
    }
}
