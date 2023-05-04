package runwar;

import static runwar.logging.RunwarLogger.CONTEXT_LOG;

import io.undertow.io.Sender;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import runwar.logging.RunwarLogger;
import runwar.options.ServerOptions;

public class LifecyleHandler implements HttpHandler {

    private final HttpHandler next;
    private final ServerOptions serverOptions;

    LifecyleHandler(final HttpHandler next, ServerOptions serverOptions) {
        this.next = next;
        this.serverOptions = serverOptions;
    }

    @Override
    public void handleRequest(final HttpServerExchange inExchange) throws Exception {

    	inExchange.addExchangeCompleteListener((httpServerExchange, nextListener) -> {
             if ( serverOptions.debug() && httpServerExchange.getStatusCode() > 399) {
                 CONTEXT_LOG.warnf("responded: Status Code %s (%s)", httpServerExchange.getStatusCode(), Server.fullExchangePath(httpServerExchange));
             }
             nextListener.proceed();
         });

    	// This only fires if there is no response returned from the exchange
    	// An example would be using the response-code handler which simply ends the exchange
        inExchange.addDefaultResponseListener(exchange -> {

        	// This usually happens when the client/browser closes the connection before the server has responded.
        	// This may not be worth logging, since it doesn't really indicate any sort of issue
            if (!exchange.isResponseChannelAvailable()) {
                RunwarLogger.CONTEXT_LOG.debug("The response channel was closed prematurely.  Request path: " + exchange.getRequestPath() + " status-code: " + exchange.getStatusCode() );
                return false;
            }

            // This is to ensure some sort of error page always makes it back to the browser.
            if (exchange.getStatusCode() != 200) {
                final String errorPage = "<html><head><title>Error</title></head><body>" + StatusCodes.getReason( exchange.getStatusCode() ) + "<br>(Check logs for more info)</body></html>";
                exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, "" + errorPage.length());
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html");
                Sender sender = exchange.getResponseSender();
                sender.send(errorPage);
                return true;
            }

            return false;
        });

        CONTEXT_LOG.debug("requested: '" + Server.fullExchangePath(inExchange) + "'");

        // This allows the exchange to be available to the IO thread.
    	Server.setCurrentExchange(inExchange);

        next.handleRequest(inExchange);

        // Clean up after
    	Server.setCurrentExchange(null);

    }
}