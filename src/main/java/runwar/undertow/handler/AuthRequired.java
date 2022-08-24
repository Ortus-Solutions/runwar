package runwar.undertow.handler;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import io.undertow.UndertowLogger;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.IPAddressAccessControlHandler;
import io.undertow.server.handlers.builder.HandlerBuilder;

/**
 * A {@link HttpHandler} that marks the current security context as needing authentication
 *
 * @author Brad Wood
 */
public final class AuthRequired implements HttpHandler {

    private final HttpHandler next;
    
    public AuthRequired(final HttpHandler handler) {
        this.next = handler;
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        SecurityContext context = exchange.getSecurityContext();
        
        if( context == null ) {
            UndertowLogger.SECURITY_LOGGER.errorf("AuthRequired handler called, but there is no security context for this exchange: %s", exchange);
            exchange.setStatusCode( 401 );
            next.handleRequest(exchange);
            return;
        }
        
        UndertowLogger.SECURITY_LOGGER.debugf("Authenticating request from AuthRequired handler for exchange %s", exchange);
        context.setAuthenticationRequired();
        
        // If we're already authenticated, continue
        if( context.isAuthenticated() ) {
            next.handleRequest(exchange);
        }
        
        // Otherwise, let's try to authenticate
        if (context.authenticate()) {
        	// We were successful, but ensure the exchange hasn't been completed
            if(!exchange.isComplete()) {
               next.handleRequest(exchange);
            }
        // We were unsuccessful
        } else {
            exchange.endExchange();
        }
    }

    @Override
    public String toString() {
        return "auth-required()";
    }

    public static class Builder implements HandlerBuilder {

        @Override
        public String name() {
            return "auth-required";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            return Collections.emptyMap();
        }

        @Override
        public Set<String> requiredParameters() {
            return Collections.emptySet();
        }

        @Override
        public String defaultParameter() {
            return null;
        }

        @Override
        public HandlerWrapper build(Map<String, Object> config) {
            return new Wrapper();
        }

    }

    private static class Wrapper implements HandlerWrapper {
        @Override
        public HttpHandler wrap(HttpHandler handler) {
            return new AuthRequired(handler);
        }
    }
}
