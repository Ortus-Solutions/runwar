package runwar.undertow.handler;

import io.undertow.attribute.ExchangeAttribute;
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.SetAttributeHandler;
import io.undertow.UndertowLogger;
import io.undertow.Handlers;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
import io.undertow.server.handlers.builder.HandlerBuilder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.List;

import runwar.Server;

/**
 * Framework rewrite handler builder that provides URL rewriting capabilities
 * for framework requests. This handler will rewrite non-file, non-directory
 * requests to a configurable rewrite file.
 *
 * @author Brad Wood
 */
public class FrameworkRewritesBuilder implements HandlerBuilder {

    public String name() {
        return "framework-rewrite";
    }

    /**
     * Returns the parameters supported by this handler builder.
     *
     * @return Map of parameter names to their expected types
     */
    public Map<String, Class<?>> parameters() {
        Map<String, Class<?>> params = new HashMap<>();
        params.put( "rewriteFile", String.class );
        return params;
    }

    public Set<String> requiredParameters() {
        return Collections.emptySet();
    }

    public String defaultParameter() {
        return null;
    }

    /**
     * Builds the handler wrapper with the given configuration.
     *
     * @param config Configuration map containing optional 'rewriteFile' parameter.
     *               If 'rewriteFile' is not provided, defaults to 'index.cfm'.
     * 
     * @return HandlerWrapper that provides framework rewriting functionality
     */
    public HandlerWrapper build( final Map<String, Object> config ) {
        // Get the rewriteFile parameter, defaulting to "index.cfm" if not provided
        final String rewriteFile = config.get( "rewriteFile" ) != null ? ( String ) config.get( "rewriteFile" ) : "index.cfm";

        return new HandlerWrapper() {

            @Override
            public HttpHandler wrap( HttpHandler toWrap ) {
                List<PredicatedHandler> ph = PredicatedHandlersParser.parse(
                    "not regex-nocase('^/(flex2gateway|flashservices/gateway|messagebroker|lucee|rest|cfide|CFIDE|cfformgateway|jrunscripts|cf_scripts|mapping-tag|CFFileServlet)/.*')"
                        + " and not path-prefix-nocase(/tuckey-status)"
                        + " and not path-nocase(/pms)"
                        + " and not path-nocase(/favicon.ico)"
                        + " and not is-file"
                        + " and not is-directory -> rewrite( '/" + rewriteFile + "%{DECODED_REQUEST_PATH}' )",
                    Server.getClassLoader() );
                return Handlers.predicates( ph, toWrap );
            }
        };
    }
}
