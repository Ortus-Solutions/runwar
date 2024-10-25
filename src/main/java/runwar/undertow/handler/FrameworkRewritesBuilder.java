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
import java.util.Map;
import java.util.Set;
import java.util.List;

import runwar.Server;

/**
 * @author Brad Wood
 */
public class FrameworkRewritesBuilder implements HandlerBuilder {
    public String name() {
        return "framework-rewrite";
    }

    public Map<String, Class<?>> parameters() {
        return Collections.emptyMap();
    }

    public Set<String> requiredParameters() {
        return Collections.emptySet();
    }

    public String defaultParameter() {
        return null;
    }

    public HandlerWrapper build(final Map<String, Object> config) {

        return new HandlerWrapper() {
            @Override
            public HttpHandler wrap(HttpHandler toWrap) {
                List<PredicatedHandler> ph = PredicatedHandlersParser.parse(
                        "not regex-nocase('^/(flex2gateway|flashservices/gateway|messagebroker|lucee|rest|cfide|CFIDE|cfformgateway|jrunscripts|cf_scripts|mapping-tag|CFFileServlet)/.*')"
                                + " and not path-prefix-nocase(/tuckey-status)"
                                + " and not path-nocase(/pms)"
                                + " and not path-nocase(/favicon.ico)"
                                + " and not is-file"
                                + " and not is-directory -> rewrite( '/index.cfm%{DECODED_REQUEST_PATH}' )",
                        Server.getClassLoader());
                return Handlers.predicates(ph, toWrap);
            }
        };
    }
}
