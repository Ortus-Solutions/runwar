package runwar.undertow.predicate;

import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.builder.HandlerBuilder;
import io.undertow.server.handlers.proxy.LoadBalancingProxyClient;
import io.undertow.server.handlers.proxy.ProxyHandler;
import io.undertow.server.handlers.proxy.ProxyHandler.Builder;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.predicate.Predicate;
import io.undertow.predicate.PredicateBuilder;
import io.undertow.predicate.RegularExpressionPredicate;
import io.undertow.attribute.ExchangeAttribute;
import io.undertow.attribute.ExchangeAttributes;
import org.xnio.Xnio;
import org.xnio.OptionMap;
import java.security.NoSuchProviderException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RegularExpressionNoCasePredicateBuilder implements PredicateBuilder {

    @Override
    public String name() {
        return "regex-nocase";
    }

    @Override
    public Map<String, Class<?>> parameters() {
        final Map<String, Class<?>> params = new HashMap<>();
        params.put("pattern", String.class);
        params.put("value", ExchangeAttribute.class);
        params.put("full-match", Boolean.class);
        params.put("case-sensitive", Boolean.class);
        return params;
    }

    @Override
    public Set<String> requiredParameters() {
        final Set<String> params = new HashSet<>();
        params.add("pattern");
        return params;
    }

    @Override
    public String defaultParameter() {
        return "pattern";
    }

    @Override
    public Predicate build(final Map<String, Object> config) {
        ExchangeAttribute value = (ExchangeAttribute) config.get("value");
        if(value == null) {
            value = ExchangeAttributes.relativePath();
        }
        Boolean fullMatch = (Boolean) config.get("full-match");
        Boolean caseSensitive = (Boolean) config.get("case-sensitive");
        String pattern = (String) config.get("pattern");
        return new RegularExpressionPredicate(pattern, value, fullMatch == null ? false : fullMatch, caseSensitive == null ? false : caseSensitive);
    }
}