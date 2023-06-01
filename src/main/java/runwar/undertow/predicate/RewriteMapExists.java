package runwar.undertow.predicate;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

import io.undertow.attribute.ExchangeAttributes;
import io.undertow.predicate.Predicate;
import io.undertow.predicate.PredicateBuilder;
import io.undertow.server.HttpServerExchange;
import io.undertow.attribute.ExchangeAttribute;
import runwar.undertow.RewriteMap;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;
import runwar.Server;

/**
 * Predicate that returns true if the rewrite map has the given value
 *
 * @author Brad Wood
 */
public class RewriteMapExists implements Predicate {

    private String map;
    private ExchangeAttribute key;

	public RewriteMapExists( String map, ExchangeAttribute key ) {
		this.map = map;
        this.key = key;
    }

    @Override
    public boolean resolve(final HttpServerExchange exchange) {
        SiteDeployment siteDeployment = exchange.getAttachment( SiteDeploymentManager.SITE_DEPLOYMENT_KEY );
        Map<String,Object> deploymentContext = siteDeployment.getDeploymentContext();
        String mapNameContextKey = "rewrite-map-" + map.toLowerCase();
        RewriteMap rewriteMap = (RewriteMap)deploymentContext.get( mapNameContextKey );

        if( rewriteMap == null ) {
            return false;
        }

        return rewriteMap.keyExists( key.readAttribute( exchange ) );
    }

    @Override
    public String toString() {
        return "rewrite-map-exists( map='" + map + "', key='" + key.toString() + "' )";
    }

    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "rewrite-map-exists";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            final Map<String, Class<?>> params = new HashMap<>();
            params.put("map", String.class);
            params.put("key", String.class);
            return params;
        }

        @Override
        public Set<String> requiredParameters() {
            return Set.of( "map", "key" );
        }

        @Override
        public String defaultParameter() {
            return null;
        }

        @Override
        public Predicate build(final Map<String, Object> config) {
            return new RewriteMapExists( (String)config.get("map"), ExchangeAttributes.parser( Server.class.getClassLoader() ).parse( (String)config.get("key") ) );
        }
    }
}
