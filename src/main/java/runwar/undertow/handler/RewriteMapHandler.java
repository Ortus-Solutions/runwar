package runwar.undertow.handler;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.io.File;
import runwar.undertow.RewriteMap;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;

import io.undertow.Handlers;
import io.undertow.predicate.Predicate;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.SetErrorHandler;
import io.undertow.server.handlers.builder.HandlerBuilder;

/**
 * A {@link HttpHandler} that create a rewrite map if it doesn't exist
 * and associates it with the current site deployment context.
 *
 * @author Brad Wood
 */
public final class RewriteMapHandler implements HttpHandler {

    private String name;
    private File mapFile;
    private Boolean caseSensitive;
    private final HttpHandler next;

    public RewriteMapHandler( String name, final HttpHandler next, File mapFile, Boolean caseSensitive ) {
        this.name = name;
        this.next = next;
        this.mapFile = mapFile;
        this.caseSensitive = caseSensitive;
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {

        SiteDeployment siteDeployment = exchange.getAttachment( SiteDeploymentManager.SITE_DEPLOYMENT_KEY );
        Map<String,Object> deploymentContext = siteDeployment.getDeploymentContext();
        String mapName = "rewrite-map-" + name.toLowerCase();
        RewriteMap rewriteMap = (RewriteMap)deploymentContext.get( mapName );

        // Double-check lock pattern
        if( rewriteMap == null ) {
            synchronized( this ) {
                rewriteMap = (RewriteMap)deploymentContext.get( mapName );
                if( rewriteMap == null ) {
                    rewriteMap = new RewriteMap( name, mapFile, caseSensitive );
                    deploymentContext.put( mapName, rewriteMap );
                }
            }
        }

        rewriteMap.checkReload();

    	next.handleRequest(exchange);
    }

    @Override
    public String toString() {
        return "rewrite-map( name='" + name + "',file='" + mapFile.toString() + "', case-sensitive=" + caseSensitive + " )";
    }

    public static class Builder implements HandlerBuilder {

        @Override
        public String name() {
            return "rewrite-map";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            Map<String, Class<?>> params = new HashMap<>();
            params.put("name", String.class);
            params.put("file", String.class);
            params.put("type", String.class);
            params.put("case-sensitive", Boolean.class);
            return params;
        }

        @Override
        public Set<String> requiredParameters() {
         return Set.of("file", "name");
        }

        @Override
        public String defaultParameter() {
            return null;
        }

        @Override
        public HandlerWrapper build(Map<String, Object> config) {
            String name = (String)config.get("name");
            File mapFile = new File( (String)config.get("file") );
            Boolean caseSensitive = (Boolean)config.get("case-sensitive");

            if( !mapFile.exists() ) {
                throw new RuntimeException( "Rewrite Map file [" + mapFile.toString() + "] does not exist." );
            }

            return new Wrapper( name, mapFile, caseSensitive );
        }

    }

    private static class Wrapper implements HandlerWrapper {

        private final String name;
        private final File mapFile;
        private final Boolean caseSensitive;

        private Wrapper( String name, File mapFile, Boolean caseSensitive ) {
            this.name = name;
            this.mapFile = mapFile;
            this.caseSensitive = caseSensitive != null && true;
        }

        @Override
        public HttpHandler wrap(HttpHandler handler) {
            return new RewriteMapHandler( name, handler, mapFile, caseSensitive );
        }
    }

}
