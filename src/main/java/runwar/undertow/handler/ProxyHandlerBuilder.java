package runwar.undertow.handler;

import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.builder.HandlerBuilder;
import io.undertow.server.handlers.proxy.LoadBalancingProxyClient;
import io.undertow.server.handlers.proxy.ProxyHandler;
import io.undertow.server.handlers.proxy.ProxyHandler.Builder;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import org.xnio.Xnio;
import org.xnio.OptionMap;
import java.security.NoSuchProviderException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Stuart Douglas
 */
public class ProxyHandlerBuilder implements HandlerBuilder {

    @Override
    public String name() {
        return "load-balanced-proxy";
    }

    @Override
    public Map<String, Class<?>> parameters() {
        Map<String, Class<?>> params = new HashMap<>();
        params.put("hosts", String[].class);
        params.put("rewrite-host-header", Boolean.class);
        params.put("reuse-x-forwarded", Boolean.class);
        params.put("max-connection-retries", Integer.class);
        params.put("max-request-time", Integer.class);
        return params;
    }

    @Override
    public Set<String> requiredParameters() {
        return Collections.singleton("hosts");
    }

    @Override
    public String defaultParameter() {
        return "hosts";
    }

    @Override
    public HandlerWrapper build(Map<String, Object> config) {
        String[] hosts = (String[]) config.get("hosts");
        List<URI> uris = new ArrayList<>();
        for (String host : hosts) {
            try {
                uris.add(new URI(host));
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
        Boolean rewriteHostHeader = (Boolean) config.get("rewrite-host-header");
        Boolean reuseXForwarded = (Boolean) config.get("reuse-x-forwarded");
        Integer maxConnectionRetries = (Integer) config.get("max-connection-retries");
        Integer maxRequestTime = (Integer) config.get("max-request-time");
        return new Wrapper( uris, rewriteHostHeader, reuseXForwarded, maxConnectionRetries, maxRequestTime );
    }

    private static class Wrapper implements HandlerWrapper {

        private final List<URI> uris;
        private final boolean rewriteHostHeader;
        private final boolean reuseXForwarded;
        private final Integer maxConnectionRetries;
        private final Integer maxRequestTime;

        private Wrapper(List<URI> uris, Boolean rewriteHostHeader, Boolean reuseXForwarded, Integer maxConnectionRetries, Integer maxRequestTime) {
            this.uris = uris;
            this.rewriteHostHeader = rewriteHostHeader != null && rewriteHostHeader;
            this.reuseXForwarded = reuseXForwarded != null && reuseXForwarded;
            this.maxConnectionRetries = maxConnectionRetries == null ? 1 : maxConnectionRetries;
            this.maxRequestTime = maxRequestTime == null ? -1 : maxRequestTime;
        }

        @Override
        public HttpHandler wrap(HttpHandler handler) {
            final LoadBalancingProxyClient loadBalancingProxyClient = new LoadBalancingProxyClient();
            for (URI url : uris) {
                // If the URL is HTTPS, add an SSL context
                if( url.getScheme().equals( "https" ) ) {
                    try {
                        loadBalancingProxyClient.addHost( url, new UndertowXnioSsl( Xnio.getInstance(), OptionMap.builder().getMap() ) );
                    } catch( Exception e ) {
                        throw new RuntimeException(e);
                    }
                } else {
                    loadBalancingProxyClient.addHost( url );
                }
            }

            return ProxyHandler.builder()
                .setProxyClient( loadBalancingProxyClient )
                .setNext( handler )
                .setRewriteHostHeader( rewriteHostHeader )
                .setReuseXForwarded( reuseXForwarded )
                .setMaxConnectionRetries( maxConnectionRetries )
                .setMaxRequestTime( maxRequestTime )
                .build();
        }
    }

}
