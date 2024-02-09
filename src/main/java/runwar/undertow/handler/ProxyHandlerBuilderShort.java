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
public class ProxyHandlerBuilderShort extends  ProxyHandlerBuilder {

    @Override
    public String name() {
        return "proxy";
    }

}
