package runwar.undertow;

import java.io.IOException;
import java.util.List;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.util.CanonicalPathUtils;
import io.undertow.util.RedirectBuilder;
import io.undertow.util.StatusCodes;
import io.undertow.util.Headers;

public class WelcomeFileHandler implements HttpHandler {

    private final HttpHandler next;
    private final ResourceManager resourceManager;
    private List<String> welcomeFiles;

    WelcomeFileHandler(final HttpHandler next, ResourceManager resourceManager, List<String> welcomeFiles) {
        this.next = next;
        this.resourceManager = resourceManager;
        this.welcomeFiles = welcomeFiles;
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        Resource resource = resourceManager.getResource(canonicalize(exchange.getRelativePath()));
        if (resource != null && resource.isDirectory()) {
            if (!exchange.getRequestPath().endsWith("/")) {
                exchange.setStatusCode(StatusCodes.FOUND);
                exchange.getResponseHeaders().put(Headers.LOCATION,
                        RedirectBuilder.redirect(exchange, exchange.getRelativePath() + "/", true));
                exchange.endExchange();
                return;
            }
            Resource indexResource = getIndexFiles(exchange, resourceManager, resource.getPath(), welcomeFiles);
            if (indexResource != null) {
                String newPath = indexResource.getPath();
                // ensure leading slash
                if (!newPath.startsWith("/")) {
                    newPath = "/" + newPath;
                }
                exchange.setRelativePath(newPath);
            }
        }

        next.handleRequest(exchange);

    }

    private Resource getIndexFiles(HttpServerExchange exchange, ResourceManager resourceManager, final String base,
            List<String> possible) throws IOException {
        if (possible == null) {
            return null;
        }
        String realBase;
        if (base.endsWith("/")) {
            realBase = base;
        } else {
            realBase = base + "/";
        }
        for (String possibility : possible) {
            Resource index = resourceManager.getResource(canonicalize(realBase + possibility));
            if (index != null) {
                return index;
            }
        }
        return null;
    }

    private String canonicalize(String s) {
        return CanonicalPathUtils.canonicalize(s);
    }
}