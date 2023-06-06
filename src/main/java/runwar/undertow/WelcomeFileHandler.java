package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import io.undertow.util.CanonicalPathUtils;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceManager;
import runwar.logging.RunwarLogger;

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
        if( resource != null && resource.isDirectory() ) {
            Resource indexResource = getIndexFiles(exchange, resourceManager, resource.getPath(), welcomeFiles);
            if (indexResource != null) {
                exchange.setRelativePath( indexResource.getPath() );
            }
        }

        next.handleRequest(exchange);

    }

    private Resource getIndexFiles(HttpServerExchange exchange, ResourceManager resourceManager, final String base, List<String> possible) throws IOException {
        if( possible == null ) {
            return null;
        }
        String realBase;
        if (base.endsWith("/")) {
            realBase = base;
        } else {
            realBase = base + "/";
        }
        for (String possibility : possible) {
            Resource index = resourceManager.getResource( canonicalize(realBase + possibility));
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