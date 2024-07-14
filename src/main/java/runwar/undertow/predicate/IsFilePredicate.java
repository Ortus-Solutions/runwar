/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package runwar.undertow.predicate;

import io.undertow.UndertowLogger;
import io.undertow.attribute.ExchangeAttribute;
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.predicate.Predicate;
import io.undertow.predicate.PredicateBuilder;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.servlet.handlers.ServletRequestContext;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;

/**
 * Predicate that returns true if the given location corresponds to a regular
 * file.
 *
 * @author Stuart Douglas
 */
public class IsFilePredicate implements Predicate {

    private static final boolean traceEnabled;

    static {
        traceEnabled = UndertowLogger.PREDICATE_LOGGER.isTraceEnabled();
    }

    private final ExchangeAttribute location;
    private final boolean requireContent;

    public IsFilePredicate(final ExchangeAttribute location) {
        this(location, false);
    }

    public IsFilePredicate(final ExchangeAttribute location, boolean requireContent) {
        this.location = location;
        this.requireContent = requireContent;
    }

    @Override
    public boolean resolve(final HttpServerExchange exchange) {
        String location = this.location.readAttribute(exchange);

        SiteDeployment deployment = exchange.getAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY);
        if (deployment == null) {
            throw new RuntimeException("is-file predicate could not access the site deployment on this exchange");
        }
        ResourceManager manager = deployment.getResourceManager();
        try {
            return resolveInternal(exchange, manager, location);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void logTrace(String format, Object... args) {
        if (traceEnabled) {
            UndertowLogger.PREDICATE_LOGGER.tracef(format, args);
        }
    }

    /**
     * internal recursive method to resolve the file. If not found, we strip path
     * segments until we find a file or run out of path
     * This allows us to ignore path info which the servlet will strip off such as
     * foo/index.cfm/bar/baz
     * 
     * @param exchange The exchange
     * @param manager  The resource manager
     * @param location The location
     * @return true if the location is a file
     * @throws IOException
     */
    private boolean resolveInternal(HttpServerExchange exchange, ResourceManager manager, String location)
            throws IOException {

        logTrace("is-file checking path [%s] ...", location);
        Resource resource = manager.getResource(location);
        if (resource == null) {
            // /a/b is min for 2 segments
            if (location.length() > 3) {
                // remove any trailing slash
                if (location.endsWith("/")) {
                    location = location.substring(0, location.length() - 1);
                }
                int lastSlashIndex = location.lastIndexOf('/');
                if (lastSlashIndex > 0) { // More than one character in the path, not counting a leading slash
                    return resolveInternal(exchange, manager, location.substring(0, lastSlashIndex));
                }
            }
            logTrace("is-file check of [%s] returned [null], so file does not exist.", location);
            return false;
        }
        if (resource.isDirectory()) {
            logTrace("is-file check of [%s] returned false because path is a directory.", location);
            return false;
        }
        if (requireContent) {
            boolean result = resource.getContentLength() != null && resource.getContentLength() > 0;
            logTrace("is-file check of [%s] and content length > 0 check returned %s.", location, result);
            return result;
        } else {
            logTrace("is-file check of [%s] returned true.", location);
            return true;
        }
    }

    @Override
    public String toString() {
        return "is-file( " + location.toString() + " )";
    }

    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "is-file";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            final Map<String, Class<?>> params = new HashMap<>();
            params.put("value", ExchangeAttribute.class);
            params.put("require-content", Boolean.class);
            return params;
        }

        @Override
        public Set<String> requiredParameters() {
            return Collections.emptySet();
        }

        @Override
        public String defaultParameter() {
            return "value";
        }

        @Override
        public Predicate build(final Map<String, Object> config) {
            ExchangeAttribute value = (ExchangeAttribute) config.get("value");
            Boolean requireContent = (Boolean) config.get("require-content");
            if (value == null) {
                value = ExchangeAttributes.relativePath();
            }
            return new IsFilePredicate(value, requireContent == null ? false : requireContent);
        }
    }

}
