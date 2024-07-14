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
import io.undertow.UndertowLogger;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;

/**
 * Predicate that returns true if the given location corresponds to a directory.
 * This is a copy of the servlet version, but uses a resource manager attached
 * to the exchange
 *
 * @author Stuart Douglas, Brad Wood
 */
public class IsDirectoryPredicate implements Predicate {

    private static final boolean traceEnabled;

    static {
        traceEnabled = UndertowLogger.PREDICATE_LOGGER.isTraceEnabled();
    }

    private final ExchangeAttribute location;

    public IsDirectoryPredicate(final ExchangeAttribute location) {
        this.location = location;
    }

    @Override
    public boolean resolve(final HttpServerExchange exchange) {
        String location = this.location.readAttribute(exchange);

        SiteDeployment deployment = exchange.getAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY);
        if (deployment == null) {
            throw new RuntimeException("is-directory predicate could not access the site deployment on this exchange");
        }
        ResourceManager manager = deployment.getResourceManager();
        try {
            Resource resource = manager.getResource(location);
            if (resource == null) {
                if (traceEnabled) {
                    UndertowLogger.PREDICATE_LOGGER.tracef(
                            "is-directory check of [%s] returned [null], so directory does not exist.", location);
                }
                return false;
            }
            if (traceEnabled) {
                UndertowLogger.PREDICATE_LOGGER.tracef("is-directory check of [%s] returned %s.", location,
                        resource.isDirectory());
            }
            return resource.isDirectory();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "is-directory( " + location.toString() + " )";
    }

    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "is-directory";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            final Map<String, Class<?>> params = new HashMap<>();
            params.put("value", ExchangeAttribute.class);
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
            if (value == null) {
                value = ExchangeAttributes.relativePath();
            }
            return new IsDirectoryPredicate(value);
        }
    }

}
