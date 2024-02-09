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
 * Predicate that returns true if the given location corresponds to a regular file.
 *
 * @author Stuart Douglas
 */
public class IsFilePredicate implements Predicate {

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
        if(deployment == null) {
           throw new RuntimeException( "is-file predicate could not access the site deployment on this exchange" );
        }
        ResourceManager manager = deployment.getResourceManager();
        try {
            Resource resource = manager.getResource(location);
            if(resource == null) {
                return false;
            }
            if(resource.isDirectory()) {
                return false;
            }
            if(requireContent){
              return resource.getContentLength() != null && resource.getContentLength() > 0;
            } else {
                return true;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
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
            Boolean requireContent = (Boolean)config.get("require-content");
            if(value == null) {
                value = ExchangeAttributes.relativePath();
            }
            return new IsFilePredicate(value, requireContent == null ? false : requireContent);
        }
    }

}
