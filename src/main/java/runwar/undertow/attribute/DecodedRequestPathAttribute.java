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

package runwar.undertow.attribute;

import runwar.undertow.RewriteMap;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;

import io.undertow.server.HttpServerExchange;
import io.undertow.attribute.ExchangeAttribute;
import io.undertow.attribute.ExchangeAttributeBuilder;
import io.undertow.attribute.ReadOnlyAttributeException;
import io.undertow.attribute.RequestPathAttribute;
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.UndertowLogger;
import io.undertow.Handlers;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
import io.undertow.util.QueryParameterUtils;
import io.undertow.server.handlers.builder.HandlerBuilder;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.List;

import runwar.Server;

/**
 * A cookie
 *
 * @author Stuart Douglas
 */
public class DecodedRequestPathAttribute implements ExchangeAttribute {

    public static final String DECODED_REQUEST_PATH = "%{DECODED_REQUEST_PATH}";

    public static final ExchangeAttribute INSTANCE = new DecodedRequestPathAttribute();

    private DecodedRequestPathAttribute() {

    }

    @Override
    public String readAttribute(final HttpServerExchange exchange) {
        return exchange.getRequestPath();
    }

    @Override
    public void writeAttribute(final HttpServerExchange exchange, final String newValue)
            throws ReadOnlyAttributeException {
        throw new ReadOnlyAttributeException();
    }

    @Override
    public String toString() {
        return DECODED_REQUEST_PATH;
    }

    public static final class Builder implements ExchangeAttributeBuilder {

        @Override
        public String name() {
            return "Decoded Request Path";
        }

        @Override
        public ExchangeAttribute build(final String token) {
            return token.equals(DECODED_REQUEST_PATH) ? INSTANCE : null;
        }

        @Override
        public int priority() {
            return 0;
        }
    }
}
