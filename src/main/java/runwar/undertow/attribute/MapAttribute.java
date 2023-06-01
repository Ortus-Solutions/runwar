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
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.UndertowLogger;
import io.undertow.Handlers;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
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
public class MapAttribute implements ExchangeAttribute {

    private String mapName;
    private ExchangeAttribute mapKey;
    private ExchangeAttribute defaultValue;

    private MapAttribute( String mapName, ExchangeAttribute mapKey, ExchangeAttribute defaultValue ) {
        this.mapName = mapName;
        this.mapKey = mapKey;
        this.defaultValue = defaultValue;
    }

    private MapAttribute( String mapName, ExchangeAttribute mapKey ) {
        this.mapName = mapName;
        this.mapKey = mapKey;
    }

    @Override
    public String readAttribute(final HttpServerExchange exchange) {
        SiteDeployment siteDeployment = exchange.getAttachment( SiteDeploymentManager.SITE_DEPLOYMENT_KEY );
        Map<String,Object> deploymentContext = siteDeployment.getDeploymentContext();
        String mapNameContextKey = "rewrite-map-" + mapName.toLowerCase();
        RewriteMap rewriteMap = (RewriteMap)deploymentContext.get( mapNameContextKey );
        String thisKey = mapKey.readAttribute( exchange );
        String thisDefault = defaultValue == null ? "" : defaultValue.readAttribute( exchange );

        // If map doesnt exist, return default.  Not sure if this should error though.
        if( rewriteMap == null ) {
            UndertowLogger.PREDICATE_LOGGER.warn( "Rewrite map [" + mapName + "] doesn't exist." );
            return thisDefault;
        }

        UndertowLogger.PREDICATE_LOGGER.trace( "Getting rewrite map key [" + thisKey + "] from map [" + mapName + "] default value [" + thisDefault + "]" );
        return rewriteMap.getKey( thisKey, thisDefault );

    }

    @Override
    public void writeAttribute(final HttpServerExchange exchange, final String newValue) throws ReadOnlyAttributeException {
        throw new ReadOnlyAttributeException("Map", newValue);
    }

    @Override
    public String toString() {
        if( defaultValue == null ) {
            return "%{map:" + mapName + ":" + mapKey.toString() + "}";
        } else {
            return "%{map:" + mapName + ":" + mapKey.toString() + "|" + defaultValue.toString() + "}";
        }
    }

    public static final class Builder implements ExchangeAttributeBuilder {

        @Override
        public String name() {
            return "Map exchange attribute";
        }

        @Override
        public ExchangeAttribute build(final String token) {
            if (token.startsWith("%{map:") && token.endsWith("}") && token.length() > 7 ) {
                String[] tokens = token.substring(6, token.length() - 1).split(":");
                String mapName = tokens[0];
                if( tokens.length < 2 ) {
                    throw new RuntimeException( "Missing Map key in exchange attribute [" + token + "]" );
                }
                String[] mapKeyTokens = tokens[1].split("\\|");
                String mapKey = mapKeyTokens[0].replace( "[", "{" ).replace( "]", "}" );

                if( mapKeyTokens.length > 1 ) {
                    return new MapAttribute(
                        mapName,
                        ExchangeAttributes.parser( Server.class.getClassLoader() ).parse( mapKey ),
                        ExchangeAttributes.parser( Server.class.getClassLoader() ).parse( mapKeyTokens[1].replace( "[", "{" ).replace( "]", "}" ) )
                    );
                }
                return new MapAttribute(
                    mapName,
                    ExchangeAttributes.parser( Server.class.getClassLoader() ).parse( mapKey )
                );
            }
            return null;
        }

        @Override
        public int priority() {
            return 101;
        }
    }
}
