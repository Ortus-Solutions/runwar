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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.PathMatcher;
import io.undertow.UndertowLogger;
import io.undertow.predicate.Predicate;
import io.undertow.predicate.PredicateBuilder;
import io.undertow.predicate.Predicates;
import io.undertow.attribute.ExchangeAttribute;

/**
 * @author Stuart Douglas
 */
public class PathPrefixPredicateNoCase implements Predicate {

    private final PathMatcher<Boolean> pathMatcher;
    private final boolean caseSensitive;
    private static final boolean traceEnabled;

    static {
        traceEnabled = UndertowLogger.PREDICATE_LOGGER.isTraceEnabled();
    }

    PathPrefixPredicateNoCase(final String... paths) {
        this(true, paths);
    }

    PathPrefixPredicateNoCase( final boolean caseSensitive, final String... paths) {
        this.caseSensitive = caseSensitive;
        PathMatcher<Boolean> matcher = new PathMatcher<>();
        for(String path : paths) {
            if(!path.startsWith("/")) {
                if(!caseSensitive) {
                    matcher.addPrefixPath("/" + path.toLowerCase(), Boolean.TRUE);
                } else {
                    matcher.addPrefixPath("/" + path, Boolean.TRUE);
                }
            } else {
                if(!caseSensitive) {
                    matcher.addPrefixPath(path.toLowerCase(), Boolean.TRUE);
                } else {
                    matcher.addPrefixPath(path, Boolean.TRUE);
                }
            }
        }
        this.pathMatcher = matcher;
    }

    @Override
    public boolean resolve(final HttpServerExchange value) {
        final String relativePath = this.caseSensitive ? value.getRelativePath() : value.getRelativePath().toLowerCase();
        PathMatcher.PathMatch<Boolean> result = pathMatcher.match(relativePath);

        boolean matches = Boolean.TRUE.equals(result.getValue());

        if (traceEnabled) {
            UndertowLogger.PREDICATE_LOGGER.tracef("Path prefix(s) [%s] %s %s input [%s] for %s.", pathMatcher.getPathMatchesSet().stream().collect(Collectors.joining(", ")), caseSensitive? "[case-sensitive]" : "[case-insensitive]", (matches ? "MATCH" : "DO NOT MATCH" ), relativePath, value);
        }
        if(matches) {
            Map<String, Object> context = value.getAttachment(PREDICATE_CONTEXT);
            if(context == null) {
                value.putAttachment(PREDICATE_CONTEXT, context = new TreeMap<>());
            }
            if (traceEnabled && result.getRemaining().length() > 0 ) {
                UndertowLogger.PREDICATE_LOGGER.tracef("Storing \"remaining\" string of [%s] for %s.", result.getRemaining(), value);
            }
            context.put("remaining", result.getRemaining());
        }
        return matches;
    }

    public String toString() {
        Set<String> matches = pathMatcher.getPathMatchesSet();
        if( matches.size() == 1 ) {
            return "path-prefix-nocase( '" + matches.toArray()[0] +  " )";
        } else {
            return "path-prefix-nocase( { '" + matches.stream().collect(Collectors.joining("', '")) +  "' } )";
        }
    }

    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "path-prefix-nocase";
        }

        @Override
        public Map<String, Class<?>> parameters() {
            final Map<String, Class<?>> params = new HashMap<>();
            params.put("path", String[].class);
            return params;
        }

        @Override
        public Set<String> requiredParameters() {
            return Collections.singleton("path");
        }

        @Override
        public String defaultParameter() {
            return "path";
        }

        @Override
        public Predicate build(final Map<String, Object> config) {
            String[] path = (String[]) config.get("path");
            return new PathPrefixPredicateNoCase(false,path);
        }
    }
}