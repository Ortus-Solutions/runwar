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
public class PathMatchPredicateNoCase implements Predicate {

    private final boolean caseSensitive;
    private final PathMatcher<Boolean> pathMatcher;
    private static final boolean traceEnabled;

    static {
        traceEnabled = UndertowLogger.PREDICATE_LOGGER.isTraceEnabled();
    }

    PathMatchPredicateNoCase(final String... paths) {
        this(true, paths);
    }

    PathMatchPredicateNoCase(final boolean caseSensitive, final String... paths) {
        this.caseSensitive = caseSensitive;
        PathMatcher<Boolean> matcher = new PathMatcher<>();
        for(String path : paths) {
            if(!path.startsWith("/")) {
                if(this.caseSensitive) {
                    matcher.addExactPath("/" +path, Boolean.TRUE);
                } else {
                    matcher.addExactPath("/" +path.toLowerCase(), Boolean.TRUE);
                }
            } else {
                if(this.caseSensitive) {
                    matcher.addExactPath(path, Boolean.TRUE);
                } else {
                    matcher.addExactPath(path.toLowerCase(), Boolean.TRUE);
                }
            }
        }
        this.pathMatcher = matcher;
    }

    public String toString() {
        Set<String> matches = pathMatcher.getExactPathMatchesSet();
        if( matches.size() == 1 ) {
            return "path-nocase( '" + matches.toArray()[0] +  "' )";
        } else {
            return "path-nocase( { '" + matches.stream().collect(Collectors.joining("', '")) +  "' } )";
        }
    }

    @Override
    public boolean resolve(final HttpServerExchange value) {
        final String relativePath = this.caseSensitive ? value.getRelativePath() : value.getRelativePath().toLowerCase();
        PathMatcher.PathMatch<Boolean> result = pathMatcher.match(relativePath);
        boolean matches = Boolean.TRUE.equals(result.getValue());
        if (traceEnabled) {
            UndertowLogger.PREDICATE_LOGGER.tracef( "Path(s) [%s] %s %s input [%s] for %s.", pathMatcher.getExactPathMatchesSet().stream().collect(Collectors.joining(", ")), caseSensitive? "[case-sensitive]" : "[case-insensitive]", ( matches ? "MATCH" : "DO NOT MATCH" ), relativePath, value );
        }
        return matches;
    }

    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "path-nocase";
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
            return new PathMatchPredicateNoCase(false, path);
        }
    }
}