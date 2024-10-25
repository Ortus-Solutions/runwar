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

import io.undertow.server.HttpServerExchange;
import io.undertow.UndertowLogger;
import io.undertow.predicate.Predicate;
import io.undertow.predicate.PredicateBuilder;
import io.undertow.predicate.Predicates;
import io.undertow.attribute.ExchangeAttribute;

/**
 * @author Stuart Douglas
 */
public class PathSuffixNoCasePredicate implements Predicate {

    private final String suffix;
    private final boolean caseSensitive;
    private static final boolean traceEnabled;

    static {
        traceEnabled = UndertowLogger.PREDICATE_LOGGER.isTraceEnabled();
    }

    PathSuffixNoCasePredicate(final String suffix) {
        this(true, suffix);
    }

    PathSuffixNoCasePredicate(final boolean caseSensitive, final String suffix) {
        this.caseSensitive = caseSensitive;
        if(this.caseSensitive) {
            this.suffix = suffix;
        } else {
            this.suffix = suffix.toLowerCase();
        }
    }

    @Override
    public boolean resolve(final HttpServerExchange value) {
        boolean matches = (this.caseSensitive ? value.getRelativePath() : value.getRelativePath().toLowerCase()).endsWith(suffix);
        if (traceEnabled) {
            UndertowLogger.PREDICATE_LOGGER.tracef("Path suffix [%s] %s %s input [%s] for %s.", suffix, caseSensitive? "[case-sensitive]" : "[case-insensitive]", (matches ? "MATCHES" : "DOES NOT MATCH" ), value.getRelativePath(), value);
        }
        return matches;
    }

    public String toString() {
        return "path-suffix-nocase( '" + suffix +  "' )";
    }


    public static class Builder implements PredicateBuilder {

        @Override
        public String name() {
            return "path-suffix-nocase";
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
            return suffixes(false, path);
        }

        private Predicate suffixes(final boolean caseSensitive, final String... paths) {
            if(paths.length == 1) {
                return suffix(caseSensitive, paths[0]);
            }
            final PathSuffixNoCasePredicate[] predicates = new PathSuffixNoCasePredicate[paths.length];
            for (int i = 0; i < paths.length; ++i) {
                predicates[i] = new PathSuffixNoCasePredicate(caseSensitive, paths[i]);
            }
            return Predicates.or(predicates);
        }

        private Predicate suffix(final boolean caseSensitive, final String path) {
            return new PathSuffixNoCasePredicate(caseSensitive, path);
        }

    }
}