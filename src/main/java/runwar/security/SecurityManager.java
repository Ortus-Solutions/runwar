package runwar.security;

import io.undertow.UndertowLogger;
import io.undertow.Undertow.Builder;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.security.handlers.AuthenticationMechanismsHandler;
import io.undertow.security.handlers.SecurityInitialHandler;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.DigestCredential;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.security.idm.X509CertificateCredential;
import io.undertow.security.impl.BasicAuthenticationMechanism;
import io.undertow.security.impl.ClientCertAuthenticationMechanism;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.api.AuthMethodConfig;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.WebResourceCollection;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.util.HexConverter;
import io.undertow.predicate.Predicates;
import io.undertow.predicate.Predicate;
import runwar.logging.RunwarLogger;
import runwar.options.ServerOptions;
import io.undertow.server.HandlerWrapper;


import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import sun.security.mscapi.SunMSCAPI;
import java.security.Security;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


import java.util.Map.Entry;

public class SecurityManager implements IdentityManager {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private final Map<String, UserAccount> users = new HashMap<>();
    
    
    public void configureAuth(DeploymentInfo servletBuilder, ServerOptions serverOptions) {
        String realm = serverOptions.serverName() + " Realm";
        RunwarLogger.SECURITY_LOGGER.debug("Enabling Basic Auth: " + realm);
        for(Entry<String,String> userNpass : serverOptions.basicAuth().entrySet()) {
            addUser(userNpass.getKey(), userNpass.getValue(), "role1");
            RunwarLogger.SECURITY_LOGGER.debug(String.format("User:%s password:****",userNpass.getKey()));
        }
        LoginConfig loginConfig = new LoginConfig(realm);
        Map<String, String> props = new HashMap<>();
        /*  props.put("charset", "ISO_8859_1");
        props.put("user-agent-charsets", "Chrome,UTF-8,OPR,UTF-8");
        props.put("silent", "false");*/
        loginConfig.addFirstAuthMethod(new AuthMethodConfig("CLIENT-CERT", props));
        servletBuilder.setIdentityManager(this).setLoginConfig(loginConfig);
        // TODO: see if we can leverage this stuff
        //addConstraints(servletBuilder, serverOptions);

    }
/*
    public void addConstraints(DeploymentInfo servletBuilder, ServerOptions serverOptions) {
        servletBuilder.addSecurityConstraint(new SecurityConstraint()
                .addWebResourceCollection(new WebResourceCollection()
                        .addUrlPattern("*"))
                .addRoleAllowed("role1")
                .setEmptyRoleSemantic(SecurityInfo.EmptyRoleSemantic.DENY));
    }
    */

    public void configureAuth( Builder serverBuilder, ServerOptions serverOptions, DeploymentInfo servletBuilder) {    	
        String realm = serverOptions.serverName() + " Realm";
        RunwarLogger.SECURITY_LOGGER.debug("Enabling Basic Auth: " + realm);
        final Map<String, String> users = new HashMap<>(2);
        for(Entry<String,String> userNpass : serverOptions.basicAuth().entrySet()) {
            users.put(userNpass.getKey(), userNpass.getValue());
            RunwarLogger.SECURITY_LOGGER.debug(String.format("User:%s password:****",userNpass.getKey()));
        }

        addSecurity(null, users, realm, serverOptions,servletBuilder);
    }

    public HttpHandler addSecurity(final HttpHandler toWrap, final Map<String, String> users, String realm, ServerOptions serverOptions, DeploymentInfo servletBuilder) {
        for(String userName : users.keySet()) {
            addUser(userName, users.get(userName), "role1");
        }
        final IdentityManager sm = this;
        RunwarLogger.SECURITY_LOGGER.warn( "Setting setInitialSecurityWrapper" );	
        servletBuilder.setInitialSecurityWrapper( new HandlerWrapper() {
            @Override
            public HttpHandler wrap(HttpHandler handler) {
            	
            	handler = new AuthenticationCallHandler(handler);	
                Predicate authRequired = ( serverOptions.basicAuthPredicate() != null && serverOptions.basicAuthPredicate().length() > 0 ) ? Predicates.parse( serverOptions.basicAuthPredicate() ) : null;
                if( authRequired != null ) {
                    RunwarLogger.SECURITY_LOGGER.debug( "Basic Auth will only apply to [ " + serverOptions.basicAuthPredicate() + " ]" );	
                }
                handler = new AuthenticationConstraintHandler(handler){
                	
                	@Override
                    protected boolean isAuthenticationRequired(final HttpServerExchange exchange) {
                		if( authRequired == null ) {
                			return true;
                		}
                		// Either auth is already been marked required for this context or our predicate resolves to true
                        return exchange.getSecurityContext().isAuthenticationRequired() || authRequired.resolve( exchange );
                    }
                	
                };
                
                final List<AuthenticationMechanism> mechanisms = new ArrayList<AuthenticationMechanism>();        
                mechanisms.add( new ClientCertAuthenticationMechanism() );
                
                //mechanisms.add( new BasicAuthenticationMechanism(realm) );
                
                handler = new AuthenticationMechanismsHandler(handler, mechanisms);
                return new SecurityInitialHandler(AuthenticationMode.PRO_ACTIVE, sm, handler);
            	
            }
        } );
       
        return toWrap;
    }

    public void addUser(final String name, final String password, final String... roles) {
        UserAccount user = new UserAccount();
        user.name = name;
        user.password = password.toCharArray();
        user.roles = new HashSet<>(Arrays.asList(roles));
        users.put(name, user);
    }

    @Override
    public Account verify(Account account) {
        // Just re-use the existing account.
        return account;
    }

    @Override
    public Account verify(String id, Credential credential) {
        Account account = users.get(id);
        if (account != null && verifyCredential(account, credential)) {
            return account;
        }

        return null;
    }

    @Override
    public Account verify(Credential credential) {
    	RunwarLogger.SECURITY_LOGGER.warn( "verify(Credential credential) called." );
        if (credential instanceof X509CertificateCredential) {

        	RunwarLogger.SECURITY_LOGGER.warn( "instance of X509CertificateCredential" );
            final Principal p = ((X509CertificateCredential) credential).getCertificate().getSubjectX500Principal();
        	RunwarLogger.SECURITY_LOGGER.warn( "Principal tostring" + p.toString() );
        	RunwarLogger.SECURITY_LOGGER.warn( "Principal name" + p.getName() );
            if (true) {
                return new Account() {

                    @Override
                    public Principal getPrincipal() {
                        return p;
                    }

                    @Override
                    public Set<String> getRoles() {
                        return Collections.emptySet();
                    }

                };
            }

        } 
    	
        return null;
    }

    private boolean verifyCredential(Account account, Credential credential) {
        if (account instanceof UserAccount) {
            if (credential instanceof PasswordCredential) {
                char[] expectedPassword = ((UserAccount) account).password;
                char[] suppliedPassword = ((PasswordCredential) credential).getPassword();

                return Arrays.equals(expectedPassword, suppliedPassword);
            } else if (credential instanceof DigestCredential) {
                DigestCredential digCred = (DigestCredential) credential;
                MessageDigest digest = null;
                try {
                    digest = digCred.getAlgorithm().getMessageDigest();

                    digest.update(account.getPrincipal().getName().getBytes(UTF_8));
                    digest.update((byte) ':');
                    digest.update(digCred.getRealm().getBytes(UTF_8));
                    digest.update((byte) ':');
                    char[] expectedPassword = ((UserAccount) account).password;
                    digest.update(new String(expectedPassword).getBytes(UTF_8));

                    return digCred.verifyHA1(HexConverter.convertToHexBytes(digest.digest()));
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("Unsupported Algorithm", e);
                } finally {
                    digest.reset();
                }
            }
        }
        return false;
    }

    private static class UserAccount implements Account {
        private static final long serialVersionUID = 8120665150347502722L;
        String name;
        char[] password;
        Set<String> roles;

        private final Principal principal = new Principal() {

            @Override
            public String getName() {
                return name;
            }
        };

        @Override
        public Principal getPrincipal() {
            return principal;
        }

        @Override
        public Set<String> getRoles() {
            return roles;
        }

    }

}
