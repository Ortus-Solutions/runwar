package runwar.security;

import io.undertow.UndertowLogger;
import io.undertow.Undertow.Builder;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.servlet.handlers.security.ServletAuthenticationCallHandler;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.security.Security;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import net.minidev.json.JSONArray;


import java.util.Map.Entry;

public class SecurityManager implements IdentityManager {

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private final Map<String, UserAccount> users = new HashMap<>();
    private List<Map<String,String>> subjectDNs = new ArrayList<Map<String,String>>();
    private List<Map<String,String>> issuerDNs = new ArrayList<Map<String,String>>();

    public void configureAuth( Builder serverBuilder, ServerOptions serverOptions, DeploymentInfo servletBuilder) {
    	splitDNs( serverOptions.clientCertSubjectDNs(), subjectDNs );
    	splitDNs( serverOptions.clientCertIssuerDNs(), issuerDNs );

        final IdentityManager sm = this;
        servletBuilder.setInitialSecurityWrapper( new HandlerWrapper() {
            @Override
            public HttpHandler wrap(HttpHandler handler) {

            	handler = new ServletAuthenticationCallHandler(handler);
                Predicate authRequired = ( serverOptions.authPredicate() != null && serverOptions.authPredicate().length() > 0 ) ? Predicates.parse( serverOptions.authPredicate() ) : null;
                if( authRequired != null ) {
                    RunwarLogger.SECURITY_LOGGER.debug( "Authentication will only apply to [ " + serverOptions.authPredicate() + " ]" );
                } else {
                    RunwarLogger.SECURITY_LOGGER.debug( "Authentication will apply to all requests" );
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

                if( serverOptions.clientCertEnable() ) {
                    RunwarLogger.SECURITY_LOGGER.debug( "Client Cert Auth mechanism enabled.  Renegotiation: " + serverOptions.clientCertRenegotiation() );
                    mechanisms.add( new ClientCertAuthenticationMechanism( serverOptions.clientCertRenegotiation() ) );
                }

                if( serverOptions.basicAuthEnable() ) {
                    RunwarLogger.SECURITY_LOGGER.debug( "Basic Auth mechanism enabled for realm [" + serverOptions.securityRealm() + "]" );
                    for(Entry<String,String> userNpass : serverOptions.basicAuth().entrySet()) {
                        addUser(userNpass.getKey(), userNpass.getValue(), "role1");
                        RunwarLogger.SECURITY_LOGGER.debug(String.format("User:%s password:****",userNpass.getKey()));
                    }

                    mechanisms.add( new BasicAuthenticationMechanism(serverOptions.securityRealm()) );
                }

                handler = new AuthenticationMechanismsHandler(handler, mechanisms);
                return new SecurityInitialHandler(AuthenticationMode.PRO_ACTIVE, sm, handler);

            }
        } );
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
        if (credential instanceof X509CertificateCredential) {

            final Principal subjectPrincipal = ((X509CertificateCredential) credential).getCertificate().getSubjectX500Principal();
            String subjectDN = subjectPrincipal.getName();
            String issuerDN = ((X509CertificateCredential) credential).getCertificate().getIssuerX500Principal().getName();

        	RunwarLogger.SECURITY_LOGGER.debug( "Authenticating X509CertificateCredential with SubjectDN: [" + subjectDN + "] and IssuerDN: [" + issuerDN + "]" );


        	// Check any subject or issuer DN requirements
        	if( !DNMatch( subjectDNs, subjectDN ) )  {
            	RunwarLogger.SECURITY_LOGGER.debug( "Client cert auth rejected, does not match required subjectDN fields: " + subjectDNs.toString() );
        		return null;
        	}
        	if( !DNMatch( issuerDNs, issuerDN ) )  {
            	RunwarLogger.SECURITY_LOGGER.debug( "Client cert auth rejected, does not match required issuerDN fields: " + issuerDNs.toString() );
        		return null;
        	}

            return new Account() {

                @Override
                public Principal getPrincipal() {
                    return subjectPrincipal;
                }

                @Override
                public Set<String> getRoles() {
                    return Collections.emptySet();
                }

            };

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

    private Boolean DNMatch( List<Map<String,String>> DNs, String certDN )  {
    	// nothing to match means allow anything
    	if( DNs.size() == 0 ) {
    		return true;
    	}
    	Map<String,String> certDNMap = splitDN( certDN, new HashMap<String,String>(), true, false );

    	// Loop over all the DNs we need to match.  Any match is ok, they don't all need to match
    	checkEachDN: for ( Map<String,String> requireDN : DNs ) {
    		// For a given DN, all fields need to match
    		for( String requireField : requireDN.keySet() ) {
    			if( !certDNMap.containsKey( requireField ) || !certDNMap.get( requireField ).equals( requireDN.get( requireField ) ) ) {
    				// We hit a dead end on this DN, so try the next
    				continue checkEachDN;
    			}
    		}
    		// We made it through all the fields in a required DN, we can stop here!
    		return true;
        }
    	// None of the DNs matched.
    	return false;

	}

    public void splitDNs( JSONArray DNs, List<Map<String,String>> list) {
    	DNs.forEach((DN) -> {
    		list.add( splitDN( (String)DN, new HashMap<String, String>(), false, false ) );
      });
    }

    public static Map<String,String> splitDN( String DN, Map<String,String> map, Boolean ignoreInvalid, Boolean retainCase) {
    	try {
    		LdapName ldapDN = new LdapName(DN);
    		for(Rdn rdn: ldapDN.getRdns()) {
    			if( retainCase ) {
        			map.put( rdn.getType(), ((String)rdn.getValue()) );
    			} else {
        			map.put( rdn.getType().toLowerCase(), ((String)rdn.getValue()).toLowerCase() );
    			}
    		}
    	} catch( Exception e ) {
    		if( ignoreInvalid ) {
    			RunwarLogger.SECURITY_LOGGER.warn( "Invalid cert distinguished name ignored: [" + DN + "]" );
    	    	return map;
    		} else {
        		throw new RuntimeException( "Could not parse Client Cert Auth subject or issuer DN [" + DN + "]", e);
    		}
    	}
    	return map;
    }

    /**
     * Turns X500 name which starts with most specific...
     * CN=brad, O=Ortus
     * to an LDAP name which starts with least specific...
     * O=Ortus, CN=brad
     *
     * @param DN The distinguished name to reverse
     * @return A reversed DB containing all the RDS from the original DN.
     */
    public static String reverseDN( String DN ) {
    	try {
            List<Rdn> rdns = new LinkedList<Rdn>();
            rdns.addAll( new LdapName( DN ).getRdns() );
            Collections.reverse( rdns );
    		return new LdapName( rdns ).toString();
    	} catch( Exception e ) {
    		return DN;
    	}
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
