package runwar.undertow;

import io.undertow.UndertowLogger;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.RenegotiationRequiredException;
import io.undertow.server.SSLSessionInfo;
import io.undertow.util.Certificates;
import io.undertow.util.HexConverter;
import io.undertow.util.HttpString;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.X509Certificate;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import java.math.BigInteger;
import java.util.HashMap;

import runwar.options.ServerOptions;
import static runwar.logging.RunwarLogger.LOG;
import runwar.security.SecurityManager;

/**
 * Handler that sets HTTP request headers based on SSL client cert
 *
 * @author Brad Wood
 */
public class SSLClientCertHeaderHandler implements HttpHandler {

	private final HttpHandler next;
	final ServerOptions serverOptions;
	// Adobe will access CGI elements from request attribtues, but Lucee requires an HTTP request header.
	final Boolean addHTTPHeaders;

	private static final HttpString SSL_CLIENT_CERT = new HttpString("SSL_CLIENT_CERT" );
	private static final HttpString X_ARR_CLIENTCERT = new HttpString("X-ARR-ClientCert" );
	private static final HttpString SSL_CLIENT_S_DN = new HttpString("SSL_CLIENT_S_DN" );
	private static final HttpString CERT_SUBJECT = new HttpString("CERT_SUBJECT" );
	private static final HttpString CERT_KEYSIZE = new HttpString("CERT_KEYSIZE" );
	private static final HttpString CERT_SERIALNUMBER = new HttpString("CERT_SERIALNUMBER" );
	private static final HttpString SSL_CLIENT_M_SERIAL	 = new HttpString("SSL_CLIENT_M_SERIAL	" );
	private static final HttpString SSL_CLIENT_I_DN = new HttpString("SSL_CLIENT_I_DN" );
	private static final HttpString CERT_ISSUER = new HttpString("CERT_ISSUER" );
	private static final HttpString SSL_CLIENT_VERIFY = new HttpString("SSL_CLIENT_VERIFY" );
	private static final HttpString SSL_SESSION_ID = new HttpString("SSL_SESSION_ID" );

    public SSLClientCertHeaderHandler(HttpHandler next, ServerOptions serverOptions, Boolean addHTTPHeaders ) {
        this.next = next;
        this.serverOptions = serverOptions;
		this.addHTTPHeaders = addHTTPHeaders;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
		Map<String, String> attrs = exchange.getAttachment(HttpServerExchange.REQUEST_ATTRIBUTES);
		if(attrs == null) {
			exchange.putAttachment(HttpServerExchange.REQUEST_ATTRIBUTES, attrs = new HashMap<>());
		}

        // If Undertow is in the business of accepting client certs, discard any incoming HTTP headers so we can ensure they are valid
        String clientCertNegotiation = serverOptions.clientCertNegotiation();
        if( clientCertNegotiation != null && ( clientCertNegotiation.equals( "REQUIRED" ) || clientCertNegotiation.equals( "REQUESTED" ) ) ) {

        	removeCGIElement( exchange, SSL_CLIENT_CERT );
        	removeCGIElement( exchange, X_ARR_CLIENTCERT );
        	removeCGIElement( exchange, SSL_CLIENT_S_DN );
        	removeCGIElement( exchange, CERT_SUBJECT );
        	removeCGIElement( exchange, SSL_CLIENT_I_DN );
        	removeCGIElement( exchange, SSL_CLIENT_VERIFY );
        	removeCGIElement( exchange, SSL_SESSION_ID );
        	removeCGIElement( exchange, CERT_ISSUER );
        	removeCGIElement( exchange, CERT_KEYSIZE );
        	removeCGIElement( exchange, CERT_SERIALNUMBER );
        	removeCGIElement( exchange, SSL_CLIENT_M_SERIAL );

            SSLSessionInfo ssl = exchange.getConnection().getSslSessionInfo();
            // SSL is enabled
            if(ssl != null) {

            	X509Certificate clientCert = getClientCert( ssl );

            	setCGIElement( exchange, CERT_KEYSIZE, String.valueOf( ssl.getKeySize() ) );


                // A client cert was negotiated
                if( clientCert != null ) {
                	LOG.trace( "Client SSL cert present, setting request headers" );

                	try {
                		String PEMCert = Certificates.toPem( clientCert );

                    	// 	PEM-encoded client certificate
                    	setCGIElement( exchange, SSL_CLIENT_CERT, PEMCert );
                    	setCGIElement( exchange, X_ARR_CLIENTCERT, PEMCert );
                	} catch ( CertificateEncodingException e ) {
                    	setCGIElement( exchange, SSL_CLIENT_CERT, "CertificateEncodingException: " + e.getMessage() );
                    	setCGIElement( exchange, X_ARR_CLIENTCERT, "CertificateEncodingException: " + e.getMessage() );
                	}

                	// Subject distinguished name
					String LDAPSName = SecurityManager.reverseDN( clientCert.getSubjectDN().toString() );
                	setCGIElement( exchange, SSL_CLIENT_S_DN, LDAPSName );
                	setCGIElement( exchange, CERT_SUBJECT, LDAPSName );

                	// Issuer distinguished name
					String LDAPIName = SecurityManager.reverseDN( clientCert.getIssuerDN().toString() );
                	setCGIElement( exchange, SSL_CLIENT_I_DN, LDAPIName );
                	setCGIElement( exchange, CERT_ISSUER, LDAPIName );

                	// Convert negative binint to positive, then base 16, then add hyphens
                	String certSerial = new BigInteger(1, clientCert.getSerialNumber().toByteArray()).toString(16).replaceAll("(?<=..)(..)", "-$1");
                	setCGIElement( exchange, CERT_SERIALNUMBER, certSerial );
                	setCGIElement( exchange, SSL_CLIENT_M_SERIAL, certSerial );


                	// The hex-encoded SSL session id
                	if( ssl.getSessionId() != null ) {
                    	setCGIElement( exchange, SSL_SESSION_ID, HexConverter.convertToHexString(ssl.getSessionId()) );
                	} else {
                    	setCGIElement( exchange, SSL_SESSION_ID, "" );
                	}

                	setCGIElement( exchange, SSL_CLIENT_VERIFY, "SUCCESS" );

                } else {
                	setCGIElement( exchange, SSL_CLIENT_VERIFY, "NONE" );
                }
            }

        }


        next.handleRequest(exchange);
    }

    private X509Certificate getClientCert( SSLSessionInfo ssl ) {
        Certificate[] certificates;
        try {
            certificates = ssl.getPeerCertificates();
            if(certificates.length > 0 && certificates[0] instanceof X509Certificate ) {
                return (X509Certificate)certificates[0];
            }
            return null;
        } catch (SSLPeerUnverifiedException | RenegotiationRequiredException e) {
            return null;
        }
    }

    private void removeCGIElement( HttpServerExchange exchange, HttpString name ) {
        exchange.getAttachment( HttpServerExchange.REQUEST_ATTRIBUTES ).remove( name.toString() );
		if( addHTTPHeaders ) {
			exchange.getRequestHeaders().remove( name );
		}
    }

    private void setCGIElement( HttpServerExchange exchange, HttpString name, String value ) {
        exchange.getAttachment( HttpServerExchange.REQUEST_ATTRIBUTES ).put( name.toString(), value );
		if( addHTTPHeaders ) {
			exchange.getRequestHeaders().put( name, value );
		}
    }

}
