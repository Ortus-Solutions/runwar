package runwar.undertow;

import io.undertow.UndertowLogger;
import io.undertow.server.BasicSSLSessionInfo;
import io.undertow.server.ExchangeCompletionListener;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.RenegotiationRequiredException;
import io.undertow.server.SSLSessionInfo;
import io.undertow.server.handlers.builder.HandlerBuilder;
import io.undertow.util.Certificates;
import io.undertow.util.HeaderMap;
import io.undertow.util.HexConverter;
import io.undertow.util.HttpString;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import runwar.options.ServerOptions;
import static runwar.logging.RunwarLogger.LOG;

/**
 * Handler that sets HTTP request headers based on SSL client cert
 *
 * @author Brad Wood
 */
public class SSLClientCertHeaderHandler implements HttpHandler {

	private final HttpHandler next;
	final ServerOptions serverOptions;
	
	private static final HttpString SSL_CLIENT_CERT = new HttpString("SSL_CLIENT_CERT" );	
	private static final HttpString X_ARR_CLIENTCERT = new HttpString("X-ARR-ClientCert" );	
	private static final HttpString SSL_CLIENT_S_DN = new HttpString("SSL_CLIENT_S_DN" );	
	private static final HttpString CERT_SUBJECT = new HttpString("CERT_SUBJECT" );
	private static final HttpString SSL_CLIENT_I_DN = new HttpString("SSL_CLIENT_I_DN" );
	private static final HttpString SSL_CLIENT_VERIFY = new HttpString("SSL_CLIENT_VERIFY" );
	private static final HttpString SSL_SESSION_ID = new HttpString("SSL_SESSION_ID" );

    public SSLClientCertHeaderHandler(HttpHandler next, ServerOptions serverOptions ) {
        this.next = next;
        this.serverOptions = serverOptions;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        HeaderMap requestHeaders = exchange.getRequestHeaders();
        
        // If Undertow is in the business of accepting client certs, discard any incoming HTTP headers so we can ensure they are valid
        String clientCertNegotiation = serverOptions.clientCertNegotiation();
        if( clientCertNegotiation != null && ( clientCertNegotiation.equals( "REQUIRED" ) || clientCertNegotiation.equals( "REQUESTED" ) ) ) {

        	requestHeaders.remove( SSL_CLIENT_CERT );
        	requestHeaders.remove( X_ARR_CLIENTCERT );
        	requestHeaders.remove( SSL_CLIENT_S_DN );
        	requestHeaders.remove( CERT_SUBJECT );
        	requestHeaders.remove( SSL_CLIENT_I_DN );
        	requestHeaders.remove( SSL_CLIENT_VERIFY );
        	requestHeaders.remove( SSL_SESSION_ID );
        	
            SSLSessionInfo ssl = exchange.getConnection().getSslSessionInfo();
            // SSL is enabled
            if(ssl != null) {

            	X509Certificate clientCert = getClientCert( ssl );
                // A client cert was negotiated
                if( clientCert != null ) {
                	LOG.trace( "Client SSL cert present, setting request headers" );
                	
                	try {
                		String PEMCert = Certificates.toPem( clientCert );
                		
                    	// 	PEM-encoded client certificate
                    	requestHeaders.add( SSL_CLIENT_CERT, PEMCert );
                    	requestHeaders.add( X_ARR_CLIENTCERT, PEMCert );
                	} catch ( CertificateEncodingException e ) {
                    	requestHeaders.add( SSL_CLIENT_CERT, "CertificateEncodingException: " + e.getMessage() );
                    	requestHeaders.add( X_ARR_CLIENTCERT, "CertificateEncodingException: " + e.getMessage() );
                	}
                	
                	// Subject distinguished name
                	requestHeaders.add( SSL_CLIENT_S_DN, clientCert.getSubjectDN().toString() );
                	requestHeaders.add( CERT_SUBJECT, clientCert.getSubjectDN().toString() );
                	
                	requestHeaders.add( SSL_CLIENT_I_DN, clientCert.getIssuerDN().toString() );
                	
                	// The hex-encoded SSL session id
                	if( ssl.getSessionId() != null ) {
                    	requestHeaders.add( SSL_SESSION_ID, HexConverter.convertToHexString(ssl.getSessionId()) );
                	} else {
                    	requestHeaders.add( SSL_SESSION_ID, "" );	
                	}
                	
                	requestHeaders.add( SSL_CLIENT_VERIFY, "SUCCESS" );
                } else {
                	requestHeaders.add( SSL_CLIENT_VERIFY, "NONE" );
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
    
}
