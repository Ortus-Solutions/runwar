package runwar.undertow;

import io.undertow.UndertowLogger;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.RenegotiationRequiredException;
import io.undertow.server.SSLSessionInfo;
import io.undertow.util.Certificates;
import io.undertow.util.HexConverter;
import io.undertow.util.HttpString;
import io.undertow.servlet.handlers.ServletRequestContext;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.X509Certificate;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import java.math.BigInteger;
import java.util.HashMap;
import jakarta.servlet.ServletRequest;

import runwar.options.SiteOptions;
import static runwar.logging.RunwarLogger.LOG;
import runwar.security.SecurityManager;

/**
 * Handler that sets HTTP request headers based on SSL client cert
 *
 * @author Brad Wood
 */
public class SSLCertHeaderHandler implements HttpHandler {

	private final HttpHandler next;
	// Adobe will access CGI elements from request attribtues, but Lucee requires an
	// HTTP request header.
	final Boolean addHTTPHeaders;

	private static final HttpString SSL_CLIENT_CERT = new HttpString("SSL_CLIENT_CERT");
	private static final HttpString X_ARR_CLIENTCERT = new HttpString("X-ARR-ClientCert");
	private static final HttpString SSL_CLIENT_S_DN = new HttpString("SSL_CLIENT_S_DN");
	private static final HttpString CERT_SUBJECT = new HttpString("CERT_SUBJECT");
	private static final HttpString CERT_KEYSIZE = new HttpString("CERT_KEYSIZE");
	private static final HttpString CERT_SERIALNUMBER = new HttpString("CERT_SERIALNUMBER");
	private static final HttpString SSL_CLIENT_M_SERIAL = new HttpString("SSL_CLIENT_M_SERIAL");
	private static final HttpString SSL_CLIENT_I_DN = new HttpString("SSL_CLIENT_I_DN");
	private static final HttpString CERT_ISSUER = new HttpString("CERT_ISSUER");
	private static final HttpString SSL_CLIENT_VERIFY = new HttpString("SSL_CLIENT_VERIFY");
	private static final HttpString SSL_SESSION_ID = new HttpString("SSL_SESSION_ID");
	private static final HttpString CERT_SERVER_SUBJECT = new HttpString("CERT_SERVER_SUBJECT");
	private static final HttpString CERT_SERVER_ISSUER = new HttpString("CERT_SERVER_ISSUER");
	private static final HttpString SUBJECT_DN_MAP = new HttpString(
			"javax.servlet.request.X509Certificate.subjectDNMap");
	private static final HttpString ISSUER_DN_MAP = new HttpString("javax.servlet.request.X509Certificate.issuerDNMap");

	public SSLCertHeaderHandler(HttpHandler next, Boolean addHTTPHeaders) {
		this.next = next;
		this.addHTTPHeaders = addHTTPHeaders;
	}

	@Override
	public void handleRequest(HttpServerExchange exchange) throws Exception {
		Map<String, String> attrs = exchange.getAttachment(HttpServerExchange.REQUEST_ATTRIBUTES);
		if (attrs == null) {
			exchange.putAttachment(HttpServerExchange.REQUEST_ATTRIBUTES, attrs = new HashMap<>());
		}

		// Get the settings for the current site
		SiteOptions siteOptions = exchange.getAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY).getSiteOptions();

		// If Undertow is in the business of accepting client certs, discard any
		// incoming HTTP headers so we can ensure they are valid
		String clientCertNegotiation = siteOptions.clientCertNegotiation();
		// If cert renegotion is enabled, we'll also assume they want Runwar to take
		// charge of cert-related headers
		Boolean clientCertRenegotiation = siteOptions.clientCertRenegotiation();
		if (clientCertNegotiation != null
				&& (clientCertNegotiation.equals("REQUIRED") || clientCertNegotiation.equals("REQUESTED"))
				|| clientCertRenegotiation) {

			// Runwar has determined it's "in charge" of cert-related headers, so it's going
			// to wipe any incoming data from upstream so you know you can trust it
			removeCGIElement(exchange, SSL_CLIENT_CERT);
			removeCGIElement(exchange, X_ARR_CLIENTCERT);
			removeCGIElement(exchange, SSL_CLIENT_S_DN);
			removeCGIElement(exchange, CERT_SUBJECT);
			removeCGIElement(exchange, SSL_CLIENT_I_DN);
			removeCGIElement(exchange, SSL_CLIENT_VERIFY);
			removeCGIElement(exchange, SSL_SESSION_ID);
			removeCGIElement(exchange, CERT_ISSUER);
			removeCGIElement(exchange, CERT_KEYSIZE);
			removeCGIElement(exchange, CERT_SERIALNUMBER);
			removeCGIElement(exchange, SSL_CLIENT_M_SERIAL);

		}

		SSLSessionInfo ssl = exchange.getConnection().getSslSessionInfo();
		// There is SSL session info
		if (ssl != null) {

			setCGIElement(exchange, CERT_KEYSIZE, String.valueOf(ssl.getKeySize()));

			// Set details of the server cert so it's in our CGI scope
			if (ssl.getSSLSession() != null && ssl.getSSLSession().getLocalCertificates() != null) {
				Certificate[] serverCerts = ssl.getSSLSession().getLocalCertificates();
				if (serverCerts.length > 0 && serverCerts[0] instanceof X509Certificate) {
					X509Certificate serverCert = (X509Certificate) serverCerts[0];

					String LDAPSName = SecurityManager.reverseDN(serverCert.getSubjectDN().toString());
					setCGIElement(exchange, CERT_SERVER_SUBJECT, LDAPSName);

					String LDAPIName = SecurityManager.reverseDN(serverCert.getIssuerDN().toString());
					setCGIElement(exchange, CERT_SERVER_ISSUER, LDAPIName);
				}
			}

			X509Certificate clientCert = getClientCert(ssl);

			// A client cert was negotiated
			if (clientCert != null) {
				LOG.trace("Client SSL cert present, setting request headers");

				try {
					String PEMCert = Certificates.toPem(clientCert);

					// PEM-encoded client certificate
					setCGIElement(exchange, SSL_CLIENT_CERT, PEMCert);
					setCGIElement(exchange, X_ARR_CLIENTCERT, PEMCert);
				} catch (CertificateEncodingException e) {
					setCGIElement(exchange, SSL_CLIENT_CERT, "CertificateEncodingException: " + e.getMessage());
					setCGIElement(exchange, X_ARR_CLIENTCERT, "CertificateEncodingException: " + e.getMessage());
				}

				// Subject distinguished name
				String LDAPSName = SecurityManager.reverseDN(clientCert.getSubjectDN().toString());
				setCGIElement(exchange, SSL_CLIENT_S_DN, LDAPSName);
				setCGIElement(exchange, CERT_SUBJECT, LDAPSName);

				// Issuer distinguished name
				String LDAPIName = SecurityManager.reverseDN(clientCert.getIssuerDN().toString());
				setCGIElement(exchange, SSL_CLIENT_I_DN, LDAPIName);
				setCGIElement(exchange, CERT_ISSUER, LDAPIName);

				// Convert negative binint to positive, then base 16, then add hyphens
				String certSerial = new BigInteger(1, clientCert.getSerialNumber().toByteArray()).toString(16)
						.replaceAll("(?<=..)(..)", "-$1");
				setCGIElement(exchange, CERT_SERIALNUMBER, certSerial);
				setCGIElement(exchange, SSL_CLIENT_M_SERIAL, certSerial);

				// Add in cert subject and issuer DN as map with key for each sub field.
				ServletRequest sr = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY).getServletRequest();
				sr.setAttribute(SUBJECT_DN_MAP.toString(),
						SecurityManager.splitDN(LDAPSName, new HashMap<String, String>(), true, true));
				sr.setAttribute(ISSUER_DN_MAP.toString(),
						SecurityManager.splitDN(LDAPIName, new HashMap<String, String>(), true, true));

				// The hex-encoded SSL session id
				if (ssl.getSessionId() != null) {
					setCGIElement(exchange, SSL_SESSION_ID, HexConverter.convertToHexString(ssl.getSessionId()));
				} else {
					setCGIElement(exchange, SSL_SESSION_ID, "");
				}

				setCGIElement(exchange, SSL_CLIENT_VERIFY, "SUCCESS");

			} else {
				setCGIElement(exchange, SSL_CLIENT_VERIFY, "NONE");
			}
		}

		next.handleRequest(exchange);
	}

	private X509Certificate getClientCert(SSLSessionInfo ssl) {
		Certificate[] certificates;
		try {
			certificates = ssl.getPeerCertificates();
			if (certificates.length > 0 && certificates[0] instanceof X509Certificate) {
				return (X509Certificate) certificates[0];
			}
			return null;
		} catch (SSLPeerUnverifiedException | RenegotiationRequiredException e) {
			return null;
		}
	}

	private void removeCGIElement(HttpServerExchange exchange, HttpString name) {
		exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY).getServletRequest()
				.removeAttribute(name.toString());
		exchange.getAttachment(HttpServerExchange.REQUEST_ATTRIBUTES).remove(name.toString());
		if (addHTTPHeaders) {
			exchange.getRequestHeaders().remove(name);
		}
	}

	private void setCGIElement(HttpServerExchange exchange, HttpString name, String value) {
		exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY).getServletRequest().setAttribute(name.toString(),
				value);
		if (addHTTPHeaders) {
			exchange.getRequestHeaders().put(name, value);
		}
	}

}
