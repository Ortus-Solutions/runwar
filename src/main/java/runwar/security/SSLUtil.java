package runwar.security;

import io.undertow.protocols.ssl.SNIContextMatcher;
import io.undertow.protocols.ssl.SNISSLContext;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.xnio.IoUtils;
import runwar.logging.RunwarLogger;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;


public class SSLUtil
{
    private static final String SERVER_KEY_STORE = "runwar/runwar.keystore";
    private static final String SERVER_TRUST_STORE = "runwar/runwar.truststore";
    public static final char[] DEFAULT_STORE_PASSWORD;

    static {
        DEFAULT_STORE_PASSWORD = "password".toCharArray();
    }

    public static SSLContext createSSLContext( final String[] addCertificatePaths, String sslTruststore, String sslTruststorePass, final String[] addCACertificatePaths, SNIContextMatcher.Builder sniMatchBuilder ) throws IOException {
    	if( sslTruststore == null ) {
            RunwarLogger.SECURITY_LOGGER.debug("Creating SSL context from: runwar/runwar.keystore trust store: runwar/runwar.truststore");
            return createSSLContext(getServerKeyStore(), getTrustStore(), DEFAULT_STORE_PASSWORD.clone(), addCertificatePaths, addCACertificatePaths, false, sniMatchBuilder);
    	} else {
            RunwarLogger.SECURITY_LOGGER.debug( "Creating SSL context from: runwar/runwar.keystore trust store: " + sslTruststore );
            return createSSLContext(getServerKeyStore(), loadKeyStoreFromFile( sslTruststore, sslTruststorePass.toCharArray() ), DEFAULT_STORE_PASSWORD.clone(), addCertificatePaths, addCACertificatePaths, false, sniMatchBuilder);
    	}
    }


    public static SSLContext createSSLContext(final File certfile, final File keyFile, char[] passphrase, final String[] addCertificatePaths, String sslTruststore, String sslTruststorePass, final String[] addCACertificatePaths, SNIContextMatcher.Builder sniMatchBuilder) throws IOException {
        if (passphrase == null ) {
            RunwarLogger.SECURITY_LOGGER.debug("Using default store passphrase of empty string");
            passphrase = "".toCharArray();
        }
        SSLContext sslContext;
        try {
            KeyStore trustStore;
            KeyStore keystore;

            // Parse as PKCS12l which is an entire keystore with cert and key combined with optional password
            if( certfile.getCanonicalPath().toLowerCase().endsWith( ".pfx" ) ) {
                RunwarLogger.SECURITY_LOGGER.debug("Creating SSL context from PKCS12l keystore: [" + certfile + "]");
                InputStream stream = new FileInputStream( certfile );
                keystore = KeyStore.getInstance( "PKCS12" );
                keystore.load( stream, passphrase );

            // Load up as DER cert with external DER key file/pass
            } else if( keyFile != null ) {
                RunwarLogger.SECURITY_LOGGER.debug("Creating SSL context from cert: [" + certfile + "]  key: [" + keyFile + "]");
                keystore = keystoreFromDERCertificate(certfile, keyFile, passphrase);
                //trustStore.setEntry("someAlias", new KeyStore.TrustedCertificateEntry(derKeystore.getCertificate("serverkey")), null);
            } else {
                throw new IOException("Keystore could not be created.  No matching Key file was passed for the Cert file." );
            }

            if( sslTruststore == null ) {
                RunwarLogger.SECURITY_LOGGER.debug("Creating SSL context from empty trust store");
                trustStore = KeyStore.getInstance("JKS", "SUN");
                trustStore.load(null, passphrase);
            } else {
                RunwarLogger.SECURITY_LOGGER.debug("Creating SSL context from trust store: [" + sslTruststore + "]");
                trustStore = loadKeyStoreFromFile( sslTruststore, sslTruststorePass.toCharArray() );
            }

            sslContext = createSSLContext(keystore, trustStore, passphrase, addCertificatePaths, addCACertificatePaths, false, sniMatchBuilder);
        }
        catch (Exception ex) {
            throw new IOException("Could not load certificate", ex);
        }
        return sslContext;
    }


    private static SSLContext createSSLContext(final KeyStore keyStore, final KeyStore trustStore, final char[] passphrase, final String[] addCertificatePaths, final String[] addCACertificatePaths, boolean openssl, SNIContextMatcher.Builder sniMatchBuilder) throws IOException {
        KeyManager[] keyManagers;
        try {
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, passphrase);
            keyManagers = keyManagerFactory.getKeyManagers();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IOException("Unable to initialise KeyManager[], no such algorithm", ex);
        }
        catch (UnrecoverableKeyException ex2) {
            throw new IOException("Unable to initialise KeyManager[], unrecoverable key.", ex2);
        }
        catch (KeyStoreException ex3) {
            throw new IOException("Unable to initialise KeyManager[]", ex3);
        }
        addCertificates(addCertificatePaths, keyStore);
        addCertificates(addCACertificatePaths, trustStore);
        TrustManager[] trustManagers;
        try {
            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        }
        catch (NoSuchAlgorithmException ex4) {
            throw new IOException("Unable to initialise TrustManager[], no such algorithm", ex4);
        }
        catch (KeyStoreException ex5) {
            throw new IOException("Unable to initialise TrustManager[]", ex5);
        }
        SSLContext sslContext;
        try {
            RunwarLogger.SECURITY_LOGGER.debug("UsingTSL");
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);
        }
        catch (NoSuchAlgorithmException ex6) {
            throw new IOException("Unable to create and initialise the SSLContext, no such algorithm", ex6);
        }
        catch (KeyManagementException ex7) {
            throw new IOException("Unable to create and initialise the SSLContext", ex7);
        }
        finally {
            Arrays.fill(passphrase, '*');
        }

        addSNIMatchers( sslContext, keyStore, sniMatchBuilder );
        return sslContext;
    }

    public static void addSNIMatchers( SSLContext sslContext, KeyStore keyStore, SNIContextMatcher.Builder sniMatchBuilder ) {
        int SUBJECT_ALTERNATIVE_NAMES__DNS_NAME = 2;
	    int KEY_USAGE__KEY_CERT_SIGN = 5;
        try {
            for (String alias : Collections.list(keyStore.aliases())) {
                Certificate certificate = keyStore.getCertificate(alias);

                if ("X.509".equals(certificate.getType())) {
                    X509Certificate x509 = (X509Certificate) certificate;

                    // Exclude certificates with special uses
                    if (x509.getKeyUsage() != null) {
                        boolean[] b = x509.getKeyUsage();
                        if (b[KEY_USAGE__KEY_CERT_SIGN])
                            continue;
                    }

                    // Look for alternative name extensions
                    boolean named = false;
                    Collection<List<?>> altNames = x509.getSubjectAlternativeNames();
                    if (altNames != null) {
                        for (List<?> list : altNames) {
                            if (((Number) list.get(0)).intValue() == SUBJECT_ALTERNATIVE_NAMES__DNS_NAME) {
                                String cn = list.get(1).toString();
                                if (cn != null) {
                                    named = true;
                                    RunwarLogger.SECURITY_LOGGER.trace("Adding SAN SNI host match of [" + cn + "] for cert [" + x509.getSubjectDN().toString() + "]");
                                    sniMatchBuilder.addMatch( cn, sslContext );
                                }
                            }
                        }
                    }

                    // If no names found, look up the cn from the subject
                    if (!named) {
                        LdapName name = new LdapName(x509.getSubjectX500Principal().getName(X500Principal.RFC2253));
                        for (Rdn rdn : name.getRdns()) {
                            if (rdn.getType().equalsIgnoreCase("cn")) {
                                String cn = rdn.getValue().toString();
                                if (cn != null && !cn.contains(" "))
                                    RunwarLogger.SECURITY_LOGGER.trace("Adding CN SNI host match of [" + cn + "] for cert [" + x509.getSubjectDN().toString() + "]");
                                    sniMatchBuilder.addMatch( cn, sslContext );
                            }
                        }
                    }
                }
            }
        } catch( Exception e ) {
            throw new RuntimeException( e );
        }

    }

    public static KeyStore getTrustStore() throws IOException {
        return loadKeyStore(SERVER_TRUST_STORE);
    }

    public static KeyStore getServerKeyStore() throws IOException {
        return loadKeyStore(SERVER_KEY_STORE);
    }

    private static KeyStore loadKeyStore(final String resourcePath) throws IOException {
        final InputStream resourceAsStream = SSLUtil.class.getClassLoader().getResourceAsStream(resourcePath);
        if (resourceAsStream == null) {
            throw new IOException(String.format("Unable to load KeyStore from classpath %s", resourcePath));
        }
        try {
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(resourceAsStream, DEFAULT_STORE_PASSWORD);
            RunwarLogger.SECURITY_LOGGER.debug("loaded store: " + resourcePath);
            return keyStore;
        }
        catch (Exception ex) {
            throw new IOException(String.format("Unable to load KeyStore %s", resourcePath), ex);
        }
        finally {
            IoUtils.safeClose(resourceAsStream);
        }
    }

    private static KeyStore loadKeyStoreFromFile(final String resourcePath, final char[] keystorePass) throws IOException {
        final InputStream resourceAsStream = new FileInputStream(resourcePath);
        if (resourceAsStream == null) {
            throw new IOException(String.format("Unable to load KeyStore from file %s", resourcePath));
        }
        try {
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(resourceAsStream, keystorePass);
            RunwarLogger.SECURITY_LOGGER.debug("loaded store: " + resourcePath);
            return keyStore;
        }
        catch (Exception ex) {
            throw new IOException(String.format("Unable to load KeyStore %s", resourcePath), ex);
        }
        finally {
            IoUtils.safeClose(resourceAsStream);
        }
    }

    public static KeyStore keystoreFromDERCertificate(final File certFile, final File keyFile, final char[] passphrase) throws Exception {
        final String defaultalias = "serverkey";
        final KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
        keyStore.load(null, passphrase);
        PrivateKey privateKey;
        try {
            privateKey = loadPKCS8PrivateKey(keyFile);
        }
        catch (InvalidKeySpecException ex) {
            privateKey = loadPemPrivateKey(keyFile, passphrase);
        }
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(fullStream(certFile));
        final ArrayList<Certificate> certs = new ArrayList<>();
        if (certificates.size() == 1) {
            try(final InputStream fullStream = fullStream(certFile)){
                RunwarLogger.SECURITY_LOGGER.debug("One certificate, no chain:");
                certs.add(certificateFactory.generateCertificate(fullStream));
            }
        }
        else {
            RunwarLogger.SECURITY_LOGGER.debug(String.valueOf(certificates.size()) + " certificates in chain:");
            for(Object certObject : certificates) {
                if(certObject instanceof Certificate) {
                    certs.add((Certificate)certObject);
                } else {
                    throw new RuntimeException("Unknown certificate type: " + certObject.getClass().getName());
                }
            }
//            certs = (Certificate[])generateCertificates.toArray();
        }
        for (Certificate certificate: certs) {
            X500Name x500name = new JcaX509CertificateHolder((X509Certificate) certificate).getSubject();
            RunwarLogger.SECURITY_LOGGER.debugf("   %s  certificate, public key [ %s ] %s", certificate.getType(), certificate.getPublicKey().getAlgorithm(), x500name.toString());
        }
        final char[] copy = Arrays.copyOf(passphrase, passphrase.length);
        Arrays.fill(copy, '*');
        RunwarLogger.SECURITY_LOGGER.debug(String.format("Adding key to store - alias:[%s]  type:[%s %s]  passphrase:[%s]  certs in chain:[%s]", defaultalias, privateKey.getAlgorithm(), privateKey.getFormat(), String.valueOf(copy), certs.size()));
        int certCount = certs.size();
        keyStore.setKeyEntry(defaultalias, privateKey, passphrase, certs.toArray(new Certificate[certCount]));
        return keyStore;
    }

    private static PrivateKey loadPKCS8PrivateKey(final byte[] keydata) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keydata));
    }

    private static PrivateKey loadPKCS8PrivateKey(final File file) throws Exception {
        try(final DataInputStream dataInputStream = new DataInputStream(new FileInputStream(file))){
            final byte[] array = new byte[(int)file.length()];
            dataInputStream.readFully(array);
            dataInputStream.close();
            return loadPKCS8PrivateKey(array);
        }
    }


    private static PrivateKey loadPKCS8PrivateKey(byte[] keyBytes, char[] passphrase) throws Exception {
        EncryptedPrivateKeyInfo encryptPKInfo = new EncryptedPrivateKeyInfo(keyBytes);
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
        SecretKeyFactory secFac = SecretKeyFactory.getInstance(encryptPKInfo.getAlgName(),"BC");
        Key pbeKey = secFac.generateSecret(pbeKeySpec);
        AlgorithmParameters algParams = encryptPKInfo.getAlgParameters();
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
        KeySpec pkcs8KeySpec = encryptPKInfo.getKeySpec(cipher);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePrivate(pkcs8KeySpec);
    }

    private static PrivateKey loadPemPrivateKey(final File file, final char[] passphrase) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        try(final PEMParser pemParser = new PEMParser(new BufferedReader(new FileReader(file)))){
            final PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase);
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            final Object object = pemParser.readObject();

            if( object == null ) {
                throw new IOException("No private key found in the file.  Please check the private key file format." );
            }

            if (object instanceof PEMEncryptedKeyPair) {
                RunwarLogger.SECURITY_LOGGER.debug( "Encrypted private key - we will use provided password" );
                return converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv)).getPrivate();
            } else if (object instanceof PEMKeyPair) {
                RunwarLogger.SECURITY_LOGGER.debug( "Unencrypted private key - no password needed" );
                return converter.getKeyPair((PEMKeyPair) object).getPrivate();
            } else if (object instanceof PrivateKeyInfo) {
                RunwarLogger.SECURITY_LOGGER.debug( "Private key in PrivateKeyInfo format" );
                return converter.getPrivateKey( (PrivateKeyInfo)object );
            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                RunwarLogger.SECURITY_LOGGER.debug( "Private key in PKCS8EncryptedPrivateKeyInfo format - we will use provided password" );
                PKCS8EncryptedPrivateKeyInfo privateKeyInfo = (PKCS8EncryptedPrivateKeyInfo)object;
                InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase);
                PrivateKeyInfo decryptedPrivateKeyInfo = privateKeyInfo.decryptPrivateKeyInfo(pkcs8Prov);
                return converter.getPrivateKey(decryptedPrivateKeyInfo);
            } else {
                throw new IOException("Unsupported private key format: [" + object.getClass().getName() + "].  Please report this as a bug." );
            }
        }
    }

    private static void addCertificates(String[] addCertificatePaths, KeyStore keyStore) {
        if (addCertificatePaths != null && addCertificatePaths.length > 0) {
            for (int length = addCertificatePaths.length, i = 0; i < length; ++i) {
                addCertificate(keyStore, new File(addCertificatePaths[i]),"addedKey" + i);
            }
        }
    }

    private static void addCertificate(final KeyStore keyStore, final File file, String alias) {
        try {
            final Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(fullStream(file));
            keyStore.setCertificateEntry(alias, certificate);
            String CN = "";
            try{
                X500Name x500name = new JcaX509CertificateHolder((X509Certificate) certificate).getSubject();
                CN =  IETFUtils.valueToString(x500name.getRDNs(BCStyle.CN)[0].getFirst().getValue());
                RunwarLogger.SECURITY_LOGGER.debug("Added certificate file:" + file.getAbsolutePath());
                RunwarLogger.SECURITY_LOGGER.debugf("  %s  certificate, public key [ %s ] CN=%s", certificate.getType(), certificate.getPublicKey().getAlgorithm(), CN);
            }catch(Exception e){
                RunwarLogger.SECURITY_LOGGER.debug("The added certificate doesn't have a CN, public key cannot be displayed:" + e.getMessage());
            }

        }
        catch (Exception ex) {
            RunwarLogger.SECURITY_LOGGER.error("Could not load certificate file:" + file.getAbsolutePath() + " " + ex.getMessage());
        }
    }

    private static InputStream fullStream(final File file) throws IOException {
        final FileInputStream fileInputStream = new FileInputStream(file);
        final DataInputStream dataInputStream = new DataInputStream(fileInputStream);
        final byte[] array = new byte[dataInputStream.available()];
        dataInputStream.readFully(array);
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(array);
        IoUtils.safeClose(fileInputStream);
        IoUtils.safeClose(dataInputStream);
        return byteArrayInputStream;
    }
}
