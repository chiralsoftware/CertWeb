package chiralsoftware.certweb;

import java.io.IOException;
import java.math.BigInteger;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import static java.util.Collections.unmodifiableList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import static org.bouncycastle.crypto.util.PrivateKeyFactory.createKey;

/**
 *
 */
public final class CertificateUtilities {

    private CertificateUtilities() {
        throw new RuntimeException("don't instantiate");
    }
    
    public static boolean isSelfSignedChain(Certificate[] certs) {
        if(certs.length != 1) return false;
        final X509Certificate cert = (X509Certificate) certs[0];
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    /**
     * Verify that the private key goes with the certificate. Only works with
     * RSA keys. Source; https://stackoverflow.com/a/31858690 FIXME: this should
     * probably be changed to just do a signature operation and verify it so
     * that it doesn't rely on any specifics of key algorithms and it's easier
     * to understand that the code is correct
     */
    public static boolean verifyKey(PrivateKey privateKey, X509Certificate certificate) {
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
        final RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        return rsaPublicKey.getModulus().equals(rsaPrivateKey.getModulus())
                && TWO.modPow(rsaPublicKey.getPublicExponent()
                        .multiply(rsaPrivateKey.getPrivateExponent()).subtract(ONE),
                        rsaPublicKey.getModulus()).equals(ONE);

    }

    public static X509Certificate generateSelfSigned(String domainName, KeyPair pair)
            throws IOException, OperatorCreationException, CertificateException {

        return generateSelfSigned(domainName, new Date(),
                Date.from(LocalDateTime.now().plusYears(2).toInstant(ZoneOffset.UTC)), pair, BigInteger.ONE);
    }

    /**
     * Generates a self-signed certificate for the given domain name. The X500
     * name is formed by adding cn= to the domain name.
     */
    public static X509Certificate generateSelfSigned(String domainName, Date validityStartDate, Date validityEndDate,
            KeyPair pair, BigInteger serialNumber) throws IOException, OperatorCreationException, CertificateException {

        final SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        final X500Name name = new X500Name("cn=" + domainName);
        final X509v3CertificateBuilder v3Builder = null; // we should switch to a v3 certificate
        // see: https://stackoverflow.com/questions/42091888/create-x509v3-certificate-with-customized-extension
        final X509v1CertificateBuilder builder = new X509v1CertificateBuilder(
                name,
                serialNumber,
                validityStartDate,
                validityEndDate,
                name,
                subPubKeyInfo);

        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption");
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        final ContentSigner contentSigner
                = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(createKey(pair.getPrivate().getEncoded()));

        final X509CertificateHolder holder = builder.build(contentSigner);

        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        // for testing
//        Files.write(cert.getEncoded(), new File("/tmp/certificate.der"));
//        LOG.info("wrote to file. Try this:");
//        LOG.info("openssl x509 -in /tmp/certificate.der -inform der -noout -text");
        return cert;
    }

    /**
     * Returns a list of errors in the X509 chain. If the returned list is empty
     * there were no errors
     *
     * @return a list of errors, which is empty if no errors, but is never null
     */
    public static List<String> verifyCerts(PrivateKey privateKey, X509Certificate[] certs) {
        final List<String> result = new ArrayList<>();
        if(! verifyKey(privateKey, certs[0])) 
                result.add("the private key does not match the first certificate in the chain. ");
        int n = certs.length;
        for (int i = 0; i < n - 1; i++) {
            final X509Certificate cert = certs[i];
            final X509Certificate issuer = certs[i + 1];
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                result.add("Cert[" + i + "] in chain has issuer: "
                        + cert.getIssuerX500Principal().getName()
                        + " but the subject of cert[" + (i + 1) + "] is: " + issuer.getSubjectX500Principal().getName());
            }
            try {
                cert.verify(issuer.getPublicKey());
            } catch(CertificateException | InvalidKeyException | NoSuchAlgorithmException | 
                    NoSuchProviderException | SignatureException ex) {
                result.add("Cert[" + i + "] failed to verify signature: " + ex.getClass());
            }
        }
        final X509Certificate last = certs[n - 1];
        // if self-signed, verify the final cert
        if (last.getIssuerX500Principal().equals(last.getSubjectX500Principal())) {
            try {
                last.verify(last.getPublicKey());
            } catch(CertificateException | InvalidKeyException | 
                    NoSuchAlgorithmException | NoSuchProviderException | SignatureException ex) {
                result.add("Self-signed last certificate in chain failed to verify: " + ex.getClass());
            }
        }
        return unmodifiableList(result);
    }

}
