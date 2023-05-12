package chiralsoftware.certweb.dto;

import static chiralsoftware.certweb.CertificateUtilities.verifyCerts;
import static com.google.common.base.Splitter.fixedLength;
import java.math.BigInteger;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import static java.util.stream.Collectors.joining;

/**
 * Information about a PrivateKeyEntry
 */
public record PrivateKeyEntryInfo(BigInteger modulus, CertificateInfo[] certificateChain, List<String> chainErrors, boolean selfSigned) {
    
    public static PrivateKeyEntryInfo build(PrivateKeyEntry pke) {
        final Certificate[] chain = pke.getCertificateChain();
        final X509Certificate[] xChain = new X509Certificate[chain.length];
        for(int i = 0; i < xChain.length; i++) xChain[i] = (X509Certificate) chain[i];
        final CertificateInfo[] certificateChain = new CertificateInfo[chain.length];
        for(int i = 0; i < certificateChain.length; i++)
            certificateChain[i] = new CertificateInfo((X509Certificate)chain[i]);
        final boolean selfSigned = xChain.length == 1 && 
                xChain[0].getSubjectX500Principal().equals(xChain[0].getIssuerX500Principal());
        
        final RSAPrivateKey privateKey = (RSAPrivateKey) pke.getPrivateKey();

        return new PrivateKeyEntryInfo(privateKey.getModulus(), 
                certificateChain, verifyCerts(privateKey, xChain), selfSigned);
    }

    public String getModulusString() {
        return fixedLength(80).splitToList(modulus.toString(16)).stream().collect(joining("\n"));
    }

    public boolean hasIntermediateCertificate() {
        return certificateChain.length > 2;
    }
    
    @Override
    public String toString() {
        return "PrivateKeyEntryInfo{" + "modulus=" + modulus + ", certificateChain=" + certificateChain + '}';
    }
    
}
