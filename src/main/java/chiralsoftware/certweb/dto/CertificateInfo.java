package chiralsoftware.certweb.dto;

import java.security.cert.X509Certificate;
import java.time.Instant;

public record CertificateInfo(String subject, String issuer, Instant validTo, Instant validFrom) {
    
    public CertificateInfo(X509Certificate xCert) {
        this(xCert.getSubjectX500Principal().getName(), xCert.getIssuerX500Principal().getName(),
                xCert.getNotAfter().toInstant(), xCert.getNotBefore().toInstant());
        
//        final X509Certificate xCert = (X509Certificate) cert;
        // as of Java 16 this is deprecated
        // https://docs.oracle.com/en/java/javase/16/docs/api/java.base/java/security/cert/X509Certificate.html#getSubjectDN()
//        subject = xCert.getSubjectDN().getName();
//        issuer = xCert.getIssuerDN().getName();

//
//        subject = xCert.getSubjectX500Principal().getName();
//        issuer = xCert.getIssuerX500Principal().getName();
//        validTo = xCert.getNotAfter().toInstant();
//        validFrom = xCert.getNotBefore().toInstant();
        
    }
    
    /** detect if the next link in the chain is valid. This doesn't test keys,
     just assumes that issuer and subject names are valid */
    boolean nextCertIsValid(CertificateInfo ci) {
        return issuer.equalsIgnoreCase(ci.subject());
    }
    
    public boolean isSelfSigned() {
        return issuer.equalsIgnoreCase(subject);
    }
    
}
