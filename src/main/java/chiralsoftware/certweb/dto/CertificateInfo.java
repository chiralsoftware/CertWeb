/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chiralsoftware.certweb.dto;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 *
 * @author hh
 */
public final class CertificateInfo {
    
    private final String subject;
    private final String issuer;
    private final Instant validTo;
    private final Instant validFrom;
    
    private static final String removeCnPattern = "^[cC][nN]=";
    
    public CertificateInfo(Certificate cert) {
        final X509Certificate xCert = (X509Certificate) cert;
        subject = xCert.getSubjectDN().getName();
        issuer = xCert.getIssuerDN().getName();
        validTo = xCert.getNotAfter().toInstant();
        validFrom = xCert.getNotBefore().toInstant();
    }
    
    /** detect if the next link in the chain is valid. This doesn't test keys,
     just assumes that issuer and subject names are valid */
    boolean nextCertIsValid(CertificateInfo ci) {
        return issuer.equalsIgnoreCase(ci.getSubject());
    }
    
    public boolean isSelfSigned() {
        return issuer.equalsIgnoreCase(subject);
    }
    
    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public Instant getValidTo() {
        return validTo;
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public static String getRemoveCnPattern() {
        return removeCnPattern;
    }

    @Override
    public String toString() {
        return "CertificateInfo{" + "subject=" + subject + ", issuer=" + issuer + ", "
                + "validTo=" + validTo + ", validFrom=" + validFrom + '}';
    }
    
}
