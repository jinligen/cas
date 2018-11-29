package org.apereo.cas.adaptors.x509.authentication.handler.support;

import org.apereo.cas.adaptors.x509.authentication.revocation.checker.AbstractCRLRevocationChecker;
import org.apereo.cas.adaptors.x509.authentication.revocation.checker.RevocationChecker;
import org.apereo.cas.util.crypto.CertUtils;

import lombok.val;
import org.springframework.core.io.ClassPathResource;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apereo.cas.util.AssertThrows.*;

/**
 * Base class for {@link RevocationChecker} unit tests.
 *
 * @author Marvin S. Addison
 * @since 3.4.6
 */
public abstract class AbstractCRLRevocationCheckerTests {
    /**
     * Test method for {@link AbstractCRLRevocationChecker#check(X509Certificate)}.
     */
    public void checkCertificate(final AbstractCRLRevocationChecker checker, final String[] certFiles, final GeneralSecurityException expected) {
        val certificates = new X509Certificate[certFiles.length];
        val i = new AtomicInteger();
        for (val file : certFiles) {
            certificates[i.getAndIncrement()] = CertUtils.readCertificate(new ClassPathResource(file));
        }

        assertThrowsOrNot(expected, () -> {
            for (val cert : certificates) {
                checker.check(cert);
            }
        });
    }
}
