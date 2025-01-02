/*-
 * #%L
 * autotls
 * %%
 * Copyright (C) 2024 Tim Orbaker
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 * #L%
 */
package com.orbaker.autotls.tools;

import com.orbaker.autotls.impl.Precheck;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.collections4.SetUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Tools for working with X509 Certificates.
 *
 * @author torbaker
 */
public final class X509CertificateTools
{
    private X509CertificateTools() {}

    /**
     * Extract the 'not before' timestamp for the given certificate.
     *
     * If there is no 'not before' in the certificate, returns
     * {@link java.time.Instant#MIN}.
     *
     * @param x509
     *      Certificate
     *
     * @return
     *      'Not Before' timestamp from certificate or {@code Instant.MIN}.
     */
    @NotNull
    public static Instant notBefore( @NotNull X509Certificate x509 )
    {
        Objects.requireNonNull( x509 );

        Date notBefore = x509.getNotBefore();

        if ( notBefore == null ) {
            return Instant.MIN;
        } else {
            return notBefore.toInstant();
        }
    }

    /**
     * Extract the 'not after' timestamp for the given certificate.
     *
     * If there is no 'not after' in the certificate, returns
     * {@link java.time.Instant#MAX}.
     *
     * @param x509
     *      Certificate
     *
     * @return
     *      'Not After' timestamp from certificate or {@code Instant.MAX}.
     */
    public static Instant notAfter( @NotNull X509Certificate x509 )
    {
        Objects.requireNonNull( x509 );

        Date notAfter = x509.getNotAfter();

        if ( notAfter == null ) {
            return Instant.MAX;
        } else {
            return notAfter.toInstant();
        }
    }

    /**
     * {@code true} if the {@code certificate} is valid as of {@code asOf}, optionally
     * skipping the check for the start date.
     *
     * @param certificate
     *      Certificate to check.
     *
     * @param asOf
     *      Point in time of interest.
     *
     * @param checkNotBefore
     *      {@code true} to check the 'not before' date as well as the 'not after' date.
     *
     * @return
     *      {@code true} if the certificate matches.
     */
    public static boolean isValidAsOf( @NotNull X509Certificate certificate, @NotNull Instant asOf, boolean checkNotBefore )
    {
        Objects.requireNonNull( asOf );

        if ( checkNotBefore ) {
            Instant begins = X509CertificateTools.notBefore( certificate );

            if ( begins.isAfter( asOf ) ) {
                return false;
            }
        }

        Instant ending = X509CertificateTools.notAfter( certificate );

        if ( ending.isBefore( asOf ) ) {
            return false;
        }

        return true;
    }

    /**
     * Extract all names from the {@code certificate}.
     *
     * @param certificate
     *      Certificate.
     *
     * @param includeSubject
     *      {@code true} to include the CN from the Subject DN.
     *
     * @param includeAlternates
     *      {@code true} to include the Subject Alt Names from the certificate.
     *
     * @return
     *      A set of the names in the certificate. Maybe empty but not {@code null}.
     *
     * @throws CertificateException
     *      If the certificate cannot be used.
     */
    @NotNull
    public static Set<String> getCertificateNames( @NotNull X509Certificate certificate, boolean includeSubject, boolean includeAlternates ) throws CertificateException
    {
        Objects.requireNonNull( certificate );

        Set<String> hostNames = new TreeSet<String>();

        if ( includeSubject ) try {
            X500Principal       subjectDN   = certificate.getSubjectX500Principal();
            String              rfc2253     = subjectDN.getName( X500Principal.RFC2253 );
            LdapName            ldapName    = new LdapName( rfc2253 );
            String              cname       = ldapName.getRdns().stream()
                                                      .filter   ( rdn -> StringUtils.equalsIgnoreCase( rdn.getType(), "CN" ) )
                                                      .map      ( rdn -> Objects.toString( rdn.getValue(), "" )              )
                                                      .findFirst()
                                                      .orElse   ( null );

            if ( StringUtils.isNotBlank( cname ) ) {
                hostNames.add( cname );
            }
        } catch ( InvalidNameException ignore ) {}

        if ( includeAlternates ) {
            Collection<List<?>> alternates  = certificate.getSubjectAlternativeNames();

            for ( List<?> alternate : alternates ) {
                if ( alternate.size() < 2 ) continue;    // Skip entries too short

                int     nameTypeId      = (Integer) alternate.get( 0 );
                String  alternateName   = Objects.toString( alternate.get( 1 ), null );

                if ( nameTypeId == GeneralName.dNSName || alternateName != null ) {
                    hostNames.add( alternateName );
                }
            }
        }

        return hostNames;
    }

    /**
     * {@code true} if the {@code certificate} provides coverage for {@code host}. This
     * takes a strict interpretation and matches '*.' in a name as a single level of DNS
     * naming.
     *
     * @param certificate
     *      Certificate
     *
     * @param host
     *      Host name to check
     *
     * @return
     *      {@code true} if the names in {@code certificate} apply to {@code host}.
     *
     * @throws CertificateException
     *      Invalid certificate.
     */
    public static boolean providesCoverageFor( @NotNull X509Certificate certificate, @NotBlank String host ) throws CertificateException
    {
        Objects.requireNonNull( certificate );

        String hostName = Precheck.requireNonBlank( host );

        Set<String> certificateNames = X509CertificateTools.getCertificateNames( certificate, true, true );

        for ( String certificateName : certificateNames ) {
            String targetName = hostName;

            if ( certificateName.equalsIgnoreCase( targetName ) ) {
                return true;
            }

            while ( certificateName.startsWith( "*." ) ) {
                int dot = targetName.indexOf( '.' );

                if ( dot == -1 ) break;

                certificateName = certificateName.substring( 2 );
                targetName      = targetName.substring( ++dot );

                if ( certificateName.equalsIgnoreCase( targetName ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * {@code true} if the certificate is self-signed
     *
     * @param certificate
     *      {@code certificate}
     *
     * @return
     *      If the string representations of SubjectDN and IssuerDN are equal.
     */
    public static boolean isSelfSigned( @NotNull X509Certificate certificate )
    {
        Objects.requireNonNull( certificate );

        String  issuer  = Objects.toString( certificate.getIssuerX500Principal(), "issuer" );
        String  subject = Objects.toString( certificate.getSubjectX500Principal(), "subject" );

        return issuer.equalsIgnoreCase( subject );
    }

    /**
     * Get the host names from the {@code certificate} with the SubjectDN appearing first in the list.
     *
     * @param certificate
     *      certificate.
     *
     * @return
     *      Host names from {@code certificate} ordered with SubjectDN first.
     *
     * @throws CertificateException
     *      On invalid certificate.
     */
    public static List<String> getOrderedNames( @NotNull X509Certificate certificate ) throws CertificateException
    {
        Set<String>     common  = X509CertificateTools.getCertificateNames( certificate, true, false );
        Set<String>     alters  = X509CertificateTools.getCertificateNames( certificate, false, true );
        Set<String>     single  = SetUtils.difference( alters, common );
        List<String>    ordered = new ArrayList<String>();

        if ( ! common.isEmpty() ) {
            ordered.addAll( common );
        }
        if ( ! single.isEmpty() ) {
            ordered.addAll( single );
        }

        return ordered;
    }
}
