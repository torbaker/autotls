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
package com.orbaker.autotls.impl;

import com.orbaker.autotls.AcmeAuthority;
import com.orbaker.autotls.CertificateAuthority;
import com.orbaker.autotls.CertificateManager;
import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.SelfSignedAuthority;
import com.orbaker.autotls.tools.HostNameTools;
import com.orbaker.autotls.tools.KeyStoreTools;
import com.orbaker.autotls.tools.X509CertificateTools;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author torbaker
 */
public class CertificateManagerImpl implements CertificateManager
{
    static final Logger LOG = LoggerFactory.getLogger( CertificateManager.class );

    private final List<CertificateAuthority>    authorities;
    private final Period                        hardRenew;
    private final KeyPairGenerator              keyPairGenerator;
    private final KeyStoreInfo                  keyStoreInfo;
    private final SecureRandom                  secureRandom;
    private final Period                        softRenew;
    private final boolean                       removeExpired;
    private final boolean                       upgradeSelfSigned;
    private final Logger                        logger;

    public CertificateManagerImpl( CertificateManagerBuilderImpl builder )
    {
        this.authorities        = Arrays.<CertificateAuthority>asList( builder.getAuthorities().toArray( CertificateAuthority[]::new ) );
        this.hardRenew          = builder.getHardRenew();
        this.keyPairGenerator   = builder.getKeyPairGenerator();
        this.keyStoreInfo       = builder.getKeyStore();
        this.secureRandom       = builder.getSecureRandom();
        this.softRenew          = builder.getSoftRenew();
        this.removeExpired      = builder.isRemoveExpiredCerts();
        this.upgradeSelfSigned  = builder.isUpgradeSelfSigned();
        this.logger             = CertificateManagerImpl.LOG;

        this.logger.info( "Certificate Manager initialized" );
    }

    private void dumpStore( String prefix, KeyStore store, ProtectionParameter keypass ) throws GeneralSecurityException
    {
        ZoneId timeZone = ZoneId.systemDefault();

        if ( store.size() == 0 ) {
            this.logger.info( prefix + ": no keys" );
        } else {
            this.logger.info( prefix + ": " + store.size() + " keys" );

            for ( String alias : Collections.list( store.aliases() ) ) {
                Entry entry = store.getEntry( alias, keypass );

                if ( entry instanceof PrivateKeyEntry privent ) {
                    Certificate certificate = privent.getCertificate();

                    if ( certificate instanceof X509Certificate x509 ) {
                        X500Principal   subjectDN   = x509.getSubjectX500Principal();
                        Date            notAfter    = Objects.requireNonNullElseGet( x509.getNotAfter(), () -> new Date( 0L ) );
                        ZonedDateTime   expiry      = notAfter.toInstant().truncatedTo( ChronoUnit.SECONDS ).atZone( timeZone );

                        this.logger.info( prefix + ": " + alias + ": for " + subjectDN + " expires " + expiry.toString() );
                    } else {
                        this.logger.info( prefix + ": " + alias + ": not an x509 certificate" );
                    }
                } else {
                    this.logger.info( prefix + ": " + alias + ": not a private key entry" );
                }
            }
        }
    }

    @Override
    public void requireCoverageFor( @NotEmpty String... hostNames ) throws IOException, GeneralSecurityException
    {
        this.requireCoverageFor( Arrays.<String>asList( hostNames ) );
    }

    @Override
    public void requireCoverageFor( @NotNull Collection<String> hostNames ) throws IOException, GeneralSecurityException
    {
        if ( hostNames == null || hostNames.isEmpty() ) {
            return;
        }

        this.logger.info( "- Requested coverage for " + String.join( ", ", hostNames ) );

        KeyStore    keyStore    = KeyStoreTools.loadOrCreateKeyStore( this.keyStoreInfo );
        var         keyPass     = new PasswordProtection( this.keyStoreInfo.keyPass() );
        ZoneId      timeZone    = ZoneId.systemDefault();
        Instant     rightNow    = Instant.now().truncatedTo( ChronoUnit.MINUTES );
        Instant     startOfDay  = LocalDate.now().atStartOfDay( timeZone ).toInstant();
        boolean     modified    = false;
        Set<String> lacking     = new TreeSet<String>();

        try {
            if ( this.removeExpired ) {
                this.logger.info( "- Removing expired certificates" );

                // Find expired certificates. We consider anything that expires any time today
                // to be expired, no matter what. Things might expire early, but if a server is
                // going to run for any period of time, don't want to expire in minutes.
                KeyStore expired = KeyStoreTools.expireCertificates( keyStore, keyPass, startOfDay );

                this.dumpStore( "  - expired", expired, keyPass );

                modified = expired.size() > 0;
            }

            // Look for certificates that are valid now, but won't be onthe soft cutoff.
            Instant softCutoff  = ZonedDateTime.ofInstant( startOfDay, timeZone ).plus( this.softRenew ).toInstant();
            boolean renew       = false;

            for ( String alias : Collections.list( keyStore.aliases() ) ) {
                if ( keyStore.getEntry( alias, keyPass ) instanceof PrivateKeyEntry privkey ) {
                    if ( privkey.getCertificate() instanceof X509Certificate x509 ) {
                        if ( X509CertificateTools.isValidAsOf( x509, startOfDay, true )
                                && ! X509CertificateTools.isValidAsOf( x509, softCutoff, true ) ) {
                            renew = true;

                            break;
                        }
                    }
                }
            }

            if ( renew ) {
                this.logger.info( "- Certificate Renewals" );

                Instant     hardCutoff  = ZonedDateTime.ofInstant( startOfDay, timeZone ).plus( this.hardRenew ).toInstant();
                KeyStore    replaced    = KeyStoreTools.emptyKeyStore( this.keyStoreInfo.storeType() );

                for ( String alias : Collections.list( keyStore.aliases() ) ) {
                    KeyStore.Entry entry = keyStore.getEntry( alias, keyPass );

                    if ( entry instanceof PrivateKeyEntry privkey ) {
                        if ( privkey.getCertificate() instanceof X509Certificate x509 ) {
                            if ( ! X509CertificateTools.isValidAsOf( x509, startOfDay, true ) ) {
                                // Do nothing. Expiration is optional and we may have an expired
                                // certificate in the store.
                            } else if ( ! X509CertificateTools.isValidAsOf( x509, softCutoff, true ) ) {
                                for ( String hostName : hostNames ) {
                                    if ( X509CertificateTools.providesCoverageFor( x509, hostName ) ) {
                                        this.logger.info( "  - Alias " + alias + " expires: " + X509CertificateTools.notAfter( x509 ).toString() );
                                        this.logger.info( "    - Provides coverage for (at least) " + hostName );

                                        for ( CertificateAuthority authority : this.authorities ) {
                                            String authId = authority.identifier();

                                            if ( authority.claimCertificate( privkey.getCertificateChain() ) ) {
                                                this.logger.info( "      - " + authId + " will attempt renewal" );


                                                try {
                                                    List<String>    ordered     = X509CertificateTools.getOrderedNames( x509 );
                                                    KeyPair         newPair     = this.keyPairGenerator.generateKeyPair();
                                                    KeyStore        acquired    = authority.acquireCoverage( this.logger, newPair, ordered, alias, keyPass );

                                                    if ( acquired.size() > 0 ) {
                                                        this.logger.info( "      - " + authId + " issued " + acquired.size() + " certificate(s)" );

                                                        keyStore.deleteEntry( alias );
                                                        replaced.setEntry( alias, entry, keyPass );

                                                        keyStore = KeyStoreTools.mergeKeyStores( keyPass, keyStore, keyPass, acquired, keyPass );
                                                        modified = true;
                                                    } else {
                                                        this.logger.info( "      - " + authId + " issued no new certificates" );
                                                    }
                                                } catch ( GeneralSecurityException ex ) {
                                                    this.logger.warn( "      * " + authId + " cannot issue certificate", ex );

                                                    if ( ! X509CertificateTools.isValidAsOf( x509, hardCutoff, true ) ) {
                                                        throw new GeneralSecurityException( authId + " cannot issue certificate and is past hard limit", ex );
                                                    }
                                                }

                                                // Certificate has been claimed by an authority, do not keep trying
                                                // other authorities for renewal. Even if the claiming authority did
                                                // not return any certificates, for any reason.
                                                break;
                                            } else {
                                                this.logger.info( "      - " + authId + " refused renewal for certificate" );
                                            }
                                        }

                                        // Certificate has been found to provide coverage for at least one of
                                        // our names, and we have made best effort attempts to renew it. Don't
                                        // try the certificate on other names. There is no reason to expect it
                                        // will succeed on a second try.
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                this.dumpStore( "  - renewed", replaced, keyPass );
                modified |= replaced.size() > 0;
            }

            // We upgrade self-signed if we are told to and have any provider that's not a self-signed provider.
            boolean upgrade = this.upgradeSelfSigned & this.authorities.stream().anyMatch( Predicate.not( p -> p instanceof SelfSignedAuthority ) );

            if ( upgrade ) {
                // Now the expensive check: are there any self-signed certificates to attempt?
                for ( String alias : Collections.list( keyStore.aliases() ) ) {
                    if ( keyStore.getEntry( alias, keyPass ) instanceof PrivateKeyEntry privkey ) {
                        if ( privkey.getCertificate() instanceof X509Certificate x509 ) {
                            if ( X509CertificateTools.isSelfSigned( x509 ) ) {
                                upgrade &= true;

                                break;
                            }
                        }
                    }
                }
            }

            if ( upgrade ) {
                this.logger.info( "- Upgrade Self-Signed Certificates" );

                KeyStore upgraded = KeyStoreTools.emptyKeyStore( this.keyStoreInfo.storeType() );

                for ( String alias : Collections.list( keyStore.aliases() ) ) {
                    if ( keyStore.getEntry( alias, keyPass ) instanceof PrivateKeyEntry privkey ) {
                        if ( privkey.getCertificate() instanceof X509Certificate x509 ) {
                            if ( X509CertificateTools.isSelfSigned( x509 ) ) {
                                this.logger.info( "  - Alias '" + alias + "' is self-signed" );

                                for ( CertificateAuthority authority : this.authorities ) {
                                    if ( ! (authority instanceof SelfSignedAuthority) ) {
                                        String authId = authority.identifier();

                                        this.logger.info( "    - Attempt to upgrade with " + authId );

                                        try {
                                            List<String>    ordered     = X509CertificateTools.getOrderedNames( x509 );
                                            KeyPair         newPair     = this.keyPairGenerator.generateKeyPair();
                                            KeyStore        acquired    = authority.acquireCoverage( this.logger, newPair, ordered, alias, keyPass );

                                            if ( acquired.size() > 0 ) {
                                                this.logger.info( "      - " + authId + " issued " + acquired.size() + " certificate(s)" );

                                                keyStore.deleteEntry( alias );
                                                upgraded.setEntry( alias, privkey, keyPass );

                                                keyStore = KeyStoreTools.mergeKeyStores( keyPass, keyStore, keyPass, acquired, keyPass );
                                                modified = true;
                                            } else {
                                                this.logger.info( "      - " + authId + " issued no new certificates" );
                                            }
                                        } catch ( GeneralSecurityException ex ) {
                                            this.logger.warn( "        - " + authId + " cannot upgrade certificate", ex );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                this.dumpStore( "  - upgraded", upgraded, keyPass );
                modified |= upgraded.size() > 0;
            }

            Set<String> uncovered = KeyStoreTools.uncoveredNames( keyStore, keyPass, rightNow, hostNames );

            if ( ! uncovered.isEmpty() ) {
                this.logger.info( "- Certificate Acquisition" );

                for ( CertificateAuthority authority : this.authorities ) {
                    String                   authId  = (authority instanceof CertificateAuthorityImpl gen)
                                                            ? gen.identifier()
                                                            : authority.getClass().getSimpleName();
                    Map<String,List<String>> divided = HostNameTools.divideNames( uncovered,
                                                                                  authority.wildcardPolicy(),
                                                                                  authority.maxAltNamesPerCert(),
                                                                                  authority.includeDomainAsAltName() );

                    for ( String alias : divided.keySet() ) {
                        // Acme authorities should not sign for invalid TLDs. Since we don't want to
                        // have to hard code and maintain a list of all the valid TLDs, we rule out
                        // common ones that we know are bad.
                        if ( authority instanceof AcmeAuthority &&
                             Constants.Acme.NOT_TLD.stream().anyMatch( (x) -> StringUtils.endsWithIgnoreCase( alias, x ) ) ) {
                            continue;
                        }

                        List<String>    names   = divided.get( alias );
                        String          subjects= String.join( ", ", names );

                        this.logger.info( "  - " + authId + " asking to cover " + subjects );

                        try {
                            KeyPair     keyPair = this.keyPairGenerator.generateKeyPair();
                            KeyStore    issued  = authority.acquireCoverage( this.logger, keyPair, names, alias, keyPass );

                            if ( issued.size() > 0 ) {
                                this.logger.info( "    " + authId + " created coverage" );

                                this.dumpStore( "    " + authId, issued, keyPass );

                                keyStore = KeyStoreTools.mergeKeyStores( keyPass, keyStore, keyPass, issued, keyPass );

                                modified = true;
                            } else {
                                this.logger.info( "    " + authId + " declined coverage" );
                            }
                        } catch ( GeneralSecurityException ex ) {
                            this.logger.info( "  * " + authId + ": " + ex.getLocalizedMessage() );
                        }
                    }

                    // Update the list of what isn't covered for the next authority
                    uncovered = KeyStoreTools.uncoveredNames( keyStore, keyPass, rightNow, hostNames );

                    if ( uncovered.isEmpty() ) {
                        break;
                    }
                }
            } else {
                this.logger.info( "- Coverage for all names found" );
            }
        } finally {
            if ( modified ) {
                KeyStoreTools.writeKeyStore( this.keyStoreInfo, keyStore );
            }
        }
    }
}
