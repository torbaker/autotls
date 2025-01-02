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

import com.orbaker.autotls.CertificateAuthority;
import com.orbaker.autotls.CertificateManager;
import com.orbaker.autotls.CertificateManager.Builder;
import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.tools.KeyPairGenTools;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Period;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.SequencedCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author torbaker
 */
public class CertificateManagerBuilderImpl implements CertificateManager.Builder
{
    private static final Logger LOG = LoggerFactory.getLogger( CertificateManagerBuilderImpl.class );

    private         KeyStoreInfo                keyStore;
    private final   List<CertificateAuthority>  authorities;
    private         boolean                     upgradeSelfSigned;
    private         boolean                     removeExpiredCerts;
    private         Period                      softRenew;
    private         Period                      hardRenew;
    private         SecureRandom                secureRandom;
    private         KeyPairGenerator            keyPairGenerator;
    private         Logger                      logger;

    public CertificateManagerBuilderImpl()
    {
        this.logger             = CertificateManagerBuilderImpl.LOG;
        this.keyStore           = Constants.CertificateManager.KEY_STORE;
        this.authorities        = new ArrayList<CertificateAuthority>();
        this.upgradeSelfSigned  = Constants.CertificateManager.UPGRADE_CERTS;
        this.removeExpiredCerts = Constants.CertificateManager.EXPIRE_CERTS;
        this.softRenew          = Constants.CertificateManager.SOFT_RENEW;
        this.hardRenew          = Constants.CertificateManager.HARD_RENEW;
        this.secureRandom       = null;
        this.keyPairGenerator   = null;
    }

    @Override
    public Logger getLogger()
    {
        return this.logger;
    }

    @Override
    public SecureRandom getSecureRandom()
    {
        return this.secureRandom;
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator()
    {
        return this.keyPairGenerator;
    }

    @Override
    public Builder setSecureRandom( @NotNull SecureRandom secureRandom )
    {
        this.secureRandom = secureRandom;

        return this;
    }

    @Override
    public Builder setKeyPairGenerator( @NotNull KeyPairGenerator keyPairGenerator )
    {
        this.keyPairGenerator = keyPairGenerator;

        return this;
    }

    @Override
    public KeyStoreInfo getKeyStore()
    {
        return this.keyStore;
    }

    @Override
    public List<CertificateAuthority> getAuthorities()
    {
        return Collections.<CertificateAuthority>unmodifiableList( this.authorities );
    }

    @Override
    public boolean isUpgradeSelfSigned()
    {
        return this.upgradeSelfSigned;
    }

    @Override
    public boolean isRemoveExpiredCerts()
    {
        return this.removeExpiredCerts;
    }

    @Override
    public Period getSoftRenew()
    {
        return this.softRenew;
    }

    @Override
    public Period getHardRenew()
    {
        return this.hardRenew;
    }

    @Override
    public Builder setLogger( @NotNull Logger logger )
    {
        this.logger = Objects.requireNonNullElse( logger, CertificateManagerBuilderImpl.LOG );

        return this;
    }

    @Override
    public Builder setKeyStore( @NotNull KeyStoreInfo keyStore )
    {
        if ( keyStore == null ) {
            this.keyStore = Constants.CertificateManager.KEY_STORE;
        } else {
            this.keyStore = keyStore;
        }

        return this;
    }

    @Override
    public Builder addAuthority( @NotNull CertificateAuthority authority )
    {
        Objects.requireNonNull( authority );

        this.authorities.add( authority );

        return this;
    }

    @Override
    public Builder addAuthorities( @NotEmpty CertificateAuthority... authorities )
    {
        for ( CertificateAuthority authority : authorities ) {
            this.addAuthority( authority );
        }

        return this;
    }

    @Override
    public Builder addAuthorities( @NotEmpty SequencedCollection<CertificateAuthority> authorities )
    {
        for ( CertificateAuthority authority : authorities ) {
            this.addAuthority( authority );
        }

        return this;
    }

    @Override
    public Builder setAuthorities( @NotEmpty CertificateAuthority ... authorities )
    {
        this.authorities.clear();

        return this.addAuthorities( authorities );
    }

    @Override
    public Builder setAuthorities( @NotEmpty SequencedCollection<CertificateAuthority> authorities )
    {
        this.authorities.clear();

        return this.addAuthorities( authorities );
    }

    @Override
    public Builder setUpgradeSelfSigned( boolean upgradeSelfSigned )
    {
        this.upgradeSelfSigned = upgradeSelfSigned;

        return this;
    }

    @Override
    public Builder setRemoveExpiredCerts( boolean removeExpiredCerts )
    {
        this.removeExpiredCerts = removeExpiredCerts;

        return this;
    }

    @Override
    public Builder setSoftRenew( @NotNull Period softRenew )
    {
        if ( softRenew == null || softRenew.isNegative() || softRenew.isZero() ) {
            this.softRenew = Constants.CertificateManager.SOFT_RENEW;
        } else {
            this.softRenew = softRenew;
        }

        return this;
    }

    @Override
    public Builder setSoftRenew( @Positive int softRenewDays )
    {
        if ( softRenewDays < 1 ) {
            this.softRenew = Constants.CertificateManager.SOFT_RENEW;
        } else {
            this.softRenew = Period.ofDays( softRenewDays );
        }

        return this;
    }

    @Override
    public Builder setHardRenew( @NotNull Period hardRenew )
    {
        if ( hardRenew == null || hardRenew.isNegative() || hardRenew.isZero() ) {
            this.hardRenew = Constants.CertificateManager.HARD_RENEW;
        } else {
            this.hardRenew = hardRenew;
        }

        return this;
    }

    @Override
    public Builder setHardRenew( @Positive int hardRenewDays )
    {
        if ( hardRenewDays < 1 ) {
            this.hardRenew = Constants.CertificateManager.HARD_RENEW;
        } else {
            this.hardRenew = Period.ofDays( hardRenewDays );
        }

        return this;
    }

    @Override
    public CertificateManager build() throws IllegalArgumentException
    {
        if ( this.authorities.isEmpty() ) {
            throw new IllegalArgumentException( "No authorities" );
        } else if ( this.hardRenew == null || this.hardRenew.isNegative() || this.hardRenew.isZero() ) {
            throw new IllegalArgumentException( "No hard renew window" );
        } else if ( this.softRenew == null || this.softRenew.isNegative() || this.softRenew.isZero() ) {
            throw new IllegalArgumentException( "No soft renew window" );
        } else if ( this.keyStore == null ) {
            throw new IllegalArgumentException( "No key store" );
        }

        if ( this.secureRandom == null ) {
            try {
                this.secureRandom = SecureRandom.getInstanceStrong();
            } catch ( NoSuchAlgorithmException ex ) {
                throw new IllegalArgumentException( "No secure random provided or created", ex );
            }
        }

        if ( this.keyPairGenerator == null ) {
            try {
                this.keyPairGenerator = KeyPairGenTools.newRSAGenerator( Constants.CertificateManager.RSA_KEY_SIZE, this.secureRandom );
            } catch ( GeneralSecurityException ex ) {
                throw new IllegalArgumentException( "No key pair generator provided or created", ex );
            }
        }

        return new CertificateManagerImpl( this );
    }

    public static CertificateManager.Builder newPropertyBuilder( @NotNull Path propertyFile ) throws Exception
    {
        Objects.requireNonNull( propertyFile );

        Path    config  = (propertyFile.isAbsolute()) ? propertyFile : propertyFile.toAbsolutePath();
        Path    baseDir = config.getParent();

        return new PropertyConfigurator( baseDir, config );
    }

    public static CertificateManager.Builder newXmlBuilder( @NotNull Path xmlFile ) throws Exception
    {
        Objects.requireNonNull( xmlFile );

        Path    config  = (xmlFile.isAbsolute()) ? xmlFile : xmlFile.toAbsolutePath();
        Path    baseDir = config.getParent();

        return new XmlConfigurator( baseDir, config );
    }

    public static CertificateManager.Builder newDefaultBuilder( Path baseDir ) throws Exception
    {
        return DefaultConfigurator.configure( baseDir );
    }
}
