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
package com.orbaker.autotls;

import com.orbaker.autotls.impl.CertificateManagerBuilderImpl;
import com.orbaker.autotls.impl.Constants;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Period;
import java.util.Collection;
import java.util.List;
import java.util.SequencedCollection;
import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;

/**
 * The main interface.
 *
 * @author torbaker
 */
public interface CertificateManager
{
    /**
     * Creates a new default instance centered in a directory named
     * 'autotls' within the current user's home directory.
     *
     * @return
     *      New {@code CertificateManager} instance.
     *
     * @throws Exception
     *      If the instance cannot be configured.
     *
     * @throws IllegalArgumentException
     *      If the configuration held in the default builder is not
     *      usable. This should probably not be thrown here.
     *
     * @throws IOException
     *      If files and directories necessary for operation cannot
     *      be created
     *
     * @throws URISyntaxException
     *      If the ACME URI cannot be parsed. This should probably
     *      not be thrown here.
     *
     * @throws GeneralSecurityException
     *      For errors in the Java security package
     */
    @NotNull
    static CertificateManager newDefaultInstance() throws Exception
    {
        Path baseDir = Paths.get( SystemUtils.USER_HOME, "autotls" );

        return CertificateManagerBuilderImpl.newDefaultBuilder( baseDir ).build();
    }

    /**
     * Creates a new instance by following the following steps:
     * <ol>
     * <li>If a file named 'autotls.xml' exists in {@code baseDir},
     *      then this is the equivalent of calling
     *      {@link #newXmlInstance(java.nio.file.Path)}</li>
     * <li>If a file named 'autotls.properties' exists in {@code baseDir},
     *      then this is the equivalent of calling
     *      {@link #newPropertyInstance(java.nio.file.Path)}</li>
     * <li>This is creates a new default instance using {@code baseDir}
     *      for storing files.</li>
     * </ol>
     *
     * @param baseDir
     *      Base directory for autotls files.
     *
     * @return
     *      New {@code CertificateManager} instance.
     *
     * @throws Exception
     *      If the instance cannot be configured.
     *
     * @throws IllegalArgumentException
     *      If the configuration held in the default builder is not
     *      usable. This should probably not be thrown here.
     *
     * @throws IOException
     *      If files and directories necessary for operation cannot
     *      be created
     *
     * @throws URISyntaxException
     *      If the ACME URI cannot be parsed. This should probably
     *      not be thrown here.
     *
     * @throws GeneralSecurityException
     *      For errors in the Java security package
     */
    @NotNull
    static CertificateManager newInstance( @NotNull Path baseDir ) throws Exception
    {
        Path                        propertyFile    = baseDir.resolve( Constants.PACKAGE_LOWER + ".properties" );
        Path                        xmlFile         = baseDir.resolve( Constants.PACKAGE_LOWER + ".xml" );
        CertificateManager.Builder  builder         = null;

        if ( Files.exists( xmlFile ) ) {
            builder = CertificateManagerBuilderImpl.newXmlBuilder( propertyFile );
        } else if ( Files.exists( propertyFile ) ) {
            builder = CertificateManagerBuilderImpl.newPropertyBuilder( propertyFile );
        } else {
            builder = CertificateManagerBuilderImpl.newDefaultBuilder( baseDir );
        }

        return builder.build();
    }

    /**
     * Creates a new instance configured by the contents of
     * {@code propertyFile}.
     *
     * @param propertyFile
     *      Property file to configure instance.
     *
     * @return
     *      New {@code CertificateManager} instance.
     *
     * @throws Exception
     *      If the instance cannot be configured.
     *
     * @throws IllegalArgumentException
     *      If the configuration held in the default builder is not
     *      usable.
     *
     * @throws IOException
     *      If files and directories necessary for operation cannot
     *      be created.
     *
     * @throws URISyntaxException
     *      If the ACME URI cannot be parsed.
     *
     * @throws GeneralSecurityException
     *      For errors in the Java security package
     */
    @NotNull
    static CertificateManager newPropertyInstance( @NotNull Path propertyFile ) throws Exception
    {
        return CertificateManagerBuilderImpl.newPropertyBuilder( propertyFile ).build();
    }

    /**
     * Creates a new instance configured by the contents of
     * {@code xmlFile}.
     *
     * @param xmlFile
     *      Property file to configure instance.
     *
     * @return
     *      New {@code CertificateManager} instance.
     *
     * @throws Exception
     *      If the instance cannot be configured.
     *
     * @throws IllegalArgumentException
     *      If the configuration held in the default builder is not
     *      usable.
     *
     * @throws IOException
     *      If files and directories necessary for operation cannot
     *      be created.
     *
     * @throws URISyntaxException
     *      If the ACME URI cannot be parsed.
     *
     * @throws GeneralSecurityException
     *      For errors in the Java security package
     */
    @NotNull
    static CertificateManager newXmlInstance( @NotNull Path xmlFile ) throws Exception
    {
        return CertificateManagerBuilderImpl.newPropertyBuilder( xmlFile ).build();
    }

    /**
     * Create a new default builder.
     *
     * @return
     *      Default builder.
     */
    @NotNull
    static CertificateManager.Builder builder()
    {
        return new CertificateManagerBuilderImpl();
    }

    /**
     * Require coverage for the given {@code hostNames} to continue. This
     * will check for existing coverage, and will try to acquire or renew
     * coverage for all listed names, failing if it is not able to.
     *
     * @param hostNames
     *      Host names requiring TLS coverage.
     *
     * @throws IOException
     *      If there is an I/O error manipulating the key store.
     *
     * @throws GeneralSecurityException
     *      If there is an error manipulating the key store, or coverage
     *      is not present and cannot be acquired for one or more names.
     */
    void requireCoverageFor( @NotEmpty String ... hostNames ) throws IOException, GeneralSecurityException;

    /**
     * Require coverage for the given {@code hostNames} to continue. This
     * will check for existing coverage, and will try to acquire or renew
     * coverage for all listed names, failing if it is not able to.
     *
     * @param hostNames
     *      Host names requiring TLS coverage.
     *
     * @throws IOException
     *      If there is an I/O error manipulating the key store.
     *
     * @throws GeneralSecurityException
     *      If there is an error manipulating the key store, or coverage
     *      is not present and cannot be acquired for one or more names.
     */
    void requireCoverageFor( @NotEmpty Collection<String> hostNames ) throws IOException, GeneralSecurityException;

    /**
     * Builder
     */
    interface Builder
    {
        /**
         * Get the logger for this instance
         *
         * @return
         *      Logger for instance.
         */
        Logger getLogger();

        /**
         * Java KeyStore information.
         *
         * @return
         *      Key store controlled by manager.
         */
        KeyStoreInfo getKeyStore();

        /**
         * Get the secure random number generator for this manager.
         *
         * @return
         *      Secure random generator
         */
        SecureRandom getSecureRandom();

        /**
         * Get the key pair generator for this manager.
         *
         * @return
         *      Key pair generator
         */
        KeyPairGenerator getKeyPairGenerator();

        /**
         * Registered certificate authorities.
         *
         * @return
         *      Certificate authorities
         */
        List<CertificateAuthority> getAuthorities();

        /**
         * Get the self-signed upgrade flag.
         *
         * @return
         *      Whether to attempt to upgrade self-signed certificates.
         *
         * @see #setUpgradeSelfSigned(boolean)
         */
        boolean isUpgradeSelfSigned();

        /**
         * If {@code true}, auto remove expired expired certificates
         * from the key store.
         *
         * @return
         *      Whether to remove expired certificates.
         *
         * @see #setRemoveExpiredCerts(boolean)
         */
        boolean isRemoveExpiredCerts();

        /**
         * Get the soft renewal time window.
         *
         * @return
         *      The soft renewal window.
         *
         * @see #setSoftRenew(int)
         */
        Period getSoftRenew();

        /**
         * Get the hard renewal time window
         *
         * @return
         *      The hard renewal window.
         *
         * @see #setHardRenew(int)
         */
        Period getHardRenew();

        /**
         * Set the keystore managed by this instance.
         *
         * @param keyStore
         *      Managed keystore.
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder setKeyStore( @NotNull KeyStoreInfo keyStore );

        /**
         * Set the logger for this instance.
         *
         * @param logger
         *      This logger.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder setLogger( @NotNull Logger logger );

        /**
         * Add a certificate authority for certificate generation.
         *
         * @param authority
         *      Certificate authority
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder addAuthority( @NotNull CertificateAuthority authority );

        /**
         * Add the given {@code authorities} to the list of authorities
         * to try to get coverage.
         *
         * @param authorities
         *      Certificate authorities.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder addAuthorities( @NotEmpty CertificateAuthority ... authorities );


        /**
         * Add the given {@code authorities} to the list of authorities
         * to try to get coverage.
         *
         * @param authorities
         *      Certificate authorities.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder addAuthorities( @NotEmpty SequencedCollection<CertificateAuthority> authorities );

        /**
         * Add set list of {@code authorities} to try to get coverage.
         *
         * @param authorities
         *      Certificate authorities.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder setAuthorities( @NotNull CertificateAuthority ... authorities );

        /**
         * Add set list of {@code authorities} to try to get coverage.
         *
         * @param authorities
         *      Certificate authorities.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder setAuthorities( @NotEmpty SequencedCollection<CertificateAuthority> authorities );

        /**
         * Set the flag to upgrade self-signed certificates. When this flag is present,
         * self-signed certificates are ignored when checking for ACME coverage. This
         * has the effect of retrying ACME coverage for existing self-signed certificates
         *
         * @param upgradeSelfSigned
         *      {@code true} to attempt to upgrade/replace self-signed certificates
         *      with ACME certificates where possible.
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder setUpgradeSelfSigned( boolean upgradeSelfSigned );

        /**
         * Set the flag to remove expired certificates.
         *
         * If {@link #setUpgradeSelfSigned(boolean)} is {@code true},
         * and this is {@code false}, it is possible that the key store
         * may end up with both a self-signed and an ACME issued certificate
         * within a key store.
         *
         * @param removeExpiredCerts
         *      {@code true} to attempt to remove expired certificates
         *      from the managed key store.
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder setRemoveExpiredCerts( boolean removeExpiredCerts );

        /**
         * Set the soft renewal window.
         *
         * When a certificate ages near enough to its expiration date
         * to fall within this window, an attempt will be made to
         * renew/replace it before continuing.
         *
         * It is not an error if certificates within the soft renewal
         * window, but not within the hard renewal window cannot be
         * renewed/replaced.
         *
         * @param softRenew
         *      Soft renew window.
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder setSoftRenew( @NotNull Period softRenew );

        /**
         * Set the soft renewal window in terms of days. This is a
         * convenience wrapper for {@link #setSoftRenew(java.time.Period)}
         *
         * @param softRenewDays
         *      Soft renewal days.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
                Builder setSoftRenew( @Positive int softRenewDays );

        /**
         * Set the hard renewal window.
         *
         * When a certificate ages near enough to its expiration date
         * to fall within this window, an attempt will be made to
         * renew/replace it before continuing.
         *
         * If certificates within the hard renewal window cannot be
         * renewed/replaced, it is considered uncovered.
         *
         * @param hardRenew
         *      Hard renew window.
         *
         * @return
         *      chainable builder
         */
        @NotNull
        Builder setHardRenew( @NotNull Period hardRenew );

        /**
         * Set the hard renewal window in terms of days. This is a
         * convenience wrapper for {@link #setHardRenew(java.time.Period)}
         *
         * @param hardRenewDays
         *      Hard renewal days.
         *
         * @return
         *      chainable builder.
         */
        @NotNull
        Builder setHardRenew( @Positive int hardRenewDays );

        /**
         * Set the secure random number generator.
         *
         * @param secureRandom
         *      Secure random number generator.
         *
         * @return
         *      Chainable builder.
         */
        @NotNull
        Builder setSecureRandom( @NotNull SecureRandom secureRandom );

        /**
         * Set the key pair generator for certificate generation.
         *
         * @param keyPairGenerator
         *      Key pair generator
         *
         * @return
         *      Chainable builder.
         */
        @NotNull
        Builder setKeyPairGenerator( @NotNull KeyPairGenerator keyPairGenerator );

        /**
         * Create a {@code CertificateManager} instance based on
         * this builder.
         *
         * @return
         *      new {@code CertificateManager}.
         *
         * @throws IOException
         *      If the key store does not exist and cannot be created.
         *
         * @throws GeneralSecurityException
         *      If the key store does not exist and cannot be created.
         *
         * @throws IllegalArgumentException
         *      If the builder's settings prevent construction.
         */
        @NotNull
        CertificateManager build() throws IOException, GeneralSecurityException, IllegalArgumentException;
    }
}
