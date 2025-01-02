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
package com.orbaker.autotls.example;

import com.orbaker.autotls.AcmeAuthority;
import com.orbaker.autotls.CertificateAuthority;
import com.orbaker.autotls.CertificateAuthority.WildcardPolicy;
import com.orbaker.autotls.CertificateManager;
import com.orbaker.autotls.Credential;
import com.orbaker.autotls.CredentialStore;
import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.SelfSignedAuthority;
import com.orbaker.autotls.tools.HostNameTools;
import com.orbaker.autotls.tools.KeyPairGenTools;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Period;
import java.util.Locale;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Examples.
 *
 * @author torbaker
 */
public class Examples
{
    private Examples() {}

    /**
     * Simplest. ShOULD work for testing. Please do not use this in production.
     *
     * This uses default settings:
     * <ul>
     * <li>Key Store is kept in a file 'autotls.properties' in a directory named 'autotls' under
     *     the user's home directory.</li>
     * <li>Credential store is stored as 'autotls.kps' in the same path.</li>
     * <li>Both stores use 'changeit' as the password.</li>
     * <li>Let's Encrypt and Self-Signed are configured.</li>
     * <ul>
     *
     * @throws Exception
     */
    public static void simplest() throws Exception
    {
        CertificateManager  manager = CertificateManager.newDefaultInstance();

        manager.requireCoverageFor( "test.example.com", "www.example.com" );
    }

    /**
     * Simplest production instance. With no configuration file, this is the
     * same as 'simplest()'. When production time comes, simply add a configuration
     * file to {@code baseDir} and the next call to {@code newInstance()} will
     * pick to run with no code changes.
     *
     * @throws Exception
     */
    public static void simple() throws Exception
    {
        Path                baseDir = Paths.get( SystemUtils.USER_HOME ).resolve( "autotls" );
        CertificateManager  manager = CertificateManager.newInstance( baseDir );

        manager.requireCoverageFor( "test.example.com", "www.example.com" );
    }

    /**
     * Example using a properties file.
     *
     * @throws Exception
     */
    public static void properties() throws Exception
    {
        Path                configFile  = Paths.get( SystemUtils.USER_HOME, "autotls", "autotls.properties" );
        CertificateManager  manager     = CertificateManager.newPropertyInstance( configFile );

        manager.requireCoverageFor( "test.example.com", "www.example.com" );
    }

    /**
     * Example using an XML file.
     *
     * @throws Exception
     */
    public static void xml() throws Exception
    {
        Path                configFile  = Paths.get( SystemUtils.USER_HOME, "autotls", "autotls.xml" );
        CertificateManager  manager     = CertificateManager.newXmlInstance( configFile );

        manager.requireCoverageFor( "test.example.com", "www.example.com" );
    }

    /**
     * This example shows full use of the library with every option shown.
     *
     * @throws Exception
     */
    public static void builders() throws Exception
    {
        Logger              logger          = LoggerFactory.getLogger( Examples.class );
        Path                baseDir         = Paths.get( SystemUtils.USER_HOME ).resolve( "autotls" );
        String              hostName        = HostNameTools.getHostName();
        String              domainName      = HostNameTools.splitHostName( hostName ).getRight();
        String              emailAddress    = SystemUtils.USER_NAME + "@" + domainName;
        SecureRandom        secureRandom    = SecureRandom.getInstanceStrong();
        String              countryCode     = StringUtils.defaultIfBlank( Locale.getDefault().getCountry(), "US" ).toLowerCase();
        KeyPairGenerator    ecgen           = KeyPairGenTools.newECGenerator( "secp384r1", secureRandom );
        KeyPairGenerator    rsagen          = KeyPairGenTools.newRSAGenerator( 4096, secureRandom );

        logger.info( "Builder Example" );
        logger.info( "- Detected Values:" );
        logger.info( "  - BaseDir      : " + baseDir.toString() );
        logger.info( "  - HostName     : " + hostName           );
        logger.info( "  - DomainName   : " + domainName         );
        logger.info( "  - EMail Address: " + emailAddress       );
        logger.info( "  - Country Code : " + countryCode        );

        // Jigger the credential store until it has two credentials we can reuse
        Path                credsFile       = baseDir.resolve( "autotls.kps" );
        CredentialStore     credentials     = (Files.exists( credsFile ))
                                                ? CredentialStore.getInstance( credsFile, "changeit".toCharArray(), true )
                                                : CredentialStore.newInstance();
        Credential          letsEncCred     = credentials.get( "letsencrypt" ).orElse( null );
        Credential          zeroSslCred     = credentials.get( "zerossl"     ).orElse( null );
        boolean             modified        = false;

        logger.info( "- Credential Store: " + credsFile );
        logger.info( "  - Loaded " + credentials.size() + " entries" );

        if ( letsEncCred == null ) {
            logger.info( "  - Creating EC credential for letsencrypt" );

            letsEncCred = Credential.builder()
                            .setEMailAddress( emailAddress )
                            .setUri( "acme://letsencrypt.org/staging" )
                            .setKeyPair( ecgen.generateKeyPair() )
                            .build();

            credentials.put( "letsencrypt", letsEncCred );
            modified = true;

            logger.info( "  - Added 'letsencrypt' to key pair store" );
        } else {
            logger.info( "  - Alias 'letsencrypt' found" );
        }

        if ( zeroSslCred == null ) {
            logger.info( "  - Creating RSA credential for zerossl" );

            zeroSslCred = Credential.builder()
                            .setEMailAddress( emailAddress )
                            .setUri( "acme://zerossl.com/v2/D30" )
                            .setKeyPair( rsagen.generateKeyPair() )
                            .setExternalKeyId( "aaa" )
                            .setExternalKey( "bbb" )
                            .build();

            credentials.put( "zerossl", zeroSslCred );
            modified = true;

            logger.info( "  - Added 'zerossl' to key pair store" );
        } else {
            logger.info( "  - Alias 'zerossl' found" );
        }

        if ( modified ) {
            credentials.save( credsFile, "changeit".toCharArray(), true );

            logger.info( "  - Saved key pair store changes" );
        }

        // What is the keystore we are managing?
        KeyStoreInfo        keyStore    = KeyStoreInfo.builder()
                                                .setStoreType( KeyStore.getDefaultType() )
                                                .setStoreFile( baseDir.resolve( "autotls.jks" ) )
                                                .setStorePass( "changeit".toCharArray() )
                                                .setKeyPass( "changeit".toCharArray() )
                                                .setStrict( true )
                                                .build();
        logger.info( "- Key Store"                              );
        logger.info( "  - Store File = " + keyStore.storeFile() );
        logger.info( "  - Store Type = " + keyStore.storeType() );
        logger.info( "  - Strict     = " + keyStore.strict()    );

        // Defina a shared authority configuration
        X500Principal                   relativeName    = new X500Principal( "OU = AutoTLS, O = My Company, C = US" );
        CertificateAuthority.Builder    acmeConfig      = CertificateAuthority.builder()
                                                            .setRelativeName( relativeName )
                                                            .setRelativeName( "OU", "AutoTLS" ) // redundant but illustratative
                                                            .setRelativeName( new Rdn( "C", countryCode ) ) // redundant but illustratative
                                                            .setWildcardPolicy( WildcardPolicy.NEVER )
                                                            .setMaxAltNamesPerCert( 4 )
                                                            .setSaveCsr( true )
                                                            .setSignatureAlgorithm( "SHA384WithRSA" )
                                                            .setCsrPath( baseDir.resolve( "csrs" ) );

        CertificateAuthority            letsEncrypt     = AcmeAuthority.builder( acmeConfig )
                                                            .setCredential( letsEncCred )
                                                            .build();

        logger.info( "- Authority: " + letsEncCred.uri().toString()                         );
        logger.info( "  - Credential:"                                                      );
        logger.info( "    - URI             = " + letsEncCred.uri()                         );
        logger.info( "    - Account EMail   = " + letsEncCred.emailAddress()                );
        logger.info( "  - Authority :"                                                      );
        logger.info( "    - Relative Name   = " + acmeConfig.getRelativeName()              );
        logger.info( "    - Wildcard Policy = " + acmeConfig.getWildcardPolicy()            );
        logger.info( "    - Max Alt Names   = " + acmeConfig.getMaxAltNamesPerCert()        );
        logger.info( "    - Include Domain  = " + acmeConfig.isIncludeDomainAsAltName()     );
        logger.info( "    - Signature Algo  = " + acmeConfig.getSignatureAlgorithm()        );
        logger.info( "    - Save CSR        = " + acmeConfig.isSaveCsr()                    );
        logger.info( "    - CSR Path        = " + acmeConfig.getCsrPath()                   );

        CertificateAuthority            zeroSsl         = AcmeAuthority.builder( acmeConfig )
                                                            .setCredential( zeroSslCred )
                                                            .build();

        logger.info( "- Authority: " + zeroSslCred.uri().toString()                         );
        logger.info( "  - Credential:"                                                      );
        logger.info( "    - URI           = " + zeroSslCred.uri()                           );
        logger.info( "    - Account EMail = " + zeroSslCred.emailAddress()                  );
        logger.info( "    - Key ID        = " + zeroSslCred.externalKeyId()                 );
        logger.info( "    - Secret Key    = " + zeroSslCred.externalKey()                   );
        logger.info( "  - Authority :"                                                      );
        logger.info( "    - Relative Name   = " + acmeConfig.getRelativeName()              );
        logger.info( "    - Wildcard Policy = " + acmeConfig.getWildcardPolicy()            );
        logger.info( "    - Max Alt Names   = " + acmeConfig.getMaxAltNamesPerCert()        );
        logger.info( "    - Include Domain  = " + acmeConfig.isIncludeDomainAsAltName()     );
        logger.info( "    - Signature Algo  = " + acmeConfig.getSignatureAlgorithm()        );
        logger.info( "    - Save CSR        = " + acmeConfig.isSaveCsr()                    );
        logger.info( "    - CSR Path        = " + acmeConfig.getCsrPath()                   );

        // Set up a tweaked configuration for the self-signed authority. When self-signing, we
        // might as well use wildcard certificates for flexibility.
        CertificateAuthority.Builder    selfConfig  = CertificateAuthority.builder( acmeConfig )
                                                        .setWildcardPolicy( WildcardPolicy.ALWAYS )
                                                        .setIncludeDomainAsAltName( true );
        SelfSignedAuthority             selfSigned  = SelfSignedAuthority.builder( selfConfig )
                                                        .setValidity( Period.ofDays( 90 ) )
                                                        .build();

        logger.info( "- Authority: Self signer"                                             );
        logger.info( "  - Authority :"                                                      );
        logger.info( "    - Relative Name   = " + selfConfig.getRelativeName()              );
        logger.info( "    - Wildcard Policy = " + selfConfig.getWildcardPolicy()            );
        logger.info( "    - Max Alt Names   = " + selfConfig.getMaxAltNamesPerCert()        );
        logger.info( "    - Include Domain  = " + selfConfig.isIncludeDomainAsAltName()     );
        logger.info( "    - Signature Algo  = " + selfConfig.getSignatureAlgorithm()        );
        logger.info( "    - Save CSR        = " + selfConfig.isSaveCsr()                    );
        logger.info( "    - CSR Path        = " + selfConfig.getCsrPath()                   );
        logger.info( "    - Validity        = " + selfSigned.validity()                     );

        // Now, make the certificate manager instance
        CertificateManager  manager = CertificateManager.builder()
                                        .setLogger( logger )
                                        .setKeyStore( keyStore )
                                        .setAuthorities( letsEncrypt )
//                                        .setAuthorities( letsEncrypt, zeroSsl )
                                        .addAuthority( selfSigned )
                                        .setUpgradeSelfSigned( true )
                                        .setRemoveExpiredCerts( true )
                                        .setSecureRandom( secureRandom )
                                        .setKeyPairGenerator( rsagen )
                                        .setSoftRenew( Period.ofDays( 14 ) )
                                        .setHardRenew( Period.ofDays(  3 ) )
                                        .build();

        manager.requireCoverageFor( "test.motoware.solutions", "sample.motoware.solutions" );
    }

    public static void main( String[] args )
    {
        try {
            try ( InputStream input = Examples.class.getResourceAsStream( "/logging.properties" ) ) {
                if ( input != null ) {
                    java.util.logging.LogManager.getLogManager().readConfiguration( input );
                }
            }

            Examples.builders();
        } catch ( Exception ex ) {
            ex.printStackTrace();
        }
    }
}
