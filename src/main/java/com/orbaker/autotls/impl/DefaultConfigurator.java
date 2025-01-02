/*-
 * #%L
 * autotls
 * %%
 * Copyright (C) 2024 - 2025 Tim Orbaker
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
import com.orbaker.autotls.CertificateAuthority.WildcardPolicy;
import com.orbaker.autotls.CertificateManager;
import com.orbaker.autotls.Credential;
import com.orbaker.autotls.CredentialStore;
import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.SelfSignedAuthority;
import com.orbaker.autotls.tools.HostNameTools;
import com.orbaker.autotls.tools.KeyPairGenTools;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Period;
import java.util.Locale;
import javax.naming.NamingException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author torbaker
 */
class DefaultConfigurator
{
    private DefaultConfigurator() {}

    public static CertificateManager.Builder configure( Path baseDir ) throws GeneralSecurityException, URISyntaxException, IOException, NamingException
    {
        Logger              logger          = LoggerFactory.getLogger( DefaultConfigurator.class );
        String              hostName        = HostNameTools.getHostName();
        String              domainName      = HostNameTools.splitHostName( hostName ).getRight();
        String              emailAddress    = SystemUtils.USER_NAME + "@" + domainName;
        SecureRandom        secureRandom    = SecureRandom.getInstanceStrong();
        String              countryCode     = StringUtils.defaultIfBlank( Locale.getDefault().getCountry(), "US" ).toLowerCase();
        KeyPairGenerator    ecgen           = KeyPairGenTools.newECGenerator( Constants.KeyGen.CURVE, secureRandom );

        logger.info( "Builder Example"                          );
        logger.info( "- Detected Values:"                       );
        logger.info( "  - BaseDir      : " + baseDir.toString() );
        logger.info( "  - HostName     : " + hostName           );
        logger.info( "  - DomainName   : " + domainName         );
        logger.info( "  - EMail Address: " + emailAddress       );
        logger.info( "  - Country Code : " + countryCode        );

        // Jigger the credential store until it has two credentials we can reuse
        Path                credsFile       = baseDir.resolve( Constants.CredentialStoreInfo.STORE_FILE );
        CredentialStore     credentials     = (Files.exists( credsFile ))
                                                ? CredentialStore.getInstance( credsFile,
                                                                               Constants.CredentialStoreInfo.STORE_PASS,
                                                                               Constants.CredentialStoreInfo.STRICT_MODE )
                                                : CredentialStore.newInstance();
        Credential          letsEncCred     = credentials.get( "letsencrypt" ).orElse( null );
        boolean             modified        = false;

        logger.info( "- Credential Store: " + credsFile );
        logger.info( "  - Loaded " + credentials.size() + " entries" );

        if ( letsEncCred == null ) {
            logger.info( "  - Creating EC credential for letsencrypt" );

            letsEncCred = Credential.builder()
                            .setEMailAddress( emailAddress )
                            .setUri( Constants.Acme.LETSENC_URI )
                            .setKeyPair( ecgen.generateKeyPair() )
                            .build();

            credentials.put( "letsencrypt", letsEncCred );
            modified = true;

            logger.info( "  - Added 'letsencrypt' to key pair store" );
        } else {
            logger.info( "  - Alias 'letsencrypt' found" );
        }

        if ( modified ) {
            credentials.save( credsFile,
                              Constants.CredentialStoreInfo.STORE_PASS,
                              Constants.CredentialStoreInfo.STRICT_MODE );

            logger.info( "  - Saved key pair store changes" );
        }

        // What is the keystore we are managing?
        KeyStoreInfo        keyStore    = KeyStoreInfo.builder()
                                                .setStoreType( Constants.KeyStoreInfo.STORE_TYPE    )
                                                .setStoreFile( Constants.KeyStoreInfo.STORE_FILE    )
                                                .setStorePass( Constants.KeyStoreInfo.STORE_PASS    )
                                                .setKeyPass  ( Constants.KeyStoreInfo.STORE_PASS    )
                                                .setStrict   ( Constants.KeyStoreInfo.STRICT_MODE   )
                                                .build();

        logger.info( "- Key Store"                              );
        logger.info( "  - Store File = " + keyStore.storeFile() );
        logger.info( "  - Store Type = " + keyStore.storeType() );
        logger.info( "  - Strict     = " + keyStore.strict()    );

        // Defina a shared authority configuration
        CertificateAuthority.Builder    acmeConfig      = CertificateAuthority.builder()
                                                            .setRelativeName        ( "OU", Constants.PACKAGE               )
                                                            .setRelativeName        ( "C", countryCode                      )
                                                            .setWildcardPolicy      ( Constants.Authority.WILDCARD_POLICY   )
                                                            .setMaxAltNamesPerCert  ( Constants.Authority.MAX_ALT_NAMES     )
                                                            .setIncludeDomainAsAltName( Constants.Authority.INCLUDE_DOMAIN  )
                                                            .setSignatureAlgorithm  ( Constants.Authority.SIGNATURE         )
                                                            .setSaveCsr             ( Constants.Authority.SAVE_CSR          )
                                                            .setCsrPath             ( Constants.Authority.CSR_PATH          );

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


        // Set up a tweaked configuration for the self-signed authority. When self-signing, we
        // might as well use wildcard certificates for flexibility.
        CertificateAuthority.Builder    selfConfig  = CertificateAuthority.builder( acmeConfig )
                                                        .setWildcardPolicy( WildcardPolicy.ALWAYS );
        SelfSignedAuthority             selfSigned  = SelfSignedAuthority.builder( selfConfig )
                                                        .setValidity( Constants.SelfSigned.VALIDITY )
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

        return  CertificateManager.builder()
                                  .setLogger( logger )
                                  .setKeyStore( keyStore )
                                  .setSecureRandom( secureRandom )
                                  .setKeyPairGenerator( ecgen )
                                  .setAuthorities( letsEncrypt, selfSigned )
                                  .setUpgradeSelfSigned ( Constants.CertificateManager.UPGRADE_CERTS    )
                                  .setRemoveExpiredCerts( Constants.CertificateManager.EXPIRE_CERTS     )
                                  .setSoftRenew         ( Constants.CertificateManager.SOFT_RENEW       )
                                  .setHardRenew         ( Constants.CertificateManager.HARD_RENEW       );
    }
}
