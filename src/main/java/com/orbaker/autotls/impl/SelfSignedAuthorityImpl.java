
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

import com.orbaker.autotls.SelfSignedAuthority;
import com.orbaker.autotls.tools.KeyStoreTools;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Period;
import java.util.Date;
import java.util.Objects;
import java.util.SequencedCollection;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author torbaker
 */
public class SelfSignedAuthorityImpl extends CertificateAuthorityImpl implements SelfSignedAuthority
{
    protected final Period  validity;

    public SelfSignedAuthorityImpl( SelfSignedAuthorityBuilderImpl builder )
    {
        super( builder );

        this.validity = builder.getValidity();
    }

    @Override
    public String identifier()
    {
        return "self-signed authority";
    }

    @NotNull
    @Override
    public Period validity()
    {
        return this.validity;
    }

    @Override
    public KeyStore acquireCoverage( Logger logger, KeyPair keyPair, SequencedCollection<String> domainNames, String alias, ProtectionParameter keyPass ) throws GeneralSecurityException
    {
        KeyStore    signed  = null;

        try {
            signed = KeyStoreTools.emptyKeyStore( KeyStore.getDefaultType() );

            if ( domainNames.isEmpty() ) {
                logger.info( "  - No host names for self-signing" );
            } else {
                X500Name                    subjectDN   = this.makeSubjectDN( domainNames.getFirst() );

                logger.info( "  - Self signing for " + domainNames.size() + " names" );
                logger.info( "    " + subjectDN.toString() );

                PKCS10CertificationRequest  csr         = this.makeCsr( keyPair, subjectDN, domainNames );

                this.writeCsr( alias, csr );

                Signature                   signature           = Signature.getInstance( this.signatureAlgorithm );
                AlgorithmIdentifier         sigAlgId            = new DefaultSignatureAlgorithmIdentifierFinder().find( this.signatureAlgorithm );
                AlgorithmIdentifier         digAlgId            = new DefaultDigestAlgorithmIdentifierFinder().find( sigAlgId );
                X500Name                    issuer              = new X500Name( csr.getSubject().toString() );
                X500Principal               issuerName          = new X500Principal( csr.getSubject().toString() );
                BigInteger                  serial              = new BigInteger( 32, new SecureRandom() );
                Instant                     notBefore           = Instant.now();
                Instant                     notAfter            = notBefore.plus( this.validity );
                SubjectPublicKeyInfo        keyInfo             = SubjectPublicKeyInfo.getInstance( keyPair.getPublic().getEncoded() );
                GeneralName[]               nameArray           = domainNames.stream()
                                                                             .map( name -> new GeneralName( GeneralName.dNSName, name ) )
                                                                             .toArray( GeneralName[]::new );
                GeneralNames                names               = new GeneralNames( nameArray );
                ExtensionsGenerator         extGenerator        = new ExtensionsGenerator();
                JcaX509ExtensionUtils       utils               = new JcaX509ExtensionUtils();
                X509v3CertificateBuilder    builder             = new X509v3CertificateBuilder( issuer,
                                                                                                serial,
                                                                                                Date.from( notBefore ),
                                                                                                Date.from( notAfter  ),
                                                                                                csr.getSubject(),
                                                                                                csr.getSubjectPublicKeyInfo() );

                // Basic constraints
                BasicConstraints    basic   = new BasicConstraints( false );
                KeyUsage            usage   = new KeyUsage( KeyUsage.keyEncipherment | KeyUsage.digitalSignature );
                ExtendedKeyUsage    exuse   = new ExtendedKeyUsage( new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth } );

                builder.addExtension( Extension.basicConstraints, true, basic );
                builder.addExtension( Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier( keyInfo ) );
                builder.addExtension( Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier( keyPair.getPublic(), issuerName, serial ) );
                builder.addExtension( Extension.keyUsage, true, usage.getEncoded() );
                builder.addExtension( Extension.extendedKeyUsage, false, exuse.getEncoded() );
                builder.addExtension( Extension.subjectAlternativeName, true, names );

                ContentSigner           signer      = new JcaContentSignerBuilder( this.signatureAlgorithm ).build( keyPair.getPrivate() );
                X509CertificateHolder   holder      = builder.build( signer );
                X509Certificate         cert        = new JcaX509CertificateConverter().getCertificate( holder );
                X509Certificate[]       chain       = new X509Certificate[] { cert };
                char[]                  password    = (keyPass instanceof PasswordProtection pwd) ? pwd.getPassword() : "changeit".toCharArray();

                signed.setKeyEntry( alias, keyPair.getPrivate(), password, chain );
            }
        } catch ( IOException ex ) {
            throw new GeneralSecurityException( "Cannot initialize key store", ex );
        } catch ( OperatorCreationException ex ) {
            throw new GeneralSecurityException( "Cannot create PKCS10 CSR", ex );
        }

        return signed;
    }
}
