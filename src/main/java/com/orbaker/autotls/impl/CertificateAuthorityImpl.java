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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SequencedCollection;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;

/**
 *
 * @author torbaker
 */
abstract class CertificateAuthorityImpl implements CertificateAuthority
{
    protected final List<Rdn>       relativeNames;
    protected final WildcardPolicy  wildcardPolicy;
    protected final Path            csrPath;
    protected final boolean         saveCsr;
    protected final boolean         includeDomainName;
    protected final int             maxAltNamesPerCert;
    protected final String          signatureAlgorithm;

    CertificateAuthorityImpl( CertificateAuthority.Builder builder )
    {
        this.relativeNames      = Arrays.<Rdn>asList( builder.getRelativeNames().toArray( Rdn[]::new ) );
        this.wildcardPolicy     = builder.getWildcardPolicy();
        this.csrPath            = builder.getCsrPath();
        this.saveCsr            = builder.isSaveCsr();
        this.includeDomainName  = builder.isIncludeDomainAsAltName();
        this.maxAltNamesPerCert = builder.getMaxAltNamesPerCert();
        this.signatureAlgorithm = builder.getSignatureAlgorithm();
    }

    @NotBlank
    @Override
    public String signatureAlgorithm()
    {
        return this.signatureAlgorithm;
    }

    @NotNull
    @Override
    public List<Rdn> relativeName()
    {
        return this.relativeNames;
    }

    @NotNull
    @Override
    public WildcardPolicy wildcardPolicy()
    {
        return this.wildcardPolicy;
    }

    @Override
    public Path csrPath()
    {
        return this.csrPath;
    }

    @Override
    public boolean saveCsr()
    {
        return this.saveCsr;
    }

    @Override
    public int maxAltNamesPerCert()
    {
        return this.maxAltNamesPerCert;
    }

    @Override
    public boolean includeDomainAsAltName()
    {
        return this.includeDomainName;
    }

    protected final X500Name makeSubjectDN( String commonName ) throws GeneralSecurityException
    {
        X500Name subjectDN = null;

        try {
            var fullNames = new ArrayList<Rdn>( this.relativeNames );
            fullNames.add( new Rdn( "CN", commonName ) );

            var ldap = new LdapName( fullNames );

            subjectDN = new X500Name( ldap.toString() );
        } catch ( InvalidNameException ex ) {
            throw new GeneralSecurityException( "Invalod DName using CN=" + commonName, ex );
        }

        return subjectDN;
    }

    protected void writeCsr( String alias, PKCS10CertificationRequest request ) throws IOException
    {
        if ( this.saveCsr ) {
            Files.createDirectories( this.csrPath );

            Path fileName = this.csrPath.resolve( alias + ".csr" );

            try ( BufferedWriter writer = Files.newBufferedWriter( fileName, StandardCharsets.UTF_8,
                                                                             StandardOpenOption.CREATE,
                                                                             StandardOpenOption.TRUNCATE_EXISTING,
                                                                             StandardOpenOption.WRITE ) ) {
                try ( JcaPEMWriter out = new JcaPEMWriter( writer ) ) {
                    out.writeObject( request );
                }
            }
        }
    }

    protected final PKCS10CertificationRequest makeCsr( KeyPair keyPair,
                                                        X500Name subjectName,
                                                        SequencedCollection<String> altNames ) throws GeneralSecurityException, IOException, OperatorCreationException
    {
        GeneralName[]               nameArray           = altNames.stream()
                                                                     .map( name -> new GeneralName( GeneralName.dNSName, name ) )
                                                                     .toArray( GeneralName[]::new );
        GeneralNames                names               = new GeneralNames( nameArray );
        ExtensionsGenerator         extGenerator        = new ExtensionsGenerator();

        extGenerator.addExtension( Extension.subjectAlternativeName, true, names );

        PKCS10CertificationRequestBuilder   p10Builder  = new JcaPKCS10CertificationRequestBuilder( subjectName, keyPair.getPublic() )
                                                                .addAttribute( PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGenerator.generate() );

        JcaContentSignerBuilder             csBuilder   = new JcaContentSignerBuilder( signatureAlgorithm );
        ContentSigner                       csrSigner   = csBuilder.build( keyPair.getPrivate() );
        PKCS10CertificationRequest          csr         = p10Builder.build( csrSigner );

        return csr;
    }

    @Override
    public boolean claimCertificate( @NotEmpty Certificate[] chain )
    {
        return false;
    }

    @NotBlank
    @Override
    public abstract String identifier();

    @NotNull
    @Override
    public abstract KeyStore acquireCoverage( @NotNull Logger logger, @NotNull KeyPair keyPair, @NotEmpty SequencedCollection<String> names, @NotBlank String alias, @NotNull ProtectionParameter keyPass ) throws GeneralSecurityException;
}
