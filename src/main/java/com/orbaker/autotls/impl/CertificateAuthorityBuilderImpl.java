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
import com.orbaker.autotls.CertificateAuthority.Builder;
import com.orbaker.autotls.CertificateAuthority.WildcardPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author torbaker
 */
public sealed class CertificateAuthorityBuilderImpl implements CertificateAuthority.Builder
        permits AcmeAuthorityBuilderImpl, SelfSignedAuthorityBuilderImpl
{
    protected final Map<String,Rdn> relativeNames;
    protected       WildcardPolicy  wildcardPolicy;
    protected       int             maxAltNames;
    protected       String          signatureAlgorithm;
    protected       boolean         saveCsr;
    protected       Path            csrPath;
    protected       boolean         includeDomain;

    public CertificateAuthorityBuilderImpl()
    {
        this.relativeNames      = new HashMap<String,Rdn>();
        this.wildcardPolicy     = null;
        this.signatureAlgorithm = null;
        this.maxAltNames        = 0;
        this.saveCsr            = false;
        this.csrPath            = null;
        this.includeDomain      = true;
    }

    public CertificateAuthorityBuilderImpl( CertificateAuthority.Builder copyFrom )
    {
        this();

        if ( copyFrom != null ) {
            this.wildcardPolicy     = copyFrom.getWildcardPolicy();
            this.signatureAlgorithm = copyFrom.getSignatureAlgorithm();
            this.maxAltNames        = copyFrom.getMaxAltNamesPerCert();
            this.saveCsr            = copyFrom.isSaveCsr();
            this.csrPath            = copyFrom.getCsrPath();
            this.includeDomain      = copyFrom.isIncludeDomainAsAltName();

            for ( Rdn rdn : copyFrom.getRelativeNames() ) {
                this.relativeNames.put( rdn.getType(), rdn );
            }
        }
    }

    @NotNull
    @Override
    public String getRelativeName()
    {
        if ( this.relativeNames.isEmpty() ) {
            return "";
        } else {
            List<Rdn>   list    = this.relativeNames.values().stream().toList();
            LdapName    ldap    = new LdapName( list );

            return ldap.toString();
        }
    }

    @NotNull
    @Override
    public List<Rdn> getRelativeNames()
    {
        return this.relativeNames.values().stream().toList();
    }

    @Override
    public WildcardPolicy getWildcardPolicy()
    {
        return this.wildcardPolicy;
    }

    @Override
    public int getMaxAltNamesPerCert()
    {
        return this.maxAltNames;
    }

    @Override
    public String getSignatureAlgorithm()
    {
        return this.signatureAlgorithm;
    }

    @Override
    public boolean isSaveCsr()
    {
        return this.saveCsr;
    }

    @Override
    public Path getCsrPath()
    {
        return this.csrPath;
    }

    @Override
    public boolean isIncludeDomainAsAltName()
    {
        return this.includeDomain;
    }

    @Override
    public Builder setRelativeName( @NotBlank String rfc2253 ) throws NamingException
    {
        String      text    = Precheck.requireNonBlank( rfc2253 );
        LdapName    ldap    = new LdapName( text );

        for ( Rdn relativeName : ldap.getRdns() ) {
            this.setRelativeName( relativeName );
        }

        return this;
    }

    @Override
    public Builder setRelativeName( @NotNull X500Principal x500 ) throws NamingException
    {
        Objects.requireNonNull( x500 );

        return this.setRelativeName( x500.getName(  X500Principal.RFC2253 ) );
    }

    @Override
    public Builder setRelativeName( @NotNull Rdn relativeName ) throws NamingException
    {
        Objects.requireNonNull( relativeName );

        boolean allow   = Arrays.stream( Constants.Authority.ALLOWED_NAMES )
                                .anyMatch( permit -> permit.equalsIgnoreCase( relativeName.getType() ) );

        if ( ! allow ) {
            throw new NamingException( "Relative name '" + relativeName.getType() + "' is not permitted." );
        }

        String  t   = relativeName.getType().toUpperCase();
        Object  v   = relativeName.getValue();

        this.relativeNames.put( t, new Rdn( t, v ) );

        return this;
    }

    @Override
    public Builder setRelativeName( @NotBlank String type, @NotBlank String value ) throws NamingException
    {
        String  t   = Precheck.requireNonBlank( type  ).toUpperCase();
        String  v   = Precheck.requireNonBlank( value );

        return this.setRelativeName( new Rdn( t, v ) );
    }

    @Override
    public Builder setRelativeNames( @NotEmpty List<Rdn> relativeNames ) throws NamingException
    {
        Precheck.requireNonEmpty( relativeNames );

        for ( Rdn relativeName : relativeNames ) {
            this.setRelativeName( relativeName );
        }

        return this;
    }

    @Override
    public Builder setWildcardPolicy( @NotNull WildcardPolicy wildcardPolicy )
    {
        this.wildcardPolicy = Objects.requireNonNull( wildcardPolicy );

        return this;
    }

    @Override
    public Builder setMaxAltNamesPerCert( @Positive int maxAltNames )
    {
        this.maxAltNames = Precheck.positive( maxAltNames );

        return this;
    }

    @Override
    public Builder setSignatureAlgorithm( @NotBlank String signatureAlgorithm )
    {
        this.signatureAlgorithm = Precheck.requireNonBlank( signatureAlgorithm );

        return this;
    }

    @Override
    public Builder setSaveCsr( boolean saveCsr )
    {
        this.saveCsr = saveCsr;

        return this;
    }

    @Override
    public Builder setCsrPath( @NotBlank String csrPath ) throws InvalidPathException
    {
        String  pathName = Precheck.requireNonBlank( csrPath );
        Path    savePath = Paths.get( pathName );

        return this.setCsrPath( savePath );
    }

    @Override
    public Builder setCsrPath( @NotNull File csrPath ) throws InvalidPathException
    {
        Objects.requireNonNull( csrPath );

        return this.setCsrPath( csrPath.toPath() );
    }

    @Override
    public Builder setCsrPath( @NotNull Path csrPath )
    {
        this.csrPath = Objects.requireNonNull( csrPath );

        return this;
    }

    @Override
    public Builder setIncludeDomainAsAltName( boolean includeDomainName )
    {
        this.includeDomain  = includeDomainName;

        return this;
    }

    protected final void validate() throws IllegalArgumentException
    {
        if ( this.saveCsr && this.csrPath == null ) {
            throw new IllegalArgumentException( "CSR saving is enabled, but path is not set" );
        } else if ( this.maxAltNames < 1 ) {
            throw new IllegalArgumentException( "Maximum alternate names is less than 1" );
        } else if ( this.signatureAlgorithm == null ) {
            throw new IllegalArgumentException( "No signature algorithm for CSRs" );
        } else if ( this.wildcardPolicy == null ) {
            throw new IllegalArgumentException( "No wildcard policy" );
        }
    }
}
