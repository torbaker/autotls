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

import com.orbaker.autotls.Credential;
import com.orbaker.autotls.Credential.Builder;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author torbaker
 */
public class CredentialBuilderImpl implements Credential.Builder
{
    static record CredentialImpl( URI uri,
                                  PublicKey publicKey,
                                  PrivateKey privateKey,
                                  String emailAddress,
                                  String externalKey,
                                  String externalKeyId ) implements Credential
    {
        @Override
        public KeyPair keyPair()
        {
            return new KeyPair( this.publicKey, this.privateKey );
        }
    }

    private URI         uri;
    private PublicKey   publicKey;
    private PrivateKey  privateKey;
    private String      emailAddress;
    private String      externalKey;
    private String      externalKeyId;

    public CredentialBuilderImpl()
    {
        this.uri            = null;
        this.publicKey      = null;
        this.privateKey     = null;
        this.emailAddress   = null;
        this.externalKey    = null;
        this.externalKeyId  = null;
    }

    @Override
    @NotNull
    public URI getUri()
    {
        return this.uri;
    }

    @Override
    @NotNull
    public PublicKey getPublicKey()
    {
        return this.publicKey;
    }

    @Override
    @NotNull
    public PrivateKey getPrivateKey()
    {
        return this.privateKey;
    }

    @Override
    @NotBlank
    public String getEMailAddress()
    {
        return this.emailAddress;
    }

    @Override
    public String getExternalKey()
    {
        return this.externalKey;
    }

    @Override
    public String getExternalKeyId()
    {
        return this.externalKeyId;
    }

    @Override
    public Builder setUri( @NotBlank String uriText ) throws URISyntaxException
    {
        if ( StringUtils.isBlank( uriText ) ) {
            throw new IllegalArgumentException();
        }

        this.uri = new URI( uriText.trim() );

        return this;
    }

    @Override
    public Builder setUri( @NotNull URL url ) throws URISyntaxException
    {
        this.uri = Objects.requireNonNull( url ).toURI();

        return this;
    }

    @Override
    public Builder setUri( @NotNull URI uri )
    {
        this.uri = Objects.requireNonNull( uri );

        return this;
    }

    @Override
    public Builder setPublicKey( @NotNull PublicKey publicKey )
    {
        this.publicKey = Objects.requireNonNull( publicKey );

        return this;
    }

    @Override
    public Builder setPrivateKey( @NotNull PrivateKey privateKey )
    {
        this.privateKey = Objects.requireNonNull( privateKey );

        return this;
    }

    @Override
    public Builder setKeyPair( @NotNull KeyPair keyPair )
    {
        Objects.requireNonNull( keyPair );

        this.privateKey = keyPair.getPrivate();
        this.publicKey  = keyPair.getPublic();

        return this;
    }

    @Override
    public Builder setEMailAddress( @NotBlank String emailAddress )
    {
        if ( StringUtils.isBlank( emailAddress ) ) {
            throw new IllegalArgumentException();
        }

        this.emailAddress = emailAddress.trim();

        return this;
    }

    @Override
    public Builder setExternalKey( String externalKey )
    {
        this.externalKey = StringUtils.trimToNull( externalKey );

        return this;
    }

    @Override
    public Builder setExternalKeyId( String externalKeyId )
    {
        this.externalKeyId = StringUtils.trimToNull( externalKeyId );

        return this;
    }

    @Override
    public Credential build()
    {
        if ( this.publicKey == null ) {
            throw new IllegalArgumentException( "No public key" );
        } else if ( this.privateKey == null ) {
            throw new IllegalArgumentException( "No private key" );
        } else if ( this.uri == null ) {
            throw new IllegalArgumentException( "No URI" );
        } else if ( StringUtils.isBlank( this.emailAddress ) ) {
            throw new IllegalArgumentException( "No email address" );
        } else if ( this.externalKeyId == null ^ this.externalKey == null ) {
            throw new IllegalArgumentException( "Only one of keyId/secretKey is provided" );
        }

        return new CredentialImpl( this.uri, this.publicKey, this.privateKey, this.emailAddress, this.externalKey, this.externalKeyId );
    }
}
