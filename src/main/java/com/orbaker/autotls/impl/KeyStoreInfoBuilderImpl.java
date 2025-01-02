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

import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.KeyStoreInfo.Builder;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Objects;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author torbaker
 */
public class KeyStoreInfoBuilderImpl implements KeyStoreInfo.Builder
{
    static record KeyStoreInfoImpl( String storeType, Path storeFile, char[] storePass, char[] keyPass, boolean strict )
            implements KeyStoreInfo {}

    private String      storeType;
    private Path        storeFile;
    private char[]      storePass;
    private char[]      keyPass;
    private boolean     strict;

    public KeyStoreInfoBuilderImpl()
    {
        this.storeType  = KeyStore.getDefaultType();
        this.storeFile  = Paths.get( "autotls.jks" );
        this.storePass  = "changeit".toCharArray();
        this.keyPass    = null;
        this.strict     = false;
    }

    @Override
    public String getStoreType()
    {
        return this.storeType;
    }

    @Override
    public Path getStoreFile()
    {
        return this.storeFile;
    }

    @Override
    public char[] getStorePass()
    {
        return Arrays.copyOf( this.storePass, this.storePass.length );
    }

    @Override
    public char[] getKeyPass()
    {
        if ( this.keyPass == null ) {
            return this.getStorePass();
        } else {
            return Arrays.copyOf( this.keyPass, this.keyPass.length );
        }
    }

    @Override
    public boolean isStrict()
    {
        return this.strict;
    }

    @NotNull
    @Override
    public Builder setStoreType( @NotBlank String storeType )
    {
        this.storeType = Precheck.requireNonBlank( storeType );

        return this;
    }

    @NotNull
    @Override
    public Builder setStoreFile( @NotBlank String storeFile ) throws InvalidPathException
    {
        String fileName = Precheck.requireNonBlank( storeFile );

        return this.setStoreFile( Paths.get( fileName ) );
    }

    @NotNull
    @Override
    public Builder setStoreFile( @NotNull File storeFile ) throws InvalidPathException
    {
        Objects.requireNonNull( storeFile );

        return this.setStoreFile( storeFile.toPath() );
    }

    @NotNull
    @Override
    public Builder setStoreFile( @NotNull Path storeFile )
    {
        this.storeFile = Objects.requireNonNull( storeFile ).toAbsolutePath().normalize();

        return this;
    }

    @NotNull
    @Override
    public Builder setStorePass( @NotBlank String storePass )
    {
        String passwd = Precheck.requireNonBlank( storePass );

        return this.setStorePass( passwd.toCharArray() );
    }

    @NotNull
    @Override
    public Builder setStorePass( @NotEmpty char[] storePass )
    {
        Precheck.requireNonEmpty( storePass );

        this.storePass = Arrays.copyOf( storePass, storePass.length );

        return this;
    }

    @NotNull
    @Override
    public Builder setKeyPass( @NotBlank String keyPass )
    {
        String passwd = Precheck.requireNonBlank( keyPass );

        return this.setKeyPass( passwd.toCharArray() );
    }

    @NotNull
    @Override
    public Builder setKeyPass( @NotEmpty char[] keyPass )
    {
        Precheck.requireNonEmpty( keyPass );

        this.keyPass = Arrays.copyOf( keyPass, keyPass.length );

        return this;
    }

    @NotNull
    @Override
    public Builder setStrict( boolean strictMode )
    {
        this.strict = strictMode;

        return this;
    }

    @Override
    public KeyStoreInfo build() throws IllegalArgumentException
    {
        if ( StringUtils.isBlank( this.storeType ) ) {
            throw new IllegalArgumentException( "No store type" );
        } else if ( this.storeFile == null ) {
            throw new IllegalArgumentException( "No store file" );
        } else if ( this.storePass == null || this.storePass.length == 0 ) {
            throw new IllegalArgumentException( "No store password" );
        }

        // Make sure this is valid for later
        try {
            KeyStore.getInstance( this.storeType );
        } catch ( KeyStoreException ex ) {
            throw new IllegalArgumentException( "Key store type '" + this.storeType + "' is not supported", ex );
        }

        return new KeyStoreInfoImpl( this.storeType, this.storeFile, this.storePass, this.keyPass, this.strict );
    }
}
