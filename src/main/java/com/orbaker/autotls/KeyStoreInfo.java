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

import com.orbaker.autotls.impl.KeyStoreInfoBuilderImpl;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.File;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Information necessary to access a Java {@link java.security.KeyStore} and its contents.
 *
 * @author torbaker
 */
public interface KeyStoreInfo
{
    /**
     * Get the store type. See {@link #strict()} for a discussion of how
     * this is used.
     *
     * @return
     *      Store type, not {@code null}.
     */
    @NotNull String storeType();

    /**
     * Get the keystore file.
     *
     * @return
     *      KeyStore filename. Not {@code null}.
     */
    @NotNull Path storeFile();

    /**
     * KeyStore password.
     *
     * @return
     *      KeyStore password, not {@code null}.
     */
    @NotEmpty char[] storePass();

    /**
     * Key password for keystore.
     *
     * @return
     *      Key password for store entries. Not {@code null}.
     */
    @NotEmpty char[] keyPass();

    /**
     * {@code true} if strict mode is enabled. Strict mode has
     * the following effects:
     * <ul>
     * <li>{@link java.nio.file.LinkOption#NOFOLLOW_LINKS} is added to all file operations.</li>
     * <li>Any keystore loaded must match the {@code storeType()} defined for this store.</li>
     * </ul>
     *
     * @return
     *      {@code} true if strict mode is enabled.
     */
    boolean strict();

    /**
     * Create a new builder for store information.
     *
     * @return
     *      New builder. Never {@code null}.
     */
    static KeyStoreInfo.Builder builder()
    {
        return new KeyStoreInfoBuilderImpl();
    }

    /**
     * Define the key store in a single call. This assumes that the
     * {@code storePass()} and {@code keyPass()} are the same and that
     * the type is {@link java.security.KeyStore#getDefaultType()}.
     *
     * @param storeFile
     *      KeyStore file.
     *
     * @param storePass
     *      KeyStore password.
     *
     * @param strict
     *      Enable/disable strict mode. See {@link #strict()} for details.
     *
     * @return
     *      New key store info. Not {@code null}.
     */
    static KeyStoreInfo newInstance( Path storeFile, char[] storePass, boolean strict )
    {
        return new KeyStoreInfoBuilderImpl()
                        .setStoreType( KeyStore.getDefaultType() )
                        .setStoreFile( storeFile )
                        .setStorePass( storePass )
                        .setStrict( strict )
                        .build();
    }

    /**
     * Builder for KeyStoreInfo
     */
    public interface Builder
    {
        /**
         * Get the KeyStore type.
         *
         * @return
         *      KeyStore type.
         */
        String getStoreType();

        /**
         * Get the KeyStore filename.
         *
         * @return
         *      KeyStore file name.
         */
        Path getStoreFile();

        /**
         * KeyStore password.
         *
         * @return
         *      KeyStore password.
         */
        char[] getStorePass();

        /**
         * Key password. If this has not been set, then the
         * {@code storePassword()} is returned.
         *
         * @return
         *      Key password.
         */
        char[] getKeyPass();

        /**
         * {@code true} if strict mode is enabled.
         *
         * @return
         *      {@code true} if strict.
         */
        boolean isStrict();

        /**
         * Set the store type.
         *
         * @param storeType
         *      KeyStore type.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setStoreType( @NotBlank String storeType );

        /**
         * Set the KeyStore file.
         *
         * @param storeFile
         *      KeyStore file name.
         *
         * @return
         *      Chainable builder, never {@code null}.
         *
         * @throws InvalidPathException
         *      If {@code storeFile} is not a valid {@code Path}.
         */
        @NotNull
        Builder setStoreFile( @NotBlank String storeFile ) throws InvalidPathException;

        /**
         * Set the KeyStore file.
         *
         * @param storeFile
         *      KeyStore file name.
         *
         * @return
         *      Chainable builder, never {@code null}.
         *
         * @throws InvalidPathException
         *      If {@code storeFile} is not a valid {@code Path}.
         */
        @NotNull
        Builder setStoreFile( @NotNull File storeFile ) throws InvalidPathException;

        /**
         * Set the KeyStore file.
         *
         * @param storeFile
         *      KeyStore file.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setStoreFile( @NotNull Path storeFile );

        /**
         * Set the KeyStore password.
         *
         * @param storePass
         *      KeyStore password.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setStorePass( @NotBlank String storePass );

        /**
         * Set the KeyStore password.
         *
         * @param storePass
         *      KeyStore password.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setStorePass( @NotEmpty char[] storePass );

        /**
         * Set the key password.
         *
         * @param keyPass
         *      Key password.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setKeyPass( @NotBlank String keyPass );

        /**
         * Set the key password.
         *
         * @param keyPass
         *      Key password.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setKeyPass( @NotEmpty char[] keyPass );

        /**
         * Enable/disable strict mode. See {@link com.orbaker.autotls.KeyStoreInfo#strict()}
         * for an explanation.
         *
         * @param strictMode
         *      {@code true} to enable strict mode.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setStrict( boolean strictMode );

        /**
         * Create a new KeyStoreInfo instance from this builder.
         *
         * This builder is valid if:
         * <ul>
         * <li>{@link #getStoreType()} is not {@code null}.</li>
         * <li>{@link #getStoreFile()} is not {@code null}.</li>
         * <li>{@link #storePass()} is neither {@code null} nor zero length.</li>
         * <li>{@code KeyStore.getInstance( getStoreType() )} throws no exception.</li>
         * </ul>
         *
         * @return
         *      New KeyStoreInfo, not {@code null}.
         *
         * @throws IllegalArgumentException
         *      If the builder state is not valid.
         */
        KeyStoreInfo build() throws IllegalArgumentException;
    }
}
