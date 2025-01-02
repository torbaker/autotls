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

import com.orbaker.autotls.impl.CredentialBuilderImpl;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Credentials and endpoint for an ACME service.
 *
 * @author torbaker
 */
public interface Credential
{
    /**
     * The URI for the ACME service.
     *
     * @return
     *      ACME URI, Not {@code null}.
     */
    @NotNull
    URI uri();

    /**
     * The contact email for the account.
     *
     * @return
     *      contact email, not {@code null}.
     */
    @NotBlank
    String emailAddress();

    /**
     * Private key for ACME credential.
     *
     * @return
     *      Private key, not {@code null}.
     */
    @NotNull
    PrivateKey privateKey();

    /**
     * Public key for ACME credential.
     *
     * @return
     *      Public key, not {@code null}.
     */
    @NotNull
    PublicKey publicKey();

    /**
     * Helper method to get both keys at once.
     *
     * @return
     *      Key pair, not {@code null}.
     */
    @NotNull
    KeyPair keyPair();

    /**
     * Optional external key Id for ACME authentication. Required
     * by some providers.
     *
     * @return
     *      Optional external key Id. May be {@code null}.
     */
    String externalKeyId();

    /**
     * Optional external key for ACME authentication. Required
     * by some providers.
     *
     * @return
     *      Optional external key. May be {@code null}.
     */
    String externalKey();

    /**
     * Create a new credential builder.
     *
     * @return
     *      New builder, not {@code null}.
     */
    static Credential.Builder builder()
    {
        return new CredentialBuilderImpl();
    }

    /**
     * Builder for ACME credentials
     */
    interface Builder
    {
        /**
         * Current URI for ACME service.
         *
         * @return
         *      ACME URI for service.
         */
        URI getUri();

        /**
         * Contact email for account.
         *
         * @return
         *      Account email
         */
        String getEMailAddress();

        /**
         * Private key for account.
         *
         * @return
         *      Account private key.
         */
        PrivateKey getPrivateKey();

        /**
         * Public key for account.
         *
         * @return
         *      Account public key.
         */
        PublicKey getPublicKey();

        /**
         * External Key Id.
         *
         * @return
         *      External key id.
         */
        String getExternalKeyId();

        /**
         * External key.
         *
         * @return
         *      External key.
         */
        String getExternalKey();

        /**
         * Set the ACME URI for this credential.
         *
         * @param uri
         *      ACME URI
         *
         * @return
         *      Chainable builder, not {@code null}.
         *
         * @throws URISyntaxException
         *      If {@code uri} is not a valid URI.
         */
        @NotNull
        Builder setUri( @NotBlank String uri ) throws URISyntaxException;

        /**
         * Set the ACME URI for this credential.
         *
         * @param uri
         *      ACME URI
         *
         * @return
         *      Chainable builder, not {@code null}.
         *
         * @throws URISyntaxException
         *      If {@code uri} is not a valid URI.
         */
        @NotNull
        Builder setUri( @NotNull URL uri ) throws URISyntaxException;

        /**
         * Set the ACME URI for this credential.
         *
         * @param uri
         *      ACME URI
         *
         * @return
         *      Chainable builder, not {@code null}.
        */
        @NotNull
        Builder setUri( @NotNull URI uri );

        /**
         * Set the account contact email.
         *
         * @param emailAddress
         *      EMail address
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setEMailAddress( @NotBlank String emailAddress );

        /**
         * Set the account private key
         *
         * @param privateKey
         *      Private key.
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setPrivateKey( @NotNull PrivateKey privateKey );

        /**
         * Set the account public key.
         *
         * @param publicKey
         *      Public key
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setPublicKey( @NotNull PublicKey publicKey );

        /**
         * Set both the public and private key at once.
         *
         * @param keyPair
         *      Account key pair.
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setKeyPair( @NotNull KeyPair keyPair );

        /**
         * Set the external key id.
         *
         * @param externalKeyId
         *      External key Id
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setExternalKeyId( String externalKeyId );

        /**
         * Set the external key.
         *
         * @param externalKey
         *      External key
         *
         * @return
         *      Chainable builder, not {@code null}.
         */
        @NotNull
        Builder setExternalKey( String externalKey );

        /**
         * Build the credential. In order for this to succeed,
         * the following are required:
         * <ul>
         * <li>{@link #getPublicKey()} is not {@code null}.</li>
         * <li>{@link #getPrivateKey()} is not {@code null}.</li>
         * <li>{@link #getUri()} is not {@code null}.</li>
         * <li>{@link #getEMailAddress()} is not {@code null}.</li>
         * <li>{@link #getExternalKey()} and {@link #getExternalKeyId()} are both
         *     either {@code null} or not {@code null}. It is an error to set one
         *     without the other.</li>
         * </ul>
         *
         * @return
         *      New credential, not {@code null}.
         *
         * @throws IllegalArgumentException
         *      If the credential is lacking components.
         */
        @NotNull
        Credential build() throws IllegalArgumentException;
    }
}
