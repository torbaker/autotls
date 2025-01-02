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

import com.orbaker.autotls.impl.AcmeAuthorityBuilderImpl;
import jakarta.validation.constraints.NotNull;

/**
 * ACME certificate authority.
 *
 * @author torbaker
 */
public interface AcmeAuthority extends CertificateAuthority
{
    /**
     * Create a new builder by copying from another builder.
     *
     * @param copyFrom
     *      The builder to copy.
     *
     * @return
     *      A new ACME builder instance created by copying from
     *      another authority builder instance.
     */
    @NotNull
    static AcmeAuthority.Builder builder( CertificateAuthority.Builder copyFrom )
    {
        return new AcmeAuthorityBuilderImpl( copyFrom );
    }

    /**
     * Builder for ACME authorities
     */
    interface Builder
    {
        /**
         * Get the current credential.
         *
         * @return
         *      ACME credential. May be {@code null}.
         */
        Credential getCredential();

        /**
         * Set the credential to use for authentication to the
         * ACME provider.
         *
         * @param credential
         *      ACME credential. Not {@code null}.
         *
         * @return
         *      Chainable builder instance. Never {@code null}.
         */
        @NotNull
        Builder setCredential( @NotNull Credential credential );

        /**
         * Build an instance of the ACME authority using the given
         * builder state.
         *
         * @return
         *      new AcmeAuthority  instance. Never {@code null}.
         *
         * @throws IllegalArgumentException
         *      If {@link #getCredential()} is {@code null}, or for any
         *      of the reasons found:
         *      {@link com.orbaker.autotls.CertificateAuthority.Builder}
         */
        @NotNull
        AcmeAuthority build() throws IllegalArgumentException;
    }
}
