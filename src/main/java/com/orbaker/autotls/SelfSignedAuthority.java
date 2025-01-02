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

import com.orbaker.autotls.impl.SelfSignedAuthorityBuilderImpl;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.time.Period;

/**
 * Certificate authority for self-signed certificates.
 *
 * @author torbaker
 */
public interface SelfSignedAuthority extends CertificateAuthority
{
    /**
     * Return the validity period for self-signed certificates.
     *
     * @return
     *      Self signed validity period.
     */
    @NotNull Period validity();

    /**
     * Create a new builder for the self-signed authority
     *
     * @param copyFrom
     *      Generic authority to copy.
     *
     * @return
     *      New builder, never {@code null}.
     */
    @NotNull
    static SelfSignedAuthority.Builder builder( @NotNull CertificateAuthority.Builder copyFrom )
    {
        return new SelfSignedAuthorityBuilderImpl( copyFrom );
    }

    /**
     * Builder for self-signed authority.
     *
     */
    interface Builder
    {
        /**
         * Get the validity period,
         *
         * @return
         *      The validity period
         */
        Period getValidity();

        /**
         * Set the validity period as number of days.
         *
         * @param validityDays
         *      Number of days in validity period
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setValidity( @Positive int validityDays );

        /**
         * Set the validity period.
         *
         * @param validity
         *      Validity period.
         *
         * @return
         *      Chainable builder, never {@code null}.
         */
        @NotNull
        Builder setValidity( @Positive Period validity );

        /**
         * Build a new instance. In order to be valid, this builder
         * must have a validity period, and it must conform to the
         * list at {@link com.orbaker.autotls.CertificateAuthority.Builder}
         *
         * @return
         *      New self-signed authority instance.
         *
         * @throws IllegalArgumentException
         *      If the builder is not fully configured.
         */
        @NotNull
        SelfSignedAuthority build() throws IllegalArgumentException;
    }
}
