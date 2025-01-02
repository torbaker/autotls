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
package com.orbaker.autotls.tools;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Tools for creating {@link java.security.KeyPairGenerator} instances.
 *
 * @author torbaker
 */
public class KeyPairGenTools
{
    private KeyPairGenTools() {}

    /**
     * Create a new Elliptic Curve key pair generator using the standard {@code curve}
     * and a locally created {@code SecureRandom} number generator.
     *
     * @param curve
     *      Standard curve name.
     *
     * @return
     *      new KeyPairGenerator initialized for use, never {@code null}.
     *
     * @throws GeneralSecurityException
     *      If an instance of {@link java.security.SecureRandom#getInstanceStrong()} fails
     *      or the specified {@code curve} is not supported.
     */
    @NotNull
    public static KeyPairGenerator newECGenerator( @NotBlank String curve ) throws GeneralSecurityException
    {
        return KeyPairGenTools.newECGenerator( curve, SecureRandom.getInstanceStrong() );
    }

    /**
     * Create a new Elliptic Curve key pair generator using the standard {@code curve}
     * and the provided {@code SecureRandom} number generator.
     *
     * @param curve
     *      Standard curve name.
     *
     * @param secureRandom
     *      SecureRandom instance for this generator.
     *
     * @return
     *      new KeyPairGenerator initialized for use.
     *
     * @throws GeneralSecurityException
     *      If the specified {@code curve} is not supported.
     */
    @NotNull
    public static KeyPairGenerator newECGenerator( @NotBlank String curve, @NotNull SecureRandom secureRandom ) throws GeneralSecurityException
    {
        var params  = new ECGenParameterSpec( curve );
        var keygen  = KeyPairGenerator.getInstance( "EC" );

        keygen.initialize( params, secureRandom );

        return keygen;
    }

    /**
     * Create a new KeyPairGenerator for RSA keys using the {@code bits} bit keys
     * and a locally created {@code SecureRandom} number generator.
     *
     * @param bits
     *      Key size in bits.
     *
     * @return
     *      new KeyPairGenerator initialized for use, never {@code null}.
     *
     * @throws GeneralSecurityException
     *      If an instance of {@link java.security.SecureRandom#getInstanceStrong()} fails
     *      or the specified {@code bits} is not supported.
     */
    @NotNull
    public static KeyPairGenerator newRSAGenerator( @Positive int bits ) throws GeneralSecurityException
    {
        return KeyPairGenTools.newRSAGenerator( bits, SecureRandom.getInstanceStrong() );
    }

    /**
     * Create a new KeyPairGenerator for RSA keys using the {@code bits} bit keys
     * and the supplied {@code SecureRandom} number generator.
     *
     * @param bits
     *      Key size in bits.
     *
     * @param secureRandom
     *      Source of random entropy for key generation,
     *
     * @return
     *      new KeyPairGenerator initialized for use, never {@code null}.
     *
     * @throws GeneralSecurityException
     *      If the specified {@code bits} is not supported.
     */
    @NotNull
    public static KeyPairGenerator newRSAGenerator( @Positive int bits, @NotNull SecureRandom secureRandom ) throws GeneralSecurityException
    {
        var params  = new RSAKeyGenParameterSpec( bits, BigInteger.valueOf( 0x10001 ) );
        var keygen  = KeyPairGenerator.getInstance( "RSA" );

        keygen.initialize( params, secureRandom );

        return keygen;
    }
}
