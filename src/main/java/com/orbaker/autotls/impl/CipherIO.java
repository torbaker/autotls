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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author torbaker
 */
public class CipherIO
{
    static final String ALGORITHM       = "AES";
    static final String KEYFACTORY      = "PBKDF2WithHmacSHA256";
    static final String CIPHER          = "AES/CBC/PKCS5Padding";
    static final int    SALT_SIZE       = 16;
    static final int    VECTOR_SIZE     = 16;
    static final int    KF_ITERATIONS   = 100_000;
    static final int    KF_KEYSIZE      = 256;

    private CipherIO() {}

    public static InputStream wrap( InputStream inputStream, char[] password ) throws GeneralSecurityException, IOException
    {
        byte[]              initialVector   = inputStream.readNBytes( CipherIO.VECTOR_SIZE );
        byte[]              passwordSalt    = inputStream.readNBytes( CipherIO.SALT_SIZE   );
        IvParameterSpec     initialSpec     = new IvParameterSpec( initialVector );
        SecretKeyFactory    factory         = SecretKeyFactory.getInstance( CipherIO.KEYFACTORY );
        KeySpec             keySpec         = new PBEKeySpec( password, passwordSalt, CipherIO.KF_ITERATIONS, CipherIO.KF_KEYSIZE );
        SecretKey           secretKey       = factory.generateSecret( keySpec );
        SecretKeySpec       secretKeySpec   = new SecretKeySpec( secretKey.getEncoded(), CipherIO.ALGORITHM );

        Cipher cipher = Cipher.getInstance( CipherIO.CIPHER );

        cipher.init( Cipher.DECRYPT_MODE, secretKeySpec, initialSpec );

        return new CipherInputStream( inputStream, cipher );
    }

    public static OutputStream wrap( OutputStream outputStream, char[] password, SecureRandom random ) throws IOException, GeneralSecurityException
    {
        byte[]  initialVector   = new byte[ CipherIO.VECTOR_SIZE ];
        byte[]  passwordSalt    = new byte[ CipherIO.SALT_SIZE   ];

        random.nextBytes( initialVector );
        random.nextBytes( passwordSalt  );

        IvParameterSpec     initialSpec     = new IvParameterSpec( initialVector );
        SecretKeyFactory    factory         = SecretKeyFactory.getInstance( CipherIO.KEYFACTORY );
        KeySpec             keySpec         = new PBEKeySpec( password, passwordSalt, CipherIO.KF_ITERATIONS, CipherIO.KF_KEYSIZE);
        SecretKey           secretKey       = factory.generateSecret( keySpec );
        SecretKeySpec       secretKeySpec   = new SecretKeySpec( secretKey.getEncoded(), CipherIO.ALGORITHM );

        Cipher cipher = Cipher.getInstance( CipherIO.CIPHER );

        cipher.init( Cipher.ENCRYPT_MODE, secretKeySpec, initialSpec );

        outputStream.write( initialVector, 0, CipherIO.VECTOR_SIZE );
        outputStream.write( passwordSalt,  0, CipherIO.SALT_SIZE   );

        return new CipherOutputStream( outputStream, cipher );
    }
}
