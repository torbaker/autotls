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
package test.orbaker.autotls;

import com.orbaker.autotls.Credential;
import com.orbaker.autotls.CredentialStore;
import com.orbaker.autotls.tools.KeyPairGenTools;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import org.apache.commons.lang3.SystemUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 *
 * @author torbaker
 */
public class CredentialStoreTest
{
    public CredentialStoreTest() {}

    @Test
    public void loadAndStore() throws IOException, GeneralSecurityException, URISyntaxException
    {
        Path    tempDir = Paths.get( SystemUtils.JAVA_IO_TMPDIR );
        Path    fname   = tempDir.resolve( "storetest.kps" );

        try {
            KeyPairGenerator    ecGen   = KeyPairGenTools.newECGenerator( "secp384r1" );
            KeyPairGenerator    rsaGen  = KeyPairGenTools.newRSAGenerator( 4096 );
            CredentialStore     store   = CredentialStore.newInstance();
            Credential          sample1 = Credential.builder()
                                                .setEMailAddress( "one@example.com" )
                                                .setKeyPair( ecGen.generateKeyPair() )
                                                .setUri( "acme://letsencrypt.org/staging" )
                                                .build();
            Credential          sample2 = Credential.builder()
                                                .setEMailAddress( "two@example.com" )
                                                .setKeyPair( rsaGen.generateKeyPair() )
                                                .setUri( "acme://zerossl.com/v2/D30" )
                                                .setExternalKey( "aaaa" )
                                                .setExternalKeyId( "bbbb" )
                                                .build();

            store.put( "one", sample1 );
            store.put( "two", sample2 );
            store.save( fname, "changeit".toCharArray(), true );

            CredentialStore     reload  = CredentialStore.getInstance( fname, "changeit".toCharArray(), true );
            Credential          got1    = reload.get( "one" ).orElse( null );
            Credential          got2    = reload.get( "two" ).orElse( null );

            Assert.assertNotNull( got1, "'one' is missing" );
            Assert.assertEquals( got1.emailAddress(), "one@example.com", "Invalid email in one" );
            Assert.assertEquals( got1.uri().toString(), "acme://letsencrypt.org/staging", "Invalid url in one" );
            Assert.assertEquals( got1.publicKey().getAlgorithm(), "EC", "Public key in one is not EC" );
            Assert.assertEquals( got1.privateKey().getAlgorithm(), "EC", "Private key in one is not EC" );
            Assert.assertNull( got1.externalKey(), "One has an external key" );
            Assert.assertNull( got1.externalKeyId(), "One has an external key Id");

            Assert.assertNotNull( got2, "'two' is missing" );
            Assert.assertEquals( got2.emailAddress(), "two@example.com", "Invalid email in two" );
            Assert.assertEquals( got2.uri().toString(), "acme://zerossl.com/v2/D30", "Invalid URL in two" );
            Assert.assertEquals( got2.publicKey().getAlgorithm(), "RSA", "Public key in two is not RSA" );
            Assert.assertEquals( got2.privateKey().getAlgorithm(), "RSA", "Private key in two is not RSA" );
            Assert.assertEquals( got2.externalKey(),   "aaaa", "Invalid external key in two" );
            Assert.assertEquals( got2.externalKeyId(), "bbbb", "Invalid external key id in two" );
       } finally {
            Files.deleteIfExists( fname );
        }
    }
}
