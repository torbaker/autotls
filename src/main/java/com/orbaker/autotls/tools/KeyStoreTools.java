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

import com.orbaker.autotls.KeyStoreInfo;
import com.orbaker.autotls.impl.Constants;
import com.orbaker.autotls.impl.Precheck;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;

/**
 * Tools for manipulating key stores.
 *
 * @author torbaker
 */
public final class KeyStoreTools
{
    private KeyStoreTools() {}

    /**
     * Load an existing KeyStore as defined by {@code storeInfo}.
     *
     * @param storeInfo
     *      KeyStore information.
     *
     * @return
     *      Loaded KeyStore. Not {@code null}.
     *
     * @throws IOException
     *      If there is a filesystem error.
     *
     * @throws GeneralSecurityException
     *      If the KeyStore cannot be decrypted.
     */
    @NotNull
    public static KeyStore loadKeyStore( @NotNull KeyStoreInfo storeInfo ) throws IOException, GeneralSecurityException
    {
        Objects.requireNonNull( storeInfo );

        KeyStore store = null;

        if ( storeInfo.strict() ) {
            store = KeyStore.getInstance( storeInfo.storeType() );

            try ( InputStream inputStream = Files.newInputStream( storeInfo.storeFile(), Constants.Files.STRICT_READ ) ) {
                store.load( inputStream, storeInfo.storePass() );
            }

            if ( ! store.getType().equalsIgnoreCase( storeInfo.storeType() ) ) {
                throw new KeyStoreException( "'" + store.getType() + "' is not '" + storeInfo.storeType() + "'" );
            }
        } else {
            store = KeyStore.getInstance( storeInfo.storeFile().toFile(), storeInfo.storePass() );
        }

        return store;
    }

    /**
     * Create a new key store. This not only creates an empty store, but it saves it
     * to the {@code storeFile()} in {@code storeInfo}. This uses {@code StandardOpenOption.CREATE_NEW}
     * to ensure that an existing file is not clobbered.
     *
     * @param storeInfo
     *      KeyStore information.
     *
     * @return
     *      New, empty KeyStore. Not {@code null}.
     *
     * @throws IOException
     *      If the file cannot be created.
     *
     * @throws GeneralSecurityException
     *      If the file cannot be encrypted.
     */
    @NotNull
    public static KeyStore createKeyStore( @NotNull KeyStoreInfo storeInfo ) throws IOException, GeneralSecurityException
    {
        LinkOption[]    existOp = (storeInfo.strict()) ? Constants.Files.STRICT_EXISTS : Constants.Files.RELAX_EXISTS;
        OpenOption[]    createOp= (storeInfo.strict()) ? Constants.Files.STRICT_CREATE : Constants.Files.RELAX_CREATE;

        if ( Files.exists( storeInfo.storeFile(), existOp ) ) {
            throw new FileAlreadyExistsException( storeInfo.storeFile().toString() );
        }

        Path storePath = storeInfo.storeFile().getParent();

        if ( storePath != null ) {
            Files.createDirectories( storePath );
        }

        KeyStore store = KeyStore.getInstance( storeInfo.storeType() );

        store.load( null, null );

        try ( OutputStream stream = Files.newOutputStream( storeInfo.storeFile(), createOp ) ) {
            store.store( stream, storeInfo.storePass() );
        }

        return store;
    }

    /**
     * Load or create a KeyStore. In either case, after this call a file will exist
     * on disk.
     *
     * @param storeInfo
     *      KeyStore information.
     *
     * @return
     *      New KeyStore. Not {@code null}.
     *
     * @throws IOException
     *      If the file cannot be read/created.
     *
     * @throws GeneralSecurityException
     *      If the file cannot be decrypted/encrypted.
     */
    @NotNull
    public static KeyStore loadOrCreateKeyStore( @NotNull KeyStoreInfo storeInfo ) throws IOException, GeneralSecurityException
    {
        KeyStore        store   = null;
        LinkOption[]    existOp = (storeInfo.strict()) ? Constants.Files.STRICT_EXISTS : Constants.Files.RELAX_EXISTS;

        if ( Files.exists( storeInfo.storeFile(), existOp ) ) {
            store = KeyStoreTools.loadKeyStore( storeInfo );
        } else {
            store = KeyStoreTools.createKeyStore( storeInfo );
        }

        return store;
    }

    /**
     * Create a new empty key store. Does not create a disk file.
     *
     * @param type
     *      KeyStore type
     *
     * @return
     *      New key store, not {@code null}.
     *
     * @throws GeneralSecurityException
     *      If a new KeyStore cannot be created for the given {@code type}.
     */
    @NotNull
    public static KeyStore emptyKeyStore( @NotBlank String type ) throws GeneralSecurityException
    {
        type = Precheck.requireNonBlank( type );

        KeyStore store = KeyStore.getInstance( type );

        try {
            store.load( null, null );
        } catch ( IOException ex ) {
            // This should never, and I mean *NEVER* happen
            throw new GeneralSecurityException( "Cannot initialize keystore", ex );
        }

        return store;
    }

    /**
     * Merge two KeyStores into one. If either store is {@code null}, this has
     * the effect of copying the non-null store. If both are null, an empty
     * KeyStore is returned.
     *
     * The type of the result KeyStore is the type of {@code one} if possible, or
     * {@code two} if possible, or the default KeyStore type.
     *
     * The merged KeyStore will contain all entries in both KeyStores, even if there
     * are duplicate aliases. Duplicate aliases are resolved by adding '-0', '-1', '-2', ...
     * to the original alias until an unused alias is found.
     *
     * @param mergePass
     *      Password for keys in the merged KeyStore.
     *
     * @param one
     *      First KeyStore to merge. This may be {@code null}.
     *
     * @param onePass
     *      Key password for first KeyStore. This may only be {@code null} if {@code one} is also.
     *
     * @param two
     *      Second KeyStore to merge. This may be {@code null}.
     *
     * @param twoPass
     *      Key password for second KeyStore. This may only be {@code null} if {@code two} is also.
     *
     * @return
     *      New KeyStore containing all entries in both KeyStores.
     *
     * @throws GeneralSecurityException
     *      If there is an error manipulating key stores.
     */
    @NotNull
    public static KeyStore mergeKeyStores( @NotNull ProtectionParameter mergePass,
                                                    KeyStore one,
                                                    ProtectionParameter onePass,
                                                    KeyStore two,
                                                    ProtectionParameter twoPass ) throws GeneralSecurityException
    {
        String type = null;

        if ( one != null ) {
            type = one.getType();
        } else if ( two != null ) {
            type = two.getType();
        } else {
            type = KeyStore.getDefaultType();
        }

        KeyStore    merged  = KeyStoreTools.emptyKeyStore( type );

        if ( one != null ) {
            // Copy everything directly.
            for ( String alias : Collections.list( one.aliases() ) ) {
                Entry entry = one.getEntry( alias, onePass );

                merged.setEntry( alias, entry, mergePass );
            }
        }

        if ( two != null ) {
            for ( String alias : Collections.list( two.aliases() ) ) {
                Entry   entry   = two.getEntry( alias, twoPass );
                String  name    = alias;
                int     counter = 0;

                while ( counter++ < Integer.MAX_VALUE && merged.containsAlias( name ) ) {
                    name = alias + "-" + Integer.toString( counter );
                }
                if ( merged.containsAlias( name ) ) {
                    throw new KeyStoreException( "Counted to " + counter + " for alias '" + alias + "' and could not find duplicate." );
                }

                merged.setEntry( name, entry, mergePass );
            }
        }

        return merged;
    }

    /**
     * Find the first {@code PrivateKeyEntry} in {@code store} that provides
     * coverage for {@code hostName} at {@code asOf}.
     *
     * @param store
     *      KeyStore to search.
     *
     * @param keypass
     *      Key password for store.
     *
     * @param hostName
     *      Host name to search for.
     *
     * @param asOf
     *      Point in time to check for.
     *
     * @return
     *      The first entry in {@code store} that provides coverage
     *      for the {@code hostName}. If none is found, returns {@code null}.
     *
     * @throws GeneralSecurityException
     *      If the KeyStore cannot be searched.
     */
    public static PrivateKeyEntry providesCoverage( @NotNull KeyStore store,
                                                    @NotNull ProtectionParameter keypass,
                                                    @NotBlank String hostName,
                                                    @NotNull Instant asOf ) throws GeneralSecurityException
    {
        asOf = Objects.requireNonNullElse( asOf, Instant.now() );

        for ( String alias : Collections.list( store.aliases() ) ) {
            Entry entry = store.getEntry( alias, keypass );

            if ( entry instanceof PrivateKeyEntry privent ) {
                Certificate certificate = privent.getCertificate();

                if ( certificate instanceof X509Certificate x509 ) {
                    if ( X509CertificateTools.isValidAsOf( x509, asOf, true ) ) {
                        if ( X509CertificateTools.providesCoverageFor( x509, hostName ) ){
                            return privent;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Find all names in {@code hostNames} that have coverage in the {@code store}
     * at {@code asOf}.
     *
     * @param store
     *      Keystore to search.
     *
     * @param keypass
     *      Key password for store.
     *
     * @param asOf
     *      Point in time of interest.
     *
     * @param hostNames
     *      Host names
     *
     * @return
     *      Set of names from {@code hostNames} that have coverage in {@code store}
     *      as of {@code asOf}.
     *
     * @throws GeneralSecurityException
     *      If the KeyStore cannot be searched.
     */
    public static Set<String> coveredNames( KeyStore store, ProtectionParameter keypass, Instant asOf, Collection<? extends String> hostNames ) throws GeneralSecurityException
    {
        var covered = new TreeSet<String>();

        for ( String hostName : hostNames ) {
            if ( KeyStoreTools.providesCoverage( store, keypass, hostName, asOf ) != null ) {
                covered.add( hostName );
            }
        }

        return covered;
    }

    /**
     * Find all names in {@code hostNames} that lack coverage in the {@code store}
     * at {@code asOf}.
     *
     * @param store
     *      Keystore to search.
     *
     * @param keypass
     *      Key password for store.
     *
     * @param asOf
     *      Point in time of interest.
     *
     * @param hostNames
     *      Host names
     *
     * @return
     *      Set of names from {@code hostNames} that have no coverage in {@code store}
     *      as of {@code asOf}.
     *
     * @throws GeneralSecurityException
     *      If the KeyStore cannot be searched.
     */
    public static Set<String> uncoveredNames( KeyStore store, ProtectionParameter keypass, Instant asOf, Collection<? extends String> hostNames ) throws GeneralSecurityException
    {
        Set<String> covered = KeyStoreTools.coveredNames( store, keypass, asOf, hostNames );
        Set<String> lacking = new TreeSet<String>( hostNames );

        lacking.removeAll( covered );

        return lacking;
    }

    /**
     * Find all the aliases for X509 certificate pairs in {@code store} that will
     * be expired at {@code asOf}. If no alias are found that are applicable and
     * will be expired at the given time, the result KeyStore is empty.
     *
     * Aliases found are moved from {@code store} to the resultant KeyStore. The
     * the new KeyStore will be of the default type.
     *
     * @param store
     *      KeyStore to search.
     *
     * @param keypass
     *      KeyPass for both {@code store} and for the resultant KeyStore.
     *
     * @param asOf
     *      Cutoff instant for expiration.
     *
     * @return
     *      KeyStore containing any expired X509 Certificate entries in {@code store}.
     *      This store may be empty but will not be {@code null}.
     *
     * @throws GeneralSecurityException
     *      If there is a KeyStore problem.
     */
    public static KeyStore expireCertificates( KeyStore store, ProtectionParameter keypass, Instant asOf ) throws GeneralSecurityException
    {
        KeyStore expired = KeyStoreTools.emptyKeyStore( KeyStore.getDefaultType() );

        for ( String alias : Collections.list( store.aliases() ) ) {
            Entry entry = store.getEntry( alias, keypass );

            if ( entry instanceof PrivateKeyEntry privkey ) {
                if ( privkey.getCertificate() instanceof X509Certificate x509 ) {
                    if ( ! X509CertificateTools.isValidAsOf( x509, asOf, false ) ) {
                        store.deleteEntry( alias );

                        expired.setEntry( alias, entry, keypass );
                    }
                }
            }
        }

        return expired;
    }

    /**
     * Safely write the KeyStore. This writes to a temp file, backs up the original and renames
     * the temp file.
     *
     * @param storeInfo
     *      KeyStore information.
     *
     * @param keyStore
     *      KeyStore to write
     *
     * @throws IOException
     *      If the files cannot be accessed.
     *
     * @throws GeneralSecurityException
     *      If the KeyStore cannot be encrypted.
     */
    public static void writeKeyStore( KeyStoreInfo storeInfo, KeyStore keyStore ) throws IOException, GeneralSecurityException
    {
        String       baseName   = storeInfo.storeFile().getFileName().toString();
        Path         storePath  = storeInfo.storeFile().getParent();
        Path         bakFile    = storePath.resolve( baseName + ".bak" );
        Path         tempFile   = null;
        OpenOption[] writeOp    = (storeInfo.strict()) ? Constants.Files.STRICT_WRITE  : Constants.Files.RELAX_WRITE;
        CopyOption[] copyOp     = (storeInfo.strict()) ? Constants.Files.STRICT_COPY   : Constants.Files.RELAX_COPY;
        LinkOption[] existOp    = (storeInfo.strict()) ? Constants.Files.STRICT_EXISTS : Constants.Files.RELAX_EXISTS;

        Files.createDirectories( storePath );

        try {
            tempFile = Files.createTempFile( storePath, "keystore", ".jks" );

            try ( OutputStream outputStream = Files.newOutputStream( tempFile, writeOp ) ) {
                keyStore.store( outputStream, storeInfo.storePass() );
            }

            if ( Files.exists( bakFile, existOp ) ) {
                Files.deleteIfExists( bakFile );
            }

            if ( Files.exists( storeInfo.storeFile(), existOp ) ) {
                Files.move( storeInfo.storeFile(), bakFile );
            }

            Files.move( tempFile, storeInfo.storeFile() );
        } finally {
            if ( tempFile != null ) {
                Files.deleteIfExists( tempFile );
            }
        }
    }
}
