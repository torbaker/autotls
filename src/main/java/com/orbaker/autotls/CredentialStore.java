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

import com.orbaker.autotls.impl.CredentialStoreImpl;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Secure(?) store of ACME {@link com.orbaker.autotls.Credential} objects in
 * the same vein as a {@code KeyStore}.
 *
 * This exists because I couldn't figure how to store more than the actual key
 * pair in a keystore. *
 *
 * @author torbaker
 */
public interface CredentialStore extends Iterable<Map.Entry<String,Credential>>
{
    /**
     * Add an entry to the credential store. If the {@code alias} is already
     * present in the store, then it is replaced.
     *
     * @param alias
     *      Credential alias.
     *
     * @param credential
     *      ACME Credential
     *
     * @return
     *      Optional. If there was a value with this {@code alias} already, the
     *      old credential that is being replaced is present.
     */
    Optional<Credential> put( @NotBlank String alias, @NotNull Credential credential );

    /**
     * Get the credential for {@code alias}.
     *
     * @param alias
     *      Credential alias.
     *
     * @return
     *      If a credential with the {@code alias} is in the store, this has
     *      a value. If not, it is empty.
     */
    Optional<Credential> get( @NotBlank String alias );

    /**
     * Remove the credential from the store. If a credential with
     * {@code alias} is present in the store when called, the removed
     * value will be returned in the Optional.
     *
     * @param alias
     *      Credential alias.
     *
     * @return
     *      The removed credential if present.
     */
    Optional<Credential> remove( @NotBlank String alias );

    /**
     * Return the number of credentials in the store.
     *
     * @return
     *      Number of store credentials.
     */
    int size();

    /**
     * {@code true} if this store is empty.
     *
     * @return
     *      {@code true} if the store contains no entries.
     */
    boolean isEmpty();

    /**
     * Stream of alias names in the store. If there are no credentials
     * in the store, returns an empty stream.
     *
     * @return
     *      Stream of aliases.
     */
    public Stream<String> aliases();

    /**
     * Write the encrypted credential store to the given {@code storeFile}.
     *
     * @param storeFile
     *      File name for credential store.
     *
     * @param storePass
     *      Store password.
     *
     * @param strict
     *      If {@code true}, use {@code LinkOption.NOFOLLOW_LINKS} on all file
     *      operations.
     *
     * @throws IOException
     *      If an I/O error prevents storing the file.
     *
     * @throws GeneralSecurityException
     *      If store cannot be encrypted.
     */
    void save( @NotNull Path storeFile, @NotEmpty char[] storePass, boolean strict )
            throws IOException, GeneralSecurityException;

    /**
     * Save the credential store to the output stream.
     *
     * @param outputStream
     *      The stream to accept the store.
     *
     * @param storePass
     *      Store password.
     *
     * @throws IOException
     *      If an I/O error prevents storing the file.
     *
     * @throws GeneralSecurityException
     *      If there is a security issue.
     */
    void save( @NotNull OutputStream outputStream, @NotEmpty char[] storePass )
            throws IOException, GeneralSecurityException;

    /**
     * Iterator over the store entries. If there are no items
     * in the list, then the iterator is empty.
     *
     * @return
     *      Credential store entries.
     */
    @Override
    public Iterator<Entry<String, Credential>> iterator();

    /**
     * Get a new, empty credential store.
     *
     * @return
     *      New CredentialStore, never {@code null}.
     */
    static CredentialStore newInstance()
    {
        return new CredentialStoreImpl();
    }

    /**
     * Create a credential store from the given {@code inputStream}.
     *
     * @param inputStream
     *      Input stream holding encrypted store.
     *
     * @param storePass
     *      Credential store password.
     *
     * @return
     *      New credential store, never {@code null}.
     *
     * @throws IOException
     *      If the store cannot be read.
     *
     * @throws GeneralSecurityException
     *      If the store cannot be decrypted.
     */
    static CredentialStore getInstance( @NotNull InputStream inputStream, @NotEmpty char[] storePass )
            throws IOException, GeneralSecurityException
    {
        return CredentialStoreImpl.getInstance( inputStream, storePass );
    }

    /**
     * Create a credential store from the given {@code storeFile}.
     *
     * @param storeFile
     *      Credential store file.
     *
     * @param storePass
     *      Store password.
     *
     * @param strict
     *      If {@code true}, use {@code LinkOption.NOFOLLOW_LINKS} on all file
     *      operations.
     *
     * @return
     *      Loaded CredentialStore, never {@code null}.
     *
     * @throws IOException
     *      If the file cannot be read.
     *
     * @throws GeneralSecurityException
     *      If the file cannot be decrypted.
     */
    static CredentialStore getInstance( @NotNull Path storeFile, @NotEmpty char[] storePass, boolean strict )
            throws IOException, GeneralSecurityException
    {
        return CredentialStoreImpl.getInstance( storeFile, storePass, strict );
    }
}
