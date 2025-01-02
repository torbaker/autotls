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

import com.orbaker.autotls.Credential;
import com.orbaker.autotls.CredentialStore;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author torbaker
 */
public class CredentialStoreImpl implements CredentialStore
{
    private static final int VERSION = 1;
    private static final String DIGEST = "SHA256";

    private final Map<String,Credential>    entries;

    public CredentialStoreImpl()
    {
        this.entries = new HashMap<String,Credential>();
    }

    @Override
    public Optional<Credential> put( @NotBlank String alias, @NotNull Credential credential )
    {
        Credential  cred    = Objects.requireNonNull( credential );
        String      name    = Precheck.requireNonBlank( alias );

        Optional<Credential> was = this.get( name );

        this.entries.put( alias, cred );

        return was;
    }

    @Override
    public int size()
    {
        return this.entries.size();
    }

    @Override
    public boolean isEmpty()
    {
        return this.entries.isEmpty();
    }

    @Override
    public Optional<Credential> get( @NotBlank String alias )
    {
        String      name    = Precheck.requireNonBlank( alias );

        return Optional.<Credential>ofNullable( this.entries.get( name ) );
    }

    @Override
    public Optional<Credential> remove( @NotBlank String alias )
    {
        String      name    = Precheck.requireNonBlank( alias );

        return Optional.<Credential>ofNullable( this.entries.remove( name ) );
    }

    @Override
    public Stream<String> aliases()
    {
        return this.entries.keySet().stream();
    }

    @Override
    public Iterator<Entry<String, Credential>> iterator()
    {
        return this.entries.entrySet().iterator();
    }

    public static CredentialStore getInstance( @NotNull Path storeFile, @NotEmpty char[] storePass, boolean strict ) throws IOException, GeneralSecurityException
    {
        Objects.requireNonNull( storeFile );
        Precheck.requireNonEmpty( storePass );

        OpenOption[]    readOp  = (strict) ? Constants.Files.STRICT_READ  : Constants.Files.RELAX_READ;
        CredentialStore store   = null;

        try ( InputStream inputStream = Files.newInputStream( storeFile, readOp ) ) {
            store = CredentialStore.getInstance( inputStream, storePass );
        }

        return store;
    }

    @Override
    public void save( @NotNull Path storeFile, @NotEmpty char[] storePass, boolean strict ) throws IOException, GeneralSecurityException
    {
        Objects.requireNonNull( storeFile );
        Precheck.requireNonEmpty( storePass );

        LinkOption[]    existOp = (strict) ? Constants.Files.STRICT_EXISTS : Constants.Files.RELAX_EXISTS;
        OpenOption[]    writeOp = (strict) ? Constants.Files.STRICT_WRITE  : Constants.Files.RELAX_WRITE;
        CopyOption[]    moveOp  = (strict) ? Constants.Files.STRICT_COPY   : Constants.Files.RELAX_COPY;
        Path            saveTo  = storeFile.getParent();
        Path            tempFile= null;

        if ( saveTo != null ) {
            Files.createDirectories( saveTo );
        } else {
            saveTo = Paths.get( "." ).toAbsolutePath();
        }

        try {
            tempFile = Files.createTempFile( saveTo, Constants.PACKAGE_LOWER, ".tmp" );

            try ( OutputStream outputStream = Files.newOutputStream( tempFile, writeOp ) ) {
                this.save( outputStream, storePass );
            }

            Files.deleteIfExists( storeFile );
            Files.move( tempFile, storeFile, moveOp );
        } finally {
            if ( tempFile != null ) {
                Files.deleteIfExists( tempFile );
            }
        }
    }

    public static CredentialStore getInstance( @NotNull InputStream inputStream, @NotEmpty char[] storePass ) throws IOException, GeneralSecurityException
    {
        var store = new CredentialStoreImpl();

        try ( InputStream wrapped = CipherIO.wrap( inputStream, storePass ) ) {
            DocumentBuilderFactory  factory = DocumentBuilderFactory.newDefaultInstance();
            DocumentBuilder         builder = factory.newDocumentBuilder();
            Document                document= builder.parse( wrapped );
            Element                 root    = document.getDocumentElement();
            int                     version = Integer.parseInt( root.getAttribute( "version" ) );
            String                  digest  = StringUtils.defaultIfBlank( root.getAttribute( "digest" ),
                                                                          CredentialStoreImpl.DIGEST );
            NodeList                entries = root.getChildNodes();

            if ( version != CredentialStoreImpl.VERSION ) {
                throw new IOException( "Invalid file version" );
            }

            for ( int i = 0 ; i < entries.getLength() ; i += 1 ) {
                if ( entries.item( i ) instanceof Element element && element.getTagName().equals( "entry" ) ) {
                    String              alias   = element.getAttribute( "id" );
                    Credential.Builder  maker      = Credential.builder();
                    NodeList            items   = element.getChildNodes();

                    for ( int j = 0 ; j < items.getLength() ; j += 1 ) {
                        if ( items.item( j ) instanceof Element child ) {
                            switch( child.getTagName() ) {
                                case "email"         -> maker.setEMailAddress ( child.getTextContent() );
                                case "uri"           -> maker.setUri          ( child.getTextContent() );
                                case "externalkey"   -> maker.setExternalKey  ( child.getTextContent() );
                                case "externalkeyid" -> maker.setExternalKeyId( child.getTextContent() );
                                case "public"        -> {
                                    byte[]  bytes   = CredentialStoreImpl.byteElement( alias, child, digest );
                                    var     keySpec = new X509EncodedKeySpec( bytes );
                                    String  keyType = child.getAttribute( "type" );
                                    var     kfactor = KeyFactory.getInstance( keyType );

                                    maker.setPublicKey( kfactor.generatePublic( keySpec ) );
                                }
                                case "private"       -> {
                                    byte[]  bytes   = CredentialStoreImpl.byteElement( alias, child, digest );
                                    var     keySpec = new PKCS8EncodedKeySpec( bytes );
                                    String  keyType = child.getAttribute( "type" );
                                    var     kfactor = KeyFactory.getInstance( keyType );

                                    maker.setPrivateKey( kfactor.generatePrivate( keySpec ) );
                                }
                            }
                        }
                    }

                    store.entries.put( alias, maker.build() );
                }
            }

        } catch ( URISyntaxException | SAXException | ParserConfigurationException ex ) {
            throw new IOException( "Cannot parse file", ex );
        }

        return store;
    }

    @Override
    public void save( @NotNull OutputStream outputStream, @NotEmpty char[] storePass ) throws IOException, GeneralSecurityException
    {
        try {
            DocumentBuilderFactory  factory = DocumentBuilderFactory.newDefaultInstance();
            DocumentBuilder         builder = factory.newDocumentBuilder();
            Document                document= builder.newDocument();
            Element                 root    = (Element) document.appendChild( document.createElement( Constants.PACKAGE_LOWER ) );
            Encoder                 encoder = Base64.getMimeEncoder();

            root.setAttribute( "version", Integer.toString( CredentialStoreImpl.VERSION ) );
            root.setAttribute( "digest", CredentialStoreImpl.DIGEST );

            for ( String alias : this.entries.keySet() ) {
                Credential  credential  = this.entries.get( alias );
                Element     entry       = (Element) root.appendChild( document.createElement( "entry" ) );

                entry.setAttribute( "id", alias );
                ((Element) entry.appendChild( document.createElement( "email"   ))).setTextContent( credential.emailAddress()     );
                ((Element) entry.appendChild( document.createElement( "uri"     ))).setTextContent( credential.uri().toString()   );
                entry.appendChild( this.byteElement( document, entry, "public",  credential.publicKey ().getAlgorithm(), credential.publicKey ().getEncoded() ) );
                entry.appendChild( this.byteElement( document, entry, "private", credential.privateKey().getAlgorithm(), credential.privateKey().getEncoded() ) );

                if ( credential.externalKey() != null ) {
                    ((Element) entry.appendChild( document.createElement( "externalkey" ))).setTextContent( credential.externalKey() );
                }

                if ( credential.externalKeyId() != null ) {
                    ((Element) entry.appendChild( document.createElement( "externalkeyid" ))).setTextContent( credential.externalKeyId() );
                }
            }

            try ( OutputStream wrapped = CipherIO.wrap( outputStream, storePass, SecureRandom.getInstanceStrong() ) ) {
                TransformerFactory      xfactor = TransformerFactory.newDefaultInstance();
                Transformer             xform   = xfactor.newTransformer();
                DOMSource               source  = new DOMSource( document );
                StreamResult            result  = new StreamResult( wrapped );

                xform.setOutputProperty( OutputKeys.ENCODING,                           Constants.ENCODING.name()   );
                xform.setOutputProperty( OutputKeys.INDENT,                             "yes"                       );
                xform.setOutputProperty( "{http://xml.apache.org/xslt}indent-amount",   "4"                         );
                xform.setOutputProperty( OutputKeys.OMIT_XML_DECLARATION,               "no"                        );

                xform.transform( source, result );
            }
        } catch ( TransformerException | ParserConfigurationException ex ) {
            throw new IOException( "Cannot format XML for writing", ex );
        }
    }

    private Element byteElement( Document document, Element parent, String tagName, String keyType, byte[] contents ) throws NoSuchAlgorithmException
    {
        var     element = (Element) parent.appendChild( document.createElement( tagName ) );
        Encoder encoder = Base64.getMimeEncoder();
        String  encoded = encoder.encodeToString( contents );
        var     digester= MessageDigest.getInstance( CredentialStoreImpl.DIGEST );
        byte[]  digest  = digester.digest( contents );
        String  checksum= HexFormat.of().formatHex( digest );

        element.setAttribute( "digest", checksum );
        element.setAttribute( "type", keyType );
        element.setTextContent( "\n" + encoded + "\n" );

        return element;
    }

    private static byte[] byteElement( String alias, Element element, String digestAlgo ) throws NoSuchAlgorithmException, KeyStoreException
    {
        Decoder decoder = Base64.getMimeDecoder();
        String  text    = element.getTextContent().trim();
        byte[]  content = decoder.decode( element.getTextContent() );
        var     digester= MessageDigest.getInstance( digestAlgo );
        byte[]  digest  = digester.digest( content );
        String  checksum= HexFormat.of().formatHex( digest );
        String  target  = element.getAttribute( "digest" );

        if ( ! checksum.equalsIgnoreCase( target ) ) {
            throw new KeyStoreException( "Alias " + alias + ", <" + element.getTagName() + "> failed checksum" );
        }

        return content;
    }}
