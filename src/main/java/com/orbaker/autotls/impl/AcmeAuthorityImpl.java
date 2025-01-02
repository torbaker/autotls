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

import com.orbaker.autotls.AcmeAuthority;
import com.orbaker.autotls.Credential;
import com.orbaker.autotls.tools.KeyStoreTools;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Objects;
import java.util.SequencedCollection;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;

/**
 *
 * @author torbaker
 */
public class AcmeAuthorityImpl extends CertificateAuthorityImpl implements AcmeAuthority
{
    protected final Credential  credential;

    public AcmeAuthorityImpl( AcmeAuthorityBuilderImpl builder )
    {
        super( builder );

        this.credential = builder.getCredential();
    }

    @Override
    public String identifier()
    {
        if ( this.credential != null && this.credential.uri() != null ) {
            return this.credential.uri().toString();
        } else {
            return "acme: generic";
        }
    }

    private boolean http01Challenge( Logger logger, Authorization authorization, Http01Challenge challenge ) throws AcmeException
    {
        String              domain      = authorization.getIdentifier().getDomain();
        String              expecting   = "http://" + domain + "/.well-known/acme-challenge/" + challenge.getToken();
        String              replyWith   = challenge.getAuthorization();
        Instant             now         = Instant.now();
        Instant             timeout     = now.plus( Constants.Acme.Http.TIMEOUT );
        Instant             nextPoll    = timeout;
        Instant             before      = now;
        ServerSocketFactory factory     = ServerSocketFactory.getDefault();

        logger.info( "        - " + domain + ":http01: expecting " + expecting );

        try ( ServerSocket acceptor = factory.createServerSocket() ) {
            // Initally, wait up to the full timeout.
            acceptor.setSoTimeout( (int) Constants.Acme.Http.TIMEOUT.toMillis() );
            acceptor.setReuseAddress( true );
            acceptor.bind( new InetSocketAddress( Constants.Acme.Http.TCP_PORT ), Constants.Acme.Http.BACKLOG );

            // Tell ACME server that we are ready to receive the verification.
            challenge.trigger();

            // repeat until we get to the 'nextPoll' interval
            while ( (now = Instant.now()).isBefore( nextPoll ) ) {
                long    delta   = ChronoUnit.MILLIS.between( now, nextPoll );

                acceptor.setSoTimeout( (int) delta );

                // Accept a probe.
                try ( Socket socket = acceptor.accept() ) {
                    logger.info( "          - " + domain + ":http01: connection from " + socket.getInetAddress().getHostAddress() );

                    // Read the probe in its entirety. Save the HTTP version in the GET request
                    try ( BufferedReader reader = new BufferedReader( new InputStreamReader( socket.getInputStream(), StandardCharsets.ISO_8859_1 ) ) ) {
                        String  line = null;
                        String  http = null;

                        while ( (line = reader.readLine()) != null ) {
                            if ( line.isBlank() ) {
                                break;
                            }

                            logger.debug( "          - " + domain + ":http01: read: " + line );

                            if ( line.startsWith( "GET " ) ) {
                                // Save the HTTP version
                                String[] fields = line.split( "\\s+" );
                                http = fields[ fields.length - 1 ];
                            }
                        }

                        // Make sure that we have at least something here.
                        if ( http == null || http.isBlank() ) {
                            http = "HTTP/1.1";
                        }

                        try ( BufferedWriter output = new BufferedWriter( new OutputStreamWriter( socket.getOutputStream(), StandardCharsets.ISO_8859_1 ) ) ) {
                            String timestamp = ZonedDateTime.now().format( DateTimeFormatter.RFC_1123_DATE_TIME );

                            // Send a success with the requested key
                            output.write( http + " 200 OK\r\n"                                  );
                            output.write( "Date: " +  timestamp + "\r\n"                        );
                            output.write( "Last-Modified: " +  timestamp + "\r\n"               );
                            output.write( "Connection: close\r\n"                               );
                            output.write( "Content-Type: text/plain\r\n"                        );
                            output.write( "Content-Length: " + replyWith.length() + "\r\n\r\n"  );
                            output.write( replyWith                                             );

                            logger.debug( "          - " + domain + ":http01: sent: " + http + " 200 OK"                     );
                            logger.debug( "          - " + domain + ":http01: sent: Date: " + timestamp                      );
                            logger.debug( "          - " + domain + ":http01: sent: Last-Modified: " + timestamp             );
                            logger.debug( "          - " + domain + ":http01: sent: Connection: close"                       );
                            logger.debug( "          - " + domain + ":http01: sent: Content-Type: text/plain"                );
                            logger.debug( "          - " + domain + ":http01: sent: Content-Length: " + replyWith.length()   );
                            logger.debug( "          - " + domain + ":http01: sent: "                                        );
                            logger.debug( "          - " + domain + ":http01: sent: " + replyWith                            );

                            before = Instant.now();
                        }
                    }
                } catch ( SocketTimeoutException ignore ) {}

                try {
                    Instant tryAgain = challenge.fetch().orElse( null );

                    if ( tryAgain != null ) {
                        nextPoll = (tryAgain.isBefore( timeout )) ? tryAgain : timeout;
                    }
                } catch ( AcmeException ex ) {
                    logger.warn( "          ** " + domain + ":http01: cannot update: " + ex.getLocalizedMessage() );
                }

                switch( challenge.getStatus() ) {
                    case Status.VALID -> {
                        logger.info( "          - " + domain + ":http01: success" );

                        return true;
                    }
                    case Status.INVALID -> {
                        logger.warn( "          ** " + domain + ":http01: polling failed" );

                        if ( challenge.getError().isPresent() ) {
                            Problem problem = challenge.getError().get();

                            logger.warn( "          ** " + domain + ":http01: Error: " + problem.toString() );
                        }

                        return false;
                    }
                    default -> {
                        logger.info( "          - " + domain + ":http01: status=" + challenge.getStatus() );
                    }
                }
            }
        } catch ( IOException ex ) {
            ex.printStackTrace();
        }

        logger.warn( "          - " + domain + ":http01: wait time expired" );

        return false;
    }

    private boolean dns01Challenge( Logger logger, Authorization authorization, Dns01Challenge challenge ) throws AcmeException
    {
        String  domain  = authorization.getIdentifier().getDomain();

        logger.warn( "        - " + domain + ":dns01: DNS challenge not implemented" );
        logger.warn( "        - " + domain + ":dns01:   Set: " + challenge.getDigest() );
        logger.warn( "        - " + domain + ":dns01:   Set: " + challenge.getJSON() );

        return false;
    }

    private boolean tls01Challenge( Logger logger, Authorization authorization, TlsAlpn01Challenge challenge ) throws AcmeException
    {
        String domain = authorization.getIdentifier().getDomain();

        logger.info( "        - " + domain + ":tlsalpn01: starting" );

        KeyPair         keyPair     = KeyPairUtils.createKeyPair( 2048 );
        X509Certificate cert        = challenge.createCertificate( keyPair, authorization.getIdentifier() );
        long            lastFetch   = System.currentTimeMillis();
        long            maxWait     = 60_000;

        try {
            KeyStore keyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
            keyStore.load( null, null );
            keyStore.setKeyEntry( "acme-tls/1", keyPair.getPrivate(), "changeit".toCharArray(), new java.security.cert.Certificate[] { cert } );

            KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
            kmf.init( keyStore, "changeit".toCharArray() );

            TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
            tmf.init( keyStore );

            SSLContext context = SSLContext.getInstance( "TLS" );

            context.init( kmf.getKeyManagers(), tmf.getTrustManagers(), SecureRandom.getInstanceStrong() );

            var factory = context.getServerSocketFactory();

            try ( SSLServerSocket acceptor  = (SSLServerSocket) factory.createServerSocket() ) {
                acceptor.setSoTimeout( 5_000 );
                acceptor.setReuseAddress( true );
                acceptor.bind( new InetSocketAddress( 443 ), 10 );

                challenge.trigger();

                while ( true ) {
                    try ( SSLSocket client = (SSLSocket) acceptor.accept() ) {
                        logger.info( "        - " + domain + ":tlsalpn01: connection from " + client.getInetAddress().getHostAddress() );

                        var parameters = client.getSSLParameters();
                        parameters.setApplicationProtocols( new String[] { "acme-tls/1" } );

                        client.setSSLParameters( parameters );
                        client.startHandshake();

                        logger.info( "        - " + domain + ":tlsalpn01: negotiated " + client.getApplicationProtocol() );
                    } catch ( SocketTimeoutException ignore ) {
                        long    now     = System.currentTimeMillis();
                        long    idle    = now - lastFetch;

                        if ( idle > maxWait ) {
                            logger.info( "        - " + domain + ":tlsalpn01: " + idle + "ms since last probe" );

                            break;
                        }
                    }

                    challenge.fetch();

                    switch( challenge.getStatus() ) {
                        case Status.VALID -> {
                            logger.info( "        - " + domain + ":tlsalpn01: success" );

                            return true;
                        }
                        case Status.INVALID -> {
                            logger.warn( "        ** " + domain + ":tlsalpn01: polling failed" );

                            if ( challenge.getError().isPresent() ) {
                                Problem problem = challenge.getError().get();

                                logger.warn( "       ** " + domain + ":tlsalpn01: Error: " + problem.toString() );
                            }

                            return false;
                        }
                        default -> {
                            logger.info( "        - " + domain + ":tlsalpn01: status=" + challenge.getStatus() );
                        }
                    }
                }
            } catch ( IOException ex ) {
                ex.printStackTrace();
            }
        } catch ( IOException | GeneralSecurityException ex ) {
            ex.printStackTrace();
        }

        logger.warn( "        - " + domain + ":tlsalpn01: wait time expired" );

        return false;
    }

    private void authorize( Logger logger, Authorization authorization ) throws AcmeException
    {
        String  domain  = authorization.getIdentifier().getDomain();

        logger.info( "      - " + domain + ": authorizing" );

        if ( authorization.getStatus() == Status.VALID ) {
            logger.info( "        - " + domain + ": is already valid" );

            return;
        }

        TlsAlpn01Challenge tls01 = authorization.findChallenge( TlsAlpn01Challenge.class ).orElse( null );
        if ( tls01 != null ) {
            if ( this.tls01Challenge( logger, authorization, tls01 ) ) {
               return;
            }
        } else {
            logger.info( "      - " + domain + ": TLS01 is not acceptable" );
        }

        Http01Challenge http01 = authorization.findChallenge( Http01Challenge.class ).orElse( null );
        if ( http01 != null ) {
            if ( this.http01Challenge( logger, authorization, http01 ) ) {
                return;
            }
        } else {
            logger.info( "      - " + domain + ": HTTP01 is not acceptable" );
        }

        Dns01Challenge dns01 = authorization.findChallenge( Dns01Challenge.class ).orElse( null );
        if ( dns01 != null ) {
            if ( this.dns01Challenge( logger, authorization, dns01 ) ) {
                return;
            }
        } else {
            logger.info( "      - " + domain + ": DNS01 is not acceptable" );
        }

        throw new AcmeException( domain + ": No supported challenge was completed" );
    }

    private boolean isHostAcceptable( String hostName )
    {
        String  lower = StringUtils.defaultIfBlank( hostName, "" ).trim().toLowerCase();

        for ( String disallowed : Constants.Acme.NOT_TLD ) {
            if ( lower.endsWith( disallowed ) ) {
                return false;
            }
        }

        return true;
    }

    @Override
    public KeyStore acquireCoverage( Logger logger, KeyPair keyPair, SequencedCollection<String> hostNames, String alias, ProtectionParameter keyPass ) throws GeneralSecurityException
    {
        Account     acmeAccount = null;
        Set<String> filtered    = hostNames.stream ()
                                           .filter ( this::isHostAcceptable )
                                           .collect( Collectors.toSet() );
        KeyStore    keyStore    = KeyStoreTools.emptyKeyStore( KeyStore.getDefaultType() );

        logger.info( "  - ACME Certificate Acquisition" );

        if ( filtered.isEmpty() ) {
            String  removed = hostNames.stream()
                                       .filter( this::isHostAcceptable )
                                       .collect( Collectors.joining( ", " ) );

            logger.warn( "    - Cannot make certificates for " + removed );

            return keyStore;
        }

        try {
            Session session = new Session( this.credential.uri() );
            session.setLocale( Locale.ENGLISH );

            logger.info( "    - Created session" );
            logger.info( "    - Credential: " + this.credential.emailAddress() );

            var builder = new AccountBuilder()
                                .agreeToTermsOfService()
                                .useKeyPair( this.credential.keyPair() )
                                .addEmail( this.credential.emailAddress() );

            if ( this.credential.externalKeyId() != null && this.credential.externalKey() != null ) {
                builder.withKeyIdentifier( this.credential.externalKeyId(), this.credential.externalKey() );
            }

            acmeAccount = builder.create( session );

            logger.info( "    - Account: " +
                                acmeAccount.getContacts()
                                           .stream()
                                           .map( uri -> uri.toString() )
                                           .collect( Collectors.joining( ", " ) ) );
        } catch ( AcmeException ex ) {
            logger.error( "** Cannot connect to ACME provider: " + ex.getLocalizedMessage(), ex );

            return keyStore;
        }

        try {
            X500Name                    subject = this.makeSubjectDN( hostNames.getFirst() );
            PKCS10CertificationRequest  csr = this.makeCsr( keyPair, subject, hostNames );

            this.writeCsr( alias, csr );

            try {
                Order order = acmeAccount.newOrder().domains( hostNames ).create();

                for ( Authorization authorization : order.getAuthorizations() ) {
                    this.authorize( logger, authorization );
                }

                order.execute( csr );

                logger.info( "    - Waiting for signature" );

                int attempts = 10;
                while ( order.getStatus() != Status.VALID && attempts-- > 0 ) {
                    // Did the order fail?
                    if ( order.getStatus() == Status.INVALID ) {
                        throw new GeneralSecurityException( order.getError().map( Problem::toString ).orElse("unknown") );
                    } else if ( order.getStatus() == Status.VALID ) {
                        break;
                    }

                    // Then update the status
                    Instant until   = order.fetch().orElse( Instant.now().plusSeconds( 5 ) );
                    long    sleep   = ChronoUnit.MILLIS.between( Instant.now(), until );

                    // Wait for a few seconds
                    try {
                        Thread.sleep( Math.max( 125, sleep ) );
                    } catch ( InterruptedException ignore ) {}
                }

                Certificate         certificate = order.getCertificate();
                X509Certificate[]   x509        = certificate.getCertificateChain().toArray( X509Certificate[]::new );
                char[]              password    = (keyPass instanceof PasswordProtection pwd) ? pwd.getPassword() : "changeit".toCharArray();

                keyStore.setKeyEntry( alias, keyPair.getPrivate(), password, x509 );
            } catch ( AcmeException ex ) {
                logger.warn( "    ** Cannot place ACME order: " + ex.getLocalizedMessage(), ex );
            }
        } catch ( OperatorCreationException | IOException | GeneralSecurityException ex ) {
            logger.warn( "    ** Cannot generate coverage for " + alias + ": " + ex.getLocalizedMessage(), ex );
        }

        return keyStore;
    }
}
