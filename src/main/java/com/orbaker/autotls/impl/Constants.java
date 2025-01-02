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

import com.orbaker.autotls.CertificateAuthority.WildcardPolicy;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Period;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.SystemUtils;

/**
 *
 * @author torbaker
 */
public interface Constants
{
    static final String     PACKAGE         = "AutoSSL";
    static final String     PACKAGE_LOWER   = Constants.PACKAGE.toLowerCase();
    static final Charset    ENCODING        = StandardCharsets.UTF_8;

    interface KeyGen
    {
        static final String     CURVE       = "secp384r1";
    }

    interface CredentialStoreInfo
    {
        static final Path       STORE_FILE  = Paths.get( SystemUtils.USER_HOME, Constants.PACKAGE_LOWER, Constants.PACKAGE_LOWER + ".kps" );
        static final char[]     STORE_PASS  = "changeit".toCharArray();
        static final boolean    STRICT_MODE = false;
    }

    interface KeyStoreInfo
    {
        static final String     STORE_TYPE  = KeyStore.getDefaultType();
        static final Path       STORE_FILE  = Paths.get( SystemUtils.USER_HOME, Constants.PACKAGE_LOWER, Constants.PACKAGE_LOWER + ".jks" );
        static final char[]     STORE_PASS  = "changeit".toCharArray();
        static final boolean    STRICT_MODE = false;
    }

    interface Authority
    {
        static final String[]       ALLOWED_NAMES   = new String[] { "OU", "O", "L", "ST", "C" };
        static final int            MAX_ALT_NAMES   = 4;
        static final WildcardPolicy WILDCARD_POLICY = WildcardPolicy.NEVER;
        static final boolean        INCLUDE_DOMAIN  = false;
        static final boolean        SAVE_CSR        = false;
        static final Path           CSR_PATH        = Paths.get( SystemUtils.USER_HOME, Constants.PACKAGE_LOWER, "csrs" ).toAbsolutePath().normalize();
        static final String         SIGNATURE       = "SHA256WithRSA";
    }

    interface SelfSigned
    {
        static final Period     VALIDITY    = Period.ofDays( 90 );
    }

    interface Acme
    {
        static final List<String>   NOT_TLD     = Arrays.<String>asList( ".localdomain", ".local", ".lan" );
        static final String         LETSENC_URI = "acme://letsencrypt.org";
        static final String         ZEROSSL_URI = "acme://zerossl.com/v2/D30";

        interface Http
        {
            static final int        TCP_PORT        = 80;
            static final int        BACKLOG         = 10;
            static final Duration   TIMEOUT         = Duration.ofMinutes( 2 );
        }
    }

    interface CertificateManager
    {
        static final com.orbaker.autotls.KeyStoreInfo   KEY_STORE   = com.orbaker.autotls.KeyStoreInfo.builder().build();
        static final boolean    UPGRADE_CERTS   = true;
        static final boolean    EXPIRE_CERTS    = true;
        static final Period     SOFT_RENEW      = Period.ofDays( 14 );
        static final Period     HARD_RENEW      = Period.ofDays(  3 );
        static final int        RSA_KEY_SIZE    = 4096;
    }

    interface Files
    {
        static final LinkOption[]   STRICT_EXISTS   = new LinkOption[] { LinkOption.NOFOLLOW_LINKS };
        static final OpenOption[]   STRICT_CREATE   = new OpenOption[] { LinkOption.NOFOLLOW_LINKS, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE };
        static final OpenOption[]   STRICT_WRITE    = new OpenOption[] { LinkOption.NOFOLLOW_LINKS, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE };
        static final OpenOption[]   STRICT_READ     = new OpenOption[] { LinkOption.NOFOLLOW_LINKS, StandardOpenOption.READ };
        static final CopyOption[]   STRICT_COPY     = new CopyOption[] { LinkOption.NOFOLLOW_LINKS };

        static final LinkOption[]   RELAX_EXISTS    = new LinkOption[ 0 ];
        static final OpenOption[]   RELAX_CREATE    = new OpenOption[] { StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE };
        static final OpenOption[]   RELAX_WRITE     = new OpenOption[] { StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE };
        static final OpenOption[]   RELAX_READ      = new OpenOption[] { StandardOpenOption.READ };
        static final CopyOption[]   RELAX_COPY      = new CopyOption[ 0 ];
    }
}
