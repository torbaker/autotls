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

import com.orbaker.autotls.CertificateAuthority.WildcardPolicy;
import jakarta.validation.constraints.NotNull;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Tools for host names.
 *
 * @author torbaker
 */
public final class HostNameTools
{
    private HostNameTools() {}

    /**
     * Split the given host name into host/domain.
     *
     * @param qualifiedName
     *      qualified host name.
     *
     * @return
     *      An immutable pair of host/domain names.
     */
    public static Pair<String,String> splitHostName( String qualifiedName )
    {
        String  host    = null;
        String  domain  = null;
        int     one     = qualifiedName.indexOf( '.' );
        int     two     = qualifiedName.lastIndexOf( '.' );

        if ( one == -1 ) {
            // No dots, single name only means the domain name is missing
            host    = qualifiedName;
            domain  = "localdomain";
        } else if ( one == two ) {
            // One dot can mean either a name on 'localdomain' or a bare
            // domain name with no host bame.
            if ( qualifiedName.substring( two ).equalsIgnoreCase( ".localdomain" ) ) {
                host    = qualifiedName.substring( 0, one );
                domain  = "localdomain";
            } else {
                host    = null;
                domain  = qualifiedName;
            }
        } else {
            // The proper code path
            host    = qualifiedName.substring( 0, one );
            domain  = qualifiedName.substring( one + 1 );
        }

        return new ImmutablePair<String,String>( host, domain );
    }

    /**
     * Divide host names by domain name.
     *
     * @param hostNames
     *      List of names to divide.
     *
     * @param wildcards
     *      Use wildcards if possible.
     *
     * @param namesPerCertificate
     *      Maximum number of SANs per certificate.
     *
     * @param addDomain
     *      Add the domain name as a SAN for non-wildcard certificates. The domain is always added to wildcards as a SAN.
     *
     * @return
     *      Names in {@code hostNames} partitioned by domain names, subject
     *      to the constraints: {@code wildcards}, and {@code namesPerCertificate}.
     */
    public static Map<String,List<String>> divideNames( Collection<? extends String> hostNames, WildcardPolicy wildcards, int namesPerCertificate, boolean addDomain )
    {
        var divided = new HashMap<String,List<String>>();

        // Degenerate case. Each is simply itself
        if ( namesPerCertificate == 1 ) {
            for ( String hostName : hostNames ) {
                List<String>    names   = new ArrayList<String>();
                String          domain  = HostNameTools.splitHostName( hostName ).getRight();

                if ( wildcards == WildcardPolicy.ALWAYS || wildcards == WildcardPolicy.PREFER ) {
                    names.add( "*" + domain );
                } else {
                    names.add( hostName );
                }

                if ( addDomain ) {
                    names.add( domain );
                }

                divided.put( hostName, names );
            }
        } else {
            // First, divide by domain name:
            for ( String hostName : hostNames ) {
                Pair<String,String> split   = HostNameTools.splitHostName( hostName );
                List<String>        names   = divided.get( split.getRight() );

                if ( names == null ) {
                    names = new ArrayList<String>();

                    divided.put( split.getRight(), names );
                }

                names.add( hostName );
            }
            // Add domain names if desired
            if ( addDomain ) {
                for ( String domainName : divided.keySet() ) {
                    List<String> names = divided.get( domainName );

                    names.add( domainName );
                }
            }

            // Convert to wildcards where applicable.
            int convertAt =
                switch( wildcards ) {
                    case ALWAYS -> { yield -1;                      }
                    case PREFER -> { yield  1;                      }
                    case AVOID  -> { yield namesPerCertificate;     }
                    case NEVER  -> { yield Integer.MAX_VALUE - 1;   }
                };

            if ( addDomain ) {
                convertAt += 1;
            }

            for ( String domainName : divided.keySet() ) {
                List<String> names = divided.get( domainName );

                if ( names.size() > convertAt ) {
                    names.clear();
                    names.add( "*." + domainName );
                    names.add( domainName );
                }
            }

            // Now, for those that are more than 'namesPerCertificate, split the list
            // into chunks of
            int limit = namesPerCertificate + ((addDomain) ? 1 : 0);

            for ( String domain : divided.keySet() ) {
                List<String> names = divided.get( domain );

                if ( names.size() > limit ) {
                    int chunks = (names.size() / limit) + (((names.size() % limit) > 0) ? 1 : 0);

                    for ( int chunk = 0 ; chunk < chunks ; chunk++ ) {
                        int             first   = (chunk * limit);
                        int             last    = Math.min( names.size(), (first + limit) );
                        String          alias   = domain + "-" + Integer.toString( chunk );
                        List<String>    sublist = names.subList( first, last );

                        divided.put( alias, sublist );
                    }

                    divided.remove( domain, names );
                }
            }
        }

        return divided;
    }

    /**
     * Get the local hostname. Fall back to 'localhost.localdomain' if all
     * else fails, just don't throw an exception.
     *
     * @return
     *      Host name via best effort method. Never {@code null}.
     */
    @NotNull
    public static String getHostName()
    {
        String hostName = "localhost.localdomain";

        try {
            hostName = InetAddress.getLocalHost().getHostName();

            // Depending on your host/DNS configuration, you may get a bare host name
            // from 'getHostName()'
            if ( ! hostName.contains( "." ) ) {
                hostName += ".localdomain";
            }
        } catch ( UnknownHostException ignore ) {}

        return hostName;
    }
}
