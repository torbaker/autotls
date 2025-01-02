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

import java.time.Period;
import java.util.Collection;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author torbaker
 */
public class Precheck
{
    private Precheck() {}

    public static String requireNonBlank( String text ) throws IllegalArgumentException
    {
        if ( StringUtils.isBlank( text ) ) {
            throw new IllegalArgumentException( "String is blank" );
        }

        return text.trim();
    }

    public static char[] requireNonEmpty( char[] passwd ) throws IllegalArgumentException
    {
        if ( passwd == null ){
            throw new IllegalArgumentException( "Password is null" );
        } else if ( passwd.length == 0 ) {
            throw new IllegalArgumentException( "Password is empty" );
        }

        return passwd;
    }

    public static <C extends Collection<?>> C requireNonEmpty( C collect ) throws IllegalArgumentException
    {
        if ( collect == null ) {
            throw new IllegalArgumentException( "Collection is null" );
        } else if ( collect.isEmpty() ) {
            throw new IllegalArgumentException( "Collection is empty" );
        }

        return collect;
    }

    public static Period requirePositive( Period value ) throws IllegalArgumentException
    {
        if ( value == null ) {
            throw new IllegalArgumentException( "Period is null" );
        } else if ( value.isNegative() || value.isNegative() ) {
            throw new IllegalArgumentException( "Period is not positive" );
        }

        return value;
    }

    public static int positive( int value ) throws IllegalArgumentException
    {
        if ( value < 1 ) {
            throw new IllegalArgumentException( "value is negative or zero" );
        }

        return value;
    }
}
