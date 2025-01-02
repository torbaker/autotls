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

import com.orbaker.autotls.CertificateAuthority;
import com.orbaker.autotls.SelfSignedAuthority;
import jakarta.validation.constraints.Positive;
import java.time.Period;

/**
 *
 * @author torbaker
 */
public final class SelfSignedAuthorityBuilderImpl extends CertificateAuthorityBuilderImpl implements SelfSignedAuthority.Builder
{
    private Period validity;

    public SelfSignedAuthorityBuilderImpl( CertificateAuthority.Builder copyFrom )
    {
        super( copyFrom );

        if ( copyFrom instanceof SelfSignedAuthority.Builder self ) {
            this.validity = self.getValidity();
        }
    }

    @Override
    public Period getValidity()
    {
        return this.validity;
    }

    @Override
    public SelfSignedAuthority.Builder setValidity( @Positive int validityDays )
    {
        return this.setValidity( Period.ofDays( validityDays ) );
    }

    @Override
    public SelfSignedAuthority.Builder setValidity( @Positive Period validity )
    {
        this.validity = Precheck.requirePositive( validity );

        return this;
    }

    @Override
    public SelfSignedAuthority build() throws IllegalArgumentException
    {
        super.validate();

        if ( this.validity == null ) {
            throw new IllegalArgumentException( "No validity period" );
        }

        return new SelfSignedAuthorityImpl( this );
    }
}
