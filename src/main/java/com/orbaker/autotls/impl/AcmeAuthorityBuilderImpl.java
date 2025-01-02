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
import com.orbaker.autotls.AcmeAuthority.Builder;
import com.orbaker.autotls.CertificateAuthority;
import com.orbaker.autotls.Credential;
import jakarta.validation.constraints.NotNull;
import java.util.Objects;

/**
 *
 * @author torbaker
 */
public final class AcmeAuthorityBuilderImpl extends CertificateAuthorityBuilderImpl implements AcmeAuthority.Builder
{
    private Credential credential;

    public AcmeAuthorityBuilderImpl( CertificateAuthority.Builder copyFrom )
    {
        super( copyFrom );

        if ( copyFrom instanceof AcmeAuthority.Builder acme ) {
            this.credential = acme.getCredential();
        }
    }

    @Override
    public Credential getCredential()
    {
        return this.credential;
    }

    @Override
    public Builder setCredential( @NotNull Credential credential )
    {
        this.credential = Objects.requireNonNull( credential );

        return this;
    }

    @Override
    public AcmeAuthority build() throws IllegalArgumentException
    {
        super.validate();

        if ( this.credential == null ) {
            throw new IllegalArgumentException( "No ACME credentials" );
        }

        return new AcmeAuthorityImpl( this );
    }
}
