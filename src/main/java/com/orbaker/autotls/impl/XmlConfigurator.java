/*-
 * #%L
 * autotls
 * %%
 * Copyright (C) 2024 - 2025 Tim Orbaker
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

import com.orbaker.autotls.CertificateManager;
import java.nio.file.Path;

/**
 *
 * @author torbaker
 */
class XmlConfigurator extends CertificateManagerBuilderImpl implements CertificateManager.Builder
{
    public XmlConfigurator( Path baseDir, Path xmlFile )
    {
        throw new UnsupportedOperationException();
    }
}
