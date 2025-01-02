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

/**
 * AutoTLS management.
 */
module com.orbaker.autotls
{
    requires            java.logging;
    requires transitive java.naming;
    requires            java.xml;

    requires transitive jakarta.validation;
    requires            org.apache.commons.collections4;
    requires transitive org.apache.commons.lang3;
    requires transitive org.slf4j;
    requires            org.shredzone.acme4j;
    requires            org.bouncycastle.pkix;
    requires            org.bouncycastle.provider;

    exports com.orbaker.autotls;
    exports com.orbaker.autotls.tools;
}
