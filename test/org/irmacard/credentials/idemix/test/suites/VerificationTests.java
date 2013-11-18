/**
 * VerificationTests.java
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2013.
 */

package org.irmacard.credentials.idemix.test.suites;

import org.irmacard.credentials.idemix.test.TestIRMACredential;
import org.irmacard.credentials.idemix.test.categories.VerificationTest;
import org.junit.experimental.categories.Categories;
import org.junit.experimental.categories.Categories.IncludeCategory;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Use this class to run all annotated verifications from
 * TestIRMACredential in one go.
 */
@RunWith(Categories.class)
@IncludeCategory(VerificationTest.class)
@SuiteClasses( { TestIRMACredential.class })
public class VerificationTests {
}
