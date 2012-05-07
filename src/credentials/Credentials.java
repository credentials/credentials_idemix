/**
 * Credentials.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */

package credentials;

import credentials.spec.IssueSpecification;
import credentials.spec.VerifySpecification;

/**
 * A generic interface for interaction with a credentials system, abstracting 
 * from the low-level credential technology specifics. 
 */
public interface Credentials {
	
	/**
	 * Issue a credential to the user according to the provided specification
	 * containing the specified values.
	 * 
	 * @param specification of the issuer and the credential to be issued.
	 * @param values to be stored in the credential.
	 * @throws CredentialsException if the issuance process fails.
	 */
	public void issue(IssueSpecification specification, Attributes values) 
	throws CredentialsException;
	
	/**
	 * Get a blank IssueSpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public IssueSpecification issueSpecification();
	
	/**
	 * Verify a number of attributes listed in the specification. 
	 * 
	 * @param specification of the credential and attributes to be verified.
	 * @return the attributes disclosed during the verification process.
	 * @throws CredentialsException if the verification process fails.
	 */
	public Attributes verify(VerifySpecification specification)
	throws CredentialsException;
	
	/**
	 * Get a blank VerifySpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public VerifySpecification verifySpecification();
	
}