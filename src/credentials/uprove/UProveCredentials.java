/**
 * UProveCredentials.java
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

package credentials.uprove;

import credentials.Attributes;
import credentials.Credentials;
import credentials.CredentialsException;
import credentials.spec.IssueSpecification;
import credentials.spec.VerifySpecification;
import credentials.uprove.spec.UProveIssueSpecification;
import credentials.uprove.spec.UProveVerifySpecification;

/**
 * A U-Prove specific implementation of the credentials interface.
 */
public class UProveCredentials implements Credentials {

	public UProveCredentials() {
		// TODO: Auto-generated constructor stub.
	}

	/**
	 * Issue a credential to the user according to the provided specification
	 * containing the specified values.
	 * 
	 * @param specification of the issuer and the credential to be issued.
	 * @param values to be stored in the credential.
	 * @throws CredentialsException if the issuance process fails.
	 */
	public void issue(IssueSpecification spec, Attributes values)
	throws CredentialsException {
		// TODO: Auto-generated method stub.
	}

	/**
	 * Get a blank IssueSpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public IssueSpecification issueSpecification() {
		return new UProveIssueSpecification();
	}
	
	/**
	 * Verify a number of attributes listed in the specification. 
	 * 
	 * @param specification of the credential and attributes to be verified.
	 * @return the attributes disclosed during the verification process.
	 * @throws CredentialsException if the verification process fails.
	 */
	public Attributes verify(VerifySpecification spec)
	throws CredentialsException {
		// TODO: Auto-generated method stub.
		
		return null;
	}
	
	/**
	 * Get a blank VerifySpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public VerifySpecification verifySpecification() {
		return new UProveVerifySpecification();
	}
}
