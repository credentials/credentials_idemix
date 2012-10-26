/**
 * IssueSpecification.java
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

package org.irmacard.credentials.spec;

/**
 * Generic IssueSpecification
 * 
 * This class implements the generic setters which can be used by application 
 * developers as input to the credentials system.
 */
public class IssueSpecification extends Specification {

	/**
	 * The credential that needs to be issued.
	 */
	protected String credential;
	
	/**
	 * The issuer who issues the credential.
	 */
	protected String issuer;
	
	public void setCredentialIdentifier(String id) {
		credential = id;
	}
	
	public String getCredentialIdentifier() {
		return credential;
	}

	public void setIssuerIdentifier(String id) {
		issuer = id;
	}
	
	public String getIssuerIdentifier() {
		return issuer;
	}
}
