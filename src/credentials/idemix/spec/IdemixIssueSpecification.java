/**
 * IdemixIssueSpecification.java
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

package credentials.idemix.spec;

import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerKeyPair;

import credentials.spec.IssueSpecification;

/**
 * Idemix flavoured IssueSpecification
 * 
 * This class implements the conversion from the generic specification to the 
 * Idemix specific one which can be used as input for the terminal and library. 
 */
public class IdemixIssueSpecification extends IssueSpecification {

	/**
	 * Get the IssuerKeyPair that should be used to issue the credential.
	 *   
	 * @return the issuer key pair.
	 */
	public IssuerKeyPair getIssuerKey() {
		// TODO: implement generation/discovery of Idemix IssuerKeyPair.
		
		return new IssuerKeyPair(null);
	}
		
	/**
	 * Get an Idemix flavoured issuance specification that should be used to 
	 * issue the credential.
	 * 
	 * @return the issuance specification.
	 */
	public IssuanceSpec getIssuanceSpec() {
		// TODO: implement generation of Idemix IssuanceSpec.
		
		return new IssuanceSpec(null, null);
	}
	
	/**
	 * Get an Idemix flavoured list of the attribute values to issued.
	 * 
	 * @return the attribute values.
	 */
	public Values getValues() {
		// TODO: implement generation of Idemix attribute Values.
		
		return new Values(null);
	}
}
