/**
 * IdemixVerifySpecification.java
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

import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.showproof.ProofSpec;

import credentials.spec.VerifySpecification;

/**
 * Idemix flavoured VerifySpecification
 * 
 * This class implements the conversion from the generic specification to the 
 * Idemix specific one which can be used as input for the terminal and library. 
 */
public class IdemixVerifySpecification extends VerifySpecification {

	/**
	 * Get the IssuerKeyPair that should be used to verify the proof.
	 *   
	 * @return the issuer key pair.
	 */
	public IssuerKeyPair getIssuerKey() {
		// TODO: implement generation/discovery of idemix IssuerKeyPair
		
		return new IssuerKeyPair(null);
	}
	
	/**
	 * Get an Idemix flavoured proof specification that should be used to 
	 * generate the proof.
	 * 
	 * @return the proof specification.
	 */
	public ProofSpec getProofSpec() {
		// TODO: implement generation of idemix IssuanceSpec
		
		return new ProofSpec(null, null);
	}
}
