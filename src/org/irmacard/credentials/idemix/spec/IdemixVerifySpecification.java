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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012,
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package org.irmacard.credentials.idemix.spec;

import java.net.URI;

import org.irmacard.credentials.spec.VerifySpecification;

import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.utils.StructureStore;


/**
 * Idemix flavoured VerifySpecification
 * 
 * This class implements the conversion from the generic specification to the 
 * Idemix specific one which can be used as input for the terminal and library. 
 */
public class IdemixVerifySpecification extends VerifySpecification {

	private ProofSpec proofSpec;
	private short credId;

	public IdemixVerifySpecification(ProofSpec proofSpec, short credId) {
		this.proofSpec = proofSpec;
		this.credId = credId;
	}

	/**
	 * Create an IdemixVerifySpecification based on an Idemix Proof
	 * Specification XML file.
	 *
	 * Note: for now we assume that the system parameters, group parameters
	 * and issuer public key have already been loaded.
	 */
	public static IdemixVerifySpecification fromIdemixProofSpec(
			URI proofSpecID, short credId) {
		ProofSpec proofSpec = (ProofSpec) StructureStore.getInstance().get(
				proofSpecID);

		return new IdemixVerifySpecification(proofSpec, credId);
	}

	/**
	 * Get an Idemix flavoured proof specification that should be used to 
	 * generate the proof.
	 * 
	 * @return the proof specification.
	 */
	public ProofSpec getProofSpec() {
		// TODO: implement generation of idemix IssuanceSpec

		return proofSpec;
	}

	/**
	 * Returns the short identifier used by the card to locate and identify the
	 * credential.
	 */
	public short getIdemixId() {
		return credId;
	}
}
