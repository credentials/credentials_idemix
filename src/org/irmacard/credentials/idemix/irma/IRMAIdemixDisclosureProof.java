/**
 * IRMAIdemixDisclosureProof.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, January 2015.
 */

package org.irmacard.credentials.idemix.irma;

import java.math.BigInteger;
import java.util.HashMap;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.descriptions.IdemixVerificationDescription;
import org.irmacard.credentials.idemix.proofs.ProofD;

public class IRMAIdemixDisclosureProof {
	ProofD proof;

	public IRMAIdemixDisclosureProof(BigInteger c, BigInteger A,
			BigInteger e_response, BigInteger v_response,
			HashMap<Integer, BigInteger> a_responses,
			HashMap<Integer, BigInteger> a_disclosed) {
		proof = new ProofD(c, A, e_response, v_response, a_responses, a_disclosed);
	}

	// TODO: is CredentialsException the right type for the exceptions?
	public Attributes verify(IdemixVerificationDescription vd, BigInteger nonce) throws CredentialsException {
		// Verify proof
		BigInteger context = vd.getContext();
		IdemixPublicKey pk = vd.getIssuerPublicKey();
		if(!proof.verify(pk, context, nonce)) {
			return null;
		}

		// Return the attributes that have been revealed during the proof
		Attributes attributes = new Attributes();
		HashMap<Integer, BigInteger> disclosed_attributes = proof.get_a_disclosed();
		for(int i : disclosed_attributes.keySet()) {
			BigInteger value = disclosed_attributes.get(i);
			attributes.add(vd.getAttributeName(i), value.toByteArray());
		}

		// Verify validity
		if (!attributes.isValid()) {
			throw new CredentialsException("The credential has expired.");
		}

		// Verify credential id (it is set if it doesn't return 0)
		if (attributes.getCredentialID() != 0
				&& !(attributes.getCredentialID() == vd
						.getVerificationDescription()
						.getCredentialDescription().getId())) {
			throw new CredentialsException("The credential id does not match.");
		}

		return attributes;
	}
}
