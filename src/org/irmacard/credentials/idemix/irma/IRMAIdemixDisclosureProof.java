/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
