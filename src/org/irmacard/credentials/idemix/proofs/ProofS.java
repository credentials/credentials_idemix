/**
 * ProofS.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */

package org.irmacard.credentials.idemix.proofs;

import java.math.BigInteger;

import org.irmacard.credentials.idemix.CLSignature;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.util.Crypto;

public class ProofS {
	private BigInteger c;
	private BigInteger e_response;

	public ProofS(BigInteger c, BigInteger e_response) {
		this.c = c;
		this.e_response = e_response;
	}

	public ProofS() {
	}

	/**
	 * Verifies this proof against the given public key, signature, context and
	 * nonce.
	 *
	 * @param pk
	 *            The public key of the signer
	 * @param signature
	 *            The signature by the signer
	 * @param context
	 *            The context used during issuance
	 * @param nonce
	 *            The nonce that was supplied when requesting the proof
	 * @return Whether the proof verified
	 */
	public boolean verify(IdemixPublicKey pk, CLSignature signature,
			BigInteger context, BigInteger nonce) {
		BigInteger n = pk.getModulus();

		// Reconstruct A_commit
		// A_commit = A^{c + e_response * e}
		BigInteger exponent = c.add(e_response.multiply(signature.get_e()));
		BigInteger A_commit = signature.getA().modPow(exponent, n);

		// Reconstruct Q
		BigInteger Q = signature.getA().modPow(signature.get_e(), n);

		// Recalculate hash
		BigInteger c_prime = Crypto.sha256Hash(Crypto.asn1Encode(context, Q,
				signature.getA(), nonce, A_commit));

		boolean matched = c.compareTo(c_prime) == 0;

		if (!matched) {
			System.out.println("Hash doesn't match");
		}

		return matched;
	}

	public void set_c(BigInteger c) {
		this.c = c;
	}

	public void set_e_response(BigInteger e_response) {
		this.e_response = e_response;
	}
}