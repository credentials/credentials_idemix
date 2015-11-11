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

	public BigInteger get_c() {
		return c;
	}

	public BigInteger get_e_response() {
		return e_response;
	}
}
