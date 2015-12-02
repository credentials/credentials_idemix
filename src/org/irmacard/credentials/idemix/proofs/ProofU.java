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

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;

/**
 * Represents a proof of correctness of the commitment in the first phase of the
 * issuance protocol.
 */
public class ProofU implements Proof {
	private BigInteger U;
	private BigInteger c;
	private BigInteger v_prime_response;
	private BigInteger s_response;

	public ProofU(BigInteger U, BigInteger c, BigInteger v_prime_response, BigInteger s_response) {
		this.U = U;
		this.c = c;
		this.v_prime_response = v_prime_response;
		this.s_response = s_response;
	}

	public boolean verify(IdemixPublicKey pk, BigInteger context, BigInteger nonce) {
		return verify(pk, context, nonce, null);
	}

	public boolean verify(IdemixPublicKey pk, BigInteger context, BigInteger nonce, BigInteger challenge) {
		IdemixSystemParameters params = pk.getSystemParameters();

		// Check range of v_prime_response
		BigInteger maximum = Crypto.TWO.pow(params.l_v_prime_commit + 1).subtract(BigInteger.ONE);
		BigInteger minimum = maximum.negate();
		if (!(v_prime_response.compareTo(minimum) >= 0 && v_prime_response
				.compareTo(maximum) <= 0)) {
			System.out.println("Range check on v_prime_response failed");
			return false;
		}

		// Recalculate hash
		BigInteger c_prime = challenge;
		if (c_prime == null) {
			BigInteger U_commit = reconstructU_commit(pk);
			c_prime = Crypto.sha256Hash(Crypto.asn1Encode(context, U, U_commit, nonce));
		}

		boolean matched = c.compareTo(c_prime) == 0;

		if(!matched) {
			System.out.println("Hash doesn't match");
		}

		return matched;
	}

	@Override
	public byte[] getChallengeContribution(IdemixPublicKey pk) {
		return Crypto.asn1Encode(U, reconstructU_commit(pk));
	}

	public BigInteger reconstructU_commit(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// Reconstruct U_commit
		// U_commit = U^{-c} * S^{v_prime_response} * R_0^{s_response}
		BigInteger Uc = U.modPow(this.c.negate(), n);
		BigInteger Sv = pk.getGeneratorS().modPow(this.v_prime_response, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(this.s_response, n);

		return Uc.multiply(Sv).multiply(R0s).mod(n);
	}

	public BigInteger getU() { return U; }

	public BigInteger get_c() {
		return c;
	}

	public BigInteger get_v_prime_response() {
		return v_prime_response;
	}

	public BigInteger get_s_response() {
		return s_response;
	}
}
