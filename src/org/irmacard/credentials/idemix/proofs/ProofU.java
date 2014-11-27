/**
 * ProofU.java
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

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;

/**
 * Represents a proof of correctness of the commitment in the first phase of the
 * issuance protocol.
 */
public class ProofU {
	private BigInteger c;
	private BigInteger v_prime_response;
	private BigInteger s_response;

	public ProofU(BigInteger c, BigInteger v_prime_response, BigInteger s_response) {
		this.c = c;
		this.v_prime_response = v_prime_response;
		this.s_response = s_response;
	}

	public boolean verify(IdemixPublicKey pk, BigInteger U, BigInteger context, BigInteger nonce) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// Check range of v_prime_response
		BigInteger maximum = Crypto.TWO.pow(params.l_v_prime_commit + 1).subtract(BigInteger.ONE);
		BigInteger minimum = maximum.negate();
		if (!(v_prime_response.compareTo(minimum) >= 0 && v_prime_response
				.compareTo(maximum) <= 0)) {
			System.out.println("Range check on v_prime_response failed");
			return false;
		}

		// Reconstruct U_commit
		// U_commit = U^{-c} * S^{v_prime_response} * R_0^{s_response}
		BigInteger Uc = U.modPow(this.c.negate(), n);
		BigInteger Sv = pk.getGeneratorS().modPow(this.v_prime_response, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(this.s_response, n);
		BigInteger U_commit = Uc.multiply(Sv).multiply(R0s).mod(n);

		// Recalculate hash
		BigInteger c_prime = Crypto.sha256Hash(Crypto.asn1Encode(context, U, U_commit, nonce));

		boolean matched = c.compareTo(c_prime) == 0;

		if(!matched) {
			System.out.println("Hash doesn't match");
		}

		return matched;
	}
}
