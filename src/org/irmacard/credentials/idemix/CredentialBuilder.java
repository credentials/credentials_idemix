/**
 * CredentialBuilder.java
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

package org.irmacard.credentials.idemix;

import java.math.BigInteger;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.util.Crypto;

public class CredentialBuilder {
	// State
	private BigInteger s;
	private BigInteger v_prime;
	private BigInteger n_2;

	// Immutable Input
	private final IdemixPublicKey pk;
	private final Attributes attrs;
	private final BigInteger context;

	// Derived immutable state
	private final IdemixSystemParameters params;
	private final BigInteger n;

	public CredentialBuilder(IdemixPublicKey pk, Attributes attrs, BigInteger context) {
		this.pk = pk;
		this.attrs = attrs;
		this.context = context;

		this.params = pk.getSystemParameters();
		this.n = pk.getModulus();
	}

	public void setSecret(BigInteger s) {
		this.s = s;
	}

	public BigInteger commitmentToSecret() {
		// State that needs to be stored
		v_prime = Crypto.randomSignedInteger(params.l_v_prime);

		// U = S^{v_prime} * R_0^{s}
		BigInteger Sv = pk.getGeneratorS().modPow(v_prime, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(s, n);
		BigInteger U = Sv.multiply(R0s).mod(n);

		return U;
	}

	public ProofU createProofU(BigInteger U, BigInteger n_1) {
		BigInteger s_commit = Crypto.randomSignedInteger(params.l_s_commit);
		BigInteger v_prime_commit = Crypto.randomSignedInteger(params.l_v_prime_commit);

		// U_commit = S^{v_prime_commit} * R_0^{s_commit}
		BigInteger Sv = pk.getGeneratorS().modPow(v_prime_commit, n);
		BigInteger R0s = pk.getGeneratorR(0).modPow(s_commit, n);
		BigInteger U_commit = Sv.multiply(R0s).mod(n);

		BigInteger c = Crypto.sha256Hash(Crypto.asn1Encode(context, U, U_commit, n_1));

		System.out.println("c: " + c);
		System.out.println("U: " + U);
		System.out.println("U_commit: " + U_commit);

		BigInteger s_response = s_commit.add(c.multiply(s));
		BigInteger v_prime_response = v_prime_commit.add(c.multiply(v_prime));

		return new ProofU(c, v_prime_response, s_response);
	}
}
