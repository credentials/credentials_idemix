/**
 * CLSignature.java
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
import java.util.List;
import java.util.Random;

import org.irmacard.credentials.idemix.util.Crypto;

/**
 * Represents a bare Camenisch-Lysyanskaya signature. The block of messages, or
 * this case the attributes are not stored with this object.
 */
public class CLSignature {
	private BigInteger A;
	private BigInteger e;
	private BigInteger v;

	public CLSignature(BigInteger A, BigInteger e, BigInteger v) {
		this.A = A;
		this.e = e;
		this.v = v;
	}

	/**
	 * Returns a Camenisch-Lysyanskaya signature using the public-private
	 * key-pair (pk,sk) on the block of messages ms. Note that we follow the
	 * credential specification and pick v from a more restricted domain.
	 *
	 * @param sk
	 *            an Idemix secret key
	 * @param pk
	 *            an Idemix public key
	 * @param ms
	 *            a block of messages
	 */
	public static CLSignature signMessageBlock(IdemixSecretKey sk, IdemixPublicKey pk, List<BigInteger> ms) {
		List<BigInteger> Rs = pk.getGeneratorsR();
		return signMessageBlockAndCommitment(sk, pk, BigInteger.ONE, ms, Rs);
	}

	/**
	 * Returns a Camenisch-Lysyanskaya signature using the public-private
	 * key-pair (pk,sk) on the block of messages ms and the commitment U. This
	 * function assumes that the commitment used the first generator. Note that
	 * we follow the credential specification and pick v from a more restricted
	 * domain.
	 *
	 * @param sk
	 *            an Idemix secret key
	 * @param pk
	 *            an Idemix public key
	 * @param U
	 *            commitment to a value that is to be included in the signature
	 * @param ms
	 *            a block of messages
	 */
	public static CLSignature signMessageBlockAndCommitment(IdemixSecretKey sk, IdemixPublicKey pk, BigInteger U, List<BigInteger> ms) {
		// Skip the first generator
		List<BigInteger> Rs = pk.getGeneratorsR().subList(1, pk.getGeneratorsR().size());
		return signMessageBlockAndCommitment(sk, pk, U, ms, Rs);
	}

	protected static CLSignature signMessageBlockAndCommitment(IdemixSecretKey sk, IdemixPublicKey pk, BigInteger U, List<BigInteger> ms, List<BigInteger> Rs) {
		BigInteger n = pk.getModulus();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger R = Crypto.representToBases(Rs, ms, n);

		Random rnd = new Random();

		BigInteger v_tilde = new BigInteger(params.l_v - 1, rnd);
		BigInteger two_l_v = new BigInteger("2").pow(params.l_v - 1);
		BigInteger v = two_l_v.add(v_tilde);

		// Q = inv( S^v * R * U) * Z
		BigInteger numerator = pk.getGeneratorS().modPow(v, n).multiply(R).multiply(U).mod(n);
		BigInteger Q = pk.getGeneratorZ().multiply(numerator.modInverse(n)).mod(n);

		BigInteger e = Crypto.probablyPrimeInBitRange(params.l_e - 1,
				params.l_e_prime - 1);

		// TODO: this is probably open to side channel attacks, maybe use a
		// safe (raw) RSA signature?
		BigInteger order = sk.get_p_prime_q_prime();
		BigInteger e_inv = e.modInverse(order);
		BigInteger A = Q.modPow(e_inv, n);

		return new CLSignature(A, e, v);
	}

	public boolean verify(IdemixPublicKey pk, List<BigInteger> ms) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// Check that e in [2^{l_e - 1}, 2^{l_e - 1} + 2^{l_e_prime -1}]
		BigInteger start = Crypto.TWO.pow(params.l_e - 1);
		BigInteger end = start.add(Crypto.TWO.pow(params.l_e_prime - 1));
		if(e.compareTo(start) < 0 || e.compareTo(end) > 0) {
			System.out.println("Prime in signature out of range");
			return false;
		}

		// Q = A^e * R * S^v
		BigInteger R = Crypto.representToBases(pk.getGeneratorsR(), ms, n);
		BigInteger Ae = this.A.modPow(e, n);
		BigInteger Sv = pk.getGeneratorS().modPow(this.v, n);
		BigInteger Q = Ae.multiply(R).multiply(Sv).mod(n);

		return pk.getGeneratorZ().equals(Q);
	}

	public BigInteger getA() {
		return A;
	}

	public BigInteger get_e() {
		return e;
	}

	public BigInteger get_v() {
		return v;
	}
}
