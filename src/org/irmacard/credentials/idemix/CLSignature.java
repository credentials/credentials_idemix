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
		BigInteger n = pk.getModulus();
		List<BigInteger> Rs = pk.getGeneratorsR();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger R = representToBases(Rs, ms, n);

		Random rnd = new Random();

		BigInteger v_tilde = new BigInteger(params.l_v, rnd);
		BigInteger two_l_v = new BigInteger("2").pow(params.l_v - 1);
		BigInteger v = two_l_v.add(v_tilde);

		// Q = inv( S^v * R ) * Z
		BigInteger numerator = pk.getGeneratorS().modPow(v, n).multiply(R).mod(n);
		BigInteger Q = pk.getGeneratorZ().multiply(numerator.modInverse(n)).mod(n);

		BigInteger e = probablyPrimeInBitRange(params.l_e,
				params.l_e_prime);

		// TODO: this is probably open to side channel attacks, maybe use a
		// safe (raw) RSA signature?
		BigInteger order = sk.get_p_prime_q_prime();
		BigInteger e_inv = e.modInverse(order);
		BigInteger A = Q.modPow(e_inv, n);

		return new CLSignature(A, e, v);
	}

	public boolean verify(IdemixPublicKey pk, List<BigInteger> ms) {
		BigInteger n = pk.getModulus();

		// Q = A^e * R * S^v
		BigInteger R = representToBases(pk.getGeneratorsR(), ms, n);
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

	private static BigInteger representToBases(List<BigInteger> bases,
			List<BigInteger> exps, BigInteger modulus) {
		BigInteger r = BigInteger.ONE;
		BigInteger tmp;
		for (int i = 0; i < exps.size(); i++) {
			// tmp = bases_i ^ exps_i (mod modulus)
			tmp = bases.get(i).modPow(exps.get(i), modulus);

			// r = r * tmp (mod modulus)
			r = r.multiply(tmp).mod(modulus);
		}
		return r;
	}

	/**
	 * Returns a BigInteger in the range [2^start, 2^start + 2^length) that is
	 * probably prime. The probability that the number is not prime is no more
	 * than 2^(-100).
	 *
	 * TODO: Make sure this code is correct
	 *
	 * @param start_in_bits
	 *            The start of the interval (in bits)
	 * @param length_in_bits
	 *            The length of the interval (non-inclusive) (in bits)
	 * @return A number in the given range that is probably prime
	 */
	private static BigInteger probablyPrimeInBitRange(int start_in_bits, int length_in_bits) {
		Random rnd = new Random();
		BigInteger two = new BigInteger("2");
		BigInteger start = two.pow(start_in_bits); // FIXME: check
		BigInteger end = two.pow(start_in_bits).add(two.pow(length_in_bits));
		BigInteger prime = end;

		// Ensure that the generated prime is never too big
		while (prime.compareTo(end) >= 0) {
			BigInteger offset = new BigInteger(length_in_bits, rnd);
			prime = start.add(offset).nextProbablePrime();
		}

		return prime;
	}
}
