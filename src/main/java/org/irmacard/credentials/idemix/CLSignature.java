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

package org.irmacard.credentials.idemix;

import java.math.BigInteger;
import java.util.List;
import java.security.SecureRandom;

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

	public CLSignature() {
	}

	public void setA(BigInteger A) {
		this.A = A;
	}

	public void set_e(BigInteger e) {
		this.e = e;
	}

	public void set_v(BigInteger v) {
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

		BigInteger R = Crypto.representToBases(Rs, ms, n, params.get_l_m());

		SecureRandom rnd = new SecureRandom();

		BigInteger v_tilde = new BigInteger(params.get_l_v() - 1, rnd);
		BigInteger two_l_v = new BigInteger("2").pow(params.get_l_v() - 1);
		BigInteger v = two_l_v.add(v_tilde);

		// Q = inv( S^v * R * U) * Z
		BigInteger numerator = pk.getGeneratorS().modPow(v, n).multiply(R).multiply(U).mod(n);
		BigInteger Q = pk.getGeneratorZ().multiply(numerator.modInverse(n)).mod(n);

		BigInteger e = Crypto.probablyPrimeInBitRange(params.get_l_e() - 1,
				params.get_l_e_prime() - 1);

		// TODO: this is probably open to side channel attacks, maybe use a
		// safe (raw) RSA signature?
		BigInteger order = sk.get_p_prime_q_prime();
		BigInteger e_inv = e.modInverse(order);
		BigInteger A = Q.modPow(e_inv, n);

		return new CLSignature(A, e, v);
	}

	public boolean verify(IdemixPublicKey pk, List<BigInteger> ms) {
		return verifyDistributed(pk, ms, null);
	}

	public boolean verifyDistributed(IdemixPublicKey pk, List<BigInteger> ms,
			List<BigInteger> public_sks) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// Check that e in [2^{l_e - 1}, 2^{l_e - 1} + 2^{l_e_prime -1}]
		BigInteger start = Crypto.TWO.pow(params.get_l_e() - 1);
		BigInteger end = start.add(Crypto.TWO.pow(params.get_l_e_prime() - 1));
		if(e.compareTo(start) < 0 || e.compareTo(end) > 0) {
			System.out.println("Prime in signature out of range");
			return false;
		}

		// Q = A^e * R * S^v
		BigInteger R = Crypto.representToBases(pk.getGeneratorsR(), ms, n, params.get_l_m());

		// Add in the public_sks
		if(public_sks != null) {
			for(BigInteger public_sk : public_sks) {
				R = R.multiply(public_sk).mod(n);
			}
		}

		BigInteger Ae = this.A.modPow(e, n);
		BigInteger Sv = pk.getGeneratorS().modPow(this.v, n);
		BigInteger Q = Ae.multiply(R).multiply(Sv).mod(n);


		return pk.getGeneratorZ().equals(Q);
	}

	/**
	 * A randomized copy of this signature. Does not modify the original.
	 * @return A randomized copy of the original
	 */
	public CLSignature randomize(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		SecureRandom rnd = new SecureRandom();

		BigInteger randomizer = new BigInteger(params.get_l_r_a(), rnd);
		BigInteger A_prime = A.multiply(pk.getGeneratorS().modPow(randomizer, n)).mod(n);
		BigInteger v_prime = v.subtract(e.multiply(randomizer));

		return new CLSignature(A_prime, e, v_prime);
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
