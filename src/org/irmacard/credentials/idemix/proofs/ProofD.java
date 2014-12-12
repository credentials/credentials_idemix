/**
 * ProofD.java
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
import java.util.HashMap;
import java.util.Map.Entry;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;

public class ProofD {
	private BigInteger c;
	private BigInteger A;
	private BigInteger e_response;
	private BigInteger v_response;
	private HashMap<Integer, BigInteger> a_responses;
	private HashMap<Integer, BigInteger> a_disclosed;

	public ProofD(BigInteger c, BigInteger A, BigInteger e_response,
			BigInteger v_response, HashMap<Integer, BigInteger> a_responses,
			HashMap<Integer, BigInteger> a_disclosed) {
		this.c = c;
		this.A = A;
		this.e_response = e_response;
		this.v_response = v_response;
		this.a_responses = a_responses;
		this.a_disclosed = a_disclosed;
	}

	public HashMap<Integer, BigInteger> getDisclosedAttributes() {
		return a_disclosed;
	}

	public boolean verify(IdemixPublicKey pk, BigInteger context, BigInteger nonce1) {
		if(!checkSizeResponses(pk)) {
			return false;
		}

		BigInteger Z = reconstructZ(pk);

		BigInteger c_prime = Crypto.sha256Hash(Crypto.asn1Encode(context, A, Z,
				nonce1));

		boolean matched = c.compareTo(c_prime) == 0;

		if (!matched) {
			System.out.println("Hash doesn't match");
		}

		return matched;
	}

	private boolean checkSizeResponses(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();

		// Check range on the a_responses
		BigInteger maximum = Crypto.TWO.pow(params.l_m_commit + 1).subtract(BigInteger.ONE);
		BigInteger minimum = maximum.negate();
		for(BigInteger a_response : a_responses.values()) {
			if(a_response.compareTo(minimum) < 0 ||
					a_response.compareTo(maximum) > 0) {
				System.out.println("Size of a_response outside of range");
				return false;
			}
		}

		// Check range e_response
		maximum = Crypto.TWO.pow(params.l_e_commit + 1).subtract(BigInteger.ONE);
		minimum = maximum.negate();
		if(e_response.compareTo(minimum) < 0 ||
				e_response.compareTo(maximum) > 0) {
			System.out.println("Size of e_response outside of range");
			return false;
		}

		return true;
	}

	private BigInteger reconstructZ(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// known = Z / ( prod_{disclosed} R_i^{a_i} * A^{2^{l_e - 1}} )
		BigInteger numerator = A.modPow(Crypto.TWO.pow(params.l_e - 1), n);
		for(Entry<Integer, BigInteger> entry : a_disclosed.entrySet()) {
			Integer idx = entry.getKey();
			BigInteger attribute = entry.getValue();

			BigInteger tmp = pk.getGeneratorR(idx).modPow(attribute, n);
			numerator = numerator.multiply(tmp).mod(n);
		}
		BigInteger known = pk.getGeneratorZ().multiply(numerator.modInverse(n));
		BigInteger known_c = known.modPow(c.negate(), n);

		BigInteger Ae = A.modPow(e_response, n);
		BigInteger Sv = pk.getGeneratorS().modPow(v_response, n);
		BigInteger Rs = BigInteger.ONE;
		for(Entry<Integer, BigInteger> entry : a_responses.entrySet()) {
			Integer idx = entry.getKey();
			BigInteger response = entry.getValue();

			BigInteger tmp = pk.getGeneratorR(idx).modPow(response, n);
			Rs = Rs.multiply(tmp).mod(n);
		}
		BigInteger Z = known_c.multiply(Ae).multiply(Rs).multiply(Sv).mod(n);

		return Z;
	}

	public BigInteger get_c() {
		return c;
	}

	public BigInteger getA() {
		return A;
	}

	public BigInteger get_e_response() {
		return e_response;
	}

	public BigInteger get_v_response() {
		return v_response;
	}

	public HashMap<Integer, BigInteger> get_a_responses() {
		return a_responses;
	}

	public HashMap<Integer, BigInteger> get_a_disclosed() {
		return a_disclosed;
	}
}
