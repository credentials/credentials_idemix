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

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.KeyException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

@SuppressWarnings("unused")
public class ProofD implements Proof {
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
		return verify(pk, context, nonce1, null);
	}

	public boolean verify(IdemixPublicKey pk, BigInteger context, BigInteger nonce1, BigInteger challenge) {
		if(!checkSizeResponses(pk)) {
			return false;
		}

		BigInteger c_prime = challenge;
		if (c_prime == null) {
			BigInteger Z = reconstructZ(pk);
			c_prime = Crypto.sha256Hash(Crypto.asn1Encode(context, A, Z, nonce1));
		}

		boolean matched = c.compareTo(c_prime) == 0;

		if (!matched) {
			System.out.println("Hash doesn't match");
		}

		return matched;
	}

	@Override
	public List<BigInteger> getChallengeContribution(IdemixPublicKey pk) {
		return Arrays.asList(A, reconstructZ(pk));
	}

	@Override
	public IdemixPublicKey extractPublicKey() throws KeyException {
		Attributes attrs = new Attributes(get_a_disclosed());

		CredentialIdentifier id = attrs.getCredentialIdentifier();
		return IdemixKeyStore.getInstance().getPublicKey(id.getIssuerIdentifier(), attrs.getKeyCounter());
	}

	@Override
	public BigInteger getSecretKeyResponse() {
		return get_a_responses().get(0);
	}

	private boolean checkSizeResponses(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();

		// Check range on the a_responses
		BigInteger maximum = Crypto.TWO.pow(params.get_l_m_commit() + 1).subtract(BigInteger.ONE);
		BigInteger minimum = maximum.negate();
		for(BigInteger a_response : a_responses.values()) {
			if(a_response.compareTo(minimum) < 0 ||
					a_response.compareTo(maximum) > 0) {
				System.out.println("Size of a_response outside of range");
				return false;
			}
		}

		// Check range e_response
		maximum = Crypto.TWO.pow(params.get_l_e_commit() + 1).subtract(BigInteger.ONE);
		minimum = maximum.negate();
		if(e_response.compareTo(minimum) < 0 ||
				e_response.compareTo(maximum) > 0) {
			System.out.println("Size of e_response outside of range");
			return false;
		}

		return true;
	}

	public BigInteger reconstructZ(IdemixPublicKey pk) {
		IdemixSystemParameters params = pk.getSystemParameters();
		BigInteger n = pk.getModulus();

		// known = Z / ( prod_{disclosed} R_i^{a_i} * A^{2^{l_e - 1}} )
		BigInteger numerator = A.modPow(Crypto.TWO.pow(params.get_l_e() - 1), n);
		for(Entry<Integer, BigInteger> entry : a_disclosed.entrySet()) {
			Integer idx = entry.getKey();
			BigInteger attribute = entry.getValue();
			if (attribute.bitLength() > params.get_l_m())
				attribute = Crypto.sha256Hash(attribute.toByteArray());
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

		// Return Z
		return known_c.multiply(Ae).multiply(Rs).multiply(Sv).mod(n);
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

	public ProofD mergeProofP(ProofP proofp, IdemixPublicKey pk) {
		BigInteger s_response = this.a_responses.get(0).add(proofp.getSecretKeyResponse());
		this.a_responses.put(0, s_response);
		return this;
	}
}
