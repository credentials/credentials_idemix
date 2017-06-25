/*
 * Copyright (c) 2016, the IRMA Team
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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.irmacard.credentials.idemix.CLSignature;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.PublicKeyIdentifier;

public class ProofDBuilder extends ProofBuilder {
	private IdemixCredential credential;
	private List<Integer> disclosed_attributes;
	private List<Integer> undisclosed_attributes;

	private ProofDRandomizers rand;

	class ProofDRandomizers implements Randomizers {
		private BigInteger e_randomizer;
		private BigInteger v_randomizer;
		private HashMap<Integer, BigInteger> a_randomizers;
		private CLSignature rand_sig;
	}

	class ProofDCommitments extends Commitments {
		private BigInteger A;
		private BigInteger Z;

		private IdemixPublicKey pk;

		public ProofDCommitments(IdemixPublicKey pk) {
			this.pk = pk;
		}

		public List<BigInteger> asList() {
			List<BigInteger> lst = Arrays.asList(A, Z);
			return lst;
		}

		@Override
		public Commitments mergeProofPCommitments(
				ProofPCommitmentMap map) {
			if(map.containsKey(pk.getIdentifier())) {
				ProofPBuilder.ProofPCommitments coms = map.get(pk.getIdentifier());
				Z = Z.multiply(coms.getPcommit()).mod(pk.getModulus());
			}
			return this;
		}
	}

	public ProofDBuilder(IdemixCredential credential, List<Integer> disclosed_attributes) {
		this.credential = credential;
		this.disclosed_attributes = disclosed_attributes;
		this.undisclosed_attributes = getUndisclosedAttributes(disclosed_attributes);
	}

	@Override
	public ProofBuilder generateRandomizers(Map<String, BigInteger> fixed) {
		SecureRandom rnd = new SecureRandom();
		ProofDRandomizers rand = new ProofDRandomizers();

		IdemixPublicKey issuer_pk = credential.getPublicKey();
		IdemixSystemParameters params = issuer_pk.getSystemParameters();
		rand.e_randomizer = new BigInteger(params.get_l_e_commit(), rnd);
		rand.v_randomizer = new BigInteger(params.get_l_v_commit(), rnd);

		rand.a_randomizers = new HashMap<>();
		for(Integer i : undisclosed_attributes) {
			rand.a_randomizers.put(i, new BigInteger(params.get_l_m_commit(), rnd));
		}

		if(fixed.containsKey(USER_SECRET_KEY)) {
			rand.a_randomizers.put(0, fixed.get(USER_SECRET_KEY));
		}

		rand.rand_sig = credential.getSignature().randomize(issuer_pk);

		this.rand = rand;
		return this;
	}

	@Override
	public ProofDCommitments calculateCommitments() {
		ProofDCommitments coms = new ProofDCommitments(credential.getPublicKey());

		IdemixPublicKey issuer_pk = credential.getPublicKey();
		BigInteger n = issuer_pk.getModulus();

		// Z = A^{e_commit} * S^{v_commit}
		//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
		BigInteger Ae = rand.rand_sig.getA().modPow(rand.e_randomizer, n);
		BigInteger Sv = issuer_pk.getGeneratorS().modPow(rand.v_randomizer, n);
		coms.Z = Ae.multiply(Sv).mod(n);
		for(Integer i : undisclosed_attributes) {
			coms.Z = coms.Z.multiply(issuer_pk.getGeneratorR(i).
					modPow(rand.a_randomizers.get(i), n)).mod(n);
		}

		coms.A = rand.rand_sig.getA();

		return coms;
	}

	public ProofD createProof(BigInteger challenge) {
		IdemixPublicKey issuer_pk = credential.getPublicKey();
		IdemixSystemParameters params = issuer_pk.getSystemParameters();

		BigInteger c = challenge;
		if (c == null) {
			// TODO change logic to generate challenge elsewhere
			throw new RuntimeException("Handle this at a different location!");
		}

		BigInteger e_prime = rand.rand_sig.get_e().subtract(Crypto.TWO.pow(params.get_l_e() - 1));
		BigInteger e_response = rand.e_randomizer.add(c.multiply(e_prime));
		BigInteger v_response = rand.v_randomizer.add(c.multiply(rand.rand_sig.get_v()));

		HashMap<Integer, BigInteger> a_responses = new HashMap<>();
		for(Integer i : undisclosed_attributes) {
			a_responses.put(i, rand.a_randomizers.get(i).
					add(c.multiply(credential.getAttribute(i))));
		}

		HashMap<Integer, BigInteger> a_disclosed = new HashMap<>();
		for(Integer i : disclosed_attributes) {
			a_disclosed.put(i, credential.getAttribute(i));
		}

		return new ProofD(c, rand.rand_sig.getA(), e_response, v_response, a_responses, a_disclosed);
	}

	private List<Integer> getUndisclosedAttributes(List<Integer> disclosed_attributes) {
		List<Integer> undisclosed_attributes = new Vector<Integer>();
		for(int i = 0; i < credential.getNrAttributes(); i++) {
			if(!disclosed_attributes.contains(i)) {
				undisclosed_attributes.add(i);
			}
		}
		return undisclosed_attributes;
	}

	@Override
	public IdemixPublicKey getPublicKey() {
		return credential.getPublicKey();
	}
}
