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

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.util.Crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

/**
 * Represents an Idemix credential.
 */
public class IdemixCredential {
	private CLSignature signature;
	private IdemixPublicKey issuer_pk;
	private List<BigInteger> attributes;

	public IdemixCredential(IdemixPublicKey issuer_pk,
			List<BigInteger> attributes, CLSignature signature) {
		this.issuer_pk = issuer_pk;
		this.attributes = attributes;
		this.signature = signature;
	}

	public CLSignature getSignature() {
		return signature;
	}

	public IdemixPublicKey getPublicKey() {
		return issuer_pk;
	}

	public IdemixCredential(IdemixPublicKey issuer_pk, BigInteger secret,
			List<BigInteger> attributes, CLSignature signature) {
		this.issuer_pk = issuer_pk;

		// Secret is 0-th attribute
		this.attributes = new Vector<BigInteger>();
		this.attributes.add(secret);
		this.attributes.addAll(attributes);

		this.signature = signature;
	}

	public Commitment commit(List<Integer> disclosed_attributes, BigInteger context,
							 BigInteger nonce1, BigInteger skCommitment) {
		return new Commitment(disclosed_attributes, context, nonce1, skCommitment);
	}

	/**
	 * A disclosure proof of this credential for the given set of disclosed
	 * attributes. The proof also contains the revealed values.
	 *
	 * @param disclosed_attributes
	 *            Indices of attributes that have to be disclosed (1-based)
	 * @param context
	 *            The context
	 * @param nonce1
	 *            Nonce for the non-interactive proof
	 *
	 * @return disclosure proof for the given disclosed attributes
	 */
	public ProofD createDisclosureProof(List<Integer> disclosed_attributes, BigInteger context, BigInteger nonce1) {
		Commitment commitment = commit(disclosed_attributes, context, nonce1, null);
		return commitment.createProof(null);
	}

	public int getNrAttributes() {
		return attributes.size();
	}

	public BigInteger getAttribute(int i) {
		return attributes.get(i);
	}

	public Attributes getAllAttributes() {
		return new Attributes(attributes);
	}

	public int getKeyCounter() {
		return new Attributes(attributes.get(1)).getKeyCounter();
	}

	private List<Integer> getUndisclosedAttributes(List<Integer> disclosed_attributes) {
		List<Integer> undisclosed_attributes = new Vector<Integer>();
		for(int i = 0; i < attributes.size(); i++) {
			if(!disclosed_attributes.contains(i)) {
				undisclosed_attributes.add(i);
			}
		}
		return undisclosed_attributes;
	}

	/**
	 * Container for a commitment for a disclosure proof of this credential. See the
	 * {@link ProofListBuilder} class for more information.
	 */
	public class Commitment {
		BigInteger context;
		BigInteger nonce1;
		List<Integer> disclosed_attributes;
		List<Integer> undisclosed_attributes;
		CLSignature rand_sig;
		BigInteger e_commit;
		BigInteger v_commit;
		HashMap<Integer, BigInteger> a_commits;
		BigInteger A;
		BigInteger Z;

		public BigInteger getA() {
			return A;
		}

		public BigInteger getZ() {
			return Z;
		}

		private Commitment(List<Integer> disclosed_attributes, BigInteger context,
						   BigInteger nonce1, BigInteger skCommit) {
			SecureRandom rnd = new SecureRandom();
			IdemixSystemParameters params = issuer_pk.getSystemParameters();
			BigInteger n = issuer_pk.getModulus();

			this.context = context;
			this.nonce1 = nonce1;
			this.disclosed_attributes = disclosed_attributes;

			undisclosed_attributes = getUndisclosedAttributes(disclosed_attributes);

			rand_sig = signature.randomize(issuer_pk);

			A = rand_sig.getA();
			e_commit = new BigInteger(params.l_e_commit, rnd);
			v_commit = new BigInteger(params.l_v_commit, rnd);

			a_commits = new HashMap<>();
			for(Integer i : undisclosed_attributes) {
				a_commits.put(i, new BigInteger(params.l_m_commit, rnd));
			}

			if (skCommit != null) {
				a_commits.put(0, skCommit);
			}

			// Z = A^{e_commit} * S^{v_commit}
			//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
			BigInteger Ae = rand_sig.getA().modPow(e_commit, n);
			BigInteger Sv = issuer_pk.getGeneratorS().modPow(v_commit, n);
			Z = Ae.multiply(Sv).mod(n);
			for(Integer i : undisclosed_attributes) {
				Z = Z.multiply(issuer_pk.getGeneratorR(i).modPow(a_commits.get(i), n)).mod(n);
			}
		}

		public ProofD createProof(BigInteger challenge) {
			if (Z == null) {
				throw new RuntimeException("Not committed yet");
			}

			IdemixSystemParameters params = issuer_pk.getSystemParameters();

			BigInteger c = challenge;
			if (c == null) {
				c = Crypto.sha256Hash(Crypto.asn1Encode(context, A, Z, nonce1));
			}

			BigInteger e_prime = rand_sig.get_e().subtract(Crypto.TWO.pow(params.l_e - 1));
			BigInteger e_response = e_commit.add(c.multiply(e_prime));
			BigInteger v_response = v_commit.add(c.multiply(rand_sig.get_v()));

			HashMap<Integer, BigInteger> a_responses = new HashMap<>();
			for(Integer i : undisclosed_attributes) {
				a_responses.put(i, a_commits.get(i).add(c.multiply(attributes.get(i))));
			}

			HashMap<Integer, BigInteger> a_disclosed = new HashMap<>();
			for(Integer i : disclosed_attributes) {
				a_disclosed.put(i, attributes.get(i));
			}

			return new ProofD(c, A, e_response, v_response, a_responses, a_disclosed);
		}
	}
}
