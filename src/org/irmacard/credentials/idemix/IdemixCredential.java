/**
 * IdemixCredential.java
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
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.util.Crypto;

/**
 * Represents and Idemix credential.
 *
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
	public ProofD createDisclosureProof(List<Integer> disclosed_attributes,
			BigInteger context, BigInteger nonce1) {
		Random rnd = new Random();
		IdemixSystemParameters params = issuer_pk.getSystemParameters();
		BigInteger n = issuer_pk.getModulus();

		List<Integer> undisclosed_attributes = getUndisclosedAttributes(disclosed_attributes);

		CLSignature rand_sig = this.signature.randomize(issuer_pk);

		BigInteger e_commit = new BigInteger(params.l_e_commit, rnd);
		BigInteger v_commit = new BigInteger(params.l_v_commit, rnd);

		HashMap<Integer, BigInteger> a_commits = new HashMap<Integer, BigInteger>();
		for(Integer i : undisclosed_attributes) {
			a_commits.put(i, new BigInteger(params.l_m_commit, rnd));
		}

		// Z = A^{e_commit} * S^{v_commit}
		//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
		BigInteger Ae = rand_sig.getA().modPow(e_commit, n);
		BigInteger Sv = issuer_pk.getGeneratorS().modPow(v_commit, n);
		BigInteger Z = Ae.multiply(Sv).mod(n);
		for(Integer i : undisclosed_attributes) {
			Z = Z.multiply(issuer_pk.getGeneratorR(i).modPow(a_commits.get(i), n)).mod(n);
		}

		BigInteger c = Crypto.sha256Hash(Crypto.asn1Encode(context, rand_sig.getA(),
				Z, nonce1));

		BigInteger e_prime = rand_sig.get_e().subtract(Crypto.TWO.pow(params.l_e - 1));
		BigInteger e_response = e_commit.add(c.multiply(e_prime));
		BigInteger v_response = v_commit.add(c.multiply(rand_sig.get_v()));

		HashMap<Integer, BigInteger> a_responses = new HashMap<Integer, BigInteger>();
		for(Integer i : undisclosed_attributes) {
			a_responses.put(i,  a_commits.get(i).add(c.multiply(attributes.get(i))));
		}

		HashMap<Integer, BigInteger> a_disclosed = new HashMap<Integer, BigInteger>();
		for(Integer i : disclosed_attributes) {
			a_disclosed.put(i, attributes.get(i));
		}

		return new ProofD(c, rand_sig.getA(), e_response, v_response, a_responses, a_disclosed);
	}

	public int getNrAttributes() {
		return attributes.size();
	}

	public BigInteger getAttribute(int i) {
		return attributes.get(i);
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
}
