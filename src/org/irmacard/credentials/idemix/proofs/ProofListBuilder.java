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

import org.irmacard.credentials.idemix.CredentialBuilder;
import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.IdemixSystemParameters1024;
import org.irmacard.credentials.idemix.util.Crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * <p>A builder for {@link ProofList}s, for creating cryptographically bound proofs of knowledge. It works as
 * follows.
 * <ul>
 *     <li>When adding a credential for which some attributes should be disclosed, or the commitment to the secret
 *     key and v_prime for a new credential (see {@link #addProofD(IdemixCredential, List)} and
 *     {@link #addCredentialBuilder(CredentialBuilder)} respectively), a Pedersen commitment to randomness
 *     (see the {@link IdemixCredential.Commitment} and {@link CredentialBuilder.Commitment} classes) is made
 *     for each of the numbers that are to be kept secret (the first step in the Schnorr Sigma-protocol).</li>
 *     <li>When building the proofs using {@link #build()}, the challenge for the second step in the Schnorr
 *     Sigma-protocol is calculated, as the hash over the context, the commitments and the elements of which
 *     knowledge is being proved, and the nonce. Using this the responses (the third step of the Sigma-protocol) are
 *     calculated and a new {@link ProofList} is populated.</li>
 * </ul>
 * </p>
 */
public class ProofListBuilder {
	private BigInteger context;
	private BigInteger nonce;

	private List<IdemixCredential> credentials = new ArrayList<>();

	private List<ProofBuilder> builders = new ArrayList<>();

	private BigInteger secret;

	private Map<String, BigInteger> fixed;

	public ProofListBuilder(BigInteger context, BigInteger nonce) {
		this.context = context;
		this.nonce = nonce;

		// The secret key may be used across credentials supporting different attribute sizes.
		// So we should take it, and hence also its commitment, to fit within the smallest,
		// otherwise we cannot perform the range proof showing that it is not too large.
		fixed = new HashMap<String, BigInteger>();
		fixed.put(ProofBuilder.USER_SECRET_KEY,
		        new BigInteger(new IdemixSystemParameters1024().get_l_m_commit(), new SecureRandom()));
	}

	/**
	 * Add a generic proofbuilder
	 */
	public ProofListBuilder addProof(ProofBuilder builder) {
		builder.generateRandomizers(fixed);
		builders.add(builder);

		return this;
	}

	/**
	 * Add a proof for the specified credential and attributes.
	 */
	public ProofListBuilder addProofD(IdemixCredential credential, List<Integer> disclosed_attributes) {
		ProofDBuilder builder = new ProofDBuilder(credential, disclosed_attributes);

		// TODO: Do we still need these?
		credentials.add(credential);

		addProof(builder);

		return this;
	}

	/**
	 * Add a credential builder for a new credential, from which to construct a proof for the commitment to the secret
	 * key and v_prime for issuing. If the builder does not yet have a secret key, we generate one.
	 */
	public ProofListBuilder addCredentialBuilder(CredentialBuilder builder) {
		if (builder.getSecret() == null) {
			BigInteger sk = getSecretKey();
			if (sk == null) {
				// See comment in constructor
				sk = new BigInteger(new IdemixSystemParameters1024().get_l_m(), new SecureRandom());
			}
			builder.setSecret(sk);
		}

		ProofBuilder pb = new ProofUBuilder(builder);
		return addProof(pb);
	}

	/**
	 * Completes the proofs, and returns a new {@link ProofList} that contains them.
	 * @throws RuntimeException if no proofs have been added yet
	 */
	public ProofList build() {
		List<BigInteger> toHash = new ArrayList<>();
		if (builders.size() == 0) { // Nothing to do? Probably a mistake
			throw new RuntimeException("No proofs have been added, can't build an empty proof collection");
		}

		toHash.add(context);
		for(ProofBuilder builder : builders) {
			Commitments coms = builder.calculateCommitments();
			toHash.addAll(coms.asList());
		}
		toHash.add(nonce);

		BigInteger challenge = Crypto.sha256Hash(Crypto.asn1Encode(toHash));

		ProofList proofs = new ProofList();

		for(ProofBuilder builder : builders) {
			proofs.add(builder.createProof(challenge));
			proofs.addPublicKey(builder.getPublicKey());
		}

		return proofs;
	}

	public BigInteger getContext() {
		return context;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public void setSecretKey(BigInteger secret) {
		this.secret = secret;
	}

	/**
	 * Gets the secret key of one of the credentials or commitments. If no credentials or commitments
	 * have been added yet, returns null.
	 *
	 * TODO: This whole thing with getSecretKey() (and when it is called) seems like
	 * a messy hack to not have to give secret keys to CredentialBuilders in the first
	 * place, seems like this should be solved elsewhere.
	 */
	public BigInteger getSecretKey() {
		if (secret == null) {
			if (credentials != null && credentials.size() > 0)
				secret = credentials.get(0).getAttribute(0);
			//if (proofUcommitments != null && proofUcommitments.size() > 0)
			//	secret = proofUcommitments.get(0).getSecretKey();
		}

		return secret;
	}

	public BigInteger getSecretKeyCommitment() {
		return fixed.get(ProofBuilder.USER_SECRET_KEY);
	}
}
