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
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
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
	private List<BigInteger> toHash = new ArrayList<>();
	private List<BigInteger> toHashU = new ArrayList<>();
	private List<IdemixCredential.Commitment> commitments = new ArrayList<>();
	private List<CredentialBuilder.Commitment> proofUcommitments = new ArrayList<>();

	private BigInteger secret;
	private BigInteger skCommitment;

	public ProofListBuilder(BigInteger context, BigInteger nonce) {
		this.context = context;
		this.nonce = nonce;
		this.skCommitment = new BigInteger(new IdemixSystemParameters().l_m_commit, new Random());

		toHash.add(context);
	}

	/**
	 * Add a proof for the specified credential and attributes.
	 */
	public ProofListBuilder addProofD(IdemixCredential credential, List<Integer> disclosed_attributes) {
		IdemixCredential.Commitment commitment = credential.commit(disclosed_attributes, context, nonce, skCommitment);

		credentials.add(credential);
		commitments.add(commitment);
		toHash.add(commitment.getA());
		toHash.add(commitment.getZ());

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
				sk = new BigInteger(builder.getPublicKey().getSystemParameters().l_m, new SecureRandom());
			}
			builder.setSecret(sk);
		}

		return addProofU(builder.commit(nonce, skCommitment));
	}

	/**
	 * Add a proof for the commitment to the secret key and v_prime for issuing.
	 */
	private ProofListBuilder addProofU(CredentialBuilder.Commitment commitment) {
		this.proofUcommitments.add(commitment);
		toHashU.add(commitment.getU());
		toHashU.add(commitment.getUcommit());

		return this;
	}

	/**
	 * Completes the proofs, and returns a new {@link ProofList} that contains them.
	 * @throws RuntimeException if no proofs have been added yet
	 */
	public ProofList build() {
		if (proofUcommitments.size() == 0 && credentials.size() == 0) { // Nothing to do? Probably a mistake
			throw new RuntimeException("No proofs have been added, can't build an empty proof collection");
		}

		toHash.addAll(toHashU);
		toHash.add(nonce);
		BigInteger[] toHashArray = toHash.toArray(new BigInteger[toHash.size()]);

		BigInteger challenge = Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));

		ProofList proofs = new ProofList();

		for (int i = 0; i < credentials.size(); ++i) {
			proofs.add(commitments.get(i).createProof(challenge));
			proofs.addPublicKey(credentials.get(i).getPublicKey());
		}

		for (CredentialBuilder.Commitment commitment : proofUcommitments) {
			proofs.add(commitment.createProof(challenge));
			proofs.addPublicKey(commitment.getPublicKey());
		}

		return proofs;
	}

	public BigInteger getContext() {
		return context;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	/**
	 * Gets the secret key of one of the credentials or commitments. If no credentials or commitments
	 * have been added yet, returns null.
	 */
	public BigInteger getSecretKey() {
		if (secret == null) {
			if (credentials != null && credentials.size() > 0)
				secret = credentials.get(0).getAttribute(0);
			if (proofUcommitments != null && proofUcommitments.size() > 0)
				secret = proofUcommitments.get(0).getSecretKey();
		}

		return secret;
	}

	public BigInteger getSecretKeyCommitment() {
		return skCommitment;
	}
}
