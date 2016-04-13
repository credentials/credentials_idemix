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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.util.Crypto;

/**
 * <p>A collection of proofs of knowledge, for one or more disclosure proofs, or for the commitment to the private key
 * in the issuing protocol. The proofs can be cryptographically bound over the secret key; see the
 * {@link #isBound(BigInteger, BigInteger)} method.</p>
 *
 * <p>Generally, two proofs are cryptographically bound if
 * <ol>
 *     <li>The hash is over the commitments to randomness of all proofs, as well as the elements of which
 *     representations are being proved (together with the nonce and context as usual);</li>
 *     <li>The response for the secret key is the same of all proofs.</li>
 * </ol>
 * </p>
 *
 * <p>Construct instances of this class using {@link ProofListBuilder}. Currently it only supports having a single
 * {@link ProofU}.</p>
 */
@SuppressWarnings("unused")
public class ProofList extends ArrayList<Proof> {
	private static final long serialVersionUID = -5986732073253740851L;

	transient private List<IdemixPublicKey> publicKeys = new ArrayList<>();

	/**
	 * Helper function to populate the public key array for the disclosure proofs, by extracting the credential id
	 * from the metadata attribute and looking up the corresponding public key for each credential in the
	 * {@link IdemixKeyStore}.
	 */
	public void populatePublicKeyArray() {
		if (size() == 0) {
			return;
		}

		publicKeys = new ArrayList<>(size());

		for (Proof proof : this)
			// If the proof is a proofU then .extractPublicKey() returns null, so not all publicKeys will have
			// non-null entries.
			publicKeys.add(proof.extractPublicKey());
	}

	/**
	 * Checks if the contained proofs are cryptographically bound with respect to the specified context and nonce.
	 */
	public boolean isBound(BigInteger context, BigInteger nonce) {
		BigInteger challenge, response;

		if (size() == 0)
			return true; // All proofs (i.e. none) are bound to all other proofs (i.e. none)

		challenge = get(0).get_c();
		response = get(0).getSecretKeyResponse();

		for (Proof proof : this) {
			if (!challenge.equals(proof.get_c()) || !response.equals(proof.getSecretKeyResponse()))
				return false;
		}

		return challenge.equals(reconstructChallenge(context, nonce));
	}

	/**
	 * Checks the validity of all contained proofs. If they must be bound then they are considered valid only if they
	 * are. However, if they need not be bound but the hashes and secret-key-responses indicate that they are, then
	 * they will still be considered valid only if they are valid as bound proofs.
	 * @throws RuntimeException if the collection contains no proofs
	 */
	public boolean verify(BigInteger context, BigInteger nonce, boolean shouldBeBound) {
		if (size() == 0)
			return true;

		if (publicKeys == null || (size() != publicKeys.size()))
			throw new RuntimeException("No public keys to verify the proofs against");

		if (shouldBeBound && !isBound(context, nonce)) {
			return false;
		}

		Proof proof;
		IdemixPublicKey pk;

		BigInteger challenge = null;
		boolean bounded = isBound(context, nonce);
		if (bounded) {
			challenge = reconstructChallenge(context, nonce);
		}

		for (int i=0; i < size(); ++i) {
			proof = get(i);
			pk = publicKeys.get(i);
			if (pk == null)
				throw new RuntimeException("Missing public key for proof " + i + " of " + size());

			if (bounded) {
				if (!proof.verify(pk, context, nonce, challenge))
					return false;
			} else {
				if (!proof.verify(pk, context, nonce))
					return false;
			}
		}

		return true;
	}

	/**
	 * <p>Reconstruct the challenge that should have been used in the proofs if they had been cryptographically bound,
	 * based on the commitments and group elements of which knowledge is being proved (along with the context and
	 * nonce). The challenge is the hash over the following elements:
	 * <ul>
	 *     <li>the context,</li>
	 *     <li>A and Z (the commitment, not the element from the Idemix public key) for each disclosure proof,</li>
	 *     <li>U and U_commit for the proofU,</li>
	 *     <li>the nonce.</li>
	 * </ul>
	 * When the instance contains only one disclosure proof, or only the proofU, this method thus returns what would
	 * otherwise have been used as the challenge.</p>
	 */
	private BigInteger reconstructChallenge(BigInteger context, BigInteger nonce) {
		Proof proof;
		IdemixPublicKey pk;
		List<BigInteger> toHash = new ArrayList<>(2*size() + 2);

		toHash.add(context);
		for (int i = 0; i < size(); ++i) {
			proof = get(i);
			pk = publicKeys.get(i);
			toHash.addAll(proof.getChallengeContribution(pk));
		}
		toHash.add(nonce);

		BigInteger[] toHashArray = toHash.toArray(new BigInteger[toHash.size()]);
		return Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));
	}

	/**
	 * Get the i-th {@link ProofU} in this proof list.
	 */
	public ProofU getProofU(int i) {
		int seen = 0;

		for (Proof proof : this) {
			if (proof instanceof ProofU) {
				if (seen == i)
					return (ProofU) proof;
				seen++;
			}
		}

		return null;
	}

	/**
	 * Get the first {@link ProofU} in this proof list.
	 */
	public ProofU getProofU() {
		return getProofU(0);
	}

	public List<IdemixPublicKey> getPublicKeys() {
		return publicKeys;
	}

	public void setPublicKeys(List<IdemixPublicKey> publicKeys) {
		this.publicKeys = publicKeys;
	}

	public IdemixPublicKey getPublicKey(int i) {
		return publicKeys.get(i);
	}

	public void addPublicKey(IdemixPublicKey pk) {
		publicKeys.add(pk);
	}

	public void setPublicKey(int i, IdemixPublicKey pk) {
		publicKeys.set(i, pk);
	}

	public int getProofDCount() {
		int i = 0;
		for (Proof proof : this)
			if (proof instanceof ProofD)
				++i;

		return i;
	}
}
