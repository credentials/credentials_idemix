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
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.AttributeIdentifier;
import org.irmacard.credentials.info.CredentialIdentifier;
import org.irmacard.credentials.info.KeyException;
import org.irmacard.credentials.info.SchemeManager;

import java.math.BigInteger;
import java.util.*;

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

	// Boolean to indicate that we have a signature instead of disclosure proof,
	// used to retain backwards compatibility (defaulting to DisclosureProof)
	transient private boolean isSig = false;

	public ProofList() {}

	public ProofList(boolean isSig) {
		this.isSig = isSig;
	}

	/**
	 * Helper function to populate the public key array for the disclosure proofs, by extracting the credential id
	 * from the metadata attribute and looking up the corresponding public key for each credential in the
	 * {@link IdemixKeyStore}.
	 */
	public void populatePublicKeyArray() throws KeyException {
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
		if (size() == 0)
			return true; // All proofs (i.e. none) are bound to all other proofs (i.e. none)

		BigInteger challenge = reconstructChallenge(context, nonce);
		HashMap<String, BigInteger> responses = new HashMap<>();

		for (int i=0; i < size(); ++i) {
			if (!challenge.equals(get(i).get_c()))
				return false;

			// If the secret key comes from a credential whose scheme manager has a keyshare server,
			// then the secretkey = userpart + keysharepart.
			// So, we can only expect two secret key responses to be equal if their credentials
			// are both associated to either no keyshare server, or the same keyshare server.
			SchemeManager manager = publicKeys.get(i).getIssuerIdentifier().getSchemeManager();
			String managerName = manager == null || !manager.hasKeyshareServer() ? "" : manager.getName();
			if (!responses.containsKey(managerName)) {
				// First response from this keyshare server that we're checking
				responses.put(managerName, get(i).getSecretKeyResponse());
			} else {
				if (!responses.get(managerName).equals(get(i).getSecretKeyResponse()))
					return false;
			}
		}

		return true;
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

		boolean isBound = isBound(context, nonce);
		if (shouldBeBound && !isBound) {
			return false;
		}

		Proof proof;
		IdemixPublicKey pk;
		BigInteger challenge = null;
		if (isBound)
			challenge = reconstructChallenge(context, nonce);

		for (int i=0; i < size(); ++i) {
			proof = get(i);
			pk = publicKeys.get(i);
			if (pk == null)
				throw new RuntimeException("Missing public key for proof " + i + " of " + size());

			if (isBound) {
				if (!proof.verify(pk, context, nonce, challenge))
					return false;
			} else {
				if (!proof.verify(pk, context, nonce))
					return false;
			}
		}

		return true;
	}

	public boolean isValid() {
		return isValidOn(Calendar.getInstance().getTime());
	}

	/**
	 * @return true only if all containing {@link ProofD}'s are valid on the specified date.
	 */
	public boolean isValidOn(Date date) {
		try {
			for (Proof proof : this) {
				if (!(proof instanceof ProofD))
					continue;

				// This throws an IllegalArgumentException if the metadata attribute is missing or the cred type is unknown
				Attributes disclosed = new Attributes(((ProofD) proof).getDisclosedAttributes());
				if (!disclosed.isValidOn(date))
					return false;
			}

			return true;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Returns all attributes contained in the disclosure proofs. Also checks the validity date
	 * of the metadata attribute of each disclosure proof. NOTE: this does not check the validity
	 * of the containing proofs! Use {@link #verify(BigInteger, BigInteger, boolean)} for that.
	 * @throws IllegalArgumentException If one of the proofs has no metadata attribute,
	 *                                  or is from an unknown credential type
	 */
	public HashMap<AttributeIdentifier, String> getAttributes() {
		HashMap<AttributeIdentifier, String> attributes = new HashMap<>();

		for (Proof proof : this) {
			if (!(proof instanceof ProofD))
				continue;

			// This throws an IllegalArgumentException if the metadata attribute is missing or the cred type is unknown
			Attributes disclosed = new Attributes(((ProofD) proof).getDisclosedAttributes());
			CredentialIdentifier credId = disclosed.getCredentialIdentifier();

			// For each of the disclosed attributes in this proof, see if they satisfy one of
			// the AttributeDisjunctions that we asked for
			for (String attributeName : disclosed.getIdentifiers()) {
				AttributeIdentifier identifier;
				String value;
				if (!attributeName.equals(Attributes.META_DATA_FIELD)) {
					identifier = new AttributeIdentifier(credId, attributeName);
					value = new String(disclosed.get(attributeName));
				} else {
					identifier = new AttributeIdentifier(credId.toString());
					value = "present";
				}

				attributes.put(identifier, value);
			}
		}

		return attributes;
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
		if (isSig) {
			return Crypto.sha256Hash(Crypto.asn1SigEncode(toHashArray));
		} else {
			return Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));
		}
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

	/**
	 * Set isSig to true to indicate that this is an IRMA signature instead of disclosure proof
	 */
	public void setSig(boolean sig) {
		isSig = sig;
	}

	/**
	 * Check whether this ProofList indicates an IRMA signature
	 */
	public boolean isSig() {
		return isSig;
	}

	public int getProofDCount() {
		int i = 0;
		for (Proof proof : this)
			if (proof instanceof ProofD)
				++i;

		return i;
	}
}
