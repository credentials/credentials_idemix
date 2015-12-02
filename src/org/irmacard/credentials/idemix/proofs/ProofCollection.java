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
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

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
 * <p>Construct instances of this class using {@link ProofCollectionBuilder}.</p>
 */
@SuppressWarnings("unused")
public class ProofCollection {
	private List<ProofD> disclosureProofs;
	private ProofU proofU;
	transient private List<IdemixPublicKey> publicKeys;
	transient private IdemixPublicKey proofUPublicKey;

	public ProofCollection(ProofU proofU, List<ProofD> disclosureProofs) {
		this.disclosureProofs = disclosureProofs;
		this.proofU = proofU;
	}

	public ProofCollection(ProofU proofU, List<ProofD> disclosureProofs, List<IdemixPublicKey> publicKeys) {
		this.disclosureProofs = disclosureProofs;
		this.proofU = proofU;
		this.publicKeys = publicKeys;
	}

	/**
	 * Helper function to populate the public key array for the disclosure proof, by extracting the credential id
	 * from the metadata attribute and looking up the corresponding public key for each credential in the
	 * {@link IdemixKeyStore}.
	 */
	public void populatePublicKeyArray() {
		if (disclosureProofs == null || disclosureProofs.size() == 0) {
			return;
		}
		publicKeys = new ArrayList<>(disclosureProofs.size());

		for (ProofD proof : disclosureProofs) {
			short id = Attributes.extractCredentialId(proof.get_a_disclosed().get(1));
			try {
				CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescription(id);
				IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(cd.getIssuerDescription());
				publicKeys.add(pk);
			} catch (InfoException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * Checks if the contained proofs are cryptographically bound with respect to the specified context and nonce.
	 */
	public boolean isBound(BigInteger context, BigInteger nonce) {
		BigInteger challenge, response;

		if (proofU == null && (disclosureProofs == null || disclosureProofs.size() == 0)) {
			return true; // All proofs (i.e. none) are bound to all other proofs (i.e. none)
		}

		if (proofU == null) {
			challenge = disclosureProofs.get(0).get_c();
			response = disclosureProofs.get(0).get_a_responses().get(0);
		} else {
			challenge = proofU.get_c();
			response = proofU.get_s_response();
		}

		if (disclosureProofs != null) {
			for (ProofD proof : disclosureProofs) {
				if (!challenge.equals(proof.get_c()) || !response.equals(proof.get_a_responses().get(0))) {
					return false;
				}
			}
		}

		return challenge.equals(reconstructChallenge(context, nonce));
	}

	/**
	 * Verify the contained disclosure proof. Note that if the proof is valid as separate unbound proof but isBound
	 * is set to true, then this method will return false if the current instance also contains disclosure proofs
	 * @param isBound if the proofs should be bound or not
	 */
	public boolean verifyProofU(BigInteger context, BigInteger nonce, boolean isBound) {
		if (proofU == null) {
			return true;
		}

		IdemixPublicKey pk = getProofUPublicKey();
		if (isBound) {
			BigInteger challenge = reconstructChallenge(context, nonce);
			return proofU.verify(pk, context, nonce, challenge);
		} else {
			return proofU.verify(pk, context, nonce);
		}
	}

	/**
	 * Verify the contained disclosure proofs. Note that if the proofs are valid as separate unbound proofs but isBound
	 * is set to true, then this method will return false.
	 * @param isBound if the proofs should be bound or not
	 */
	public boolean verifyProofDs(BigInteger context, BigInteger nonce, boolean isBound) {
		if (disclosureProofs == null || disclosureProofs.size() == 0) {
			return true;
		}

		if (publicKeys == null || (disclosureProofs.size() != publicKeys.size())) {
			throw new RuntimeException("No public keys to verify the proofs against");
		}

		BigInteger challenge = reconstructChallenge(context, nonce);

		ProofD proof;
		IdemixPublicKey pk;
		for (int i=0; i < disclosureProofs.size(); ++i) {
			proof = disclosureProofs.get(i);
			pk = publicKeys.get(i);
			if (isBound) {
				if (!proof.verify(pk, context, nonce, challenge)) {
					return false;
				}
			} else {
				if (!proof.verify(pk, context, nonce)) {
					return false;
				}
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
		if (proofU == null && (disclosureProofs == null || disclosureProofs.size() == 0)) {
			throw new RuntimeException("ProofCollection contains no proofs, can't verify");
		}

		if (shouldBeBound && !isBound(context, nonce)) {
			return false;
		}

		if (!shouldBeBound)
			shouldBeBound = isBound(context, nonce);

		return verifyProofU(context, nonce, shouldBeBound) && verifyProofDs(context, nonce, shouldBeBound);
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
		ProofD proof;
		IdemixPublicKey pk;
		List<BigInteger> toHash = new ArrayList<>(2*disclosureProofs.size() + 2);

		toHash.add(context);
		if (disclosureProofs != null) {
			for (int i = 0; i < disclosureProofs.size(); ++i) {
				proof = disclosureProofs.get(i);
				pk = publicKeys.get(i);
				toHash.add(proof.getA());
				toHash.add(proof.reconstructZ(pk));
			}
		}
		if (proofU != null) {
			pk = proofUPublicKey;
			toHash.add(proofU.getU());
			toHash.add(proofU.reconstructU_commit(pk));
		}
		toHash.add(nonce);

		BigInteger[] toHashArray = toHash.toArray(new BigInteger[toHash.size()]);
		return Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));
	}

	public ProofU getProofU() {
		return proofU;
	}

	public ProofD getProofD(int i) {
		return disclosureProofs.get(i);
	}

	public int getProofDcount() {
		return disclosureProofs.size();
	}

	public IdemixPublicKey getProofUPublicKey() {
		return proofUPublicKey;
	}

	public void setProofUPublicKey(IdemixPublicKey pk) {
		this.proofUPublicKey = pk;
	}

	public void setProofDPublicKeys(List<IdemixPublicKey> keys) {
		this.publicKeys = keys;
	}
}
