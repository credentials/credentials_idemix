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

public class ProofCollection {
	private List<ProofD> disclosureProofs;
	transient private List<IdemixPublicKey> publicKeys;

	public ProofCollection(ProofU proofU, List<ProofD> disclosureProofs) {
		this.disclosureProofs = disclosureProofs;
		populatePublicKeyArray();
	}

	public ProofCollection(ProofU proofU, List<ProofD> disclosureProofs, List<IdemixPublicKey> publicKeys) {
		this.disclosureProofs = disclosureProofs;
		this.publicKeys = publicKeys;
	}

	public void populatePublicKeyArray() {
		if (disclosureProofs == null || disclosureProofs.size() == 0) {
			return;
		}
		publicKeys = new ArrayList<>(disclosureProofs.size());

		for (ProofD proof : disclosureProofs) {
			Attributes attrs = new Attributes();
			attrs.add(Attributes.META_DATA_FIELD, proof.get_a_disclosed().get(1).toByteArray());
			short id = attrs.getCredentialID();
			try {
				CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescription(id);
				IdemixPublicKey pk = IdemixKeyStore.getInstance().getPublicKey(cd.getIssuerDescription());
				publicKeys.add(pk);
			} catch (InfoException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public boolean verify(BigInteger context, BigInteger nonce, boolean shouldBeBound) {
		if (disclosureProofs == null || disclosureProofs.size() == 0) {
			return false;
		}

		if (shouldBeBound && !isBound()) {
			return false;
		}

		if (disclosureProofs.size() != publicKeys.size()) {
			populatePublicKeyArray();
		}

		BigInteger challenge = reconstructChallenge(context, nonce);

		ProofD proof;
		IdemixPublicKey pk;
		for (int i=0; i < disclosureProofs.size(); ++i) {
			proof = disclosureProofs.get(i);
			pk = publicKeys.get(i);
			if (!proof.verify(pk, context, nonce, challenge)) {
				return false;
			}
		}

		return true;
	}

	private BigInteger reconstructChallenge(BigInteger context, BigInteger nonce) {
		ProofD proof;
		IdemixPublicKey pk;
		List<BigInteger> toHash = new ArrayList<>(2*disclosureProofs.size() + 2);

		toHash.add(context);
		for (int i=0; i < disclosureProofs.size(); ++i) {
			proof = disclosureProofs.get(i);
			pk = publicKeys.get(i);
			toHash.add(proof.getA());
			toHash.add(proof.reconstructZ(pk));
		}
		toHash.add(nonce);

		BigInteger[] toHashArray = toHash.toArray(new BigInteger[toHash.size()]);
		return Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));
	}

	public boolean isBound() {
		BigInteger challenge = disclosureProofs.get(0).get_c();
		BigInteger response = disclosureProofs.get(0).get_a_responses().get(0);

		for (ProofD proof : disclosureProofs) {
			if (!challenge.equals(proof.get_c()) || !response.equals(proof.get_a_responses().get(0))) {
				return false;
			}
		}

		return true;
	}
}
