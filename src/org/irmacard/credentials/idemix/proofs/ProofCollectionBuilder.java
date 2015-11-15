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

import org.irmacard.credentials.idemix.IdemixCredential;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSystemParameters;
import org.irmacard.credentials.idemix.util.Crypto;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ProofCollectionBuilder {
	private BigInteger context;
	private BigInteger nonce;

	private List<IdemixCredential> credentials = new ArrayList<>();
	private List<IdemixPublicKey> publicKeys = new ArrayList<>();
	private List<BigInteger> toHash = new ArrayList<>();
	private List<IdemixCredential.Commitment> commitments = new ArrayList<>();

	private BigInteger skCommitment;

	public ProofCollectionBuilder(BigInteger context, BigInteger nonce) {
		this.context = context;
		this.nonce = nonce;
		this.skCommitment = new BigInteger(new IdemixSystemParameters().l_m_commit, new Random());

		toHash.add(context);
	}

	public ProofCollectionBuilder addProofD(IdemixCredential credential, List<Integer> disclosed_attributes) {
		IdemixCredential.Commitment commitment = credential.commit(disclosed_attributes, context, nonce, skCommitment);

		credentials.add(credential);
		commitments.add(commitment);
		toHash.add(commitment.getA());
		toHash.add(commitment.getZ());

		return this;
	}

	public ProofCollection build() {
		toHash.add(nonce);

		BigInteger[] toHashArray = toHash.toArray(new BigInteger[toHash.size()]);
		BigInteger challenge = Crypto.sha256Hash(Crypto.asn1Encode(toHashArray));

		List<ProofD> disclosureProofs = new ArrayList<>(credentials.size());
		for (int i = 0; i < credentials.size(); ++i) {
			disclosureProofs.add(commitments.get(i).createProof(challenge));
			publicKeys.add(credentials.get(i).getPublicKey());
		}

		return new ProofCollection(null, disclosureProofs, publicKeys);
	}
}
