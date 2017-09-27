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

package org.irmacard.credentials.idemix.messages;

import org.irmacard.credentials.idemix.proofs.ProofList;
import org.irmacard.credentials.idemix.proofs.ProofU;

import java.math.BigInteger;
import java.util.Map;

/**
 * Encapsulates the messages sent by the receiver to the issuer in the second
 * step of the issuance protocol.
 *
 */
public class IssueCommitmentMessage {
	private ProofU proofU;
	private ProofList combinedProofs;
	private String proofPJwt;
	private Map<String, String> proofPJwts;
	private BigInteger n_2;

	public IssueCommitmentMessage(ProofU proofU, BigInteger n_2) {
		this.proofU = proofU;
		this.n_2 = n_2;
	}

	public IssueCommitmentMessage(ProofList combinedProofs, BigInteger n_2) {
		this.combinedProofs = combinedProofs;
		this.proofU = combinedProofs.getProofU();
		this.n_2 = n_2;
	}

	public IssueCommitmentMessage(ProofList combinedProofs, BigInteger n_2, String proofPJwt) {
		this(combinedProofs, n_2);
		this.proofPJwt = proofPJwt;
	}

	public IssueCommitmentMessage(ProofList combinedProofs, BigInteger n_2, Map<String, String> proofPJwts) {
		this(combinedProofs, n_2);
		this.proofPJwts = proofPJwts;
	}

	public ProofU getCommitmentProof() {
		return proofU;
	}

	public BigInteger getNonce2() {
		return n_2;
	}

	public ProofList getCombinedProofs() {
		return combinedProofs;
	}

	public String getProofPJwt() {
		return proofPJwt;
	}

	public String getProofPJwt(String manager) {
		return proofPJwts.get(manager);
	}
}
