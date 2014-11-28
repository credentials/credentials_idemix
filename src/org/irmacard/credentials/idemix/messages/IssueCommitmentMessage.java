package org.irmacard.credentials.idemix.messages;

import java.math.BigInteger;

import org.irmacard.credentials.idemix.proofs.ProofU;

public class IssueCommitmentMessage {
	private BigInteger U;
	private ProofU proofU;
	private BigInteger n_2;

	public IssueCommitmentMessage(BigInteger U, ProofU proofU, BigInteger n_2) {
		this.U = U;
		this.proofU = proofU;
		this.n_2 = n_2;
	}

	public BigInteger getCommitment() {
		return U;
	}

	public ProofU getCommitmentProof() {
		return proofU;
	}

	public BigInteger getNonce2() {
		return n_2;
	}
}
