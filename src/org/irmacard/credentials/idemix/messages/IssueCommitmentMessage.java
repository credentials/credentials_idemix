/**
 * IssueCommitmentMessage.java
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

package org.irmacard.credentials.idemix.messages;

import java.math.BigInteger;

import org.irmacard.credentials.idemix.proofs.ProofU;

/**
 * Encapsulates the messages sent by the receiver to the issuer in the second
 * step of the issuance protocol.
 *
 */
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
