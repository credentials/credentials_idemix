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

import org.irmacard.credentials.idemix.CLSignature;
import org.irmacard.credentials.idemix.proofs.ProofS;

/**
 * Encapsulates the messages send from the issuer to the receiver in the
 * final step of the issuance protocol.
 *
 */
public class IssueSignatureMessage {
	private CLSignature signature;
	private ProofS proof;

	public IssueSignatureMessage(CLSignature signature, ProofS proof) {
		this.signature = signature;
		this.proof = proof;
	}

	public IssueSignatureMessage() {
		signature = new CLSignature();
		proof = new ProofS();
	}

	public CLSignature getSignature() {
		return signature;
	}

	public ProofS getProofS() {
		return proof;
	}
}
