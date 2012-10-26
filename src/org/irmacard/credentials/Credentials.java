/**
 * Credentials.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012,
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package org.irmacard.credentials;

import java.util.Date;
import java.util.List;

import org.irmacard.credentials.Nonce;
import org.irmacard.credentials.keys.PrivateKey;
import org.irmacard.credentials.spec.IssueSpecification;
import org.irmacard.credentials.spec.VerifySpecification;


import service.ProtocolCommand;
import service.ProtocolResponses;

/**
 * A generic interface for interaction with a credentials system, abstracting
 * from the low-level credential technology specifics.
 */
public interface Credentials {

	/**
	 * Issue a credential to the user according to the provided specification
	 * containing the specified values.
	 * 
	 * @param specification
	 *            of the issuer and the credential to be issued.
	 * @param secretkey
	 * 			  of the issuer, to be used when issueing credential.
	 * @param values
	 *            to be stored in the credential.
	 * @throws CredentialsException
	 *             if the issuance process fails.
	 */
	public void issue(IssueSpecification specification, PrivateKey pkey, Attributes values, Date expires)
			throws CredentialsException;

	/**
	 * Get a blank IssueSpecification matching this Credentials provider.
	 * TODO: WL: would suggest to remove this.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public IssueSpecification issueSpecification();

	/**
	 * Verify a number of attributes listed in the specification.
	 * 
	 * @param specification
	 *            of the credential and attributes to be verified.
	 * @return the attributes disclosed during the verification process or null
	 *         if verification failed
	 * @throws CredentialsException
	 */
	public Attributes verify(VerifySpecification specification)
			throws CredentialsException;

	/**
	 * Returns the ProtocolCommands necessary to request a proof from the card.
	 * This is a lower-level entry-point to the API, that allows the user to
	 * process the resulting APDU commands using a separate, possibly
	 * asynchronous interface.
	 *
	 * @param specification
	 *            specification of the credential and attributes to be verified.
	 * @param nonce The nonce used as part of the challenge
	 * @return
	 * @throws CredentialsException
	 */
	public List<ProtocolCommand> requestProofCommands(
			VerifySpecification specification, Nonce nonce) throws CredentialsException;

	/**
	 * Compile the cards responses into a proof and check this proof for correctness.
	 * This is a lower-level entry-point to the API, that allows the user to
	 * process the resulting APDU commands using a separate, possibly
	 * asynchronous interface.
	 *
	 * @param specification
	 *            specification of the credential and attributes to be verified.
	 * @param nonce The nonce used when requesting the proof commands
	 * @param responses The responses to the proof requests
	 * @return the attributes disclosed during the verification process or null
	 *         if verification failed
	 * @throws CredentialsException
	 */
	public Attributes verifyProofResponses(VerifySpecification specification,
			Nonce nonce, ProtocolResponses responses) throws CredentialsException;

	/**
	 * Generate a nonce for use in the asynchronous API. This nonce contains all the
	 * randomness required in the proof run, and hence acts as an explicit state.
	 *
	 * @return The nonce
	 * @throws CredentialsException
	 */
	public Nonce generateNonce(VerifySpecification specification)
			throws CredentialsException;

	/**
	 * Get a blank VerifySpecification matching this Credentials provider.
	 * TODO: WL: Would suggest to remove this.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public VerifySpecification verifySpecification();

}