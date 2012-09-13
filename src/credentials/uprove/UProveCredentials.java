/**
 * UProveCredentials.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, August 2012.
 */

package credentials.uprove;

import java.io.IOException;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import com.microsoft.uprove.InvalidProofException;
import com.microsoft.uprove.Issuer;
import com.microsoft.uprove.PresentationProof;
import com.microsoft.uprove.PresentationProtocol;
import com.microsoft.uprove.UProveToken;

import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.TerminalCardService;
import service.ProtocolCommand;
import service.ProtocolResponses;
import service.UProveService;
import credentials.Attributes;
import credentials.Credentials;
import credentials.CredentialsException;
import credentials.Nonce;
import credentials.keys.PrivateKey;
import credentials.spec.IssueSpecification;
import credentials.spec.VerifySpecification;
import credentials.uprove.spec.UProveIssueSpecification;
import credentials.uprove.spec.UProveVerifySpecification;

/**
 * A U-Prove specific implementation of the credentials interface.
 */
public class UProveCredentials implements Credentials {

	private UProveService service;

	public UProveCredentials() 
	throws CredentialsException {
		try {
	    	// TODO: implement a better solution to connect to the card 
			CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);
	        service = new UProveService(new TerminalCardService(terminal));
		} catch (CardException e) {
        	throw new CredentialsException("Failed to initialise the service");
		}
	}

	/**
	 * Issue a credential to the user according to the provided specification
	 * containing the specified values.
	 * 
	 * TODO: WL: actually use the private key
	 * 
	 * @param specification of the issuer and the credential to be issued.
	 * @param values to be stored in the credential.
	 * @throws CredentialsException if the issuance process fails.
	 */
	public void issue(IssueSpecification specification, PrivateKey pkey, Attributes values)
	throws CredentialsException {
		if (!(specification instanceof UProveIssueSpecification)) {
			throw new CredentialsException(
					"specification is not an UProveIssueSpecification");
		}
		UProveIssueSpecification spec = (UProveIssueSpecification) specification;

		// Initialise the issuer
		Issuer issuer;
		try {
			issuer = spec.getIssuerProtocolParameters().generate();
		} catch (IllegalStateException e) {
			throw new CredentialsException(
					"issuer generation failed");
		} catch (IOException e) {
			throw new CredentialsException(
					"issuer generation failed");
		}

		// Initialise the prover
        try {
			service.open();
			service.testMode((byte) 0x00);
			service.testMode((byte) 0x02);
			service.setProverProtocolParameters(spec.getProverProtocolParameters());
		} catch (CardServiceException e1) {
			throw new CredentialsException("Failed to issue the credential (SCUBA)");
		}

        // Issue the credential
		try {
			service.precomputation();
		} catch (IOException e) {
			throw new CredentialsException("Failed to issue the credential (0)");
		}
        byte[][] message1;
		try {
			message1 = issuer.generateFirstMessage();
		} catch (IOException e) {
			throw new CredentialsException("Failed to issue the credential (1)");
		}
        byte[][] message2;
		try {
			message2 = service.generateSecondMessage(message1);
		} catch (IOException e) {
			throw new CredentialsException("Failed to issue the credential (2)");
		}
        byte[][] message3;
		try {
			message3 = issuer.generateThirdMessage(message2);
		} catch (IOException e) {
			throw new CredentialsException("Failed to issue the credential (3)");
		}
        try {
			service.generateTokens(message3);
		} catch (IOException e) {
			throw new CredentialsException("Failed to issue the credential (4)");
		}
	}

	/**
	 * Get a blank IssueSpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public IssueSpecification issueSpecification() {
		return new UProveIssueSpecification();
	}
	
	/**
	 * Verify a number of attributes listed in the specification. 
	 * 
	 * @param specification of the credential and attributes to be verified.
	 * @return the attributes disclosed during the verification process.
	 * @throws CredentialsException if the verification process fails.
	 */
	public Attributes verify(VerifySpecification specification)
	throws CredentialsException {
		if (!(specification instanceof UProveVerifySpecification)) {
			throw new CredentialsException(
					"specification is not an UProveVerifySpecification");
		}
		UProveVerifySpecification spec = (UProveVerifySpecification) specification;
		
        PresentationProof proof;
		try {
			proof = service.generateProof(
					spec.getDisclosed(), spec.getMessage());
		} catch (CardServiceException e) {
			throw new CredentialsException("Failed to generate the proof");
		}

        // prover transmits the U-Prove token and presentation proof to the verifier 
        UProveToken token;
		try {
			token = service.getUProveToken();
		} catch (CardServiceException e) {
			throw new CredentialsException("Failed to get the token");
		}

        // verifier verifies the presentation proof
        try {
			PresentationProtocol.verifyPresentationProof(
					spec.getIssuerParameters(), spec.getDisclosed(), spec.getMessage(), null, token, proof);
		} catch (InvalidProofException e) {
        	throw new CredentialsException("Failed to verify the attributes (invalid proof)");
		} catch (IOException e) {
        	throw new CredentialsException("Failed to verify the attributes (proof verification failed)");
		}
        
        // Return the attributes that have been revealed during the proof        
        Attributes attributes = new Attributes();
        byte[][] values = proof.getDisclosedAttributes();
        for (int i = 0; i < values.length; i++) {
    		// TODO: Fix attribute identifiers
        	attributes.add(Integer.toString(i), values[i]);
        }

		return attributes;
	}
	
	/**
	 * Get a blank VerifySpecification matching this Credentials provider.
	 * 
	 * @return a blank specification matching this provider.
	 */
	public VerifySpecification verifySpecification() {
		return new UProveVerifySpecification();
	}

	@Override
	public List<ProtocolCommand> requestProofCommands(
			VerifySpecification specification, Nonce nonce) {
	// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attributes verifyProofResponses(VerifySpecification specification,
			Nonce nonce, ProtocolResponses responses)
			throws CredentialsException {
	// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Nonce generateNonce(VerifySpecification specification)
			throws CredentialsException {
		// TODO Auto-generated method stub
		return null;
	}
}
