/**
 * VerifyCredentialInformation.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, September 2012.
 */

package org.irmacard.credentials.idemix.util;

import java.net.URI;
import java.net.URISyntaxException;

import org.irmacard.credentials.idemix.spec.IdemixVerifySpecification;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.VerificationDescription;

public class VerifyCredentialInformation extends CredentialInformation {
	private URI proofSpecLocation;
	private URI verifierBaseLocation;

	private String verifier;
	private String verificationID;

	public VerifyCredentialInformation(String issuer, String credName,
			String verifier, String verifySpecName) {
		super(issuer, credName);
		completeVerifierSetup(verifier, verifySpecName);
	}

	public VerifyCredentialInformation(String verifier, String verificationID) throws InfoException {
		super(DescriptionStore.getInstance().getVerificationDescriptionByName(verifier, verificationID).getCredentialDescription());
		completeVerifierSetup(verifier, verificationID);
	}
	
	private void completeVerifierSetup(String verifier, String verificationID) {
		this.verifier = verifier;
		this.verificationID = verificationID;

		try {
			verifierBaseLocation = new URI(verifier + "/");
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		proofSpecLocation = verifierBaseLocation.resolve("Verifies/"
				+ verificationID + "/specification.xml");
	}

	public IdemixVerifySpecification getIdemixVerifySpecification() {
		try {
			VerificationDescription vd = DescriptionStore.getInstance()
					.getVerificationDescriptionByName(verifier, verificationID);
			init(proofSpecLocation,
					IdemixVerificationStructureCreator
							.createProofSpecification(vd));
		} catch (InfoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		return IdemixVerifySpecification.fromIdemixProofSpec(proofSpecLocation, credNr);
	}
}
