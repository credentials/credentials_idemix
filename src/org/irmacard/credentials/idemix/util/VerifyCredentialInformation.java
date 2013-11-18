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

	private VerificationDescription vd;

	public VerifyCredentialInformation(String verifier, String verificationID) throws InfoException {
		super(DescriptionStore.getInstance().getVerificationDescriptionByName(verifier, verificationID).getCredentialDescription());
		vd = DescriptionStore.getInstance().getVerificationDescriptionByName(verifier, verificationID);
		completeVerifierSetup();
	}
	
	private void completeVerifierSetup() {
		try {
			verifierBaseLocation = new URI(vd.getVerifierID() + "/");
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		proofSpecLocation = verifierBaseLocation.resolve("Verifies/"
				+ vd.getVerificationID() + "/specification.xml");
	}

	public IdemixVerifySpecification getIdemixVerifySpecification() {
		init(proofSpecLocation,
				IdemixVerificationStructureCreator.createProofSpecification(vd));
		return IdemixVerifySpecification.fromIdemixProofSpec(proofSpecLocation, credNr);
	}
}
