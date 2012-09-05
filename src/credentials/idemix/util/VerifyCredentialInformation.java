package credentials.idemix.util;

import java.net.URI;

import credentials.idemix.spec.IdemixVerifySpecification;

public class VerifyCredentialInformation extends CredentialInformation {
	private URI proofSpecLocation;
	private URI verifierBaseLocation;
	
	public VerifyCredentialInformation(String issuer, String credName,
			String verifier, String verifySpecName) {
		super(issuer, credName);
	
		verifierBaseLocation = CORE_LOCATION.resolve(verifier + "/");
		proofSpecLocation = verifierBaseLocation.resolve("Verifies/"
				+ verifySpecName + "/specification.xml");
	}
	
	public IdemixVerifySpecification getIdemixVerifySpecification() {
		return IdemixVerifySpecification.fromIdemixProofSpec(proofSpecLocation, credNr);
	}
}
