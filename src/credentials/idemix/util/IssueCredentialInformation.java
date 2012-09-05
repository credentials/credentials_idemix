package credentials.idemix.util;

import java.net.URI;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.key.IssuerKeyPair;

import credentials.Attributes;
import credentials.idemix.IdemixPrivateKey;
import credentials.idemix.spec.IdemixIssueSpecification;

public class IssueCredentialInformation extends CredentialInformation {
	URI issuerSKLocation;
	
	public IssueCredentialInformation(String issuer, String credName) {
		super(issuer, credName);

		issuerSKLocation = baseLocation.resolve("private/isk.xml");
		System.out.println("HELLO: set issuerSKLoc to: " + issuerSKLocation.toString());

		setupIssuer();
	}
	
	public IdemixIssueSpecification getIdemixIssueSpecification() {
		return IdemixIssueSpecification.fromIdemixIssuanceSpec(
				issuerPKLocation, credStructID, credNr);
	}
	
	public IdemixPrivateKey getIdemixPrivateKey() {
		IssuerKeyPair ikp = (IssuerKeyPair) Locations.init(issuerSKLocation);
		return new IdemixPrivateKey(ikp.getPrivateKey());
	}
	
    public void setupIssuer() {
    	Locations.initIssuer(baseLocation, issuerBaseID.toString(),
    			issuerSKLocation, issuerPKLocation, issuerBaseID.resolve("ipk.xml"));
    }
    
    public Issuer getIssuer(Attributes attributes) {
		return new Issuer(getIdemixPrivateKey().getIssuerKeyPair(),
				getIdemixIssueSpecification().getIssuanceSpec(), null, null,
				getIdemixIssueSpecification().getValues(attributes));
	}
}
