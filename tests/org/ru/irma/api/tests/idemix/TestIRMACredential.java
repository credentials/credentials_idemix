package org.ru.irma.api.tests.idemix;

import static org.junit.Assert.fail;

import java.io.File;

import javax.smartcardio.CardException;

import net.sourceforge.scuba.smartcards.CardService;

import org.junit.Test;
import org.junit.BeforeClass;

import credentials.Attributes;
import credentials.CredentialsException;
import credentials.idemix.IdemixCredentials;
import credentials.idemix.IdemixPrivateKey;
import credentials.idemix.spec.IdemixIssueSpecification;
import credentials.idemix.spec.IdemixVerifySpecification;
import credentials.idemix.util.CredentialInformation;
import credentials.idemix.util.IssueCredentialInformation;
import credentials.idemix.util.VerifyCredentialInformation;


public class TestIRMACredential {
	@BeforeClass
	public static void initializeInformation() {
		CredentialInformation.setCoreLocation(new File(System
				.getProperty("user.dir")).toURI()
				.resolve("irma_configuration/"));
	}

	@Test
	public void issueRootCredential() throws CardException, CredentialsException {
		IssueCredentialInformation ici = new IssueCredentialInformation("Surfnet", "root");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);
		
		Attributes attributes = getSurfnetAttributes();

		ic.issue(spec, isk, attributes);
	}

	@Test
	public void verifyRootCredential() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"Surfnet", "root", "Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);

		Attributes attr = ic.verify(vspec);
		
		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}

	@Test
	public void issueStudentCredential() throws CardException, CredentialsException {
		IssueCredentialInformation ici = new IssueCredentialInformation("RU", "studentCard");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);
		
		Attributes attributes = getStudentCardAttributes();

		ic.issue(spec, isk, attributes);
	}

	@Test
	public void verifyStudentCredential() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("RU",
				"studentCard", "RU", "studentCardAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);

		Attributes attr = ic.verify(vspec);
		
		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}
	
	@Test
	public void issueAgeCredential() throws CardException, CredentialsException {
		IssueCredentialInformation ici = new IssueCredentialInformation("MijnOverheid", "ageLower");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);
		Attributes attributes = getAgeAttributes();

		ic.issue(spec, isk, attributes);
	}

	@Test
	public void verifyAgeCredential() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid",
				"ageLower", "MijnOverheid", "ageLowerAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);

		Attributes attr = ic.verify(vspec);
		
		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}

    private Attributes getStudentCardAttributes() {
        // Return the attributes that have been revealed during the proof
        Attributes attributes = new Attributes();
        
        System.out.println("Data: " + "Radboud University".getBytes().toString() + " Length: " + "Radboud University".getBytes().length);

		attributes.add("university", "Radboud University".getBytes());
		attributes.add("studentCardNumber", "0812345673".getBytes());
		attributes.add("studentID", "s1234567".getBytes());
		attributes.add("level", "PhD".getBytes());
		
		return attributes;
	}

    private Attributes getSurfnetAttributes() {
        // Return the attributes that have been revealed during the proof
        Attributes attributes = new Attributes();

		attributes.add("userID", "s123456@ru.nl".getBytes());
		attributes.add("securityHash", "DEADBEEF".getBytes());
		
		return attributes;
	}
    
    private Attributes getAgeAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("over12", "yes".getBytes());
		attributes.add("over16", "yes".getBytes());
		attributes.add("over18", "no".getBytes());
		attributes.add("over21", "no".getBytes());
		
		return attributes;
    }
    
}
