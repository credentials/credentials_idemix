/**
 * TestIRMACredential.java
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


package org.irmacard.credentials.idemix.test;

import static org.junit.Assert.fail;

import java.io.File;
import java.net.URI;

import javax.smartcardio.CardException;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixCredentials;
import org.irmacard.credentials.idemix.IdemixPrivateKey;
import org.irmacard.credentials.idemix.spec.IdemixIssueSpecification;
import org.irmacard.credentials.idemix.spec.IdemixVerifySpecification;
import org.irmacard.credentials.idemix.util.CredentialInformation;
import org.irmacard.credentials.idemix.util.IssueCredentialInformation;
import org.irmacard.credentials.idemix.util.VerifyCredentialInformation;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.idemix.IdemixService;
import org.junit.BeforeClass;
import org.junit.Test;


public class TestIRMACredential {
	@BeforeClass
	public static void initializeInformation() throws InfoException {
		URI core = new File(System
				.getProperty("user.dir")).toURI()
				.resolve("irma_configuration/");
		CredentialInformation.setCoreLocation(core);
		DescriptionStore.setCoreLocation(core);
		DescriptionStore.getInstance();
	}

	@Test
	public void generateMasterSecret() throws CardException, CardServiceException {
		IdemixService is = new IdemixService(TestSetup.getCardService());
		is.open();
		try {
		is.generateMasterSecret();
		} catch (CardServiceException e) {
			if (!e.getMessage().contains("6986")) {
				throw e;
			}
		}
	}

	@Test
	public void issueRootCredential() throws CardException, CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation("Surfnet", "root");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getSurfnetAttributes();

		ic.issue(spec, isk, attributes, null);
	}

	@Test
	public void verifyRootCredentialAll() throws CardException, CredentialsException {
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
	public void verifyRootCredentialAll_withDS() throws CardException,
			CredentialsException, InfoException {

		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootAll");
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
	public void verifyRootCredentialNone() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"Surfnet", "root", "Surfnet", "rootNone");
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
	public void removeRootCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName("Surfnet", "root");

		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
	}

	@Test
	public void issueStudentCredential() throws CardException, CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation("RU", "studentCard");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getStudentCardAttributes();

		ic.issue(spec, isk, attributes, null);
	}

	@Test
	public void verifyStudentCredentialAll() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("RU",
				"studentCard", "RU", "studentCardAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		IdemixCredentials ic = new IdemixCredentials(TestSetup.getCardService());

		Attributes attr = ic.verify(vspec);
		
		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}

	@Test
	public void verifyStudentCredentialNone() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("RU",
				"studentCard", "RU", "studentCardNone");
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
	public void removeStudentCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName("RU", "studentCard");

		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
	}

	@Test
	public void issueAgeCredential() throws CardException, CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation("MijnOverheid", "ageLower");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getAgeAttributes();
		ic.issue(spec, isk, attributes, null);
	}


	@Test
	public void verifyAgeCredentialAll() throws CardException, CredentialsException {
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

	@Test
	public void verifyAgeCredentialNone() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid",
				"ageLower", "MijnOverheid", "ageLowerNone");
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
	public void verifyAgeCredentialOver16() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid",
				"ageLower", "UitzendingGemist", "ageLowerOver16");
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
	public void removeAgeCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName("MijnOverheid", "ageLower");

		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
	}

	@Test
	public void issueAddressNijmegenCredential() throws CardException, CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation("MijnOverheid", "address");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getAddressNijmegenAttributes();
		ic.issue(spec, isk, attributes, null);
	}
	
	@Test
	public void removeAddressNijmegenCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName("MijnOverheid", "address");

		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
	}

	@Test
	public void issueAddressReuverCredential() throws CardException, CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation("MijnOverheid", "address");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getAddressReuverAttributes();
		ic.issue(spec, isk, attributes, null);
	}
	
	@Test
	public void verifyAddressCredentialAll() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid",
				"address", "MijnOverheid", "addressAll");
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
	public void verifyAddressCredentialNone() throws CardException, CredentialsException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid",
				"address", "MijnOverheid", "addressNone");
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
	public void removeAddressCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance().getCredentialDescriptionByName("MijnOverheid", "address");

		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
	}

	@Test
	public void issueMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "root");

		Attributes attributes = new Attributes();
		attributes.add("BSN", "123456789".getBytes());

		issue(ici, attributes);
	}

	@Test
	public void verifyMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "rootAll");
		verify(vci);
	}

	@Test
	public void removeMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "root");
		remove(cd);
	}

	@Test
	public void issueFullNameCredential() throws CardException, CredentialsException,
			CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "fullName");

		Attributes attributes = new Attributes();
		attributes.add("firstnames", "Johan Pieter".getBytes());
		attributes.add("firstname", "Johan".getBytes());
		attributes.add("familyname", "Stuivezand".getBytes());
		attributes.add("prefix", "van".getBytes());

		issue(ici, attributes);
	}

	@Test
	public void verifyFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "fullNameAll");
		verify(vci);
	}

	@Test
	public void removeFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "fullName");
		remove(cd);
	}

	@Test
	public void issueBirthCertificate() throws CardException, CredentialsException,
			CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "birthCertificate");

		Attributes attributes = new Attributes();
		attributes.add("dateofbirth", "29-2-2004".getBytes());
		attributes.add("placeofbirth", "Stuivezand".getBytes());
		attributes.add("countryofbirth", "Nederland".getBytes());
		attributes.add("gender", "male".getBytes());

		issue(ici, attributes);
	}

	@Test
	public void verifyBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "birthCertificateAll");
		verify(vci);
	}

	@Test
	public void removeBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "birthCertificate");
		remove(cd);
	}

	@Test
	public void issueSeniorAgeCredential() throws CardException, CredentialsException,
			CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "ageHigher");

		Attributes attributes = new Attributes();
		attributes.add("over50", "yes".getBytes());
		attributes.add("over60", "no".getBytes());
		attributes.add("over65", "no".getBytes());
		attributes.add("over75", "no".getBytes());

		issue(ici, attributes);
	}

	@Test
	public void verifySeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "ageHigherAll");
		verify(vci);
	}

	@Test
	public void removeSeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "ageHigher");
		remove(cd);
	}

	@Test
	public void issueIRMATubeMemberCredential() throws CardException, CredentialsException,
			CardServiceException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"IRMATube", "member");

		Attributes attributes = new Attributes();
		attributes.add("name", "J.P. Stuivezand".getBytes());
		attributes.add("type", "regular".getBytes());
		attributes.add("id", "123456".getBytes());

		issue(ici, attributes);
	}

	@Test
	public void verifyIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMATube", "memberAll");
		verify(vci);
	}

	@Test
	public void verifyIRMATubeMemberTypeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMATube", "memberType");
		verify(vci);
	}

	@Test
	public void removeIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "ageHigher");
		remove(cd);
	}

	private void issue(IssueCredentialInformation ici, Attributes attributes)
			throws CardException, CredentialsException, CardServiceException {
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();

		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		ic.issue(spec, isk, attributes, null);
	}

	private void verify(VerifyCredentialInformation vci) throws CardException, CredentialsException {
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

	private void remove(CredentialDescription cd) throws CardException, CredentialsException, CardServiceException, InfoException {
		IdemixService is = TestSetup.getIdemixService();
		IdemixCredentials ic = new IdemixCredentials(is);

		ic.connect();
		is.sendCardPin(TestSetup.DEFAULT_CARD_PIN);
		try {
			ic.removeCredential(cd);
		} catch (CardServiceException e) {
			if (!e.getMessage().toUpperCase().contains("6A88")) {
				throw e;
			}
		}
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

		attributes.add("userID", "u921154@ru.nl".getBytes());
		attributes.add("securityHash", "DEADBEEF".getBytes());
		
		return attributes;
	}
    
    private Attributes getAgeAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("over12", "yes".getBytes());
		attributes.add("over16", "yes".getBytes());
		attributes.add("over18", "yes".getBytes());
		attributes.add("over21", "no".getBytes());
		
		return attributes;
    }
    
    private Attributes getAddressNijmegenAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("country", "Nederland".getBytes());
		attributes.add("city", "Nijmegen".getBytes());
		attributes.add("street", "Heyendaalseweg 135".getBytes());
		attributes.add("zipcode", "6525 AJ".getBytes());
		
		return attributes;
    }

    private Attributes getAddressReuverAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("country", "Nederland".getBytes());
		attributes.add("city", "Reuver".getBytes());
		attributes.add("street", "Snavelbies 19".getBytes());
		attributes.add("zipcode", "5953 MR".getBytes());
		
		return attributes;
    }
    
}
