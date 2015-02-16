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
import org.irmacard.credentials.idemix.test.categories.IssueTest;
import org.irmacard.credentials.idemix.test.categories.RemovalTest;
import org.irmacard.credentials.idemix.test.categories.VerificationTest;
import org.irmacard.credentials.idemix.util.CredentialInformation;
import org.irmacard.credentials.idemix.util.IssueCredentialInformation;
import org.irmacard.credentials.idemix.util.VerifyCredentialInformation;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.idemix.IdemixService;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import javax.smartcardio.CardTerminal;

import net.sourceforge.scuba.smartcards.TerminalCardService;

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
	@Category(IssueTest.class)
	public void issueRootCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
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
	@Category(VerificationTest.class)
	public void verifyRootCredentialAll() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootAll");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		TerminalCardService cs = (TerminalCardService) TestSetup.getCardService();

		IdemixService is = new IdemixService (cs);
		try {
			is.open();
			is.selectApplication ();
		} catch (CardServiceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CardTerminal terminal = cs.getTerminal ();
		terminal.connect("*");
		if (terminal.isCardPresent()) {
			System.out.println ("with card");
			terminal.connect("*");
		} else
			System.out.println ("without card");
		IdemixCredentials ic = new IdemixCredentials(is);

		Attributes attr = ic.verify(vspec);
		
		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
		
		attr.print();
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyRootCredentialNone() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootNone");
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
	@Category(VerificationTest.class)
	public void verifyRootCredentialVoucher() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("Surfnet", "rootVoucher");
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
	@Category(RemovalTest.class)
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
	@Category(IssueTest.class)
	public void issueStudentCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
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
	@Category(VerificationTest.class)
	public void verifyStudentCredentialAll() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("RU", "studentCardAll");
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
	@Category(VerificationTest.class)
	public void verifyStudentCredentialNone() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("RU", "studentCardNone");
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
	@Category(RemovalTest.class)
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
	@Category(IssueTest.class)
	public void issueAgeCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
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
	@Category(VerificationTest.class)
	public void verifyAgeCredentialAll() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid", "ageLowerAll");
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
	@Category(VerificationTest.class)
	public void verifyAgeCredentialNone() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid", "ageLowerNone");
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
	@Category(VerificationTest.class)
	public void verifyAgeCredentialOver16() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("UitzendingGemist", "ageLowerOver16");
		IdemixVerifySpecification vspec = vci.getIdemixVerifySpecification();

		CardService cs = TestSetup.getCardService();
		IdemixCredentials ic = new IdemixCredentials(cs);

		for (int i = 0; i < 1000; i++) {
		Attributes attr = ic.verify(vspec);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}

		attr.print();
		}
	}

	@Test
	@Category(RemovalTest.class)
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
	@Category(IssueTest.class)
	public void issueAddressNijmegenCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
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
	@Category(RemovalTest.class)
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
	public void issueAddressReuverCredential() throws CardException, CredentialsException, CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation("MijnOverheid", "address");
		IdemixIssueSpecification spec = ici.getIdemixIssueSpecification();
		IdemixPrivateKey isk = ici.getIdemixPrivateKey();
		
		IdemixService is = new IdemixService(TestSetup.getCardService());
		IdemixCredentials ic = new IdemixCredentials(is);
		ic.connect();
		is.sendPin(TestSetup.DEFAULT_CRED_PIN);
		Attributes attributes = getAddressReuverAttributes();
		spec.setCardVersion(is.getCardVersion());
		ic.issue(spec, isk, attributes, null);
	}
	
	@Test
	@Category(VerificationTest.class)
	public void verifyAddressCredentialAll() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid", "addressAll");
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
	@Category(VerificationTest.class)
	public void verifyAddressCredentialNone() throws CardException, CredentialsException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation("MijnOverheid", "addressNone");
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
	@Category(RemovalTest.class)
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
	@Category(IssueTest.class)
	public void issueMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "root");

		Attributes attributes = new Attributes();
		attributes.add("BSN", "123456789".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "rootAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeMijnOverheidRoot() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "root");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueFullNameCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "fullName");
		
		Attributes attributes = new Attributes();
		attributes.add("firstnames", "Jaap-Henk".getBytes());
		attributes.add("firstname", "Jaap-Henk".getBytes());
		attributes.add("familyname", "Hoepman".getBytes());
		attributes.add("prefix", " ".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "fullNameAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeFullNameCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "fullName");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueBirthCertificate() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "birthCertificate");

		Attributes attributes = new Attributes();
		attributes.add("dateofbirth", "29-2-2004".getBytes());
		attributes.add("placeofbirth", "Stuivezand".getBytes());
		attributes.add("countryofbirth", "The Netherlands".getBytes());
		attributes.add("gender", "male".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "birthCertificateAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeBirthCertificate() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "birthCertificate");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueSeniorAgeCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"MijnOverheid", "ageHigher");

		Attributes attributes = new Attributes();
		attributes.add("over50", "no".getBytes());
		attributes.add("over60", "no".getBytes());
		attributes.add("over65", "no".getBytes());
		attributes.add("over75", "no".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifySeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"MijnOverheid", "ageHigherAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeSeniorAgeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("MijnOverheid", "ageHigher");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueIRMATubeMemberCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"IRMATube", "member");

		Attributes attributes = new Attributes();
		attributes.add("type", "regular".getBytes());
		attributes.add("id", "1592371553".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMATube", "memberAll");
		verify(vci);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMATubeMemberTypeCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMATube", "memberType");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeIRMATubeMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("IRMATube", "member");
		remove(cd);
	}

	@Test
	@Category(IssueTest.class)
	public void issueIRMAWikiMemberCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"Thalia", "member");

		Attributes attributes = new Attributes();
		attributes.add("type", "regular".getBytes());
		attributes.add("nickname", "irmawikiuser".getBytes());
		attributes.add("realname", "Irma Wiki User".getBytes());
		attributes.add("email", "irmawikiuser@example.com".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMAWikiMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMAWiki", "memberAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeIRMAWikiMemberCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("IRMAWiki", "member");
		remove(cd);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyIRMAWikiSurfnetRootNone() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"IRMAWiki", "surfnetRootNone");
		verify(vci);
	}

	@Test
	@Category(IssueTest.class)
	public void issueThaliaCredential() throws CardException, CredentialsException,
			CardServiceException, InfoException {
		IssueCredentialInformation ici = new IssueCredentialInformation(
				"Thalia", "thalia");

		Attributes attributes = new Attributes();
		attributes.add("memberID", "660202".getBytes());

		issue(ici, attributes);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyThaliaCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"Thalia", "thaliaAll");
		verify(vci);
	}

	@Test
	@Category(RemovalTest.class)
	public void removeThaliaCredential() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		CredentialDescription cd = DescriptionStore.getInstance()
				.getCredentialDescriptionByName("Thalia", "thalia");
		remove(cd);
	}

	@Test
	@Category(VerificationTest.class)
	public void verifyThaliaNone() throws CardException,
			CredentialsException, CardServiceException, InfoException {
		VerifyCredentialInformation vci = new VerifyCredentialInformation(
				"Thalia", "surfnetRootNone");
		verify(vci);
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
		attributes.add("studentCardNumber", "Unknown".getBytes());
		attributes.add("studentID", "s4530837".getBytes());
		attributes.add("level", "master".getBytes());
		
		return attributes;
	}

    private Attributes getSurfnetAttributes() {
        // Return the attributes that have been revealed during the proof
        Attributes attributes = new Attributes();

		attributes.add("userID", "j_henselmans@demo.irmacard.org".getBytes());	
        attributes.add("securityHash", "00000000".getBytes());
		
		return attributes;
	}
    
    private Attributes getAgeAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("over12", "yes".getBytes());
		attributes.add("over16", "yes".getBytes());
		attributes.add("over18", "yes".getBytes());
		attributes.add("over21", "yes".getBytes());
		
		return attributes;
    }
    
    private Attributes getAddressNijmegenAttributes () {
        Attributes attributes = new Attributes();

		attributes.add("country", "Nederland".getBytes());
		attributes.add("city", "Apeldoorn".getBytes());
		attributes.add("street", "?".getBytes());
		attributes.add("zipcode", "?".getBytes());
		
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
