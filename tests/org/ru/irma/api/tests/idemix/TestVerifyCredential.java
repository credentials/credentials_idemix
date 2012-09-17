/**
 * TestVerifyCredential.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package org.ru.irma.api.tests.idemix;

import java.math.BigInteger;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.IResponseAPDU;
import net.sourceforge.scuba.smartcards.TerminalCardService;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import service.IdemixService;
import service.IdemixSmartcard;
import service.ProtocolCommand;
import service.ProtocolResponses;

import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.utils.SystemParameters;

import credentials.Attributes;
import credentials.CredentialsException;
import credentials.Nonce;
import credentials.idemix.IdemixCredentials;
import credentials.idemix.spec.IdemixVerifySpecification;

public class TestVerifyCredential {
	
	@Before
	public void setupIdemix() {
    	TestSetup.setupIssuer();
    	TestSetup.setupCredentialStructure();
    	TestSetup.setupIssuanceSpec();
	}

	@Test
	public void verifyCredentialWithoutAPI() {
        // load the proof specification
        ProofSpec spec = TestSetup.setupProofSpec();
        System.out.println(spec.toStringPretty());

        SystemParameters sp = spec.getGroupParams().getSystemParams();

        // first get the nonce (done by the verifier)
        System.out.println("Getting nonce.");
        BigInteger nonce = Verifier.getNonce(sp);

        IdemixService prover = null;
        try {
            CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);
			prover = new IdemixService(new TerminalCardService(terminal), TestSetup.CRED_NR);
            prover.open();
        } catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
        }

        // create the proof
        Proof p = prover.buildProof(nonce, spec);

        // now p is sent to the verifier
        Verifier verifier = new Verifier(spec, p, nonce);
        if (!verifier.verify()) {
            fail("The proof does not verify");
        } else {
            System.out.println("Proof verified");
        }
	}

	@Test
	public void verifyCredentialWithCardService() throws CredentialsException, CardException {
		IdemixVerifySpecification vspec = IdemixVerifySpecification
				.fromIdemixProofSpec(TestSetup.PROOF_SPEC_LOCATION, TestSetup.CRED_NR);

		CardService cs = TestSetup.getCardService();

		IdemixCredentials ic = new IdemixCredentials(cs);

		Attributes attr = ic.verify(vspec);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
	}

	@Test
	public void verifyCredentialAsync() throws CredentialsException, CardException, CardServiceException {
		IdemixCredentials ic = new IdemixCredentials();

		IdemixVerifySpecification vspec = IdemixVerifySpecification
				.fromIdemixProofSpec(TestSetup.PROOF_SPEC_LOCATION, TestSetup.CRED_NR);

		System.out.println("Running ASync test now");
		Nonce nonce = ic.generateNonce(vspec);
		List<ProtocolCommand> commands = ic.requestProofCommands(vspec, nonce);
		// FIXME: verify that this actually helps
		commands.add(0, IdemixSmartcard.selectAppletCommand);
		ProtocolResponses responses = executeCommands(commands);
		Attributes attr = ic.verifyProofResponses(vspec, nonce, responses);

		if (attr == null) {
			fail("The proof does not verify");
		} else {
			System.out.println("Proof verified");
		}
	}

	private ProtocolResponses executeCommands(List<ProtocolCommand> commands)
			throws CardServiceException, CardException {
		CardService service = TestSetup.getCardService();

		service.open();

		ProtocolResponses responses = new ProtocolResponses();
		for (ProtocolCommand c : commands) {
			IResponseAPDU response = IdemixService.transmit(service, c.command);
			responses.put(c.key, response);
			if (response.getSW() != 0x00009000) {
				// don't bother with the rest of the commands...
				// TODO: get error message from global table
				String errorMessage = c.errorMap != null
						&& c.errorMap.containsKey(response.getSW()) ? c.errorMap
						.get(response.getSW()) : "";
				throw new CardServiceException(String.format(
						"Command failed: \"%s\", SW: %04x (%s)", c.description,
						response.getSW(), errorMessage));
			}
		}

		service.close();
		return responses;
	}
}
