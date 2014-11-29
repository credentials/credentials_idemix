/**
 * IRMACryptoTest.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */


package org.irmacard.credentials.idemix;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofS;
import org.irmacard.credentials.idemix.proofs.ProofU;
import org.irmacard.credentials.idemix.util.Crypto;
import org.junit.Test;

public class IRMACryptoTest {
	static BigInteger p = new BigInteger("10436034022637868273483137633548989700482895839559909621411910579140541345632481969613724849214412062500244238926015929148144084368427474551770487566048119");
	static BigInteger q = new BigInteger("9204968012315139729618449685392284928468933831570080795536662422367142181432679739143882888540883909887054345986640656981843559062844656131133512640733759");

	static BigInteger n = new BigInteger("96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321");
	static BigInteger S = new BigInteger("68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136");
	static BigInteger Z = new BigInteger("44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636");

	static List<BigInteger> R = Arrays.asList(
			new BigInteger("75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251"),
			new BigInteger("16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766"),
			new BigInteger("13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840"),
			new BigInteger("86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187"),
			new BigInteger("68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513"),
			new BigInteger("65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387"));

	List<BigInteger> attributes = Arrays.asList(
			new BigInteger(1, "one".getBytes()),
			new BigInteger(1, "two".getBytes()),
			new BigInteger(1, "three".getBytes()),
			new BigInteger(1, "four".getBytes()));

	static IdemixSecretKey sk = new IdemixSecretKey(p, q);
	static IdemixPublicKey pk = new IdemixPublicKey(n, Z, S, R);

	@Test
	public void testPublicKey() {
		assertEquals(p.multiply(q), n);
	}

	@Test
	public void testCLSignature() {
		List<BigInteger> ms = new Vector<BigInteger>();
		ms.add(new BigInteger("1"));
		ms.add(new BigInteger("2"));
		ms.add(new BigInteger("3"));

		CLSignature sig = CLSignature.signMessageBlock(sk, pk, ms);
		assertTrue("Signature is not valid", sig.verify(pk, ms));

		ms.set(0, new BigInteger("1337"));
		assertFalse("Signature should not verify", sig.verify(pk, ms));
	}

	@Test
	public void testCLSignatureRandomize() {
		List<BigInteger> ms = new Vector<BigInteger>();
		ms.add(new BigInteger("1"));
		ms.add(new BigInteger("2"));

		CLSignature sig = CLSignature.signMessageBlock(sk, pk, ms);
		CLSignature sig_randomized = sig.randomize(pk);

		assertTrue("Signature is not valid", sig_randomized.verify(pk, ms));
	}

	@Test
	public void testASN1Encoding1() {
		byte[] enc = Crypto.asn1Encode(new BigInteger("1"),
				new BigInteger("65"), new BigInteger("1025"));

		byte[] expected = { 0x30, 0x0D,
				0x02, 0x01, 0x03, // The number of elements is additionally encoded
				0x02, 0x01, 0x01,
				0x02, 0x01, 0x41,
				0x02, 0x02, 0x04, 0x01 };

		assertTrue(Arrays.equals(enc, expected));
	}

	@Test
	public void testProofU() {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger n_1 = new BigInteger(params.l_statzk, rnd);
		BigInteger secret = new BigInteger(params.l_m, rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		cb.setSecret(secret);

		BigInteger U = cb.commitmentToSecret();
		ProofU proofU = cb.proveCommitment(U, n_1);

		assertTrue(proofU.verify(pk, U, context, n_1));
	}

	@Test
	public void testProofULogged() {
		BigInteger context = new BigInteger("34911926065354700717429826907189165808787187263593066036316982805908526740809");
		BigInteger n_1 = new BigInteger("724811585564063105609243");
		BigInteger c = new BigInteger("4184045431748299802782143929438273256345760339041229271411466459902660986200");
		BigInteger U = new BigInteger("53941714038323323772993715692602421894514053229231925255570480167011458936488064431963770862062871590815370913733046166911453850329862473697478794938988248741580237664467927006089054091941563143176094050444799012171081539721321786755307076274602717003792794453593019124224828904640592766190733869209960398955");
		BigInteger v_prime_response = new BigInteger("930401833442556048954810956066821001094106683380918922610147216724718347679854246682690061274042716015957693675615113399347898060611144526167949042936228868420203309360695585386210327439216083389841383395698722832808268885873389302262079691644125050748391319832394519920382663304621540520277648619992590872190274152359156399474623649137315708728792245711389032617438368799004840694779408839779419604877135070624376537994035936");
		BigInteger s_response = new BigInteger("59776396667523329313292302350278517468587673934875085337674938789292900859071752886820910103285722288747559744087880906618151651690169988337871960870439882357345503256963847251");

		ProofU proofU = new ProofU(c, v_prime_response, s_response);

		assertTrue(proofU.verify(pk, U, context, n_1));
	}

	@Test
	public void testCommitmentMessage() {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger n_1 = new BigInteger(params.l_statzk, rnd);
		BigInteger secret = new BigInteger(params.l_m, rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		IssueCommitmentMessage msg = cb.commitToSecretAndProve(secret, n_1);
		assertTrue(msg.getCommitmentProof().verify(pk, msg.getCommitment(), context, n_1));
	}

	@Test
	public void testProofS() {
		Random rnd = new Random();

		// Silly commitment, content doesn't matter for this test.
		BigInteger exponent = new BigInteger(pk.getSystemParameters().l_m, rnd);
		BigInteger U = pk.getGeneratorS().modPow(exponent, pk.getModulus());

		// Silly context
		BigInteger context = new BigInteger(pk.getSystemParameters().l_h, rnd);

		// Nonce (normally from the credential recipient)
		BigInteger nonce = new BigInteger(pk.getSystemParameters().l_statzk, rnd);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		CLSignature sig = issuer.signCommitmentAndAttributes(U, attributes);
		ProofS proof = issuer.proveSignature(sig, nonce);

		assertTrue(proof.verify(pk, sig, issuer.getContext(), nonce));

		// Silly nonce test
		System.out.println("TEST: Will warn that hash doesn't match, that is expected");
		assertFalse(proof.verify(pk, sig, issuer.getContext(), BigInteger.TEN));

		// Silly context test
		System.out.println("TEST: Will warn that hash doesn't match, that is expected");
		assertFalse(proof.verify(pk, sig, BigInteger.TEN, nonce));
	}

	@Test
	public void testProofSLogged() {
		BigInteger context = new BigInteger("34911926065354700717429826907189165808787187263593066036316982805908526740809");
		BigInteger n_2 = new BigInteger("1424916368173409716606");

		// Signature
		BigInteger A = new BigInteger("66389313221915836241271893803869162372470096003861448260498566798077037255866372791540928160267561756794143545532118654736979223658343806335872047371607436291528588343320128898584874264796312130159695427439025355009934986408160536404163490935544221152821545871675088845781351195696518382628790514628112517886");
		BigInteger e = new BigInteger("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930207251663943512715842083759814664217");
		BigInteger v = new BigInteger("32427566863312925183262683355749521096160753564085736927716798279834745436154181827687524960554513739692930154573915901486008843583586162755818099731448281905764117842382407835789897633042765641230655956290191876265377547222981221260311549695231999461733778383779100992221748503727598149536948999564401095816377323412637286891625085960745712119714441272446053177642615033258689648568679017384011895908901362352242970432640019866501367925956123252426587516554347912178721773507440862343752105273189184247444400383");

		// Proof
		BigInteger c = new BigInteger("60359393410007276721785600209946099643760005142374188599509762410975853354415");
		BigInteger e_response = new BigInteger("1139627737042307991725447845798004742853435356249558932466535799661640630812910641126155269500348608443317861800376689024557774460643901450316279085276256524076388421890909312661873221470626068394945683125859434135652717426417681918932528613003921792075852313319584079881881807505760375270399908999784672094");

		CLSignature sig = new CLSignature(A, e, v);
		ProofS proof = new ProofS(c, e_response);

		assertTrue(proof.verify(pk, sig, context, n_2));
	}

	@Test
	public void testSignatureMessage() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger n_1 = new BigInteger(params.l_statzk, rnd);
		BigInteger secret = new BigInteger(params.l_m, rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, null, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		issuer.issueSignature(commit_msg, attributes, n_1);
	}

	@Test
	public void fullIssuance() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger n_1 = new BigInteger(params.l_statzk, rnd);
		BigInteger secret = new BigInteger(params.l_m, rnd);

		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);

		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);

		cb.constructCredential(msg);
	}

	@Test
	public void testShowingProof() {
		CLSignature signature = CLSignature.signMessageBlock(sk, pk, attributes);
		IdemixCredential cred = new IdemixCredential(pk, attributes, signature);
		List<Integer> disclosed = Arrays.asList(1, 2);

		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger nonce1 = new BigInteger(params.l_statzk, rnd);

		ProofD proof = cred.createDisclosureProof(disclosed, context, nonce1);

		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, nonce1));
	}

	@Test
	public void testShowingProofLogged() {
		BigInteger nonce1 = new BigInteger("356168310758183945030882");
		BigInteger context = new BigInteger("59317469690166962413036802769129097120995929488116634148207386064523180296869");

		BigInteger c = new BigInteger("92405256824458923934294175762399873039847432841647909261385804859937404075570");
		BigInteger A = new BigInteger("66467922530801909191099602528137141713616048447732479189179865050384832390931230033112445547628606292639430708552418462959456337530534055700746138057512598497120682196611341962749384189596253759402224308748002860890211498962735924481685975488607793795169788837476493253297353146422154392391732925567178805607");
		BigInteger e_response = new BigInteger("44022597110989879399510333540268555303613344906583879371531630680320900347240418258690335759375210734514869637566864349585531295946323809");
		BigInteger v_response = new BigInteger("26326301830460880582628741955953428491879823201714737915103888193625032953131902593859116395461541557845953939714765660366793552012359281854190756504190064959818584175057775414324351414234450208391534497565506441579960808534266557458251190151268682500197950418141493586125049371381626638554299245282498637246703583102656876690825544275995631773170789236920674341621008537679924624747222821679128060382072191284077393034573357698475000667180794116538132628586533009732462826119381931507809052573496513689222244701991737191273263148163121236326525677935993049602389899306007664212328515456044738278420");

		HashMap<Integer, BigInteger> a_responses = new HashMap<Integer, BigInteger>();
		a_responses.put(0, new BigInteger("55247823867049193571627241180110605447453053126985891402640532123848293918217459966028364637387399903283634100097425890971508590427350301193682412170041146212137866279677802531"));
		HashMap<Integer, BigInteger> a_disclosed = new HashMap<Integer, BigInteger>();
		a_disclosed.put(1,  new BigInteger("1100598411265"));
		a_disclosed.put(2,  new BigInteger("43098508374675488371040117572049064979183030441504364"));
		a_disclosed.put(3,  new BigInteger("4919409929397552454"));

		ProofD proof = new ProofD(c, A, e_response, v_response, a_responses, a_disclosed);

		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, nonce1));
	}

	@Test
	public void fullIssuanceAndShowing() throws CredentialsException {
		Random rnd = new Random();
		IdemixSystemParameters params = pk.getSystemParameters();

		BigInteger context = new BigInteger(params.l_h, rnd);
		BigInteger n_1 = new BigInteger(params.l_statzk, rnd);
		BigInteger secret = new BigInteger(params.l_m, rnd);

		// Issuance
		CredentialBuilder cb = new CredentialBuilder(pk, attributes, context);
		IssueCommitmentMessage commit_msg = cb.commitToSecretAndProve(secret, n_1);
		IdemixIssuer issuer = new IdemixIssuer(pk, sk, context);
		IssueSignatureMessage msg = issuer.issueSignature(commit_msg, attributes, n_1);
		IdemixCredential cred = cb.constructCredential(msg);

		// Showing
		n_1 = new BigInteger(params.l_statzk, rnd);
		List<Integer> disclosed = Arrays.asList(1, 2);

		ProofD proof = cred.createDisclosureProof(disclosed, context, n_1);
		assertTrue("Proof of disclosure should verify", proof.verify(pk, context, n_1));
	}
}
