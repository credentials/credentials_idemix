/**
 * Test.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012,
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package org.irmacard.credentials.idemix.test;

import java.math.BigInteger;

import net.sourceforge.scuba.util.Hex;

public class Test {

/*    static { Security.addProvider(new BouncyCastleProvider()); }
    
    private static final IvParameterSpec ZERO_IV_PARAM_SPEC = 
			new IvParameterSpec(new byte[8]);
    
	public static void main(String[] args) {
		try {
			Mac mac = Mac.getInstance("DESEDEMAC64WITHISO7816-4PADDING");
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			byte[] key = new byte[16];//{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
			SecretKey ksMac = new SecretKeySpec(key, "DESEDE");
			mac.init(ksMac);
			byte[] in = new byte[]{ 0x02 };
			byte[] out = mac.doFinal(in);
			System.out.println(Hex.toHexString(out));
			byte[] in2 = new byte[]{1,2,3,4,5,6,7,8,1,(byte)0x80,0,0,0,0,0,0};
			cipher.init(Cipher.ENCRYPT_MODE, ksMac, ZERO_IV_PARAM_SPEC);
			byte[] out2 = cipher.doFinal(in2);
			System.out.println(Hex.toHexString(out2));
			
			String credStruct = "studentCard";
			URI BASE_LOCATION = new File(System.getProperty("user.dir")).toURI().resolve("irma_configuration/RU/");
			System.out.println("got base");
	        URI CRED_LOCATION = BASE_LOCATION.resolve("Issues/structure.xml");
	        System.out.println("got cred");
	        URI ISSUER_LOCATION = BASE_LOCATION.resolve("ipk.xml");
	        System.out.println("got issuer");
	        URI credStructId = new URI("http://www.ngo.org/" + credStruct + ".xml");
	        System.out.println("got struct");
	        // loading credential structure linked to a URI
	        Locations.init(credStructId, CRED_LOCATION);
	        System.out.println("got init");
	        // create the issuance specification
	        IssuanceSpec issuanceSpec = new IssuanceSpec(ISSUER_LOCATION, credStructId);
	        System.out.println("got spec");
	        URI iskLocation = BASE_LOCATION.resolve("private/isk.xml");
	        URI ipkLocation = ISSUER_LOCATION.resolve("ipk.xml");
	        URI BASE_ID = new URI("http://www.irmacard.org/credentials/phase1/RU/");
	        URI ISSUER_ID = new URI("http://www.issuer.com/");
	        IssuerKeyPair issuerKey = Locations.initIssuer(BASE_LOCATION, BASE_ID.toString(),
	                iskLocation, ipkLocation, ISSUER_ID.resolve("ipk.xml"));
	        short CRED_NR = (short) 4;

			Values values = new Values(issuerKey.getPublicKey().getGroupParams().getSystemParams());
	        System.out.println("got val");
	        values.add("attr1", BigInteger.valueOf(1313));
	        values.add("attr2", BigInteger.valueOf(1314));
	        values.add("attr3", BigInteger.valueOf(1315));
	        values.add("attr4", BigInteger.valueOf(1316));
			System.out.println("test");
			
			// Terminal for communication with the actual card
            TerminalCardService terminal = new TerminalCardService(TerminalFactory.getDefault().terminals().list().get(0));
            CardHolderVerificationService pinpad = new CardHolderVerificationService(terminal);
            
            // Wrapper which performs secure messaging
			SecureMessagingWrapper sm = new SecureMessagingWrapper(ksMac, ksMac);
			
			// Turn the terminal in a wrapping enabled service, wrapping is disabled by default, enable using wrapper.enable() 
			WrappingCardService wrapper = new WrappingCardService(pinpad, sm);
			
			// Finally make an idemix service out of all this.
			IdemixService service = new IdemixService(wrapper, CRED_NR);

			// Some tests
            service.open();
            //wrapper.enable();
            service.generateMasterSecret();
            int tries = pinpad.verifyPIN();
            if (tries != CardHolderVerificationService.PIN_OK) {
            	System.err.println("PIN verification failed. Tries left: " + tries);
            }
            service.setIssuanceSpecification(issuanceSpec);
            service.setAttributes(issuanceSpec, values);
            
            Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null, values);
            Message msgToRecipient1 = issuer.round0();
            Message msgToIssuer1 = service.round1(msgToRecipient1);
            Message msgToRecipient2 = issuer.round2(msgToIssuer1);
            service.round3(msgToRecipient2);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
*/
    
	public static void main(String[] args) {
		String hexN = "88CC7BD5EAA39006A63D1DBA18BDAF00130725597A0A46F0BACCEF163952833BCBDD4070281CC042B4255488D0E260B4D48A31D94BCA67C854737D37890C7B21184A053CD579176681093AB0EF0B8DB94AFD1812A78E1E62AE942651BB909E6F5E5A2CEF6004946CCA3F66EC21CB9AC01FF9D3E88F19AC27FC77B1903F141049";
		String hexS = "617DB25740673217DF74BDDC8D8AC1345B54B9AEA903451EC2C6EFBE994301F9CABB254D14E4A9FD2CD3FCC2C0EFC87803F0959C9550B2D2A2EE869BCD6C5DF7B9E1E24C18E0D2809812B056CE420A75494F9C09C3405B4550FD97D57B4930F75CD9C9CE0A820733CB7E6FC1EEAF299C3844C1C9077AC705B774D7A20E77BA30";
		String hexR = "6B4D9D7D654E4B1285D4689E12D635D4AF85167460A3B47DB9E7B80A4D476DBEEC0B8960A4ACAECF25E18477B953F028BD71C6628DD2F047D9C0A6EE8F2BC7A8B34821C14B269DBD8A95DCCD5620B60F64B132E09643CFCE900A3045331207F794D4F7B4B0513486CB04F76D62D8B14B5F031A8AD9FFF3FAB8A68E74593C5D8B";
		
		String hexM = "0000000000";

		String hexVPrime = "96D37B2C8A0DC8C9A6B4961A9A33AFEE78232A32D237746D70F387D91F4D4C2FDD9F4F59778BB29068145D06CBB6F795596F6C417DF46A3A32DE1EECD11310556DA159A8E6988025016955FFF3CE8FBEFF2959BA2F92D92EB8C534A6303C502528AB7E86371C21F5F144AB08FB8A7B3A672391007C6E2E5E46D20910D22B141EE1BE846616F3AA61AF02";
		
		String hexA = "1401FA0C7E3BBB77E96C95A57B01B1DCE360B6251392E11DCD59FFA8A90E0B738E83DE57E4033B24AF53BC89E87BBC9A7190E98E9F67EA4C0801CAE8B556E976C331B45E26A2ADB6660135FA7CDC81CD3A8FF17573F512164FE2D5D7DF7445AD3FF39358C07EDADCD2B8EA79B99B05FBF9C51BA51FA7075486FDB7B1175EC92A";
		String hexE = "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002BF473D003B4C3A492B4B335886045";
		String hexEPrime = "2BF473D003B4C3A492B4B335886045";
		String hexV = "0EE7F72F048A6BF4CFC86E3B87E87DAC572B24725138403924F263EEADBD335096D3B6633E6F10BC0DF39C9FE02515DCBE20BA200D7AFDD039F33EABEED7DE0E9E748EC5E4F48E3C7A8066699363B6C55125F2AABB44CB28D336466258FD30B1E00890D2032CFAA36D1FED1E42D4E4A1B7EFB07A8D37B09129AECD15E6DDB49D44106BC9CAC6F4A028EDDAABB616E38EA99D65B90550422012FBA033352ABC11861F140D523C00BA27C261E84C3BEDF4256538B389518CF430675D684E1BC37070CC85213A29981A70867E549F06615A9FF8B0E536";
		
		String hexVPrimeTilde = "7C15A2660145F6D16583ADB5F4E6BAEAD1B5E4C25484AF5A007BEA5C21B5A4E828C69FBB1D16C8A05AC732418FFE13D0B8F560DDEDBCC969DD235D9D75D1D1A93F6C11A8D4AB2075DA5C0662E3894CD5D462BFF408F83516F5EF9AEC70F4FB883BC718571480EA3FFF69E34BC06CD97248A1C712FB9D8072441F6A4991AC918D55C920192098F7ACCDDF5399503D57C3DAB594C2857868C6790385489DFDAB95C79D836CBF10880FE310A7D68146CEE48917327E";
		String hexSTilde = "00FE8C4AC44D45B5300FC68A6EA6A8201885ECF8FDA83AC55D943F9BF201CE4CC73675F956B4AC45AEC6785F71D0D381E7D656A0A5ED262296EAD8C9AB6763AD1447C54D2DD9FA35DB3C4D";

		String hexRA = "00075B775C94C8E1C33053597D29347D53EC9FA8241E9812D145049DA47B05EFB57C9E025FCF63C633E83DC345A2B1CADF845F6EA28E5B80B9452B0C80BAFCE99932F35AFDB5D56808728CD390FBE090DCD6940517B537DB8168C09D02F90B5E99C95632749CBAB8338BE3B7BFCB4959C62A5DD99071DA36DDD85080B7CAC1514E5C01CCBAF397B0A8C1";
		String hexMTilde = "3D9A8F38929B51D55748AC4E0139341F5E25552781561D168436ADCF216CC47A98CB68844B7CC561EA45840D92C1C210AC6EDE5464B43CDFF96230FAE3FDBC6D021DA2F32DBE6AF3A8BD";
		String hexETilde = "0F37C427DD0FF32740E6D19369EE7210701A66252E24B5AFED824640625323AC175F080BC8615E6B85E90C3E91B11CA44948DBCABEB34DCA1C";
		String hexVTilde = "03DB77DB1DAD5ACA2E7EE0A6E3764F04E160EB5927B4A234114C21552E85865B6372266D6ED24B699067089C55872D7E3B61DDDC1B432D3B812B2F1C93CF62BD429F9AF59E6F09DF06ECCB7E55615B4B7BBBCE2222FA68AEB2D0EBE70587EB17381D3372785FD366DEAE7A3F9566E71A762BC5E33185F4C741F6A0FE31CC29345393C47A051C63C93C0DAF95FB037B57A3ED0B9A6A47B067AC4C2034C2DB454B143D2F8D24D35715EF26C4578687A18EDF14FD29505588DEEAE0FB2B9BEFB01AE3BF6C273C66DBF3F308579D0455C48569817A9ADC3A55D2FADB512EBCA171BC56043E7C77DDA1230720FE9C41E45B197C422536EBE60952B077D127DBD5AF";

		String hexC = "4FB2EF869219E2C5EE858DFFD042CC6345518B0B1415161718191A1B1C1D1E1F";
//		String hexVPrime = "C259DAFBFF54D4223C8098FCBDEDFB6A6DA9F75E00EE65F174936896E3DD0D53A0975324BA92DC61E2D6EEA79A2E2BB3D868AE8BBACA35C346C116B6793E66BD41F7B72C06A3818910A42FBC9C5C9CE5AED6AF16480A69114C4A385E42DBDFA280F617D942AFF904EF661BB735A8864ADDB18E961557B669DA1108A61DB876BAA1C4B0127C7AF8F9672864858E138082BD6F11CD74AB31860B80A56018564A325F08F1F09B333DB758866DA9D7B7DB7041158548BB3F2EA76023BAAA8C729EDB6AD39B02B64F8C94AAD2C270D3DB07C2593B430931";

		BigInteger n = new BigInteger(1, Hex.hexStringToBytes(hexN));
		BigInteger S = new BigInteger(1, Hex.hexStringToBytes(hexS));
		BigInteger R = new BigInteger(1, Hex.hexStringToBytes(hexR));
		
		BigInteger m = new BigInteger(1, Hex.hexStringToBytes(hexM));
		
		BigInteger vPrime = new BigInteger(1, Hex.hexStringToBytes(hexVPrime));
		
		BigInteger A = new BigInteger(1, Hex.hexStringToBytes(hexA));
		BigInteger e = new BigInteger(1, Hex.hexStringToBytes(hexE));
		BigInteger ePrime = new BigInteger(1, Hex.hexStringToBytes(hexEPrime));
		BigInteger v = new BigInteger(1, Hex.hexStringToBytes(hexV));
		
		BigInteger vPrimeTilde = new BigInteger(1, Hex.hexStringToBytes(hexVPrimeTilde));
		BigInteger sTilde = new BigInteger(1, Hex.hexStringToBytes(hexSTilde));

		BigInteger rA = new BigInteger(1, Hex.hexStringToBytes(hexRA));
		BigInteger mTilde = new BigInteger(1, Hex.hexStringToBytes(hexMTilde));
		BigInteger eTilde = new BigInteger(1, Hex.hexStringToBytes(hexETilde));
		BigInteger vTilde = new BigInteger(1, Hex.hexStringToBytes(hexVTilde));
		
		BigInteger c = new BigInteger(1, Hex.hexStringToBytes(hexC));
		
		// Issuance
		BigInteger U = S.modPow(vPrime, n);
		System.out.println("U = S^vPrime mod n: " + Hex.toHexString(U.toByteArray()));
		
		BigInteger buf = R.modPow(m, n);
		System.out.println("buffer = R[0]^m[0] mod n: " + Hex.toHexString(buf.toByteArray()));
		
		U = U.multiply(buf).mod(n);
		System.out.println("U = U * buffer mod n: " + Hex.toHexString(U.toByteArray()));
		
		BigInteger UTilde = S.modPow(vPrimeTilde, n);
		System.out.println("UTilde = S^vPrimeTilde mod n: " + Hex.toHexString(UTilde.toByteArray()));
		
		buf = R.modPow(sTilde, n);		
		System.out.println("buffer = R[0]^sTilde mod n: " + Hex.toHexString(buf.toByteArray()));

		UTilde = UTilde.multiply(buf).mod(n);
		System.out.println("UTilde = UTilde * buffer mod n: " + Hex.toHexString(UTilde.toByteArray()));
		

		
		BigInteger APrime = S.modPow(rA, n);		
		System.out.println("A' = S^r_A mod n: " + Hex.toHexString(APrime.toByteArray()));
		
		APrime = APrime.multiply(A).mod(n);
		System.out.println("A' = A' * A mod n: " + Hex.toHexString(APrime.toByteArray()));
		
		BigInteger ZTilde = S.modPow(vTilde, n);
		System.out.println("ZTilde = S^vTilde: " + Hex.toHexString(ZTilde.toByteArray()));

		BigInteger buffer = APrime.modPow(eTilde, n);
		System.out.println("buffer = A'^eTilde: " + Hex.toHexString(buffer.toByteArray()));

		ZTilde = ZTilde.multiply(buffer).mod(n);
		System.out.println("ZTilde = ZTilde * buffer: " + Hex.toHexString(ZTilde.toByteArray()));

		buffer = R.modPow(mTilde, n);
		System.out.println("R_i^m_i: " + Hex.toHexString(buffer.toByteArray()));
				
		ZTilde = ZTilde.multiply(buffer).mod(n);
		System.out.println("ZTilde = ZTilde * buffer: " + Hex.toHexString(ZTilde.toByteArray()));
		
		BigInteger eHat = eTilde.add(c.multiply(ePrime));
		System.out.println("e^ = e~ + c*e': "  + Hex.toHexString(eHat.toByteArray()));
		
		vPrime = v.subtract(e.multiply(rA));
		System.out.println("v' = v - e*r_A:"  + Hex.toHexString(vPrime.toByteArray()));
		
		BigInteger vHat = vTilde.add(c.multiply(vPrime));
		System.out.println("vHat: " + Hex.toHexString(vHat.toByteArray()));
		
		BigInteger mHat = mTilde.add(c.multiply(m));
		System.out.println("mHat[0]: " + Hex.toHexString(mHat.toByteArray()));

		
	}
}
