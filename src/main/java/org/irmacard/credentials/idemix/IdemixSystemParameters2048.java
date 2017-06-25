package org.irmacard.credentials.idemix;

public class IdemixSystemParameters2048 extends IdemixSystemParameters {
	private final int l_e_prime = 120;
	private final int l_m = 256;
	private final int l_n = 2048;
	private final int l_statzk = 128;

	public IdemixSystemParameters2048() {
		super();
	}

	@Override public int get_l_e_prime() { return l_e_prime; }
	@Override public int get_l_m() { return l_m; }
	@Override public int get_l_n() { return l_n; }
	@Override public int get_l_statzk() { return l_statzk; }
}
