package org.irmacard.credentials.idemix;

import org.irmacard.credentials.info.InfoException;

public abstract class IdemixSystemParameters {
	private final int l_h = 256;

	// Dependent parameters, these are calculated by the constructor
	private int l_v;
	private int l_e;
	private int l_r;
	private int l_e_commit;
	private int l_m_commit;
	private int l_r_a;
	private int l_s_commit;
	private int l_v_commit;
	private int l_v_prime;
	private int l_v_prime_commit;

	private int size_h;
	private int size_n;
	private int size_m;
	private int size_statzk;

	private int size_v;
	private int size_e;

	private int size_a_response;
	private int size_e_response;
	private int size_s_response;
	private int size_v_response;

	public IdemixSystemParameters() {
		l_e_commit = get_l_e_prime() + get_l_statzk() + get_l_h();
		l_m_commit = get_l_m() + get_l_statzk() + get_l_h();
		l_r_a = get_l_n() + get_l_statzk();
		l_s_commit = get_l_m() + get_l_statzk() + get_l_h() + 1;
		l_v_prime = get_l_n() + get_l_statzk();
		l_v_prime_commit = get_l_n() + 2*get_l_statzk() + get_l_h();
		l_r = get_l_statzk();

		l_v = get_l_n() + get_l_statzk() + get_l_h() + Math.max(get_l_m() + l_r + 3, get_l_statzk() + 2) + 1;
		l_e = get_l_statzk() + get_l_h() + Math.max(get_l_m()+4, get_l_e_prime()+2) + 1;

		l_v_commit = l_v + get_l_statzk() + get_l_h();

		// The size_ parameters are the l_ parameters in bytes.
		// Unholy trick alert: to calculate these, we want to do integer division
		// that rounds up, not down. We do this by first adding 7, and then doing
		// normal integer division. This works:
		// If l = 0 mod 8:
		//     then (l+7)/8 = l/8
		// Otherwise:
		//     then l = r mod 8 where 0 < r < 8
		//     then l = 8x + r for some integer x
		//     then (l+7)/8 = (8x+r+7)/8 = x + (r+7)/8
		//     and since r > 0 and r < 8, (r+7)/8 == 1
		//     so (l+7)/8 = x + 1 = l/8 + 1.

		size_h = (get_l_h()+7) / 8;
		size_n = (get_l_n()+7) / 8;
		size_m = (get_l_m()+7) / 8;
		size_statzk = (get_l_statzk()+7) / 8;

		size_v = (l_e+7) / 8;
		size_e = (l_v+7) / 8;

		size_a_response = size_m + size_statzk + size_h;
		size_e_response = size_e + size_statzk + size_h;
		size_s_response = size_m + size_statzk + size_h + 1;
		size_v_response = size_v + size_statzk + size_h;
	}

	/**
	 * Get an instance corresponding to the given bitsize.
	 * @throws InfoException if the bitsize does not equal an allowed value (currently 1024, 2048 or 4096).
	 */
	public static IdemixSystemParameters get(int bitsize) throws InfoException {
		switch (bitsize) {
			case 1024:
				return new IdemixSystemParameters1024();
			case 2048:
				return new IdemixSystemParameters2048();
			case 4096:
				return new IdemixSystemParameters4096();
			default:
				throw new InfoException("Modulus was of an unexpected keysize: " + bitsize);
		}
	}

	/**
	 * Checks if the parameters satisfy the constraints from table:constraints from the Idemix spec.
	 */
	public boolean isValid() {
		return l_e > get_l_statzk() + get_l_h() + Math.max(get_l_m()+4, get_l_e_prime()+2)
				&& l_v > get_l_n() + get_l_statzk() + get_l_h() + Math.max(get_l_m()+l_r+3, get_l_statzk()+2)
				&& get_l_h() < l_e
				&& get_l_e_prime() < l_e - get_l_statzk() - get_l_h() - 3;
	}

	public abstract int get_l_e_prime();
	public abstract int get_l_m();
	public abstract int get_l_n();
	public abstract int get_l_statzk();

	// Since we always use SHA256 in Crypto.java, this is not configurable, so we don't allow overrides.
	public final int get_l_h() {
		return l_h;
	}

	public int get_l_v() { return l_v; }
	public int get_l_e() { return l_e; }
	public int get_l_r() { return l_r; }
	public int get_l_e_commit() { return l_e_commit; }
	public int get_l_m_commit() { return l_m_commit; }
	public int get_l_r_a() { return l_r_a; }
	public int get_l_s_commit() { return l_s_commit; }
	public int get_l_v_commit() { return l_v_commit; }
	public int get_l_v_prime() { return l_v_prime; }
	public int get_l_v_prime_commit() { return l_v_prime_commit; }
	public int get_size_h() { return size_h; }
	public int get_size_n() { return size_n; }
	public int get_size_m() { return size_m; }
	public int get_size_statzk() { return size_statzk; }
	public int get_size_v() { return size_v; }
	public int get_size_e() { return size_e; }
	public int get_size_a_response() { return size_a_response; }
	public int get_size_e_response() { return size_e_response; }
	public int get_size_v_response() { return size_v_response; }
	public int get_size_s_response() { return size_s_response; }
}
