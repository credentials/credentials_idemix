/**
 * IdemixSystemParameters.java
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

public class IdemixSystemParameters {
	public final int l_e = 597;
	public final int l_e_prime = 120;
	public final int l_h = 256;
	public final int l_m = 256;
	public final int l_n = 1024;
	public final int l_statzk = 80;
	public final int l_v = 1700;

	public final int l_s_commit = l_m + l_statzk + l_h + 1;
	public final int l_v_prime = l_n + l_statzk;
	public final int l_v_prime_commit = l_n + 2*l_statzk + l_h;
}
