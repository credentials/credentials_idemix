/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

	public final int l_e_commit = l_e_prime + l_statzk + l_h;
	public final int l_m_commit = l_m + l_statzk + l_h;
	public final int l_r_a = l_n + l_statzk;
	public final int l_s_commit = l_m + l_statzk + l_h + 1;
	public final int l_v_commit = l_v + l_statzk + l_h;
	public final int l_v_prime = l_n + l_statzk;
	public final int l_v_prime_commit = l_n + 2*l_statzk + l_h;

	public final int size_h = l_h / 8;
	public final int size_n = l_n / 8;
	public final int size_m = l_m / 8;
	public final int size_statzk = l_statzk / 8;

	public final int size_v = 213;
	public final int size_e = 75;

	public final int size_a_response = size_m + size_statzk + size_h;
	public final int size_e_response = size_e + size_statzk + size_h;
	public final int size_s_response = size_m + size_statzk + size_h + 1;
	public final int size_v_response = size_v + size_statzk + size_h;
}
