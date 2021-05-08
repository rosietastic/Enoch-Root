/*
 * libenoch.h
 * 
 * Copyright 2021 Paul Rose <rosietastic@lavabit.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#define DEV_PATH_MAX	30
#define SIZE_LEN 		25
#define ERR_MSG_MAXLEN	80
#define ERR_MSG_SUFFIX	66
#define MAX_FSP_PATH	128

typedef struct {
	int						verbose;
	char					devname[DEV_PATH_MAX];
	char					sizestr[SIZE_LEN];
	char					errmsg[ERR_MSG_MAXLEN];
	unsigned long long int	size;
	int						cmd_index;
	int						cmd_mode;
	int						pyx_binary;
	int						padout_pdotp;
	FILE					*input;
	FILE					*output;
	FILE					*otp;
	FILE					*encrypted;
	int						device;
	char					input_fsp[MAX_FSP_PATH];
	char					output_fsp[MAX_FSP_PATH];
	char					otp_fsp[MAX_FSP_PATH];
	char					encrypted_fsp[MAX_FSP_PATH];
} options_t;

typedef int (*FUNC)(options_t *options);

extern int set_default_device(options_t *options);
extern int g_generate(options_t *options);
extern int e_encrypt(options_t *options);
extern int d_decrypt(options_t *options);
extern int p_pyx(options_t *options);

extern int enoch(char *version);
