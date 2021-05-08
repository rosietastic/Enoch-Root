/*
 * libenoch.c
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


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define LE_VERSION		"0.1"
#define FALSE 			0
#define TRUE  			1
#define log2of10 		3.32192809488736234787
#define	Z_MAX			6.0            /* maximum meaningful z value */
#define	LOG_SQRT_PI		0.5723649429247000870717135 /* log (sqrt (pi)) */
#define	I_SQRT_PI		0.5641895835477562869480795 /* 1 / sqrt (pi) */
#define	BIGX			20.0         /* max value to represent exp (x) */
#define	ex(x)			(((x) < -BIGX) ? 0.0 : exp(x))
#define MONTEN			6		/* Bytes used as Monte Carlo
								co-ordinates. This should be no more
								bits than the mantissa of your
								"double" floating point type. */
#define DEV_PATH_MAX	30
#define SIZE_LEN 		25
#define ERR_MSG_MAXLEN	80
#define MAX_FSP_PATH	128

#define DEV_DEFAULT_1	"/dev/TrueRNG"
#define DEV_DEFAULT_2	"/dev/random"
#define ERR_DEF_DEV 	"Default RNG devices not operating"
#define CMD_STD			9
#define CMD_ALT			1
#define ERR_WRITE_OTP 	"Error writing OTP file"
#define ERR_WRITE_PDOTP "Error writing PD OTP file"
#define ERR_READ_STAT	"Error reading encrypted file statistics"
#define ERR_OTP_STAT	"Error reading OTP file statistics"
#define ERR_GET_DEV 	"Error reading RNG device"
#define ERR_ENC_SHORT 	"Encrypted file is too short"
#define ERR_ENC_SIZE 	"Size specified is larger than input encrypted file"
#define ERR_OTP_SIZE 	"Size specified is larger than OTP file"
#define ERR_READ_INPUT 	"Error reading input clear file"
#define ERR_WRITE_ENC 	"Error writing encrypted file"
#define ERR_OTP_SHORT 	"Warning - OTP file is short for input encrypted file"
#define ERR_WRITE_DEC 	"Error writing decrypted file"
#define ERR_READ_INPUT 	"Error reading input clear file"
#define PI				3.14159265358979323846
#define PASS			"PASS"
#define FAIL			"FAIL"


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


static int binary = FALSE;		/* Treat input as a byte stream */
static long	ccount[256],		/* Bins to count occurrences of values */
			totalc = 0;			/* Total bytes counted */
static double prob[256];		/* Probabilities per bin for entropy */
static int mp, sccfirst;
static unsigned int monte[MONTEN];
static long inmont, mcount;
static double	cexp, incirc, montex, montey, montepi,
				scc, sccun, sccu0, scclast, scct1, scct2, scct3,
				ent, chisq, datasum;

/*FUNCTION poz: probability of normal z value */

/*ALGORITHM
	Adapted from a polynomial approximation in:
		Ibbetson D, Algorithm 209
		Collected Algorithms of the CACM 1963 p. 616
	Note:
		This routine has six digit accuracy, so it is only useful for absolute
		z values < 6.  For z values >= to 6.0, poz() returns 0.0.
*/

/*VAR returns cumulative probability from -oo to z */
/*VAR normal z value */

static double poz(const double z)
{
	double y, x, w;
	if (z == 0.0)
		x = 0.0;
	else {
		y = 0.5 * fabs(z);
		if (y >= (Z_MAX * 0.5))
			x = 1.0;
		else
			if (y < 1.0) {
				w = y * y;
				x = ((((((((0.000124818987 * w
				-0.001075204047) * w +0.005198775019) * w
				-0.019198292004) * w +0.059054035642) * w
				-0.151968751364) * w +0.319152932694) * w
				-0.531923007300) * w +0.797884560593) * y * 2.0;
			} else {
				y -= 2.0;
				x = (((((((((((((-0.000045255659 * y
				+0.000152529290) * y -0.000019538132) * y
				-0.000676904986) * y +0.001390604284) * y
				-0.000794620820) * y -0.002034254874) * y
				+0.006549791214) * y -0.010557625006) * y
				+0.011630447319) * y -0.009279453341) * y
				+0.005353579108) * y -0.002141268741) * y
				+0.000535310849) * y +0.999936657524;
			}
	}	
	return (z > 0.0 ? ((x + 1.0) * 0.5) : ((1.0 - x) * 0.5));
}

/*
	Module:       chisq.c
	Purpose:      compute approximations to chisquare distribution probabilities
	Contents:     pochisq()
	Uses:         poz() in z.c (Algorithm 209)
	Programmer:   Gary Perlman
	Organization: Wang Institute, Tyngsboro, MA 01879
	Copyright:    none
	Tabstops:     4
*/

/*FUNCTION pochisq: probability of chi sqaure value */
/*ALGORITHM Compute probability of chi square value.
	
	Adapted from:
		Hill, I. D. and Pike, M. C.  Algorithm 299
		Collected Algorithms for the CACM 1967 p. 243
	Updated for rounding errors based on remark in
		ACM TOMS June 1985, page 185
*/

double pochisq(
		const double ax,    /* obtained chi-square value */
		const int df	    /* degrees of freedom */
		)
{
	double x = ax;
	double a, y, s;
	double e, c, z;
	int even;	    	    /* true if df is an even number */

	if (x <= 0.0 || df < 1)
		return 1.0;

	a = 0.5 * x;
	even = (2 * (df / 2)) == df;
	if (df > 1)
		y = ex(-a);

	s = (even ? y : (2.0 * poz(-sqrt(x))));
	if (df > 2) {
		x = 0.5 * (df - 1.0);
		z = (even ? 1.0 : 0.5);
		if (a > BIGX) {
			e = (even ? 0.0 : LOG_SQRT_PI);
			c = log(a);
			while (z <= x) {
				e = log(z) + e;
				s += ex(c * z - a - e);
				z += 1.0;
    	    }
			return (s);
		} else {
			e = (even ? 1.0 : (I_SQRT_PI / sqrt(a)));
			c = 0.0;
			while (z <= x) {
				e = e * (a / z);
				c = c + e;
				z += 1.0;
    	    }
		return (c * y + s);
    	}
	} else {
		return s;
    }
}

/*  pyx_log2  --  calculate log to the base 2  */

static double pyx_log2(double x)
{
	return log2of10 * log10(x);
}

int enoch(char *version)
{
	strncpy(version, LE_VERSION, (strlen(LE_VERSION)+1)); 
	return TRUE;
}

/*  pyx_init  --  initialise random test counters.  */

void pyx_init(int binmode)
{
	int i;

	binary = binmode;		/* Set binary / byte mode */

	/* Initialise for calculations */

	ent = 0.0;				/* Clear entropy accumulator */
	chisq = 0.0;			/* Clear Chi-Square */
	datasum = 0.0;			/* Clear sum of bytes for arithmetic mean */

	mp = 0;					/* Reset Monte Carlo accumulator pointer */
	mcount = 0;				/* Clear Monte Carlo tries */
	inmont = 0;				/* Clear Monte Carlo inside count */
	incirc = 65535.0 * 65535.0;/* In-circle distance for Monte Carlo */

	sccfirst = TRUE;		/* Mark first time for serial correlation */
	scct1 = scct2 = scct3 = 0.0; /* Clear serial correlation terms */

	incirc = pow(pow(256.0, (double) (MONTEN / 2)) - 1, 2.0);

	for (i = 0; i < 256; i++) {
		ccount[i] = 0;
	}
	totalc = 0;
}

/*  pyx_add  --	add one or more bytes to accumulation.	*/

void pyx_add(void *buf, int bufl)
{
	unsigned char *bp = buf;
	int oc, c, bean, mj;

	while (bean = 0, (bufl-- > 0)) {
		oc = *bp++;

		do {
			if (binary) {
				c = !!(oc & 0x80);
			} else {
				c = oc;
			}
		ccount[c]++;		/* Update counter for this bin */
		totalc++;

		/* Update inside / outside circle counts for Monte Carlo
		computation of PI */

		if (bean == 0) {
			monte[mp++] = oc;       /* Save character for Monte Carlo */
			if (mp >= MONTEN) {     /* Calculate every MONTEN character */
				mp = 0;
				mcount++;
				montex = montey = 0;
				for (mj = 0; mj < MONTEN / 2; mj++) {
					montex = (montex * 256.0) + monte[mj];
					montey = (montey * 256.0) + monte[(MONTEN / 2) + mj];
				}
				if ((montex * montex + montey *  montey) <= incirc)
					inmont++;
			}
		}	

	/* Update calculation of serial correlation coefficient */

		sccun = c;
		if (sccfirst) {
			sccfirst = FALSE;
			scclast = 0;
			sccu0 = sccun;
		} else
			scct1 = scct1 + scclast * sccun;

		scct2 = scct2 + sccun;
		scct3 = scct3 + (sccun * sccun);
		scclast = sccun;
		oc <<= 1;
		} while (binary && (++bean < 8));
    }
}

/*  pyx_end  --	complete calculation and return results.  */

void pyx_end	(double *r_ent, double *r_chisq, double *r_mean,
				double *r_montepicalc, double *r_scc)
{
	int i;
	double a;

	/* Complete calculation of serial correlation coefficient */

	scct1 = scct1 + scclast * sccu0;
	scct2 = scct2 * scct2;
	scc = totalc * scct3 - scct2;
	if (scc == 0.0)
		scc = -100000;
	else {
		scc = (totalc * scct1 - scct2) / scc;
    }

	/* 	Scan bins and calculate probability for each bin and
		Chi-Square distribution.  The probability will be reused
		in the entropy calculation below.  While we're at it,
		we sum of all the data which will be used to compute the
		mean. */
       
	cexp = totalc / (binary ? 2.0 : 256.0);  /* Expected count per bin */
	for (i = 0; i < (binary ? 2 : 256); i++) {
		a = ccount[i] - cexp;;

		prob[i] = ((double) ccount[i]) / totalc;       
		chisq += (a * a) / cexp;
		datasum += ((double) i) * ccount[i];
    }

	/* Calculate entropy */

	for (i = 0; i < (binary ? 2 : 256); i++) {
		if (prob[i] > 0.0)
			ent += prob[i] * pyx_log2(1 / prob[i]);
    }

	/* 	Calculate Monte Carlo value for PI from percentage of hits
		within the circle */

	montepi = 4.0 * (((double) inmont) / mcount);

	/* Return results through arguments */

	*r_ent = ent;
	*r_chisq = chisq;
	*r_mean = datasum / totalc;
	*r_montepicalc = montepi;
	*r_scc = scc;
}

int set_default_device(options_t *options) 
{
	strncpy(options->devname, DEV_DEFAULT_1, DEV_PATH_MAX);
	if ((options->device = open(options->devname, O_RDONLY)) < 0) {
		strncpy(options->devname, DEV_DEFAULT_2, DEV_PATH_MAX);
		if ((options->device = open(options->devname, O_RDONLY)) < 0) {
			strncpy(options->errmsg, ERR_DEF_DEV, (strlen(ERR_DEF_DEV)+1)); 
			return(EXIT_FAILURE);
		}    
	}

	return(EXIT_SUCCESS);

}

/* G -s<size BKMG> -pfsp || G -ifsp -efsp -pfsp -f */
/* [G -s1M -pnew.otp] */
/* [G -iclear.in -eexisting.enc -pnew.otp -f] */

int	g_generate(options_t *options)
{
unsigned long long keep_count, i;
char byte;
int clear_ch, enc_ch;
struct stat sb;

	keep_count=i=0;

	switch (options->cmd_mode) {
		case CMD_STD:

		keep_count = options->size;

		while (keep_count-- > 0) {
			if (read(options->device, &byte, 1) > 0) {
				if (fputc(byte, options->otp) == EOF) {
					strncpy(options->errmsg, ERR_WRITE_OTP, (strlen(ERR_WRITE_OTP)+1)); 
					return(EXIT_FAILURE);
				}
			} else {
				strncpy(options->errmsg, ERR_GET_DEV, (strlen(ERR_GET_DEV)+1)); 
				return(EXIT_FAILURE);
			}
		}

		break;

		case CMD_ALT:

		while ((clear_ch = fgetc(options->input) ) != EOF) {
			keep_count++;
			if ((enc_ch = fgetc(options->encrypted) ) != EOF) {
				if (fputc((clear_ch^enc_ch), options->otp) == EOF) {
					strncpy(options->errmsg, ERR_WRITE_PDOTP, (strlen(ERR_WRITE_PDOTP)+1)); 
					return(EXIT_FAILURE);
				}
			} else {
				strncpy(options->errmsg, ERR_ENC_SHORT, (strlen(ERR_ENC_SHORT)+1)); 
				return(EXIT_FAILURE);
			}
		}

		if (keep_count == 0) {
			strncpy(options->errmsg, ERR_READ_INPUT, (strlen(ERR_READ_INPUT)+1)); 
			return(EXIT_FAILURE);
		} else
			if(options->padout_pdotp) {
				if (stat(options->encrypted_fsp, &sb)==-1) {
					strncpy(options->errmsg, ERR_READ_STAT, (strlen(ERR_READ_STAT)+1)); 
					return(EXIT_FAILURE);
				}			
				for(i=keep_count; i<(unsigned long long)sb.st_size; i++) {
					if (read(options->device, &byte, 1) > 0) {
						if (fputc(byte, options->otp) == EOF) {
							strncpy(options->errmsg, ERR_WRITE_OTP, (strlen(ERR_WRITE_OTP)+1)); 
							return(EXIT_FAILURE);
						}
					}
				}
			}
		break;
	}
	return(EXIT_SUCCESS);
}

/* E -ifsp -pfsp -ofsp  || E -ifsp -pnewfsp -ofsp */
/* [E -iclear.in -pexisting.otp -oencrypted.out] */
/* [E -iclear.in -pnew.otp -oencrypted.out] */

int	e_encrypt(options_t *options)
{
char byte;
int clear_ch, otp_ch;
int inp_fine = FALSE;
	
	switch (options->cmd_mode) {
		case CMD_STD:

		while ((clear_ch = fgetc(options->input) ) != EOF) {
			inp_fine = TRUE;
			if ((otp_ch = fgetc(options->otp) ) != EOF) {
				if ((fputc((clear_ch^otp_ch), options->output)) == EOF) {
					strncpy(options->errmsg, ERR_WRITE_ENC, (strlen(ERR_WRITE_ENC)+1)); 
					return(EXIT_FAILURE);
				}
			} else {
				strncpy(options->errmsg, ERR_OTP_SHORT, (strlen(ERR_OTP_SHORT)+1)); 
				return(EXIT_FAILURE);
			}
		}

		if (inp_fine == FALSE) {
			strncpy(options->errmsg, ERR_READ_INPUT, (strlen(ERR_READ_INPUT)+1)); 
			return(EXIT_FAILURE);
		}

		break;

		case CMD_ALT:

		while ((clear_ch = fgetc(options->input) ) != EOF) {
			if (read(options->device, &byte, 1) > 0) {
				if (fputc(byte, options->otp) == EOF) {
					strncpy(options->errmsg, ERR_WRITE_OTP, (strlen(ERR_WRITE_OTP)+1)); 
					return(EXIT_FAILURE);
				}
				if (fputc(clear_ch^byte, options->output) == EOF) {
					strncpy(options->errmsg, ERR_WRITE_ENC, (strlen(ERR_WRITE_ENC)+1)); 
					return(EXIT_FAILURE);
				}
			} else {
				strncpy(options->errmsg, ERR_GET_DEV, (strlen(ERR_GET_DEV)+1)); 
				return(EXIT_FAILURE);
			}
		}

		break;
	}
	return(EXIT_SUCCESS);
}

/* D -ifsp -pfsp -ofsp || D -ifsp -pfsp -ofsp -s<size BKMG> */
/* [D -iencrypted.in -pexisting.otp -oclear.out] */ 
/* [D -iencrypted.in -pexisting.otp -oclear.out -s1M] */ 

int	d_decrypt(options_t *options)
{
int enc_ch, otp_ch;
int inp_fine = FALSE;
unsigned long long keep_count;
struct stat sb;

	keep_count=0;

	if(options->size>0) {
		if (stat(options->input_fsp, &sb)==-1) {
			strncpy(options->errmsg, ERR_READ_STAT, (strlen(ERR_READ_STAT)+1)); 
			return(EXIT_FAILURE);
		}

		if(options->size>(unsigned long long)sb.st_size) {
			strncpy(options->errmsg, ERR_ENC_SIZE, (strlen(ERR_ENC_SIZE)+1)); 
			return(EXIT_FAILURE);
		}

		if (stat(options->otp_fsp, &sb)==-1) {
			strncpy(options->errmsg, ERR_OTP_STAT, (strlen(ERR_OTP_STAT)+1)); 
			return(EXIT_FAILURE);
		}

		if(options->size>(unsigned long long)sb.st_size) {
			strncpy(options->errmsg, ERR_OTP_SIZE, (strlen(ERR_OTP_SIZE)+1)); 
			return(EXIT_FAILURE);
		}
	}

	while ((enc_ch = fgetc(options->input) ) != EOF) {
		inp_fine = TRUE;
		if ((otp_ch = fgetc(options->otp) ) != EOF) {
			if ((fputc((enc_ch^otp_ch), options->output)) == EOF) {
				strncpy(options->errmsg, ERR_WRITE_DEC, (strlen(ERR_WRITE_DEC)+1)); 
				return(EXIT_FAILURE);
			}
			if (options->size >0)
				if ((++keep_count)>=options->size)
						break;
		} else {
			strncpy(options->errmsg, ERR_OTP_SHORT, (strlen(ERR_OTP_SHORT)+1)); 
			return(EXIT_FAILURE);
		}
	}

	if (inp_fine == FALSE) {
		strncpy(options->errmsg, ERR_READ_INPUT, (strlen(ERR_READ_INPUT)+1)); 
		return(EXIT_FAILURE);
	}

	return(EXIT_SUCCESS);
}

/* perform pyx trial on existing otp : entropy, chi square, mean */ 
/* binary/byte mode and text stdout/terse fsp output */

/* P -pfsp -b || P -pfsp -ofsp -b */
/* [P -pexisting.otp] [-b] */
/* [P -pexisting.otp -oterse.rpt] [-b] */

int	p_pyx(options_t *options)
{
	int b, oc, result[6];
	long ccount[256];	      /* Bins to count occurrences of values */
	long totalc = 0;	      /* Total character count */
	char *samp;
	double montepi, chip, scc, ent, mean, chisq;
	unsigned char ocb, ob;

	samp = options->pyx_binary ? "bit" : "byte";
	memset(ccount, 0, sizeof ccount);
	memset(result, FALSE, sizeof result);

	/* Initialise for calculations */

	pyx_init(options->pyx_binary);

	/* Scan input file and count character occurrences */

	while ((oc = fgetc(options->otp)) != EOF) {
		ocb = (unsigned char) oc;
		totalc += options->pyx_binary ? 8 : 1;
		if (options->pyx_binary) {
			ob = ocb;
			for (b = 0; b < 8; b++) {
				ccount[ob & 1]++;
				ob >>= 1;
			}	
		} else
			ccount[ocb]++;	      /* Update counter for this bin */

	pyx_add(&ocb, 1);
	}

	/* Complete calculation and return sequence metrics */

	pyx_end(&ent, &chisq, &mean, &montepi, &scc);

	if (options->cmd_mode==CMD_ALT) {
		fprintf(options->output, "0,File-%ss,Entropy,Chi-square,Mean,Monte-Carlo-Pi,Serial-Correlation\n", options->pyx_binary ? "bit" : "byte");
		fprintf(options->output, "1,%ld,%f,%f,%f,%f,%f\n", totalc, ent, chisq, mean, montepi, scc);
	}

	/* Print calculated results */

	if (options->cmd_mode!=CMD_ALT) {
	/* Calculate probability of observed distribution occurring from
	   the results of the Chi-Square test */

		chip = pochisq(chisq, (options->pyx_binary ? 1 : 255));

		result[0] = (ent <= 7.5)?FALSE:TRUE;
		result[1] = (((short) ((100 * ((options->pyx_binary ? 1 : 8) - ent) / (options->pyx_binary ? 1.0 : 8.0)))) > 1)?FALSE:TRUE;
		result[2] = ((chip * 100 <= 10) || (chip * 100 >= 90))?FALSE:TRUE;
		result[3] = (((options->pyx_binary)&&(mean <= 4.5)&&(mean >= 5.5))||((!options->pyx_binary)&&(mean <= 127)&&(mean >= 128)))?FALSE:TRUE;
		result[4] = (((100.0 * (fabs(PI - montepi) / PI)) > 0.3)&&((100.0 * (fabs(PI - montepi) / PI)) > 0.01))?FALSE:TRUE;
		result[5] = (scc >= 0.1)?FALSE:TRUE;

		printf("Pyx Trial Assessment\n");
		printf("OVERALL		: %s && %s && %s && %s && %s = %s\n\n", (result[0]&&result[1])?PASS:FAIL, result[2]?PASS:FAIL, result[3]?PASS:FAIL, result[4]?PASS:FAIL, result[5]?PASS:FAIL, (result[0]&&result[1]&&result[2]&&result[3]&&result[4]&&result[5])?PASS:FAIL);
		printf("One Time Pad Density\n");
		printf("Entropy : %f bits per %s.\n", ent, samp);
		printf("Optimum compression of OTP file size %ld %ss by %d percent\n", totalc, samp, (short) ((100 * ((options->pyx_binary ? 1 : 8) - ent) / (options->pyx_binary ? 1.0 : 8.0))));
		printf("\t[GOOD 		= Entropy close to 8 bits, compression 0 percent]\n\n");
		printf("One Time Pad Distribution\n");
		printf("Chi Square : for %ld samples is %1.2f\n", totalc, chisq);
		if (chip < 0.0001)
			printf("Value would be exceeded randomly less than 0.01 percent of the times.\n");
		else 
			if (chip > 0.9999)
				printf("Value would be exceeded randomly more than than 99.99 percent of the times.\n");
			else {
				printf("Value would be exceeded randomly %1.2f percent of the times.\n", chip * 100);
			}
		printf("\t[GOOD 		= 10 percent to 90 percent]\n");
		printf("\t[SUSPECT 	= 5 to 10 percent or 90 to 95 percent]\n");
		printf("\t[WORSE		= 1 to 5 percent or 95 to 99 percent]\n");
		printf("\t[WORST		= 0 to 1 percent or 99 to 100 percent]\n");
				
		printf("Arithmetic mean of data %ss is %1.4f\n", samp, mean);
		printf("\t[RANDOM 	= %.1f]\n", options->pyx_binary ? 0.5 : 127.5);

		printf("Monte Carlo value for Pi is %1.9f (error %1.2f percent)\n", montepi, 100.0 * (fabs(PI - montepi) / PI));
		printf("\t[RANDOM		= error 0.06 percent]\n");

		printf("Serial correlation coefficient is ");

		if (scc >= -99999)
			printf("%1.6f\n", scc);
		else
			printf("undefined (all values are equal)\n");
		printf("\t[RANDOM		= 0.0]\n");
		printf("\t[PREDICTED	= 1.0]\n");
	}
	return(EXIT_SUCCESS);
}
