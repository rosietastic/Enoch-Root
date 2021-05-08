/*
 * er.c
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

/* er : Equivocable dual acronym. "Encrypt Right" and "Enoch Root" */
/* er : One Time Pad management to encrypt, decrypt, assess and deny */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <ctype.h>
#include <math.h>
#include "libenoch.h"

/* er usage */

/* Commands : G, E, D, P */
/* Generate OTP/PD OTP, Encrypt, Decrypt, Pyx */

/* G -s<size BKMG> -pfsp || G -ifsp -efsp -pfsp -f */
/* [G -s1M -pnew.otp] */
/* [G -iclear.in -eexisting.enc -pnew.otp -f] */

/* E -ifsp -pfsp -ofsp  || E -ifsp -pnewfsp -ofsp */
/* [E -iclear.in -pexisting.otp -oencrypted.out] */
/* [E -iclear.in -pnew.otp -oencrypted.out] */

/* D -ifsp -pfsp -ofsp || D -ifsp -pfsp -ofsp -s<size BKMG> */
/* [D -iencrypted.in -pexisting.otp -oclear.out] */ 
/* [D -iencrypted.in -pexisting.otp -oclear.out -s1M] */ 

/* P -pfsp -b || P -pfsp -ofsp -b */
/* [P -pexisting.otp] [-b] */
/* [P -pexisting.otp -oterse.rpt] [-b] */

/* -v : verbose output */
/* -r : select random number generation device */
/* -b ; binary mode for Pyx */
/* -f : fill PD OTP for plausible deniability */

#define ER_VERSION	"0.1"
#define REQ_LE_VERSION "0.1"
#define ERR_LE_MISMATCH "Mismatch with libenoch version : Required %s; libenoch installed %s\n"
#define OPTSTR "GEDPvfbr:i:s:o:p:e:h"
#define GCMD			0
#define	ECMD			1
#define DCMD			2
#define PCMD			3
#define ZCMD			4
#define CMD_STD			9
#define CMD_ALT			1
#define FALSE			0
#define TRUE			1
#define START			0
#define END				1
#define USAGE_FMT0 "%s : Equivocable dual acronym \"Encrypt Right\"/\"Enoch Root\" (v%s;libenoch:v%s)\n"
#define USAGE_FMT9 "%s : Equivocable dual acronym \"Encrypt Right\"/\"Enoch Root\" (v%s)\n"
#define USAGE_FMT1 "%s : -G : Generate OTP/PD OTP, -E : Encrypt, -D : Decrypt, -P : Pyx\n[-i inputfile] [-e inputfile] [-p otp file] [-o outputfile]\n[-s size] [-r devname] [-v] [-b] [-f] [-h]\n\n"
#define USAGE_FMT2 "-G -s<size BKMG> -pfsp || -G -ifsp -efsp -pfsp -f\n[-G -s1M -pnew.otp]\n[-G -iclear.in -eexisting.enc -pnew.otp -f]\n\n"
#define USAGE_FMT3 "-E -ifsp -pfsp -ofsp  || -E -ifsp -pnewfsp -ofsp\n[-E -iclear.in -pexisting.otp -oencrypted.out]\n[-E -iclear.in -pnew.otp -oencrypted.out]\n\n"
#define USAGE_FMT4 "-D -ifsp -pfsp -ofsp || -D -ifsp -pfsp -ofsp -s<size BKMG>\n[-D -iencrypted.in -pexisting.otp -oclear.out]\n[-D -iencrypted.in -pexisting.otp -oclear.out -s1M]\n\n"
#define USAGE_FMT5 "-P -pfsp -b || -P -pfsp -ofsp -b\n[-P -pexisting.otp] [-b]\n[-P -pexisting.otp -oterse.rpt] [-b]\n\n"
#define USAGE_FMT6 "-v : Verbose output, -r : RNG device, -b : Pyx binary mode, -f : Fill PD OTP\n"
#define USAGE_FMT7 "%s : One Time Pad management to generate, encrypt, decrypt, assess and deny\n"

#define VERB_FMT10 "%s : \"Encrypt Right\"/\"Enoch Root\"\n"
#define VERB_FMT10a "(An equivocable dual acronym)\n"
#define VERB_FMT10b "(C)2021 Paul Rose <rosietastic@lavabit.com>\n"
#define VERB_FMT11 "%s : v%s; libenoch : v%s\n\n"
#define VERB_FMT12 "RNG device is %s\n"
#define VERB_FMT13 "Command selected is %c : %s\n"
#define VERB_FMT14 "Mode description :\n"
#define VERB_FMT14a "Generate new OTP by size\n"
#define VERB_FMT14b "Generate new OTP from clear file and encrypted file for plausible deniability\n"
#define VERB_FMT14bb "(Fill new OTP to encrypted file size)\n"
#define VERB_FMT14c "Encrypt clear file with existing OTP to create new encrypted file\n"
#define VERB_FMT14d "Encrypt clear file with dynamically created OTP to create new encrypted file\n"
#define VERB_FMT14e "Decrypt input encrypted file with existing OTP to create clear file\n"
#define VERB_FMT14ee "Decrypt input encrypted file (to size) with existing OTP to create clear file\n"
#define VERB_FMT14f "Perform Pyx Assessment of input OTP (bytemode); detailed output to stdout\n"
#define VERB_FMT14g "Perform Pyx Assessment of input OTP (bitmode); detailed output to stdout\n"
#define VERB_FMT14h "Perform Pyx Assessment of input OTP (bytemode); terse output to file\n"
#define VERB_FMT14i "Perform Pyx Assessment of input OTP (bitmode); terse output to file\n"
#define VERB_FMT15 "\nInput fsp : <%s>\n"
#define VERB_FMT16 "Output fsp : <%s>\n"
#define VERB_FMT17 "Encrypted fsp <%s>\n"
#define VERB_FMT18 "OTP fsp : <%s>\n"
#define VERB_FMT19 "OTP size is <%s>\n"
#define VERB_FMT20 "OTP fsp for plausible deniability : <%s>\n"
#define VERB_FMT21 "OTP size for plausible deniability : <%s>\n"

#define CMD_GENERATE "Generate"
#define CMD_ENCRYPT "Encrypt"
#define CMD_DECRYPT "Decrypt"
#define CMD_PYX "Pyx Assessment"

#define ERR_CLOSE "Error closing: "
#define ERR_CLOSE_INPUT "Input fsp; "
#define ERR_CLOSE_OUTPUT "Output fsp; "
#define ERR_CLOSE_ENCRYPT "Encrypted fsp; "
#define ERR_CLOSE_OTP "OTP fsp; "
#define ERR_CLOSE_DEV "RNG device; "

#define ERR_FOPEN_INPUT  "Can't open Input file specified (read)"
#define ERR_FOPEN_OUTPUT "Can't open Output file specified (write)"
#define ERR_FOPEN_OTP "Can't open OTP file specified"
#define ERR_FOPEN_ENCRYPTED "Can't open Encrypted dile specified"
#define ERR_BINARY_SPECIFIED "Binary option only to be used with Pyx command"
#define ERR_PADOTP_SPECIFIED "Fill OTP only to be used with Generate/plausible deniability command"
#define ERR_CHK_DEV "Device specified cannot be opened"
#define DEV_PREFIX_STR "/dev/"
#define ERR_CHK_SIZE "Size specified in error"
#define ERR_CHK_MULTICMD "Only a single commqnd should be specified, multiple commands not allowed"
#define ERR_CHK_GCMD "Error : G (Generate) command usage is incorrect. Reference -h or manual"
#define ERR_CHK_ECMD "Error : E (Encrypt) command usage is incorrect. Reference -h or manual"
#define ERR_CHK_DCMD "Error : D (Decrypt) command usage is incorrect. Reference -h or manual"
#define ERR_CHK_PCMD "Error : P (Pyx assessment) command usage is incorrect. Reference -h or manual"
#define ERR_CHK_ZCMD "Error : No valid command specified. Reference -h or manual"
#define ERR_PARAMSIZE_INP "Specified -i (input) fsp is too long"
#define ERR_PARAMSIZE_ENC "Specified -e (encrypted) fsp is too long"
#define ERR_PARAMSIZE_OUT "Specified -o (output) fsp is too long"
#define ERR_PARAMSIZE_OTP "Specified -p (OTP) fsp is too long"
#define ERR_PARAMSIZE_SIZ "Specified -s (size) value is too long"
#define ERR_PARAMSIZE_DEV "Specified -r (device) name is too long"
#define DEFAULT_PROGNAME "er"

extern int errno;
extern char *optarg;
extern int opterr, optind;

void	verbose(int mode, char *ver, int cmd, char *progname, options_t *options);
int		validate_cli_multicmd(int opt, options_t *options, char *progname, int *cmd, int *onecmd, char *ver);
int		validate_cli_options(int opt, options_t *options, char *progname, int *cmd, int *onecmd, char *ver);
int 	validate_cli_command(int cmd, options_t *options);
void	usage(char *ver, char *progname);
int		factor_suffix(options_t *options);
int		tidy_up(FUNC *ptrfunc, options_t *options);

int	main(int argc, char *argv[]) {
	int opt, cmd, onecmd;
	char ver[5];

	FUNC *ptrfunc = (FUNC *)malloc(sizeof(FUNC) * 4);
	
	ptrfunc[0] = &g_generate;
    ptrfunc[1] = &e_encrypt;
	ptrfunc[2] = &d_decrypt;
	ptrfunc[3] = &p_pyx;

	options_t options = { FALSE, "", "", "", 0LL, ZCMD, CMD_STD, FALSE, FALSE, stdin, stdout, stdin, stdin, 0, "", "", "", "" };
	opterr = onecmd = 0;
	memset(options.devname,	'\0', DEV_PATH_MAX);
	memset(options.sizestr,	'\0', SIZE_LEN);
	memset(options.errmsg,	'\0', ERR_MSG_MAXLEN);
	memset(options.input_fsp, '\0', MAX_FSP_PATH);
	memset(options.output_fsp, '\0', MAX_FSP_PATH);
	memset(options.otp_fsp, '\0', MAX_FSP_PATH);
	memset(options.encrypted_fsp,'\0', MAX_FSP_PATH);
	memset(ver,	'\0', 5);

	if(enoch(&(ver[0])))
		if (strncmp(&(ver[0]), REQ_LE_VERSION, 3) !=0) {
			fprintf(stderr, ERR_LE_MISMATCH, REQ_LE_VERSION, &(ver[0]));
			if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
				fprintf(stderr,"%s\n", options.errmsg);
			
			return(EXIT_FAILURE);
			/* NOTREACHED */
		}

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
		if (validate_cli_multicmd(opt, &options, argv[0], &cmd, &onecmd, &(ver[0]))!=EXIT_SUCCESS) {
			fprintf(stderr,"%s\n", options.errmsg);
			if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
				fprintf(stderr,"%s\n", options.errmsg);

			return(EXIT_FAILURE);
			/* NOTREACHED */
		}

	opterr = 0;
	optind = 1;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
		if (validate_cli_options(opt, &options, argv[0], &cmd, &onecmd, &(ver[0]))!=EXIT_SUCCESS) {
			fprintf(stderr,"%s\n", options.errmsg);
			if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
				fprintf(stderr,"%s\n", options.errmsg);

			return(EXIT_FAILURE);
			/* NOTREACHED */
		}

	if (options.devname[0]=='\0')
		if(set_default_device(&options)!=EXIT_SUCCESS) {
			fprintf(stderr,"%s\n", options.errmsg);
			if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
				fprintf(stderr,"%s\n", options.errmsg);

			return(EXIT_FAILURE);
			/* NOTREACHED */
	}

	if (validate_cli_command(cmd, &options)!=EXIT_SUCCESS) {
		fprintf(stderr,"%s\n", options.errmsg);
		if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
			fprintf(stderr,"%s\n", options.errmsg);

		return(EXIT_FAILURE);
		/* NOTREACHED */
	}

	if (options.cmd_index==ZCMD) {
		strncpy(options.errmsg, ERR_CHK_ZCMD, (strlen(ERR_CHK_ZCMD)+1)); 
		fprintf(stderr,"%s\n", options.errmsg);
		if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
			fprintf(stderr,"%s\n", options.errmsg);

		return(EXIT_FAILURE);
		/* NOTREACHED */
	}
	else {
		if (options.verbose == TRUE)
			verbose(START, &(ver[0]), cmd, argv[0], &options);
			
		if (ptrfunc[options.cmd_index](&options) != EXIT_SUCCESS) {
			fprintf(stderr,"%s\n", options.errmsg);
			if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS)
				fprintf(stderr,"%s\n", options.errmsg);

			return(EXIT_FAILURE);
			/* NOTREACHED */
		}

		if (options.verbose == TRUE)
			verbose(END, &(ver[0]), cmd, argv[0], &options);
	}

	if(tidy_up(ptrfunc, &options)!=EXIT_SUCCESS) {
		fprintf(stderr,"%s\n", options.errmsg);

		return(EXIT_FAILURE);
		/* NOTREACHED */
	}

	return(EXIT_SUCCESS);
}

int tidy_up(FUNC *ptrfunc, options_t *options) 
{
char compound_errors[ERR_MSG_SUFFIX];

	free((void *)ptrfunc);
	memset(options->errmsg,'\0', ERR_MSG_MAXLEN);
	memset(compound_errors,'\0', ERR_MSG_SUFFIX);

	if((options->input!=stdin)&&(options->input!=NULL))
		if(fclose(options->input)==EOF)
			strncat(compound_errors, ERR_CLOSE_INPUT, (strlen(ERR_CLOSE_INPUT)+1));

	if((options->output!=stdout)&&(options->output!=NULL))
		if(fclose(options->output)==EOF)
			strncat(compound_errors, ERR_CLOSE_OUTPUT, (strlen(ERR_CLOSE_OUTPUT)+1));

	if((options->otp!=stdin)&&(options->otp!=NULL))
		if(fclose(options->otp)==EOF)
			strncat(compound_errors, ERR_CLOSE_OTP, (strlen(ERR_CLOSE_OTP)+1));

	if((options->encrypted!=stdin)&&(options->encrypted!=NULL))
		if(fclose(options->encrypted)==EOF)
			strncat(compound_errors, ERR_CLOSE_ENCRYPT, (strlen(ERR_CLOSE_ENCRYPT)+1));

	if(options->device > 0)
		if(close(options->device)==-1)
			strncat(compound_errors, ERR_CLOSE_DEV, (strlen(ERR_CLOSE_DEV)+1));

	if(compound_errors[0]!='\0') {
		strncpy(options->errmsg, ERR_CLOSE, (strlen(ERR_CLOSE)+1));
		strncat(options->errmsg, compound_errors, (strlen(compound_errors)+1));
		return(EXIT_FAILURE);
	}

	return(EXIT_SUCCESS);
}

void verbose(int mode, char *ver, int cmd, char *progname, options_t *options)
{
char desc[16];
char mode_desc[81];
char mode_desc2[40];

	memset(&(desc[0]),'\0', 16);
	memset(&(mode_desc[0]),'\0', 81);
	memset(&(mode_desc2[0]),'\0', 40);

	switch((char)cmd) {
		case 'G':
			strncpy(&(desc[0]), CMD_GENERATE, (strlen(CMD_GENERATE)+1)); 
			if (options->cmd_mode == CMD_STD)
				strncpy(&(mode_desc[0]), VERB_FMT14a, (strlen(VERB_FMT14a)+1)); 
			else {
				strncpy(&(mode_desc[0]), VERB_FMT14b, (strlen(VERB_FMT14b)+1)); 
				if(options->padout_pdotp)
					strncpy(&(mode_desc2[0]), VERB_FMT14bb, (strlen(VERB_FMT14bb)+1)); 
			}
			break;

		case 'E':
			strncpy(&(desc[0]), CMD_ENCRYPT, (strlen(CMD_ENCRYPT)+1)); 
			if (options->cmd_mode == CMD_STD)
				strncpy(&(mode_desc[0]), VERB_FMT14c, (strlen(VERB_FMT14c)+1)); 
			else
				strncpy(&(mode_desc[0]), VERB_FMT14d, (strlen(VERB_FMT14d)+1)); 

			break;

		case 'D':
			strncpy(&(desc[0]), CMD_DECRYPT, (strlen(CMD_DECRYPT)+1)); 
			if (options->sizestr[0]!='\0')
				strncpy(&(mode_desc[0]), VERB_FMT14ee, (strlen(VERB_FMT14ee)+1));
			else
				strncpy(&(mode_desc[0]), VERB_FMT14e, (strlen(VERB_FMT14e)+1)); 

			break;

		case 'P':
			strncpy(&(desc[0]), CMD_PYX, (strlen(CMD_PYX)+1)); 
			if (options->cmd_mode == CMD_STD) {
				if (options->pyx_binary)
					strncpy(&(mode_desc[0]), VERB_FMT14g, (strlen(VERB_FMT14g)+1)); 
				else
					strncpy(&(mode_desc[0]), VERB_FMT14f, (strlen(VERB_FMT14f)+1)); 
			}
			else {
				if (options->pyx_binary)
					strncpy(&(mode_desc[0]), VERB_FMT14i, (strlen(VERB_FMT14i)+1)); 
				else
					strncpy(&(mode_desc[0]), VERB_FMT14h, (strlen(VERB_FMT14h)+1)); 
			}

			break;
	}

	switch(mode) {
		case START:
			fprintf(stdout, VERB_FMT10, progname?progname:DEFAULT_PROGNAME);
			fprintf(stdout, VERB_FMT10a);
			fprintf(stdout, VERB_FMT10b);
			fprintf(stdout, VERB_FMT11, progname?progname:DEFAULT_PROGNAME, ER_VERSION, ver);
			fprintf(stdout, VERB_FMT12, options->devname);
			fprintf(stdout, VERB_FMT13, (char)cmd, &(desc[0]));
			fprintf(stdout, VERB_FMT14);
			fprintf(stdout, "%s", &(mode_desc[0]));
			if(mode_desc2[0]!='\0')
				fprintf(stdout, "%s", &(mode_desc2[0]));
			break;

		case END:
			if(*options->input_fsp!='\0')
				fprintf(stdout, VERB_FMT15, options->input_fsp);
			if(*options->output_fsp!='\0')
				fprintf(stdout, VERB_FMT16, options->output_fsp);
			if(*options->encrypted_fsp!='\0')
				fprintf(stdout, VERB_FMT17, options->encrypted_fsp);

			if((cmd=='G')&&(options->cmd_mode==CMD_ALT)&&(*options->otp_fsp!='\0'))
				fprintf(stdout, VERB_FMT20, options->otp_fsp);
			else
				if(*options->otp_fsp!='\0')
					fprintf(stdout, VERB_FMT18, options->otp_fsp);

			if(*options->sizestr!='\0')
				fprintf(stdout, VERB_FMT19, options->sizestr);
		
			break;

	}
}

int validate_cli_multicmd(int opt, options_t *options, char *progname, int *cmd, int *onecmd, char *ver) {

	switch(opt) {
		case 'G':
		case 'E':
		case 'D':
		case 'P':
			*cmd=opt;
			if (++(*onecmd)>1) {
				strncpy(options->errmsg, ERR_CHK_MULTICMD, (strlen(ERR_CHK_MULTICMD)+1)); 
				return(EXIT_FAILURE);
			}

			break;

		case 'i':
			break;

		case 'o':
			break;

		case 'p':
			break;

		case 'e':
			break;

		case 'v':
			break;

		case 'b':
			break;

		case 'r':
			break;

		case 's':
			break;

		case 'f':
			break;

		case 'h':
		default:
			usage(ver, basename(progname));
			return(EXIT_FAILURE);
			break;
		}

	return(EXIT_SUCCESS);
}

int validate_cli_options(int opt, options_t *options, char *progname, int *cmd, int *onecmd, char *ver) {
char dname[DEV_PATH_MAX] = DEV_PREFIX_STR;

	switch(opt) {
		case 'i':
			if (strlen(optarg)>MAX_FSP_PATH) {
				strncpy(options->errmsg, ERR_PARAMSIZE_INP, (strlen(ERR_PARAMSIZE_INP)+1)); 
				return(EXIT_FAILURE);
			}

			if (!(options->input = fopen(optarg, "r")) ) {
				strncpy(options->errmsg, ERR_FOPEN_INPUT, (strlen(ERR_FOPEN_INPUT)+1)); 
				return(EXIT_FAILURE);
			}
			strncpy(options->input_fsp, optarg, (strlen(optarg)+1));

			break;

		case 'o':
			if (strlen(optarg)>MAX_FSP_PATH) {
				strncpy(options->errmsg, ERR_PARAMSIZE_OUT, (strlen(ERR_PARAMSIZE_OUT)+1)); 
				return(EXIT_FAILURE);
			}

			if (!(options->output = fopen(optarg, "w")) ) {
				strncpy(options->errmsg, ERR_FOPEN_OUTPUT, (strlen(ERR_FOPEN_OUTPUT)+1)); 
				return(EXIT_FAILURE);
			}
			strncpy(options->output_fsp, optarg, (strlen(optarg)+1));

			break;

		case 'p':
			if (strlen(optarg)>MAX_FSP_PATH) {
				strncpy(options->errmsg, ERR_PARAMSIZE_OTP, (strlen(ERR_PARAMSIZE_OTP)+1)); 
				return(EXIT_FAILURE);
			}

			if (*cmd==(int)'E'&&(options->otp = fopen(optarg, "r"))) {
				strncpy(options->otp_fsp, optarg, (strlen(optarg)+1));
				break;
			} else
				if (*cmd==(int)'E'&&(options->otp = fopen(optarg, "w"))) {
					options->cmd_mode=CMD_ALT;
					strncpy(options->otp_fsp, optarg, (strlen(optarg)+1));
					break;
				}

			if (*cmd==(int)'G'&&(options->sizestr[0]!='\0')) {
				if (!(options->otp = fopen(optarg, "w")) ) {
					strncpy(options->errmsg, ERR_FOPEN_OTP, (strlen(ERR_FOPEN_OTP)+1)); 
					return(EXIT_FAILURE);
				}
				strncpy(options->otp_fsp, optarg, (strlen(optarg)+1));
				break;
			}
			else
				if (*cmd==(int)'G'&&(options->otp = fopen(optarg, "w"))) {
					options->cmd_mode=CMD_ALT;
					strncpy(options->otp_fsp, optarg, (strlen(optarg)+1));
					break;
				}

			if (!(options->otp = fopen(optarg, "r")) ) {
				strncpy(options->errmsg, ERR_FOPEN_OTP, (strlen(ERR_FOPEN_OTP)+1)); 
				return(EXIT_FAILURE);
			}
			strncpy(options->otp_fsp, optarg, (strlen(optarg)+1));
			break;

		case 'e':
			if (strlen(optarg)>MAX_FSP_PATH) {
				strncpy(options->errmsg, ERR_PARAMSIZE_ENC, (strlen(ERR_PARAMSIZE_ENC)+1)); 
				return(EXIT_FAILURE);
			}

			if (!(options->encrypted = fopen(optarg, "r")) ) {
				strncpy(options->errmsg, ERR_FOPEN_ENCRYPTED, (strlen(ERR_FOPEN_ENCRYPTED)+1)); 
				return(EXIT_FAILURE);
			}
			strncpy(options->encrypted_fsp, optarg, (strlen(optarg)+1));
			break;
			
		case 'G':
		case 'E':
		case 'D':
		case 'P':

			break;

		case 'v':
			options->verbose = TRUE;
			break;

		case 'b':
			if (*cmd!=(int)'P') {
				strncpy(options->errmsg, ERR_BINARY_SPECIFIED, (strlen(ERR_BINARY_SPECIFIED)+1)); 
				return(EXIT_FAILURE);
			}
			options->pyx_binary = TRUE;
			break;

		case 'f':
			if ((*cmd!=(int)'G') && (options->cmd_mode==CMD_STD)) {
				strncpy(options->errmsg, ERR_PADOTP_SPECIFIED, (strlen(ERR_PADOTP_SPECIFIED)+1)); 
				return(EXIT_FAILURE);
			}
			options->padout_pdotp = TRUE;
			break;

		case 'r':
			if (strlen(optarg)>(DEV_PATH_MAX-strlen(DEV_PREFIX_STR))) {
				strncpy(options->errmsg, ERR_PARAMSIZE_DEV, (strlen(ERR_PARAMSIZE_DEV)+1)); 
				return(EXIT_FAILURE);
			}

			if (optarg!=NULL) {
				strncpy(options->devname, (strncat(&dname[0],optarg,DEV_PATH_MAX)), DEV_PATH_MAX);
				if ((options->device = open(options->devname, O_RDONLY)) < 0 ) {
					strncpy(options->errmsg, ERR_CHK_DEV, (strlen(ERR_CHK_DEV)+1)); 
					return(EXIT_FAILURE);
				}
			}
			else {
				strncpy(options->errmsg, ERR_CHK_DEV, (strlen(ERR_CHK_DEV)+1)); 
				return(EXIT_FAILURE);
			}

			break;

		case 's':
			if (strlen(optarg)>SIZE_LEN) {
				strncpy(options->errmsg, ERR_PARAMSIZE_SIZ, (strlen(ERR_PARAMSIZE_SIZ)+1)); 
				return(EXIT_FAILURE);
			}

			if (optarg!=NULL){
				strncpy(options->sizestr, optarg, SIZE_LEN);
				options->size = (unsigned long long)strtoul(options->sizestr, NULL, 10);

				if (factor_suffix(options) != EXIT_SUCCESS) {
					strncpy(options->errmsg, ERR_CHK_SIZE, (strlen(ERR_CHK_SIZE)+1)); 
					return(EXIT_FAILURE);
				}
			} 
			   
			break;

		case 'h':
		default:
			usage(ver,basename(progname));
			return(EXIT_FAILURE);
			break;
		}
	return(EXIT_SUCCESS);
}

int	validate_cli_command(int cmd, options_t *options) {

	switch(cmd) {
		case 'P':
			if ((options->input!=stdin)||(options->otp==stdin)||(options->encrypted!=stdin)) {
				strncpy(options->errmsg, ERR_CHK_PCMD, (strlen(ERR_CHK_PCMD)+1)); 
				return(EXIT_FAILURE);
			}

			options->cmd_index = PCMD;
			if (options->output!=stdout)
				options->cmd_mode=CMD_ALT;

			break;

		case 'D':
			if (((options->input==stdin)||(options->otp==stdin)||(options->output==stdout))||(options->encrypted!=stdin)) {
				strncpy(options->errmsg, ERR_CHK_DCMD, (strlen(ERR_CHK_DCMD)+1)); 
				return(EXIT_FAILURE);
			}

			options->cmd_index = DCMD;
				
			break;

		case 'E':
			if ((options->input==stdin)||(options->output==stdout)||(options->otp==stdin)) {
				strncpy(options->errmsg, ERR_CHK_ECMD, (strlen(ERR_CHK_ECMD)+1)); 
				return(EXIT_FAILURE);
			}
			else {
				options->cmd_index = ECMD;
				break;	
			} 

			break;

		case 'G':
			if (options->sizestr[0]!='\0') {
				if (options->otp==stdin) {
					strncpy(options->errmsg, ERR_CHK_GCMD, (strlen(ERR_CHK_GCMD)+1)); 
					return(EXIT_FAILURE);
				}

				if ((options->output!=stdout)||(options->encrypted!=stdin)||(options->input!=stdin)) {
					strncpy(options->errmsg, ERR_CHK_GCMD, (strlen(ERR_CHK_GCMD)+1)); 
					return(EXIT_FAILURE);
				}
			}
			else {
				if ((options->input==stdin)||(options->encrypted==stdin)||(options->otp==stdin)||(options->output!=stdout)) {
					strncpy(options->errmsg, ERR_CHK_GCMD, (strlen(ERR_CHK_GCMD)+1)); 
					return(EXIT_FAILURE);
				}
				options->cmd_mode=CMD_ALT;
			}

			options->cmd_index = GCMD;

			break;
	}
	return(EXIT_SUCCESS);
}

void usage(char *ver, char *progname) {

	fprintf(stdout, USAGE_FMT0, progname?progname:DEFAULT_PROGNAME, ER_VERSION, ver);
	fprintf(stdout, USAGE_FMT1, progname?progname:DEFAULT_PROGNAME);
	fprintf(stdout, USAGE_FMT2);
	fprintf(stdout, USAGE_FMT3);
	fprintf(stdout, USAGE_FMT4);
	fprintf(stdout, USAGE_FMT5);
	fprintf(stdout, USAGE_FMT6);
	fprintf(stdout, USAGE_FMT7, progname?progname:DEFAULT_PROGNAME);
}

int factor_suffix(options_t *options) {
int factor;

	factor=1;

	if (options->sizestr==NULL) 
		return (EXIT_FAILURE);

	switch ((char)toupper(*(options->sizestr+(strlen(options->sizestr)-1)))) {
		case 'K':
		factor=1024;
		break;

		case 'M':
		factor=1048576;
		break;

		case 'G':
		factor=1073741824;
		break;
	}

	options->size*=factor;

	return(EXIT_SUCCESS);
}
