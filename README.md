# Enoch-Root
Enoch Root related Cryptography

A repository to house er ("encrypt right" / "enoch root") code, including:

	er : "encrypt right" / "enoch root" one time pad management command line utility

	libenoch : dynamic Linux library that supports core functions

**Objective**

One Time Pad management to encrypt, decrypt, assess and deny. 

**Why a Dual Acronym?**

In a nod to er's plausible denialability function, even its name is equivocable.

**Why Enoch Root?**

Enoch Root, also known as Enoch the Red, is a recurring character through The Baroque Cycle, Cryptonomicon, and Fall, or Dodge in Hell. Although he is not one of the main protagonists of the books, he often appears at crucial times and places. And his surname is "root".Thank you Neal Stephenson

https://baroquecycle.fandom.com/wiki/Enoch_Root

**Why One Time Pads?**

If based upon true random numbers and implemented properly, they provide mathematically proven "perfect encryption" and functions such as "plausible denialability".

**What is a Pyx Assessment?**

Another nod to history, an assessment of the quality and suitability of the OTP random numbers, through a number of tests. Tests include Entropy assessment, Chi Square, Monte Carlo distribution and mean. 

https://en.wikipedia.org/wiki/Trial_of_the_Pyx

https://www.royalmint.com/discover/uk-coins/history-of-the-trial-of-the-pyx/

**Functionality and er examples**

Generate a new OTP by specifying size:

	er -G -s512M -pnew.otp

Generate a new OTP from a clear file and an encrypted file for plausible deniability:

	er -G -iclear.inp -eexisting.enc -pnew_pd.otp

Encrypt a clear file with an existing OTP to create a new encrypted file

	er -E -iclear.inp -pexisting.otp -oencrypted.out

Encrypt a clear file with a dynamically created OTP to create a new encrypted file

	er -E -iclear.inp -pnew.otp -oencrypted.out

Decrypt an input encrypted file with an existing OTP to create a clear file

	er -D -iencrypted.inp -pexisting.otp -oclear.out

Perform an assessment of an input OTP; the "Pyx Assessment" for ascertaining worthiness of random numbers

	er -P -pexisting.otp

Additional flags include verbose output (-v), selection of pyx assessment byte or binary mode (-b) and the selection of a specific Linux device for random number input (-r)

**Random Number Generation**

Interfaces with standard Linux random number generation (/dev/random) and defaults to use of the "TrueRNG3" hardware random number generator (HRNG) if present (/dev/TrueRNG). TrueRNG3 provides hardware random number generation by leveraging the "avalanche effect" of semi-conductors. TrueRNG3 is fast and performs very well at the Pyx Assessment.

https://ubld.it/truerng_v3


**er Usage** 

	er -h

er : Equivocable dual acronym "Encrypt Right"/"Enoch Root" (v0.1;libenoch:v0.1)

er : -G : Generate OTP/PD OTP, -E : Encrypt, -D : Decrypt, -P : Pyx

[-i inputfile] [-e inputfile] [-p otp file] [-o outputfile]

[-s size] [-r devname] [-v] [-b| [-h]


-G -s<size BKMG> -pfsp || -G -ifsp -efsp -pfsp

[-G -s1M -pnew.otp]

[-G -iclear.in -eexisting.enc -pnew.otp]


-E -ifsp -pfsp -ofsp  || -E -ifsp -pnewfsp -ofsp

[-E -iclear.in -pexisting.otp -oencrypted.out]

[-E -iclear.in -pnew.otp -oencrypted.out]


-D -ifsp -pfsp -ofsp

[-D -iencrypted.in -pexisting.otp -oclear.out]


-P -pfsp -b || -P -pfsp -ofsp -b

[-P -pexisting.otp] [-b]

[-P -pexisting.otp -oterse.rpt] [-b]


-v : verbose output, -r : random number generation device, -b : Pyx binary mode

**Example Pyx Assessment output:**


**libenoch Summary**

Dynamic library providing core OTP cryptography functions supporting encryption, decryption, generation and assessment. 

typedef structure object as an interface:

	typedef struct{ 

	int	verbose;

	char 	devname[DEV_PATH_MAX];

	char	sizestr[SIZE_LEN];

	char	errmsg[ERR_MSG_MAXLEN];

	unsigned long long int  size;

	int	cmd_index;

	int	cmd_mode;

	int	pyx_binary;

	FILE	*input;

	FILE	*output;

	FILE	*otp;

	FILE	*encrypted;

	int	device;

	char	input_fsp[MAX_FSP_PATH];

	char	output_fsp[MAX_FSP_PATH];

	char	otp_fsp[MAX_FSP_PATH];

	char	encrypted_fsp[MAX_FSP_PATH];

	} options_t;


**External functions summarised**

Selecting the RNG device by default

	extern void set_default_device(options_t *options);

Generating an OTP

	extern int g_generate(options_t *options);

Encrypting a file with an OTP/device

	extern int e_encrypt(options_t *options);

Decrypting an encrypted file with an OTP

	extern int d_decrypt(options_t *options);

Performing the Pyx Assessment 

	extern int p_pyx(options_t *options);

Getting libenoch version details

	extern int enoch(char *version);


**Internal Pyx Assessment functions summarised**

	static double poz (const double z)

	double pochisq (const double ax, const int df)

	static double pyx_log2(double x)

	void pyx_init (int binmode)

	void pyx_add (void *buf, int bufl)

	void pyx_end (double *r_ent, double *r_chisq, double *r_mean, double *r_montepicalc, double *r_scc)

