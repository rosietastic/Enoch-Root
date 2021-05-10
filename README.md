# Enoch-Root
Enoch Root related Cryptography

A repository to house er ("encrypt right" / "enoch root") code, including:

	er : "encrypt right" / "enoch root" one time pad management command line utility

	libenoch : dynamic Linux library that supports core functions

Please see the wiki, with a summary below. 

**Objective**

One Time Pad management to encrypt, decrypt, assess and deny. 

**Why a Dual Acronym?**

In a nod to er's plausible deniability function, even its name is equivocable.

**Why Enoch Root?**

Enoch Root, also known as Enoch the Red, is a recurring character through The Baroque Cycle, Cryptonomicon, and Fall, or Dodge in Hell. Although he is not one of the main protagonists of the books, he often appears at crucial times and places. And his surname is "root".Thank you Neal Stephenson

https://baroquecycle.fandom.com/wiki/Enoch_Root

**Why One Time Pads?**

If based upon true random numbers and implemented properly, they provide mathematically proven "perfect encryption" and functions such as "plausible deniability".

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

Additional flags include verbose output (-v), selection of pyx assessment byte or binary mode (-b) and the selection of a specific Linux device for random number input (-r). Plausibly deniable one time pads can be "filled" with random data, by use of the -f flag to match the size of the original one time pad, if the target alternate clear file is smaller than the original.

**Random Number Generation**

While standard Linux random number generation (/dev/random) can be used, the er utility defaults to use of the "TrueRNG3" hardware random number generator (HRNG) if present (/dev/TrueRNG). TrueRNG3 provides hardware random number generation by leveraging the "avalanche effect" of semi-conductors. TrueRNG3 is fast and performs very well at the Pyx Assessment.

https://ubld.it/truerng_v3


**er Usage** 

	er -h

er : Equivocable dual acronym "Encrypt Right"/"Enoch Root" (v0.1;libenoch:v0.1)

er : -G : Generate OTP/PD OTP, -E : Encrypt, -D : Decrypt, -P : Pyx

[-i inputfile] [-e inputfile] [-p otp file] [-o outputfile]

[-s size] [-r devname] [-v] [-b] [-f] [-h]


-G -s<size BKMG> -pfsp || -G -ifsp -efsp -pfsp -f

[-G -s1M -pnew.otp]

[-G -iclear.in -eexisting.enc -pnew.otp -f]


-E -ifsp -pfsp -ofsp  || -E -ifsp -pnewfsp -ofsp

[-E -iclear.in -pexisting.otp -oencrypted.out]

[-E -iclear.in -pnew.otp -oencrypted.out]


-D -ifsp -pfsp -ofsp || -D -ifsp -pfsp -ofsp -s<size BKMG>

[-D -iencrypted.in -pexisting.otp -oclear.out]

[-D -iencrypted.in -pexisting.otp -oclear.out -s1M]


-P -pfsp -b || -P -pfsp -ofsp -b

[-P -pexisting.otp] [-b]

[-P -pexisting.otp -oterse.rpt] [-b]


-v : Verbose output, -r : RNG device, -b : Pyx binary mode, -f : Fill PD OTP

**Example Pyx Assessment output:**

	er -P -ptest.otp

Pyx Trial Assessment

OVERALL		: PASS && PASS && PASS && PASS && PASS = PASS

One Time Pad Density

Entropy : 7.999982 bits per byte.

Optimum compression of OTP file size 10485760 bytes by 0 percent

[GOOD 		= Entropy close to 8 bits, compression 0 percent]


One Time Pad Distribution

Chi Square : for 10485760 samples is 261.00

Value would be exceeded randomly 38.47 percent of the times.

[GOOD 		= 10 percent to 90 percent]

[SUSPECT 	= 5 to 10 percent or 90 to 95 percent]

[WORSE		= 1 to 5 percent or 95 to 99 percent]

[WORST		= 0 to 1 percent or 99 to 100 percent]

Arithmetic mean of data bytes is 127.4685

[RANDOM 	= 127.5]

Monte Carlo value for Pi is 3.141701943 (error 0.00 percent)

[RANDOM		= error 0.06 percent]

Serial correlation coefficient is -0.000180

[RANDOM		= 0.0]

[PREDICTED	= 1.0]

**Features**

Features of the er utility include the ability to generate one time pads to encrypt a whole specified file, or simply by size alone. Also, existing encrypted files can be used to generate alternate one time pads to facilitate plausible deniability. Plausibly deniable one time pads can be "filled" with random data to match the size of the original one time pad, if the target alternate clear file is smaller than the original. Decryption allows for a whole file (if the one time pad is large enough) or can be restricted by user specified size. 


**libenoch Summary**

Dynamic library providing core OTP cryptography functions supporting encryption, decryption, generation and assessment. 

A typedef "options_t" structure object is used as a library interface for applications:

	typedef struct{ 

	int	verbose;

	char 	devname[DEV_PATH_MAX];

	char	sizestr[SIZE_LEN];

	char	errmsg[ERR_MSG_MAXLEN];

	unsigned long long int  size;

	int	cmd_index;

	int	cmd_mode;

	int	pyx_binary;

	int	padout_pdotp;

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

**Installation of the er utility and libenoch dynamic library**

Please see the install_notes.txt file (in the Enoch-Root/projects folder) for specific details on how to clone the repository, compile and link the code and other notes on implementation and usage.
