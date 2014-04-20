#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <ncurses.h>
#include <signal.h>

time_t start,end;

/* Function prototypes */

typedef uint64_t felem;
	unsigned long long target = 17102374048997504131LL;
	int ntimes = 6;
static void self_check(uint32_t* hash, unsigned long long secret);
static void concurrent_check(uint32_t* hash, uint8_t* secret);
static void shittify_secret(uint8_t* mysecret);
void
fsum(felem *output, const felem *in);
void sha256_hash(uint8_t *message, uint32_t len, uint32_t *hash);
unsigned long long endian_swap(unsigned long long x);
void serialize_int(unsigned char *buffer, uint32_t value);

// Link this program with an external C or x86 compression function
extern void sha256_compress(uint32_t *state, uint8_t *block);

// Link this program with an external C or x86 curve25519 function
typedef uint8_t u8;
static const uint8_t basepoint[32] = {9};
extern void curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);

unsigned long long global_iter = 0LL;
pthread_mutex_t mutex_iter;

/* Main program */
unsigned 
rand256()
{
    
    static unsigned const limit = RAND_MAX - RAND_MAX % 256;
    unsigned result = rand();
    while ( result >= limit ) {
        result = rand();
    }
    return result % 256;
}

unsigned long long
rand64bits()
{
    unsigned long long results = 0ULL;
    for ( int count = 8; count > 0; -- count ) {
        results = 256U * results + rand256();
    }
    return results;
}

void watchdog(){

	while(1==1){
		pthread_mutex_lock(&mutex_iter);
		unsigned long long olditer = global_iter;
		global_iter = 0;
		pthread_mutex_unlock(&mutex_iter);
		sleep(1);
		//printf("Speed: %llu / sec\n",(olditer));
	attron(A_STANDOUT);
time (&end);
double dif = difftime (end,start);
char str[256];
sprintf (str,"Elasped time is %.2lf seconds.", dif );
mvaddstr(0,0,str);
attron(A_BOLD);
	attroff(A_STANDOUT);
sprintf (str,"Threads:\t%d", ntimes );
mvaddstr(3,0,str);
attron(COLOR_PAIR(3));
sprintf (str,"Key-Speed:\t%llu / sec\n",(olditer) );
mvaddstr(4,0,str);
attron(COLOR_PAIR(1));
sprintf (str,"NXT Target:\t%llu\n",(target) );
mvaddstr(5,0,str);

attroff(A_BOLD);
attron(COLOR_PAIR(7));
sprintf (str,"If the cracker finds a match, a file named 'found.pcl'",(olditer) );
mvaddstr(7,0,str);
sprintf (str,"will be created for further inspection. The program will exit.",(olditer) );
mvaddstr(8,0,str);
refresh();
	}
}
void end_curses(){
 endwin();                  /* End curses mode    */
exit(0);
}

void get_result(){

	uint32_t hash[8];
	char	 secret[32];
	uint8_t  pubkey[32];
	uint8_t hashchar[32];
	unsigned long long local_iter = 0LL;
	int i;

	unsigned long long thread_seed = rand64bits();
	
	

	// initial hashchar (only once)
	self_check(hash, thread_seed);
	for(i=0;i<8;++i){
		serialize_int(hashchar+i*4, hash[i]);
	}
	shittify_secret(hashchar);
	curve25519_donna(pubkey, hashchar, basepoint);
	felem bp[5];
	fexpand(bp, basepoint);
	felem x[5];
	fexpand(x, pubkey);

	// at this time we have created a public key, of which the private key is known.
	// in the next step(s) it is sufficient to increment:
	// PubKey = PubKey + G
	// priv = priv + 1
	// This adjusted Pub/Priv Keypair remains VALiD!

	// Now just checking the sha256 against the accountID is sufficient.
	//printf("Starting Thread (%llu): local_seed: %llu\n", target, thread_seed);
	while(1==1){

		++local_iter;
		if(local_iter % 10000==0){
		pthread_mutex_lock(&mutex_iter);
		global_iter=global_iter+10000;
		pthread_mutex_unlock(&mutex_iter);
		}
	
		fsum(x, bp);
		fcontract(pubkey, x);

		// sha256 round
		concurrent_check(hash, pubkey);
		for(i=0;i<8;++i){
			serialize_int(hashchar+i*4, hash[i]);
		}


		// At this point account id is trivial
		unsigned long long id = (unsigned long long)(((unsigned long long)hashchar[7] << 56) | ((unsigned long long)hashchar[6] << 48) | ((unsigned long long)hashchar[5] << 40) | ((unsigned long long)hashchar[4] << 32) | ((unsigned long long)hashchar[3] << 24) | ((unsigned long long)hashchar[2] << 16) | ((unsigned long long)hashchar[1] << 8) | (unsigned long long)hashchar[0]);
	   

		if (id == target){
			//printf("Found Target: %llu, local_iter: %llu, local_seed: %llu\n", target, local_iter, thread_seed);
			FILE *f;
			    f = fopen("found.pcl", "w");
			    fprintf(f, "Found Target: %llu, local_iter: %llu, local_seed: %llu\n", target, local_iter, thread_seed);
			    fclose(f);
end_curses();
printf("FOUND AND SAVED TO 'found.pcl'.\n");
			exit(1);
		}
		
	}

}


void start_curses(){

    (void) signal(SIGINT, end_curses);      /* arrange interrupts to terminate */

    (void) initscr();      /* initialize the curses library */
    keypad(stdscr, TRUE);  /* enable keyboard mapping */
    (void) nonl();         /* tell curses not to do NL->CR/NL on output */
    (void) cbreak();       /* take input chars one at a time, no wait for \n */
    (void) echo();         /* echo input - in color */

    if (has_colors())
    {
        start_color();

        /*
         * Simple color assignment, often all we need.  Color pair 0 cannot
         * be redefined.  This example uses the same value for the color
         * pair as for the foreground color, though of course that is not
         * necessary:
         */
        init_pair(1, COLOR_RED,     COLOR_BLACK);
        init_pair(2, COLOR_GREEN,   COLOR_BLACK);
        init_pair(3, COLOR_YELLOW,  COLOR_BLACK);
        init_pair(4, COLOR_BLUE,    COLOR_BLACK);
        init_pair(5, COLOR_CYAN,    COLOR_BLACK);
        init_pair(6, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(7, COLOR_WHITE,   COLOR_BLACK);
    }
attron(COLOR_PAIR(7));
    refresh();                 /* Print it on to the real screen */

   
}

int main(int argc, char **argv) {
time (&start);
	start_curses();
	srand (time(NULL));

	pthread_t *tid = malloc( (ntimes+1) * sizeof(pthread_t) );
	int i;
	for( i=0; i<ntimes; i++ ) 
	    pthread_create( &tid[i], NULL, get_result, NULL );

	// watchdog
   // pthread_create( &tid[ntimes], NULL, watchdog, NULL );

	// join watchdog, which equivalates to a runloop
watchdog();
    //pthread_join(  tid[ntimes], NULL);
	end_curses();
}

/* endian magic */
void serialize_int(unsigned char *buffer, uint32_t value)
{
  /* Write big-endian int value into buffer; assumes 32-bit int and 8-bit char. */
  buffer[0] = value >> 24;
  buffer[1] = value >> 16;
  buffer[2] = value >> 8;
  buffer[3] = value;
}

unsigned long long endian_swap(unsigned long long x)
{
    return (x>>56) | 
        ((x<<40) & 0x00FF000000000000) |
        ((x<<24) & 0x0000FF0000000000) |
        ((x<<8)  & 0x000000FF00000000) |
        ((x>>8)  & 0x00000000FF000000) |
        ((x>>24) & 0x0000000000FF0000) |
        ((x>>40) & 0x000000000000FF00) |
        (x<<56);
}

/* Self-check */
static void self_check(uint32_t* hash, unsigned long long secret) {
	char mysecret[32];
	sprintf(mysecret, "%llu",secret);
	uint8_t* uint_secret = (uint8_t*)mysecret;
	int i;
	sha256_hash(uint_secret, 5, hash);
}

static void concurrent_check(uint32_t* hash, uint8_t* secret)
{
	sha256_hash(secret, 32, hash);
}
static void shittify_secret(uint8_t* mysecret){
	mysecret[0] &= 248;
  	mysecret[31] &= 127;
  	mysecret[31] |= 64;
}


/* Full message hasher */
void sha256_hash(uint8_t *message, uint32_t len, uint32_t *hash) {
	hash[0] = UINT32_C(0x6A09E667);
	hash[1] = UINT32_C(0xBB67AE85);
	hash[2] = UINT32_C(0x3C6EF372);
	hash[3] = UINT32_C(0xA54FF53A);
	hash[4] = UINT32_C(0x510E527F);
	hash[5] = UINT32_C(0x9B05688C);
	hash[6] = UINT32_C(0x1F83D9AB);
	hash[7] = UINT32_C(0x5BE0CD19);
	
	int i;
	for (i = 0; i + 64 <= len; i += 64)
		sha256_compress(hash, message + i);
	
	uint8_t block[64];
	int rem = len - i;
	memcpy(block, message + i, rem);
	
	block[rem] = 0x80;
	rem++;
	if (64 - rem >= 8)
		memset(block + rem, 0, 56 - rem);
	else {
		memset(block + rem, 0, 64 - rem);
		sha256_compress(hash, block);
		memset(block, 0, 56);
	}
	
	uint64_t longLen = ((uint64_t)len) << 3;
	for (i = 0; i < 8; i++)
		block[64 - 1 - i] = (uint8_t)(longLen >> (i * 8));
	sha256_compress(hash, block);
}
