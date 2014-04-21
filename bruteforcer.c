#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <ncurses.h>
#include <signal.h>


// Hard coded array of HiberNXT accounts
// This array must be sorted for binary search
int number_targets = 310;
unsigned long long targets[] = {100000,7777777720939977,86606036627043330,126809591970516518,251795443549596447,
267236661632590366,313973741858395747,335837209231127735,383299955435318247,390306173247910305,
403589511794890487,451793079706569197,609839928703115580,634963660042830581,644069735061695395,
731170200321503319,866453771566674343,870972343445047662,882976197938949733,944849750359647468,
962055828131158565,1024222614581941534,1062312131687240629,1105982420270930697,1149626686529266622,
1209091477353803506,1261557230839801393,1348045933097340592,1348154245966536431,1397156367064801698,
1455023576432826983,1507753992272412000,1513539848724798504,1528025465909890614,1533450779595934745,
1618130350063133088,1632208218548529101,1642033478096235068,1673734447210079813,1722846003036452238,
1905171593250402489,2096657707348059480,2097936323370659125,2122930641428341852,2148516918911626095,
2162214990048874764,2216345710084684988,2273634605390327483,2479463022776789223,2537141963220212380,
2551980465038322456,2559434844593866915,2655988648446882704,2720070054937042482,2787174730635244402,
2796733479095662871,2868317034041725632,2871842195033655274,3041433146235555849,3106041710018585245,
3223123290801133718,3285768344857409875,3317696488251984889,3372956447277676518,3408724568625521663,
3450483686800418680,3452736903168463642,3477179078171411238,3493602285798222562,3647474929749934151,
3705267191944214622,3786563671078479111,3794799336143303133,3802397417387028904,3965768772265466750,
3972349175617282883,4044985131374266276,4055600426170395638,4076358419623297185,4151281272122649038,
4170303990051860470,4227834301472594653,4260795125989817310,4261913415301022027,4476728778078333344,
4660823155485185748,4676918490340905658,4720403269066119606,4769868130171100552,4786490575167575781,
4871386306603390970,4913905090824560524,4988627384044104069,5075742014843900680,5111389824270631129,
5145569047866880043,5171210824660340536,5193427004383467450,5275968107737148071,5372923620481211619,
5382158836431468966,5412820758088002695,5420301106094260933,5429431634627886938,5530680728616986314,
5603748206057310825,5605923133278618056,5708750149135511433,6053237521357188462,6074889351318228369,
6104328881228374537,6125068959841464306,6176343809576431834,6445323280442194255,6498157460316964552,
6550575638500529959,6556476178255092692,6588602049923882032,6676699993343525365,6723430970083344431,
6773200019014467234,6837199537415325106,6915614948687355799,6955041961592774446,7017261574549954165,
7068168273582355539,7228245532066601490,7232586379886647533,7321509355669036355,7353839932698993422,
7367977306797083954,7409100001471005841,7470937227795205943,7514598931901178302,7533448781394644842,
7579280979279424436,7658628237473396197,7696388372871145059,7808957934806968659,8056619408086889890,
8093086450423286866,8204991249433760906,8210349942546499309,8306529587442854966,8372557037695677292,
8601163964998119115,8715485890776649219,8856092137600015513,8872075948407427586,8915657182911395705,
8941391215200236792,8942807310844100951,8979911463366006679,9002382028261065550,9036230364752615410,
9053616565823965377,9059274406471912208,9089799541703737936,9165701670138280678,9250774527672475809,
9310571847616340889,9361833426785599589,9373648575506816844,9402102825676878734,9499748754559782987,
9587625254755912921,9595930061574932683,9616584841222968347,9701738262200124796,9723502548277457058,
9797710692481249252,9817894274756822675,9904552604432087696,9925296645360338798,9940581398741936476,
9950286777219541002,9961915816998043309,10100518980035756105,10174456066050181335,10204516688239923777,
10247471010768584564,10264233429420132369,10292881343918436620,10295732270190935182,10303182092718373961,
10382892628664504800,10482145205211770916,10491635971002311855,10530202806025660672,10564057114747343356,
10639320523880687052,11007982154266385225,11008119530725812802,11031124957488143665,11052917612404826548,
11084820352452471841,11163787122543230206,11252556956573237686,11499483291086802824,11510232914681789721,
11539599741956672522,11622879585370458828,11691097405853407852,11744808983302018588,11816954356846379223,
11864677621363447297,11942238125668316903,11946626305050296962,12118057129850453636,12137383984547758523,
12181867592269842138,12188790362271123101,12215777796964136352,12348952401294151851,12361000643386321839,
12564415476840447935,12682812311705690635,12784819895932740603,12883201973226272980,12898636000396314855,
13007707631222746702,13136665270045102399,13149072374725626668,13173868295457561945,13191862521949837415,
13322033152996629475,13336554091044517462,13344771909220650488,13417675986272443941,13448161576813353598,
13469429734814035239,13486151767340490934,13497803376326773303,13591317994340665555,13678183588576673087,
13696680082994549926,13785983057761027489,13866776928372605689,13998106196885495163,14069427737290756417,
14180032662585794148,14221705579657696666,14225432986435157409,14238557166256908857,14267186059441562952,
14382124125485769068,14388097140475368991,14431339140437110408,14487362433993688056,14497625700283886321,
14544444716689899421,14617507185653113052,14666922996254449542,14723297104976410550,14786420770652706548,
15070619947186539685,15156903382443004905,15206823584986290664,15381857440330203153,15392180950897216001,
15477185161189311781,15501364011972226993,15599104276735666799,15615312994765874916,15644913612980810563,
15737534362278353250,15863864010913337562,15959055750983803898,15969443644097018100,16022074703162988361,
16035830365123437227,16137772128017446356,16154703371776302422,16164321635615827916,16242786511692874144,
16289019465821061486,16298631690524516036,16320763544793039487,16340920018585485120,16347351096377757524,
16445952868657658036,16529323319802994686,16746812840087460088,16791625805354648438,16937007902771935002,
16984612206043604312,16986457950536444687,17058276076678976552,17062666447854032475,17102374048997504131,
17139177526259025165,17208767457721775914,17274187684895380545,17415604494481755560,17451009969859334223,
17516312037220442959,17542412758586007495,17595624190077635192,17614924111017813128,17662840483204025410,
17696243374104193944,17722454788509356049,17722608641427244083,17735970785646375851,17879947394225649770,
17992580640556029041,18084506661333820000,18409960111362350211,18414221922073461281,18415014402881706599}; 

time_t start,end;

/* Function prototypes */

typedef uint64_t felem;
	//unsigned long long target = 17102374048997504131LL;




unsigned int ntimes = 1;
bool automatic_calibration = 1;
unsigned int last_ntimes = 0;
unsigned int last_peak = 0;
unsigned int current_peak = 0;
unsigned int observing_window=0;
#define MAX_OBSERVING_WINDOW 5
pthread_t *tid = 0;
bool kill_indications[128];
void *get_result(void *id);
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

/**
Binary Search Algorithm to check multiple Targets with O(log n)
**/
int 
binary_search (unsigned long long key) 
{
  int min = 0;
  int max = number_targets - 1;

  while (max >= min) 
    {
      int i = (min + max) / 2;
      if (key < targets[i]) 
        max = i - 1;
      else if (key > targets[i]) 
        min = i + 1;
      else 
        return i;
    }

  return -1;
}


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
//sleep(1);
	while(1==1){

		
		pthread_mutex_lock(&mutex_iter);
		unsigned long long olditer = global_iter;
		global_iter = 0;
		pthread_mutex_unlock(&mutex_iter);
		

		if(automatic_calibration==1){
			if(current_peak<olditer)
				current_peak=olditer;

			observing_window++;

			

			if(observing_window>=MAX_OBSERVING_WINDOW){
				// check if we found our goal
				if(ntimes>1){
					// ENFORCE INCREMENTS BY AT LEAST 1000000 KEYS/s, otherwise extra threads are worthless
					if(current_peak-1000000>last_peak){
						last_peak = current_peak;
						last_ntimes = ntimes;
						ntimes++;
						observing_window=0;
						current_peak=0;
						pthread_create( &tid[ntimes-1], NULL, get_result, &ntimes );
						
					}else{
						// last configuration was the best,
						// kill latest thread and keep it this way
						pthread_mutex_lock(&mutex_iter);
						kill_indications[ntimes-1]=1; // trigger interruption point to kill the slowing thread;
						pthread_mutex_unlock(&mutex_iter);
						automatic_calibration = 0;



					}
				}else{
						last_peak = current_peak;
						last_ntimes = ntimes;
						ntimes++;
						observing_window=0;
						current_peak=0;
						pthread_create( &tid[ntimes-1], NULL, get_result, &ntimes );
					}
			}
		}



		//printf("Speed: %llu / sec\n",(olditer));
	attron(A_STANDOUT);
time (&end);
double dif = difftime (end,start);
char str[256];
sprintf (str,"Elasped time is %.2lf seconds.", dif );
mvaddstr(0,0,str);
attron(A_BOLD);
	attroff(A_STANDOUT);

if(automatic_calibration==1){	
sprintf (str,"Threads:\t%d (calibration phase %d)", ntimes,MAX_OBSERVING_WINDOW-observing_window );
}else{
sprintf (str,"Threads:\t%d (peak was %d key/s)", last_ntimes, last_peak);	
}

mvaddstr(3,0,str);
attron(COLOR_PAIR(3));
sprintf (str,"Key-Speed:\t%llu / sec\n",(olditer) );
mvaddstr(4,0,str);
attron(COLOR_PAIR(1));
sprintf (str,"NXT Targets:\t%d accounts (simultaneously)\n",(number_targets) );
mvaddstr(5,0,str);

attroff(A_BOLD);
attron(COLOR_PAIR(7));
sprintf (str,"If the cracker finds a match, a file named 'found.pcl'",(olditer) );
mvaddstr(7,0,str);
sprintf (str,"will be created for further inspection. The program will exit.",(olditer) );
mvaddstr(8,0,str);
refresh();
sleep(1);
	}
}
void end_curses(){
 endwin();                  /* End curses mode    */
exit(0);
}

void *get_result(void *id){
	int my_id = *((int *) id);
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
			// interruption point, so we can kill thread who slow down the algorithm

			if(kill_indications[my_id-1]==1){
				pthread_mutex_unlock(&mutex_iter);
				return;
			}
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
	   
		int result = binary_search(id);
		if (result != -1){
			//printf("Found Target: %llu, local_iter: %llu, local_seed: %llu\n", target, local_iter, thread_seed);
			FILE *f;
			    f = fopen("found.pcl", "w");
			    fprintf(f, "Found Target: %llu, local_iter: %llu, local_seed: %llu\n", targets[result], local_iter, thread_seed);
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



	// Allocate enough thread slots, just in case
	tid = malloc( (128) * sizeof(pthread_t) );
	for(int i=0;i<128;++i)
		kill_indications[i]=0;

	// start with one thread only, rest will be done in calibration phase
	pthread_create( &tid[ntimes-1], NULL, get_result, (void*)&ntimes );

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
