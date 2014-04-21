#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <ncurses.h>
#include <signal.h>
#include <unistd.h>

// Hard coded array of HiberNXT accounts
// This array must be sorted for binary search
int number_targets = 310;
unsigned long long targets[] = {100000ULL,7777777720939977ULL,86606036627043330ULL,126809591970516518ULL,251795443549596447ULL,
267236661632590366ULL,313973741858395747ULL,335837209231127735ULL,383299955435318247ULL,390306173247910305ULL,
403589511794890487ULL,451793079706569197ULL,609839928703115580ULL,634963660042830581ULL,644069735061695395ULL,
731170200321503319ULL,866453771566674343ULL,870972343445047662ULL,882976197938949733ULL,944849750359647468ULL,
962055828131158565ULL,1024222614581941534ULL,1062312131687240629ULL,1105982420270930697ULL,1149626686529266622ULL,
1209091477353803506ULL,1261557230839801393ULL,1348045933097340592ULL,1348154245966536431ULL,1397156367064801698ULL,
1455023576432826983ULL,1507753992272412000ULL,1513539848724798504ULL,1528025465909890614ULL,1533450779595934745ULL,
1618130350063133088ULL,1632208218548529101ULL,1642033478096235068ULL,1673734447210079813ULL,1722846003036452238ULL,
1905171593250402489ULL,2096657707348059480ULL,2097936323370659125ULL,2122930641428341852ULL,2148516918911626095ULL,
2162214990048874764ULL,2216345710084684988ULL,2273634605390327483ULL,2479463022776789223ULL,2537141963220212380ULL,
2551980465038322456ULL,2559434844593866915ULL,2655988648446882704ULL,2720070054937042482ULL,2787174730635244402ULL,
2796733479095662871ULL,2868317034041725632ULL,2871842195033655274ULL,3041433146235555849ULL,3106041710018585245ULL,
3223123290801133718ULL,3285768344857409875ULL,3317696488251984889ULL,3372956447277676518ULL,3408724568625521663ULL,
3450483686800418680ULL,3452736903168463642ULL,3477179078171411238ULL,3493602285798222562ULL,3647474929749934151ULL,
3705267191944214622ULL,3786563671078479111ULL,3794799336143303133ULL,3802397417387028904ULL,3965768772265466750ULL,
3972349175617282883ULL,4044985131374266276ULL,4055600426170395638ULL,4076358419623297185ULL,4151281272122649038ULL,
4170303990051860470ULL,4227834301472594653ULL,4260795125989817310ULL,4261913415301022027ULL,4476728778078333344ULL,
4660823155485185748ULL,4676918490340905658ULL,4720403269066119606ULL,4769868130171100552ULL,4786490575167575781ULL,
4871386306603390970ULL,4913905090824560524ULL,4988627384044104069ULL,5075742014843900680ULL,5111389824270631129ULL,
5145569047866880043ULL,5171210824660340536ULL,5193427004383467450ULL,5275968107737148071ULL,5372923620481211619ULL,
5382158836431468966ULL,5412820758088002695ULL,5420301106094260933ULL,5429431634627886938ULL,5530680728616986314ULL,
5603748206057310825ULL,5605923133278618056ULL,5708750149135511433ULL,6053237521357188462ULL,6074889351318228369ULL,
6104328881228374537ULL,6125068959841464306ULL,6176343809576431834ULL,6445323280442194255ULL,6498157460316964552ULL,
6550575638500529959ULL,6556476178255092692ULL,6588602049923882032ULL,6676699993343525365ULL,6723430970083344431ULL,
6773200019014467234ULL,6837199537415325106ULL,6915614948687355799ULL,6955041961592774446ULL,7017261574549954165ULL,
7068168273582355539ULL,7228245532066601490ULL,7232586379886647533ULL,7321509355669036355ULL,7353839932698993422ULL,
7367977306797083954ULL,7409100001471005841ULL,7470937227795205943ULL,7514598931901178302ULL,7533448781394644842ULL,
7579280979279424436ULL,7658628237473396197ULL,7696388372871145059ULL,7808957934806968659ULL,8056619408086889890ULL,
8093086450423286866ULL,8204991249433760906ULL,8210349942546499309ULL,8306529587442854966ULL,8372557037695677292ULL,
8601163964998119115ULL,8715485890776649219ULL,8856092137600015513ULL,8872075948407427586ULL,8915657182911395705ULL,
8941391215200236792ULL,8942807310844100951ULL,8979911463366006679ULL,9002382028261065550ULL,9036230364752615410ULL,
9053616565823965377ULL,9059274406471912208ULL,9089799541703737936ULL,9165701670138280678ULL,9250774527672475809ULL,
9310571847616340889ULL,9361833426785599589ULL,9373648575506816844ULL,9402102825676878734ULL,9499748754559782987ULL,
9587625254755912921ULL,9595930061574932683ULL,9616584841222968347ULL,9701738262200124796ULL,9723502548277457058ULL,
9797710692481249252ULL,9817894274756822675ULL,9904552604432087696ULL,9925296645360338798ULL,9940581398741936476ULL,
9950286777219541002ULL,9961915816998043309ULL,10100518980035756105ULL,10174456066050181335ULL,10204516688239923777ULL,
10247471010768584564ULL,10264233429420132369ULL,10292881343918436620ULL,10295732270190935182ULL,10303182092718373961ULL,
10382892628664504800ULL,10482145205211770916ULL,10491635971002311855ULL,10530202806025660672ULL,10564057114747343356ULL,
10639320523880687052ULL,11007982154266385225ULL,11008119530725812802ULL,11031124957488143665ULL,11052917612404826548ULL,
11084820352452471841ULL,11163787122543230206ULL,11252556956573237686ULL,11499483291086802824ULL,11510232914681789721ULL,
11539599741956672522ULL,11622879585370458828ULL,11691097405853407852ULL,11744808983302018588ULL,11816954356846379223ULL,
11864677621363447297ULL,11942238125668316903ULL,11946626305050296962ULL,12118057129850453636ULL,12137383984547758523ULL,
12181867592269842138ULL,12188790362271123101ULL,12215777796964136352ULL,12348952401294151851ULL,12361000643386321839ULL,
12564415476840447935ULL,12682812311705690635ULL,12784819895932740603ULL,12883201973226272980ULL,12898636000396314855ULL,
13007707631222746702ULL,13136665270045102399ULL,13149072374725626668ULL,13173868295457561945ULL,13191862521949837415ULL,
13322033152996629475ULL,13336554091044517462ULL,13344771909220650488ULL,13417675986272443941ULL,13448161576813353598ULL,
13469429734814035239ULL,13486151767340490934ULL,13497803376326773303ULL,13591317994340665555ULL,13678183588576673087ULL,
13696680082994549926ULL,13785983057761027489ULL,13866776928372605689ULL,13998106196885495163ULL,14069427737290756417ULL,
14180032662585794148ULL,14221705579657696666ULL,14225432986435157409ULL,14238557166256908857ULL,14267186059441562952ULL,
14382124125485769068ULL,14388097140475368991ULL,14431339140437110408ULL,14487362433993688056ULL,14497625700283886321ULL,
14544444716689899421ULL,14617507185653113052ULL,14666922996254449542ULL,14723297104976410550ULL,14786420770652706548ULL,
15070619947186539685ULL,15156903382443004905ULL,15206823584986290664ULL,15381857440330203153ULL,15392180950897216001ULL,
15477185161189311781ULL,15501364011972226993ULL,15599104276735666799ULL,15615312994765874916ULL,15644913612980810563ULL,
15737534362278353250ULL,15863864010913337562ULL,15959055750983803898ULL,15969443644097018100ULL,16022074703162988361ULL,
16035830365123437227ULL,16137772128017446356ULL,16154703371776302422ULL,16164321635615827916ULL,16242786511692874144ULL,
16289019465821061486ULL,16298631690524516036ULL,16320763544793039487ULL,16340920018585485120ULL,16347351096377757524ULL,
16445952868657658036ULL,16529323319802994686ULL,16746812840087460088ULL,16791625805354648438ULL,16937007902771935002ULL,
16984612206043604312ULL,16986457950536444687ULL,17058276076678976552ULL,17062666447854032475ULL,17102374048997504131ULL,
17139177526259025165ULL,17208767457721775914ULL,17274187684895380545ULL,17415604494481755560ULL,17451009969859334223ULL,
17516312037220442959ULL,17542412758586007495ULL,17595624190077635192ULL,17614924111017813128ULL,17662840483204025410ULL,
17696243374104193944ULL,17722454788509356049ULL,17722608641427244083ULL,17735970785646375851ULL,17879947394225649770ULL,
17992580640556029041ULL,18084506661333820000ULL,18409960111362350211ULL,18414221922073461281ULL,18415014402881706599ULL}; 

time_t start,end;

/* Function prototypes */

typedef uint64_t felem;
	//unsigned long long target = 17102374048997504131LL;



typedef uint8_t u8;
typedef uint64_t felem;

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
extern void fmul(felem *output, const felem *in1, const felem *in2);
extern void fsquare(felem *output, const felem *in1);
extern void fexpand(felem *ouptut, const u8 *input);
extern void fcontract(u8 *output, const felem *input);
extern void freduce_coefficients(felem *inout);
extern void fscalar(felem *output, const felem *input);
extern void fdifference_backwards(felem *output, const felem *input);
extern void cmult(felem *x, felem *z, const u8 *n, const felem *q);
extern void
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
char cpumodel[512];
void get_cpu_model () 

{

   FILE* fp; 
   char buffer[4096]; 
   unsigned int bytes_read; 
   char* match; 

   /* Read the entire contents of /proc/cpuinfo into the buffer.  */ 
   fp = fopen ("/proc/cpuinfo", "r"); 
   bytes_read = fread (buffer, 1, sizeof (buffer), fp); 
   fclose (fp); 

   printf("bytes read: %u\n",bytes_read);
   /* Bail if read failed or if buffer isn't big enough.  */ 
   if (bytes_read == 0) {
   	 sprintf(cpumodel,"could not be detected");	
     return; 
 }

   /* NUL-terminate the text.  */ 
   buffer[bytes_read] == '\0'; 
   /* Locate the line that starts with "cpu MHz".  */ 
   match = strstr (buffer, "model name"); 

   if (match == NULL) {
   	 sprintf(cpumodel,"could not be detected");	
     return; 
 }
   char* ptr = strtok(match, ":\n");
   ptr = strtok(NULL, ":\n");
   char tmp[256];
   sprintf(tmp,"%s",ptr);
   sprintf(cpumodel,"%s",&tmp[0]+1);
   return; 

} 

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
sprintf (str,"Processor:\t%s",(cpumodel) );
mvaddstr(3,0,str);

if(automatic_calibration==1){	
sprintf (str,"Threads:\t%d (calibration phase %d)", ntimes,MAX_OBSERVING_WINDOW-observing_window );
}else{
sprintf (str,"Threads:\t%d (peak was %d key/s)", last_ntimes, last_peak);	
}

mvaddstr(4,0,str);
attron(COLOR_PAIR(3));
sprintf (str,"Key-Speed:\t%llu / sec\n",(olditer) );
mvaddstr(5,0,str);
attron(COLOR_PAIR(1));
sprintf (str,"NXT Targets:\t%d accounts (simultaneously)\n",(number_targets) );
mvaddstr(6,0,str);

attroff(A_BOLD);
attron(COLOR_PAIR(7));
sprintf (str,"If the cracker finds a match, a file named 'found.pcl'");
mvaddstr(8,0,str);
sprintf (str,"will be created for further inspection. The program will exit." );
mvaddstr(9,0,str);
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
				return 0;
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
	get_cpu_model();


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
