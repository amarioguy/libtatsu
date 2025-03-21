//
// request_tss - a lightweight TSS multi-tool based on libtatsu.
//

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define TOOL_NAME "request_tss"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>

#include <libtatsu/tss.h>

//
// TODO: lookup table for translating Chip ID, Board ID, Security Domain to product identifiers
// IPSW.me uses the product identifier, and since we want to retain support for custom
// Chip/Board/SDOM combos, we need to have this translation table to allow us to
// download the latest BuildManifest.
//
// The "latest" command will not work for devices not in this translation table.
// Dev boards for recent devices (having bit 0 set in the board ID) will be treated as not in
// the translation table for now, although we could quite easily add support for it.
//

typedef product_struct {
    uint32_t chip_id;
    uint32_t board_id;
    uint8_t security_domain;
    char *product_identifier;
} product_struct_t;

product_struct_t known_products[] = {
    { 0x8140, 0x08, 0x1, "iPhone17,3"},
    { 0x8140, 0x0A, 0x1, "iPhone17,4"},
    { 0x8140, 0x0C, 0x1, "iPhone17,1"},
    { 0x8140, 0x0E, 0x1, "iPhone17,2"},
    //
    // continue this.
    //
};

static struct options longopts[] = {
    { "chip-id", required_argument, NULL, "c"},
    { "board-id", required_argument, NULL, "b"},
    { "ecid", required_argument, NULL, "e"},
    { "security-domain", required_argument, NULL, 1},
    { "production-mode", required_argument, NULL, "p"},
    { "secure-mode", required_argument, NULL, 2},
    { "ios-build", required_argument, NULL, "i"},
    { "latest", no_argument, NULL, "l"},
    { "erase-variant", no_argument, NULL, "r"},
    { "update-variant", no_argument, NULL, "u"},
    { "ota-variant", no_argument, NULL, "o"},
    { "boot-nonce-hash", required_argument, NULL, "n"},
    { "sep-nonce", required_argument, NULL, "s"},
    { "variant", required_argument, NULL, 3},
    { "boot-nonce-raw", required_argument, NULL, 4},
    { "sika", required_argument, NULL, 5},
    { "uid-mode", required_argument, NULL, 6},
    //{ "tss-url", required_argument, NULL, 7}, // custom TSS url requests are disabled for now.
    { "raw-request", required_argument, NULL, 8},
    { "debug", no_argument, NULL, "d"},
    { "help", no_argument, NULL, 'h'},
    { "version", no_argument, NULL, 'v'},

};

static void print_usage(int argc, char **argv, int is_error) {
    char *name = strrchr(argv[0], '/');
    FILE *output = (is_error ? stderr : stdout);
    fprintf(output, "Usage: %s [options] BUILDMANIFEST [OUTPUT_DIRECTORY]\n", (name ? name + 1 : argv[0]));
	fprintf(output,
		"\n"
		"Request a personalized firmware signature from a remote TSS server.\n"
		"\n"
		"Options:\n"
		"  -c, --chip-id         specify a Chip ID to request the TSS blob for. (example: A15/T8110 would put 0x8110)\n"
		"  -b, --board-id        specify a Board ID to request the TSS blob for. (an integer value specified as 0xAB where AB is a byte corresponding to an integer for board ID)\n"
        "  -e  --ecid            specify an ECID to request the TSS blob for. (device-specific, can specify an arbitrary integer if you only care about signing status or don't have to care about it's value.)\n"
        "  --security-domain     specify which security domain to request the TSS blob for. (an integer, nearly always 0x1 except in special cases, and defaults to 0x1 if unspecified)\n"
        "  -p  --production-mode specify the production mode status to request the TSS blob for (a boolean, not required except in special cases, defaults to true/0x1 if left unspecified)\n"
        "  --secure-mode     specify the secure mode status to request the TSS blob for (a boolean, not required except in special cases, defaults to true/0x1 if left unspecified)\n"
        "  -i  --ios-build       specify an iOS build to request the TSS blob for. (a string that should be yyAzz where yy is the major version, A is the letter, and zz is the minor version.)\n"
        "  -r  --erase-variant   specify for the customer variant that when constructing the TSS request, use the digest of the erase ramdisk. (mutually exclusive with --variant, the default if no variant is specified.)\n"
        "  -u  --update-variant  specify for the customer variant that when constructing the TSS request, use the digest of the Recovery Mode update ramdisk. (mutually exclusive with --variant, in the case of both -e and -u, separate requests will be made for both and saved to separate files.)\n"
        "  -o  --ota-variant     specify that when constructing the TSS request, use the OTA update manifest as the basis (mutually exclusive with -e, -u and --variant)\n"
        "  -l  --latest          use the latest iOS build for the device specified instead of a manually specified build. (overrides -i)\n"
        "  -n  --boot-nonce-hash specify the ApNonce/BNCH/boot nonce hash to request the TSS blob for. (uses a random value if unspecified)\n"
        "  -s  --sep-nonce       specify the SepNonce to request the TSS blob for. (uses a random value if unspecified)\n"
        "  --variant             specify a variant to request the TSS blob for. (default variant is Customer, this is not needed except in special cases, and overrides all other variant options.)\n"
        "  --boot-nonce-raw      specify a raw boot nonce/BNCN to request the TSS blob for. (converts the nonce to the nonce hash, only results in matching nonce hashes on devices without nonce entanglement enabled.)\n"
        "  --sika                specify an Ap,SikaFuse value to request the TSS blob for. (an integer, not required except in special cases, defaults to 0 if unspecified)\n"
        "  --uid-mode            specify a UID_MODE value to request the TSS blob for. (a boolean, nearly always false except in special cases, defaults to false/0x0 if unspecified.)"
        "  --tss-url             specify a TSS server URL to request a TSS response from. (not needed except in special cases, default's to Apple's public TSS server.)\n"
        "  --raw-request         specify a raw TSS request to request a response for. (overrides all other options, sends the request verbatim.)\n"
		"  -d, --debug           enable communication debugging (one d prints the TSS request, two d's prints request and response)\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);

}


int main(int argc, char *argv[]) {

    int opt = 0;
    int opt_index = 0;
    uint32_t debug_level = 0;
    //int status = EXIT_FAILURE; // assume failure.
    uint32_t chip_id = 0x0;
    uint32_t board_id = 0x0;
    uint64_t ecid = 0x0;
    bool production_mode, secure_mode = true;
    bool uid_mode = false;
    bool custom_variant_specified = false;
    bool use_customer_erase_variant = true;
    bool use_customer_upgrade_variant = false;
    bool use_customer_ota_upgrade_variant = false;
    char *ap_nonce = NULL;
    char *sep_nonce = NULL;
    char *raw_tss_request = NULL;
    plist_t tss_req;
    char ipsw_me_url[256];
    char custom_tatsu_url[256];
    
    //
    // parse out arguments the user specified.
    //
    while ((opt = getopt_long(argc, argv, "c:b:e:p:i:lruon:s:dhv", longopts, &optindex)) > 0) {
        switch(opt) {
            case 'h':
                print_usage(argc, argv, 0);
                return EXIT_SUCCESS;
                break; //a precaution
            case 'd':
                if(debug_level >= 3) {
                    //
                    // we already have max debug level, ignore extras.
                    //
                    break;
                }
                debug_level++;
                idevice_set_debug_level(debug_level);
                tss_set_debug_level(debug_level);
                break;
            case 'c':
                if(!*optarg) {
                    fprintf(stderr, "ERROR: Chip ID cannot be empty in a TSS request!\n");
                    print_usage(argc, argv, 1);
                    return EXIT_FAILURE;
                }
                //
                // Set the Chip ID appropriately.
                //
                chip_id = strtoul(optarg, NULL, 0);
                printf("DEBUG: Chip ID: 0x%x\n", chip_id);
                break;
            case 'b':
                if(!*optarg) {
                    fprintf(stderr, "ERROR: Board ID cannot be empty in a TSS request!\n");
                    print_usage(argc, argv, 1);
                    return EXIT_FAILURE;
                }
                //
                // Set the Board ID appropriately.
                //
                board_id = strtoul(optarg, NULL, 0);
                printf("DEBUG: Board ID: 0x%x\n", board_id);
                break;
            case 'e':
                if(!*optarg) {
                    fprintf(stderr, "ERROR: ECID cannot be empty in a TSS request!\n");
                    print_usage(argc, argv, 1);
                    return EXIT_FAILURE;
                }
                ecid = strtoull(optarg, NULL, 0);
                printf("DEBUG: ECID: 0x%llx\n");
                break;

            case 'p':
                if((strtoul(optarg, NULL, 0) != 0) && (strtoul(optarg, NULL, 0) != 1)) {
                    fprintf(stderr, "ERROR: Production mode must be 0 or 1!\n");
                    print_usage(argc, argv, 1);
                    return EXIT_FAILURE;
                }
                else {
                    production_mode = (bool)strtoul(optarg, NULL, 0);
                    printf("DEBUG: Production mode set to 0x%x\n", production_mode);
                    break;
                }

            case 'i':
                //
                // TODO: this. need to look further into how to request build info from
                // ipsw.me.
                //
                break;
                
            case 'l':
                //
                // TODO: this. need to see how to pull latest for a given device from ipsw.me.
                // How does TSSChecker currently do boardconfig -> BORD/CHIP/SDOM translation?
                //
                break;
            
            case 'r':
                //
                // technically redundant and so probably should be removed 
                // but just for completeness sake for now.
                // this bool will have to be set to false in the custom variant case however.
                //
                use_customer_erase_variant = true; 
                break;

            case 'u':
                //
                // enable getting the update variant.
                //
                use_customer_upgrade_variant = true;
                break;

            case 'o':
                //
                // enable fetching for the OTA variant.
                //
                use_customer_ota_upgrade_variant = true;
                break;

            case 'n':
            case 's':
                //
                // TODO: implement these switches. should just be a strncpy from optarg -> dedicated buffers.
                //
                break;
        }
    }

    //
    // start parsing the actual arguments.
    // (TODO: implement build number parsing, for now we are just assuming the latest version
    // purely for testing reasons.)
    //

    snprintf(ipsw_me_url, sizeof(ipsw_me_url), "https://api.ipsw.me/v4/device/%s", product);

    
}