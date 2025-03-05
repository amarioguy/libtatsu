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

static void print_usage(int argc, char **argv, int is_error) {
    char *name = strrchr(argv[0], '/');
    FILE *output = (is_error ? stderr : stdout);
    fprintf(output, "Usage: %s [options] DIRECTORY\n", (name ? name + 1 : argv[0]));
	fprintf(output,
		"\n"
		"Request a personalized firmware signature from a remote TSS server.\n"
		"\n"
		"Options:\n"
		"  -c, --chip-id         specify a Chip ID to request the TSS blob for. (example: A15/T8110 would put 0x8110)\n"
		"  -b, --board-id        specify a Board ID to request the TSS blob for. (an integer value specified as 0xAB where AB is a byte corresponding to an integer for board ID)\n"
        "  -e  --ecid            specify an ECID to request the TSS blob for. (device-specific, can specify an arbitrary integer if you only care about signing status or don't have to care about it's value.)\n"
        "  -s  --security-domain specify which security domain to request the TSS blob for. (an integer, nearly always 0x1 except in special cases, and defaults to 0x1 if unspecified)\n"
        "  -p  --production-mode specify the production mode status to request the TSS blob for (a boolean, not required except in special cases, defaults to true/0x1 if left unspecified)\n"
        "  -s  --secure-mode     specify the secure mode status to request the TSS blob for (a boolean, not required except in special cases, defaults to true/0x1 if left unspecified)\n"
        "  -i  --ios-build       specify an iOS build to request the TSS blob for. (a string that should be yyAzz where yy is the major version, A is the letter, and zz is the minor version.)\n"
        "  -e  --erase-variant   specify for the customer variant that when constructing the TSS request, use the digest of the erase ramdisk. (mutually exclusive with --variant, the default if no variant is specified.)\n"
        "  -u  --update-variant  specify for the customer variant that when constructing the TSS request, use the digest of the Recovery Mode update ramdisk. (mutually exclusive with --variant, in the case of both -e and -u, separate requests will be made for both and saved to separate files.)\n"
        "  -o  --ota-variant     specify that when constructing the TSS request, use the OTA update manifest as the basis (mutually exclusive with -e, -u and --variant)\n"
        "  -n  --boot-nonce-hash specify the ApNonce/BNCH/boot nonce hash to request the TSS blob for. (uses a random value if unspecified)\n"
        "  -s  --sep-nonce       specify the SepNonce to request the TSS blob for. (uses a random value if unspecified)\n"
        "  --variant             specify a variant to request the TSS blob for. (default variant is Customer, this is not needed except in special cases, and overrides all other variant options.)\n"
        "  --boot-nonce-raw      specify a raw boot nonce/BNCN to request the TSS blob for. (converts the nonce to the nonce hash, only results in matching nonce hashes on devices without nonce entanglement enabled.)\n"
        "  --sika                specify an Ap,SikaFuse value to request the TSS blob for. (an integer, not required except in special cases, defaults to 0 if unspecified)"
        "  --uid-mode            specify a UID_MODE value to request the TSS blob for. (a boolean, nearly always false except in special cases, defaults to false/0x0 if unspecified.)"
        "  --tss-url             specify a TSS server URL to request a TSS response from. (not needed except in special cases, default's to Apple's public TSS server.)\n"
        "  --raw-request         specify a raw TSS request to request a response for. (overrides all other options, sends the request verbatim.)"
		"  -d, --debug           enable communication debugging (one d prints the TSS request, two d's prints request and response)\n"
		"  -h, --help            prints usage information\n"
		"  -v, --version         prints version information\n"
		"\n"
		"Homepage:    <" PACKAGE_URL ">\n"
		"Bug Reports: <" PACKAGE_BUGREPORT ">\n"
	);

}


int main(int argc, char *argv[]) {
    //
    // do work.
    //
}