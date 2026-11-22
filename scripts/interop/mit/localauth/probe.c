/*
 * Plan 2 todo 25 (WP-17, localauth): a probe of MIT krb5 1.22.2's own
 * krb5_aname_to_localname and krb5_kuserok, built against the installed
 * library by the Dockerfile, so tests/interop_localauth compares this crate's
 * answers with MIT's on the same krb5.conf and the same accounts.
 *
 *   localauth-probe an2ln PRINCIPAL            local name, or NOTRANS
 *   localauth-probe kuserok PRINCIPAL ACCOUNT  yes or no
 */
#include <krb5.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_principal principal;
    krb5_error_code ret;
    char name[65];

    if (argc < 3 || krb5_init_context(&context) != 0)
        return 2;
    if (krb5_parse_name(context, argv[2], &principal) != 0)
        return 2;
    if (strcmp(argv[1], "an2ln") == 0 && argc == 3) {
        ret = krb5_aname_to_localname(context, principal, sizeof(name), name);
        if (ret == 0)
            printf("%s\n", name);
        else if (ret == KRB5_LNAME_NOTRANS)
            printf("NOTRANS\n");
        else
            printf("ERROR %ld\n", (long)ret);
        return 0;
    }
    if (strcmp(argv[1], "kuserok") == 0 && argc == 4) {
        printf("%s\n", krb5_kuserok(context, principal, argv[3]) ? "yes" : "no");
        return 0;
    }
    return 2;
}
