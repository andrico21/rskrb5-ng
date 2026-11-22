# shellcheck shell=bash
# Plan 2 todo 25 (WP-17, local authorization and name translation): the
# `localauth` suite. It needs only the MIT fixture. The drop-ins numbered 85
# under scripts/interop/mit/ add the local accounts, their .k5login files and
# the auth_to_local relations of the realm (provision.d/85-localauth.sh,
# krb5.conf.d/85-localauth.conf) and the Dockerfile builds MIT's own probe
# (localauth/probe.c) so the test asks MIT's krb5_kuserok and
# krb5_aname_to_localname the same questions it asks this crate. No port and no
# secret is added. The directory name `suite-localauth` sorts after every
# fixture directory, so mit-kdc is registered already.
interop_suite localauth interop_localauth mit-kdc
