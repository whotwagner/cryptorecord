#!/bin/bash

EXEDIR=/app/exe

case "$1" in
	tlsarecord)
		$EXEDIR/tlsarecord ${*:2}
		;;

	openpgpkeysrecord)
		$EXEDIR/openpgpkeysrecord ${*:2}
		;;

	sshfprecord)
		$EXEDIR/sshfprecord ${*:2}
		;;
	*)
		echo "Usage: [ tlsarecord | openpgpkeysrecord | sshfprecord ] <options>"
		exit 1
		;;
esac

exit 0
