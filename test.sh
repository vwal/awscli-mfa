#!/bin/bash

currently_selected_profile_ident="blahblah-mfasession"
final_selection="jotainmuuta"

declare -a testarray

testarray[2]='hey'
testarray[5]='lala'

echo "this is testarray 2: ${testarray[2]}"
echo "this is testarray 5: ${testarray[5]}"
echo "this is testarray 3: ${testarray[3]}"

profile_ident="asfasdfasdf-mfasession"

		if [[ "$profile_ident" != "" ]] &&
			[[ ! "$profile_ident" =~ -mfasession$ ]] &&
			[[ ! "$profile_ident" =~ -rolesession$ ]] ; then

				echo "joujoujou"

		fi

echo > testfile
echo "blabla" >> testfile
echo -e "\\n\\n" >> testfile
echo "blabla again" >> testfile
