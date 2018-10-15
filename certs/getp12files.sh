
export FGLLDPATH=../bin

#CERT=999963401
#PASSWD=6ab5b841

#CERT=999962922
#PASSWD=ac6bfe36

CERT=1073032130
PASSWD=7660b444

IN=${CERT}.p12
PRIVKEY=${CERT}.key
SIGNKEY=${CERT}.signkey
PUBCERT=${CERT}.pem
PASSWDMD5=$( fglrun bin/md5_password.42r $PASSWD )

echo "Trying to unpack $IN using $PASSWDMD5"

echo "openssl pkcs12 -in $IN -clcerts -nokeys -out $PUBCERT -password pass:$PASSWDMD5"
echo "Extract the Cert from $IN"
openssl pkcs12 -in $IN -clcerts -nokeys -out $PUBCERT -password pass:$PASSWDMD5
if [ $? -ne 0 ]; then
	exit 1
fi

#echo "openssl pkcs12 -in $IN -nocerts -out $PRIVKEY -password pass:$PASSWDMD5"
echo "Extract the private key from $IN and give it a temporary pass phrase"
openssl pkcs12 -in $IN -nocerts -out $PRIVKEY -password pass:$PASSWDMD5 -passout pass:TemporaryPassword

echo "Now remove the pass phrase from the key so we can automate signing stuff"
openssl rsa -in $PRIVKEY -out $SIGNKEY -passin pass:TemporaryPassword

ls -lart ${CERT}.*
