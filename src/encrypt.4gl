IMPORT security
IMPORT os
IMPORT xml

CONSTANT C_KEY_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
--CONSTANT C_KEY_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

--------------------------------------------------------------------------------
-- Sign a STRING with a private key file
-- @param l_str String to sign
-- @param l_keyFile File name for private key
-- @returns The base64 encoded version of the signed string
FUNCTION withKeyFile( l_str STRING, l_keyFile STRING ) RETURNS STRING
	DEFINE l_result, l_cmd STRING, l_signedFile, l_textFile STRING
	DEFINE l_data BYTE
	DEFINE l_text TEXT

-- Save the 'l_str' to encrypt to a temporary .txt file
	LET l_textFile = fgl_getPID()||".str"
	LOCATE l_text IN FILE l_textFile
	LET l_text = l_str

-- Use openssl to encrypt the .txt using the key file.
	LET l_signedFile = fgl_getPID()||".tmp"
	LET l_cmd = SFMT("openssl dgst -sha512 -sign %1 -out %2 %3", l_keyFile, l_signedFile, l_textFile )
	RUN l_cmd

-- Read the encrypted file
	LOCATE l_data IN MEMORY
	CALL l_data.readFile( l_signedFile )

-- Return the base64 version of the encrypted file
	LET l_result = security.Base64.FromByte(l_data)
{
-- Do the clean up of temp files
	IF NOT os.path.delete( l_textFile ) THEN
		DISPLAY SFMT( "Failed to delete %1 %2!",l_textFile, ERR_GET(STATUS) )
	END IF
	IF NOT os.path.delete( l_signedFile ) THEN
		DISPLAY SFMT( "Failed to delete %1 %2!",l_textFile, ERR_GET(STATUS) )
	END IF
}
	RETURN l_result
END FUNCTION
--------------------------------------------------------------------------------
-- Unfortunately we don't support SHA512 yet!
--
-- @param l_keyFile Private key to use for encryption
-- @param l_str String to encrypt
-- @returns string of the base64 encoded version of the encrypted data
FUNCTION glsec_encryptWithKeyFile( l_str STRING, l_keyFile STRING ) RETURNS STRING
	DEFINE l_ret STRING
	DEFINE l_key xml.CryptoKey

	IF NOT os.path.exists( l_keyFile ) THEN
		RETURN SFMT(%"ERROR: Key File '%1' doesn't Exist!", l_keyFile )
	END IF

	TRY
		LET l_key = xml.CryptoKey.Create(C_KEY_ALG)
	CATCH
		RETURN SFMT(%"ERROR: %1 : %2",STATUS,ERR_GET(STATUS))
	END TRY
	CALL l_key.loadPEM( l_keyFile )
	LET l_ret = xml.Signature.signString(l_key,l_str)

	RETURN l_ret
END FUNCTION