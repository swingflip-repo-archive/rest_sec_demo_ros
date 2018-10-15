IMPORT security
IMPORT os

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
	LET l_textFile = fgl_getPID()||".txt"
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

-- Do the clean up of temp files
	IF NOT os.path.delete( l_textFile ) THEN
		DISPLAY SFMT( "Failed to delete %1 %2!",l_textFile, ERR_GET(STATUS) )
	END IF
	IF NOT os.path.delete( l_signedFile ) THEN
		DISPLAY SFMT( "Failed to delete %1 %2!",l_textFile, ERR_GET(STATUS) )
	END IF

	RETURN l_result
END FUNCTION
--------------------------------------------------------------------------------