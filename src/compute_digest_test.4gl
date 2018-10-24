
IMPORT security
IMPORT os
--------------------------------------------------------------------------------
-- Return an base64 encoded version of the hashed string 
-- @param l_str String to hah
-- @param l_algo Algorithm to use, eg: MD5, sha512
-- @return result or NULL
FUNCTION ComputeHash(l_str STRING, l_algo STRING) RETURNS STRING
	DEFINE l_dgst security.Digest
	DEFINE l_result STRING

	TRY
		LET l_dgst = security.Digest.CreateDigest( l_algo.toUpperCase() )
    DISPLAY "TEST:" || l_dgst
		CALL l_dgst.AddStringData( l_str )
    DISPLAY "TEST2:" || l_dgst
		LET l_result = l_dgst.DoBase64Digest()
    DISPLAY "TEST3:" || l_result
		--DISPLAY "Hex: ",l_dgst.DoHexBinaryDigest()," Base64 of Hex: ", security.Base64.FromString(l_dgst.DoHexBinaryDigest() )
	CATCH
		DISPLAY "ERROR : ", STATUS, " - ", SQLCA.SQLERRM
		RETURN NULL
	END TRY

	RETURN l_result
END FUNCTION
--------------------------------------------------------------------------------
-- Return an base64 encoded version of the hashed string 
-- @param l_str String to hah
-- @param l_algo Algorithm to use, eg: MD5, sha512
-- @return result or NULL
FUNCTION ComputeHash_openssl(l_str STRING, l_algo STRING) RETURNS STRING
	DEFINE l_result, l_cmd STRING, l_signedFile, l_textFile STRING
	DEFINE l_text TEXT

-- Save the 'l_str' to encrypt to a temporary .txt file
	LET l_textFile = fgl_getPID()||".str"
	LOCATE l_text IN FILE l_textFile
	LET l_text = l_str

-- Use openssl to encrypt the .txt using the key file.
	LET l_signedFile = fgl_getPID()||".tmp"
	LET l_cmd = SFMT("cat %1 | openssl dgst -%2 -binary > %3", l_textFile, l_algo, l_signedFile  )
	DISPLAY "CMD: ",l_cmd
	RUN l_cmd

	IF NOT os.path.exists(l_signedFile) THEN
		RETURN "Failed to create .tmp file! check permissions!"
	END IF

-- Return the base64 version of the encrypted file
	LET l_result = security.Base64.LoadBinary(l_signedFile) -- .FromByte(l_data)
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