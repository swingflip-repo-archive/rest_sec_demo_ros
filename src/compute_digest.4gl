
IMPORT security
--------------------------------------------------------------------------------
-- Return an base64 encoded version of the hashed string 
-- @param l_str String to hah
-- @param l_algo Algorithm to use, eg: MD5, sha512
-- @return result or NULL
FUNCTION ComputeHash(l_str STRING, l_algo STRING) RETURNS STRING
	DEFINE l_dgst security.Digest
	DEFINE l_result STRING

	TRY
		LET l_dgst = security.Digest.CreateDigest( l_algo )
		CALL l_dgst.AddStringData( l_str )
		LET l_result = l_dgst.DoBase64Digest()
		--DISPLAY "Hex: ",l_dgst.DoHexBinaryDigest()," Base64 of Hex: ", security.Base64.FromString(l_dgst.DoHexBinaryDigest() )
	CATCH
		--DISPLAY "ERROR : ", STATUS, " - ", SQLCA.SQLERRM
		RETURN NULL
	END TRY

--	DISPLAY SFMT("ComputeHash( '%1', '%2' ) RET[ %3 ]", l_str, l_algo, l_result)
	RETURN l_result
END FUNCTION