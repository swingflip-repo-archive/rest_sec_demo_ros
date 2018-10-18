
IMPORT JAVA CalcSha512digest
--------------------------------------------------------------------------------
-- Return an base64 encoded version of the hashed string 
-- @param l_str String to hah
-- @param l_algo Algorithm to use, eg: MD5, sha512
-- @return result or NULL
FUNCTION ComputeHash_javaInterface(l_str STRING, l_algo STRING) RETURNS STRING
	DEFINE l_result STRING
	DEFINE l_CalcSha512digest CalcSha512digest

	LET l_calcSha512digest = CalcSha512digest.create()
	LET l_result = l_CalcSha512digest.calculateAndEncodeElementDigestString( l_str, l_algo )

	RETURN l_result
END FUNCTION