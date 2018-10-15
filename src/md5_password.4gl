
{
1. First get the bytes of the original password, assuming a "Latin-1" encoding. 
For the password "Password123", these bytes are: 80 97 115 115 119 111 114 100 49 50 51
(i.e. the value of "P" is 80, "a" is 97, etc.).

2. Then get the MD5 hash of these bytes. MD5 is a standard, public algorithm. 
Once again, for the password "Password123" these bytes work out as: 66 -9 73 -83 -25 -7 -31 -107 -65 71 95 55 -92 76 -81 -53.

3. Finally, create the new password by Base64-encoding the bytes from the previous step. 
For example, the password, "Password123" this is “QvdJref54ZW/R183pEyvyw==”. 
}

IMPORT FGL compute_digest

MAIN
	DEFINE l_clearVal STRING
	DEFINE l_encoded STRING

	LET l_clearVal = ARG_VAL(1)
	IF l_clearVal.getLength() < 2 THEN
		PROMPT "Enter String:" FOR l_clearVal
	END IF
	IF l_clearVal.getLength() < 2 THEN
		DISPLAY "Invalid aborting"
		EXIT PROGRAM
	END IF
	LET l_encoded = compute_digest.ComputeHash(l_clearVal, "MD5") -- Compute a Base64 encoded MD5 hash
	--DISPLAY SFMT("Clear: %1  Base64 Encoded MD5: %2", l_clearVal, l_encoded )
	DISPLAY l_encoded
END MAIN