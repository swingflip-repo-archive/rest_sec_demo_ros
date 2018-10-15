IMPORT security

DATABASE ibsldata

CONSTANT algo = "MD5"

MAIN
  DEFINE clearVal STRING
  DEFINE val64 STRING
		DEFINE ret BYTE


		CREATE TEMP TABLE t_char
		(
		char CHAR(100)
		)
		LOCATE ret IN MEMORY
		LET clearVal = "Password123"
		LET val64 = security.Base64.FromString(clearVal) 


		CALL security.Base64.ToByte(val64,ret)
		LET val64 = ret
		INSERT INTO t_char VALUES(val64)

		unload to "/tmp/t_char.unl" select * FROM t_char

		LOCATE ret IN MEMORY

		CALL fnGetBYTEPassword(clearVal) RETURNING val64

  CALL ComputeHash(val64, algo) RETURNING val64

		display "RET[",ret,"] AsComputeHash[",val64 CLIPPED,"]"
END MAIN

PRIVATE 
FUNCTION fnGetBYTEPassword(i_password STRING) RETURNS STRING
  DEFINE r_byte_password STRING
		DEFINE f_loop INTEGER

		display "\nfnGetBYTEPassword('",i_password CLIPPED,"')v"
		INITIALIZE r_byte_password TO NULL

		FOR f_loop = 1 TO i_password.Getlength()

						IF LENGTH(r_byte_password) = 0 THEN
--							display SFMT("Loop[%1] Char[%2] Ascii[%3]",f_loop,i_password.SubString(f_loop,f_loop),ORD(i_password.SubString(f_loop,f_loop) )  )
									LET r_byte_password = ORD(i_password.SubString(f_loop,f_loop) ) USING "<<<<<&"
						ELSE
									LET r_byte_password = r_byte_password CLIPPED," ",ORD(i_password.SubString(f_loop,f_loop) ) USING "<<<<<&"
						END IF

		END FOR

		display "\nfnGetBYTEPassword() RET[",r_byte_password CLIPPED,"]"
		RETURN r_byte_password
END FUNCTION

PRIVATE
FUNCTION ComputeHash(toDigest STRING, algo STRING) RETURNS STRING
  DEFINE dgst security.Digest
  DEFINE result STRING

		display "ComputeHash( '",toDigest CLIPPED,"','",algo CLIPPED,"') v"

  TRY
    LET dgst = security.Digest.CreateDigest(algo)
    CALL dgst.AddStringData(toDigest)
    LET result = dgst.DoBase64Digest()
  CATCH
    DISPLAY "ERROR : ", STATUS, " - ", SQLCA.SQLERRM
    EXIT PROGRAM(-1)
  END TRY

		display "ComputeHash() ^ RET[",result CLIPPED,"]"
  RETURN result
END FUNCTION
