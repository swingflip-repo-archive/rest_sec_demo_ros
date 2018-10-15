
IMPORT util
IMPORT com
IMPORT security

IMPORT FGL getBase64Cert
IMPORT FGL generateSignature
IMPORT FGL encrypt
IMPORT FGL compute_digest
IMPORT FGL lib_log

CONSTANT C_SOFTWARE = "FourJsTest"
CONSTANT C_SOFTWAREVER = "0.1"
CONSTANT C_TZ = "GMT"
CONSTANT C_CON_TIMEOUT = 5

CONSTANT C_HOST = "softwaretest.ros.ie"

DEFINE m_txt STRING
DEFINE m_arr DYNAMIC ARRAY OF RECORD
	key STRING,
	val STRING,
	addToSig BOOLEAN
	END RECORD
MAIN
	DEFINE l_cert, l_empRegNo, l_taxYear STRING
	DEFINE l_reqTarget, l_payload STRING

	LET l_cert = "../certs/999962922" -- "1073032130"
	LET l_empRegNo = "8001274QH"
	LET l_taxYear = "2018"
	LET l_payload = ""
	LET l_reqTarget = SFMT("paye-employers/v1/rest/rpn/%1/%2?softwareUsed=%3&softwareVersion=%4", l_empRegNo, l_taxYear, C_SOFTWARE, C_SOFTWAREVER )

	OPEN FORM frm FROM "testConnect"
	DISPLAY FORM frm

	CALL test1( l_reqTarget, l_cert, l_payload )

	DISPLAY ARRAY m_arr TO scr_arr.* ATTRIBUTES( ACCEPT=FALSE, CANCEL=FALSE )
		ON ACTION close EXIT DISPLAY
		ON ACTION exit EXIT DISPLAY
	END DISPLAY

END MAIN
--------------------------------------------------------------------------------
FUNCTION test1( l_reqTarget STRING, l_cert STRING, l_payload STRING )
	DEFINE x SMALLINT
	DEFINE l_method STRING
	DEFINE l_signature, l_date, l_signed STRING
	DEFINE l_url, l_keyId, l_headers STRING
	DEFINE l_reply STRING

	CALL disp("Starting test1 ...")

	LET l_method = "GET"
	LET l_url = SFMT("https://%1/%2",C_HOST, l_reqTarget)

	CALL disp(SFMT("Get the base64 version of '%1'", l_cert||".pem"))
	LET l_keyId = getBase64Cert.getBase64Cert(l_cert||".pem")
	LET l_date = util.Datetime.format( util.Datetime.getCurrentAsUTC(), "%a, %d %b %Y %H:%M:%S "||C_TZ)
-- Fri, 12 Oct 2018 15:42:54 GMT   -- no way to get the Timezone?
--	LET l_date = util.Datetime.format( CURRENT, "%a %d %b %Y %H:%M:%S "||C_TZ)

	CALL arr_addItem( "(request-target)", "get /"||l_reqTarget, TRUE)
	CALL arr_addItem( "Host", C_HOST, TRUE)

--	CALL arr_addItem( "Date", l_date, TRUE) -- Date can't be set manually!!
	CALL arr_addItem( "X-Date", l_date, TRUE)

	IF l_payload.getLength() > 1 THEN
		LET l_method = "POST"
		CALL arr_addItem( "X-HTTP-Method-Override","GET", TRUE)
		CALL arr_addItem( "Digest", compute_digest.ComputeHash(l_payload,"sha512"), TRUE )
		CALL arr_addItem( "Content-Type","application/x-www-form-urlencoded", FALSE)
	END IF

	FOR x = 1 TO m_arr.getLength()
		IF m_arr[x].addToSig THEN
			IF x > 1 THEN LET l_headers = l_headers.append(" ") END IF
			LET l_headers = l_headers.append(m_arr[x].key.toLowerCase())
		END IF
	END FOR

	LET l_signed = generateSignature.fromArray( m_arr )

	CALL disp("URL: "||l_url)
	CALL disp("KeyId: "||l_keyId)
	CALL disp("Headers: "||l_headers)
	CALL disp("Date: "||l_date)
	CALL disp("To Sign: \n"||l_signed)
	DISPLAY BY NAME l_url, l_headers, l_date, l_keyId, l_signed
	DISPLAY ARRAY m_arr TO scr_arr.*
		BEFORE DISPLAY EXIT DISPLAY
	END DISPLAY

	CALL disp(SFMT("Get encrypted sig using private key '%1'", l_cert||".signkey") )
	LET l_signed = encrypt.withKeyFile( l_signed, l_cert||".signkey")
	LET l_signature = SFMT('keyId="%1",algorithm="%2",headers="%3",signature="%4"',
					l_keyId, "rsa-sha512",l_headers, l_signed)

	CALL disp("Signed: "||l_signed)
	CALL disp("Signature: "||l_signature)
	DISPLAY "\n\n\n"

	LET l_reply = do_rest_request(l_method, l_url, l_signature, l_payload)
	DISPLAY BY NAME l_reply
	CALL disp("Finished test1.")
END FUNCTION

--------------------------------------------------------------------------------
-- a simple GET doesn't need Digest or X-HTTP-Method-Override
-- POST does require a Digest
FUNCTION do_rest_request(l_method STRING, l_url STRING, l_signature STRING, l_payload STRING )
	DEFINE l_req com.HttpRequest
	DEFINE l_resp com.HTTPResponse
	DEFINE l_info RECORD
		status SMALLINT,
		header STRING
	END RECORD
	DEFINE x SMALLINT
	DEFINE l_txt STRING

	CALL disp(SFMT("Create '%1'  ...",l_url))
	LET l_req = com.HttpRequest.Create(l_url)
	CALL disp(SFMT("setMethod %1 ...",l_method))
	CALL l_req.setMethod(l_method)

	CALL disp("setHeaders ...")
	FOR x = 2 TO m_arr.getLength()
		CALL disp( SFMT("setHeader(%1,%2)",m_arr[x].key, m_arr[x].val) )
		CALL l_req.setHeader(m_arr[x].key, m_arr[x].val)
	END FOR
	CALL disp( SFMT("setHeader(%1,%2)","Signature", l_signature) )
	CALL l_req.setHeader("Signature",l_signature)
	CALL l_req.setConnectionTimeOut( C_CON_TIMEOUT )
	IF l_method = "GET" THEN
		CALL disp("doRequest ...")
		TRY
			CALL l_req.doRequest()
		CATCH
			LET l_txt = "Failed to doRequest for "||l_url||" "||STATUS||" "||ERR_GET(STATUS)
			CALL disp( l_txt  )
			RETURN l_txt
		END TRY
	ELSE
		CALL disp(SFMT("doTextRequest('%1') ...",l_payload))
		TRY
			CALL l_req.doTextRequest( l_payload )
		CATCH
			LET l_txt = "Failed to doTextRequest for "||l_url||" "||STATUS||" "||ERR_GET(STATUS)
			CALL disp( l_txt  )
			RETURN l_txt
		END TRY
	END IF

	CALL disp("getResponse ...")
	TRY
		LET l_resp = l_req.getResponse()
	CATCH
		LET l_txt =  "Failed to getResponse for "||l_url||" "||STATUS||" "||ERR_GET(STATUS)
		CALL disp( l_txt )
		RETURN l_txt
	END TRY

	LET l_info.status = l_resp.getStatusCode()
	IF l_info.status != 200 THEN
		CALL disp( "Failed:"|| l_info.status )
--		RETURN
	ELSE
		CALL disp( "Success!" )
	END IF

	LET l_info.header = l_resp.getHeader("Content-Type")
	CALL disp( "StatusCode:"||l_info.status )
	CALL disp( "Header:"||l_info.header )
	LET l_txt = l_resp.getTextResponse()
	CALL disp( "Response:"||l_txt )
	RETURN l_info.status||" "||l_txt 
END FUNCTION
--------------------------------------------------------------------------------
FUNCTION disp(l_txt STRING)
	DISPLAY l_txt
	LET l_txt = CURRENT||":"||l_txt
	CALL log(l_txt)
	LET m_txt = m_txt.append( l_txt||"\n" )
	DISPLAY BY NAME m_txt
	CALL ui.Interface.refresh()
END FUNCTION
--------------------------------------------------------------------------------
FUNCTION arr_addItem(l_key STRING,l_val STRING, l_addToSig BOOLEAN)
	LET m_arr[m_arr.getLength()+1].key = l_key
	LET m_arr[m_arr.getLength()].val = l_Val
	LET m_arr[m_arr.getLength()].addToSig = l_addToSig
END FUNCTION