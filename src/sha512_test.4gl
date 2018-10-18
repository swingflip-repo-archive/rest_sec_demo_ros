IMPORT util
IMPORT FGL compute_digest_test

CONSTANT C_EX1 = "employeeIDs=7000043NA-12&employeeIDs=7009397BA-1&employeeIDs=7013003WA-10"
CONSTANT C_EXP1 = "KdQDkUyVUpSURIIoV9BhsW883Lq8rzMMdQtPYVK1jfXt83PCkwS0Sf1ti2NJQvAhI5RhrYvxzJN8zk4kvecXlQ=="

CONSTANT C_EX2 = '{ "payslips": [{ "lineItemID": "E1-v1", "employeeID": { "employeePpsn": "00000008P", "employmentID": "1" }, "name": { "firstName": "Ann", "familyName": "Doe" }, "payFrequency": "WEEKLY", "rpnNumber": "5", "taxCredits": 63.46, "taxRates": [{ "index": 1, "rateCutOff": 650 }], "calculationBasis": "CUMULATIVE", "payDate": "2019-02-01", "grossPay": 307.50, "payForIncomeTax": 307.50, "incomeTaxPaid": 0, "payForEmployeePRSI": 307.50, "payForEmployerPRSI": 307.50, "prsiExempt": false, "prsiClassDetails": [{ "prsiClass": "A0", "insurableWeeks": 5 }], "employeePRSIPaid": 0, "employerPRSIPaid": 33.06, "payForUSC": 307.50, "uscStatus": "ORDINARY", "uscPaid": 3.07, "lptDeducted": 3.67 }] }'
CONSTANT C_EXP2 = "b1RH7nPCJqiykwDrLSZzG3rKWlwSHhrE4MJdanUYR7IJAG8m4ML5P4TOql6zPObL/+q0rHQVhqLPV67m82pJvQ=="
DEFINE m_payload, m_expect, m_genero, m_openssl, m_java STRING
MAIN

	OPEN FORM f FROM "payload"
	DISPLAY FORM f

	INPUT BY NAME m_payload, m_expect, m_genero, m_openssl, m_java ATTRIBUTES(WITHOUT DEFAULTS, UNBUFFERED,ACCEPT=FALSE, CANCEL=FALSE)
		ON ACTION ex1
			LET m_payload = C_EX1
			LET m_expect = C_EXP1
			CALL calculate()

		ON ACTION ex2
			LET m_payload = C_EX2
			LET m_expect = C_EXP2
			CALL calculate()

		ON ACTION clear
			LET m_payload = ""
			LET m_expect = ""
			LET m_genero = ""
			LET m_openssl = ""
			LET m_java = ""

		ON ACTION format_json
			TRY
				LET m_payload = util.JSON.format( m_payload )
			CATCH
				ERROR "Invalid JSON !"
			END TRY

		ON ACTION downshift
			LET m_payload = m_payload.toLowerCase()

		ON ACTION calculate
			IF m_payload IS NOT NULL THEN
				CALL calculate()
			END IF

		ON ACTION close EXIT INPUT
		ON ACTION exit EXIT INPUT
	END INPUT
END MAIN
--------------------------------------------------------------------------------
FUNCTION calculate()
	DISPLAY "\nGenero:"
	LET m_genero = compute_digest_test.ComputeHash( m_payload, "sha512" )
	DISPLAY m_genero," ( ",m_genero.getLength() USING "##&"," )"
	DISPLAY "\nopenssl"
	LET m_openssl = compute_digest_test.ComputeHash_openssl( m_payload, "sha512" )
	DISPLAY m_openssl," ( ",m_openssl.getLength() USING "##&"," )"
	DISPLAY "\nGenero+Java"
	LET m_java = compute_digest_test.ComputeHash_javaInterface( m_payload, "sha-512" )
	DISPLAY m_java," ( ",m_java.getLength() USING "##&"," )"
END FUNCTION