IMPORT util
IMPORT FGL compute_digest
MAIN
	DEFINE l_str, l_ret STRING
	LET l_str = "employeeIDs=7000043NA-12&employeeIDs=7009397BA-1&employeeIDs=7013003WA-10"
	LET l_str = '{
    "payslips": [{
        "lineItemID": "E1-v1",
        "employeeID": {
            "employeePpsn": "00000008P",
            "employmentID": "1"
        },
        "name": {
            "firstName": "Ann",
            "familyName": "Doe"
        },
        "payFrequency": "WEEKLY",
        "rpnNumber": "5",
        "taxCredits": 63.46,
        "taxRates": [{
            "index": 1,
            "rateCutOff": 650
        }],
        "calculationBasis": "CUMULATIVE",
        "payDate": "2019-02-01",
        "grossPay": 307.50,
        "payForIncomeTax": 307.50,
        "incomeTaxPaid": 0,
        "payForEmployeePRSI": 307.50,
        "payForEmployerPRSI": 307.50,
        "prsiExempt": false,
        "prsiClassDetails": [{
            "prsiClass": "A0",
            "insurableWeeks": 5
        }],
        "employeePRSIPaid": 0,
        "employerPRSIPaid": 33.06,
        "payForUSC": 307.50,
        "uscStatus": "ORDINARY",
        "uscPaid": 3.07,
        "lptDeducted": 3.67
    }]
}'
	LET l_str = util.JSON.format( l_str )
	DISPLAY ""
	LET l_ret = compute_digest.ComputeHash( l_str, "sha512" )
	DISPLAY l_ret,"  ( ",l_ret.getLength()," )"
	DISPLAY ""
	LET l_ret = compute_digest.ComputeHash_openssl( l_str, "sha512" )
	DISPLAY l_ret,"  ( ",l_ret.getLength()," )"
END MAIN