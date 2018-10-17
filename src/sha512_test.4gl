IMPORT util
IMPORT FGL compute_digest_test
MAIN
	DEFINE l_str, l_ret STRING
	LET l_str = "employeeIDs=7000043NA-12&employeeIDs=7009397BA-1&employeeIDs=7013003WA-10"

	LET l_str = '{"requestId":"1C1F2290-4EDD-4B2C-AAEC-98053568F607","newEmployeeDetails":[{"employeeID":{"employeePpsn":"123","employeeID":"1"},"name":{"firstName":"Neil","familyName":"Martin"},"employmentStartDate":"2018-10-17"}]}'
--	LET l_str = util.JSON.format( l_str )
	DISPLAY "\nGenero:"
	LET l_ret = compute_digest_test.ComputeHash( l_str, "sha512" )
	DISPLAY l_ret," ( ",l_ret.getLength() USING "##&"," )"
	DISPLAY "\nopenssl"
	LET l_ret = compute_digest_test.ComputeHash_openssl( l_str, "sha512" )
	DISPLAY l_ret," ( ",l_ret.getLength() USING "##&"," )"
	DISPLAY "\nJava"
	LET l_ret = compute_digest_test.ComputeHash_java( l_str, "sha-512" )
	DISPLAY l_ret," ( ",l_ret.getLength() USING "##&"," )"
	DISPLAY "\nGenero+Java"
	LET l_ret = compute_digest_test.ComputeHash_javaInterface( l_str, "sha-512" )
	DISPLAY l_ret," ( ",l_ret.getLength() USING "##&"," )"
	DISPLAY "\nGenero+Java 2"
	LET l_ret = compute_digest_test.ComputeHash_javaInterface2( l_str, "sha-512" )
	DISPLAY l_ret," ( ",l_ret.getLength() USING "##&"," )"
END MAIN