IMPORT security
FUNCTION getBase64Cert( l_file STRING ) RETURNS STRING
	DEFINE l_cert TEXT
	LOCATE l_cert IN MEMORY
	CALL l_cert.readFile( l_file )
	RETURN security.Base64.FromString(l_cert)
END FUNCTION