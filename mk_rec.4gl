
IMPORT util
MAIN
	DEFINE l_file STRING
	DEFINE l_filedata TEXT
	DEFINE l_json_str util.JSON
	LET l_file = ARG_VAL(1)
	LOCATE l_filedata IN FILE l_file
	DISPLAY util.JSON.proposeType( l_filedata )
END MAIN
