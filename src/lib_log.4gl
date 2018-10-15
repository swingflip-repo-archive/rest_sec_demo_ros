--------------------------------------------------------------------------------
FUNCTION log(l_txt STRING)
	DEFINE c base.channel
	LET c = base.Channel.create()
	CALL c.openFile( base.application.getProgramName()||".log","a+")
	CALL c.writeLine(l_txt)
	CALL C.close()
END FUNCTION