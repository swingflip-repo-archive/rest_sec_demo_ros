
-- Generate the String that needs to be signed.

--------------------------------------------------------------------------------
-- Item may appear in a different order then created!!
FUNCTION fromDict( l_dict DICTIONARY OF STRING ) RETURNS STRING
	DEFINE l_sig STRING
	DEFINE x SMALLINT
	DEFINE l_key DYNAMIC ARRAY OF STRING
	LET l_key = l_dict.getKeys()
	FOR x = 1 TO l_key.getLength()
		LET l_sig = l_sig.append(l_key[x].trim()||": "||l_dict[l_key[x]].trim() )
		IF x != l_key.getLength() THEN LET l_sig = l_sig.append("\n") END IF
	END FOR
	RETURN l_sig.trim()
END FUNCTION
--------------------------------------------------------------------------------
--
FUNCTION fromArray( l_arr DYNAMIC ARRAY OF RECORD key STRING, val STRING, addToSig BOOLEAN END RECORD ) RETURNS STRING
	DEFINE l_sig STRING
	DEFINE x SMALLINT
	FOR x = 1 TO l_arr.getLength()
		IF l_arr[x].addToSig THEN
			IF x > 1 THEN LET l_sig = l_sig.append("\n") END IF
			LET l_sig = l_sig.append(l_arr[x].key.toLowerCase()||": "||l_arr[x].val.trim() )
		END IF
	END FOR
	RETURN l_sig.trim()
END FUNCTION