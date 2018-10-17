import java.io.*;
import java.security.*;
import java.util.Base64;

public class CalcSha512digest {

	public static void main(String[] args) {

		try {
			InputStream inputstream = new FileInputStream( args[0] );
			String l_str = calculateAndEncodeElementDigest( inputstream, args[1] );
			System.out.print( l_str );
		} catch (FileNotFoundException fnfe) {
				// Do something useful with that error
				// For example:
				System.out.println(fnfe);
		}

	}

// Take a file and return an hashed + base64 encoded string
	public String fromFile(String l_file, String l_algo) {
		String l_str = "Failed";
		try {
			InputStream inputstream = new FileInputStream( l_file );
			l_str = calculateAndEncodeElementDigest( inputstream, l_algo );
			//System.out.print( l_str );
		} catch (FileNotFoundException fnfe) {
				// Do something useful with that error
				// For example:
				System.out.println(fnfe);
		}
		return l_str;
	}

// Simple method for String to hashed + base64 encoded string
	public String calculateAndEncodeElementDigestString(String l_str, String l_algo) {
		byte[] sha_result = new byte[1];

		try {
			MessageDigest sha512Digest = MessageDigest.getInstance(l_algo.toUpperCase());
			sha_result = sha512Digest.digest( l_str.getBytes() );
		} catch (NoSuchAlgorithmException msg ) {
			System.out.println(msg);
		}

		return Base64.getEncoder().encodeToString( sha_result );
	}

// Take input stream and return String of hashed + base64 encoded data
	public static String calculateAndEncodeElementDigest(InputStream element, String l_algo) {
		ByteArrayOutputStream elementOutputStream = new ByteArrayOutputStream();
		byte[] elementData = new byte[1];

		try {
			while(element.read(elementData) != -1) {
				elementOutputStream.write(elementData);
			}
		} catch (IOException msg) {
				System.out.println(msg);
		}
		try {
			elementOutputStream.flush();
		} catch (IOException msg) {
				System.out.println(msg);
		}

		//String l_str = "Input: ";
		//l_str += elementOutputStream.toString();
		//System.out.println( l_str );

		byte[] sha_result = new byte[1];

		try {
			MessageDigest sha512Digest = MessageDigest.getInstance(l_algo.toUpperCase());
			sha_result = sha512Digest.digest( elementOutputStream.toByteArray() );
		} catch (NoSuchAlgorithmException msg ) {
			System.out.println(msg);
		}

		return Base64.getEncoder().encodeToString( sha_result );
	}
}
