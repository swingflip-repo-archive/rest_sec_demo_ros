import java.io.*;
import java.security.*;
import java.util.Base64;

public class HelloWorld {

	public static void main(String[] args) {
		// Prints "Hello, World" to the terminal window.

		try {
			InputStream inputstream = new FileInputStream("text.txt");
			String l_str = calculateAndEncodeElementDigest( inputstream );
			System.out.println( l_str );
		} catch (FileNotFoundException fnfe) {
				// Do something useful with that error
				// For example:
				System.out.println(fnfe);
		}

	}

	public static String calculateAndEncodeElementDigest(InputStream element) {
	
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

		String l_str = "Input: ";
		l_str += elementOutputStream.toString();
		System.out.println( l_str );

		byte[] sha_result = new byte[1];

		try {
			MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
			sha_result = sha512Digest.digest( elementOutputStream.toByteArray() );
		} catch (NoSuchAlgorithmException msg ) {
			System.out.println(msg);
		}

		return Base64.getEncoder().encodeToString( sha_result );
	}
}
