package ee.joonasvali.sha256eli5;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * <p>
 * Sha256ELI5 is a Sha256 digester, which is designed to be human readable and debuggable.
 * As a result it is not suitable for production use due to extremely bad performance compared to real implementations.
 * </p>
 * <p>
 * The variable names in main loops are paired with SHA256 pseudocode implementation in
 * <a href="https://en.wikipedia.org/wiki/SHA-2#Pseudocode">Wikipedia</a>
 * so that their meaning would be easily understandable in the context of existing theory.
 * </p>
 * <p>
 * Any String named 'bin' in this class means Binary String, which is just String representation
 * of bits, so that the String is usually of length which is multiple of 8 and looks something like "0001110110101010"
 * simulating an array of bytes.
 * </p>
 * <p>
 * Sha256Explained is licensed as UNLICENSED.
 * For more information, please refer to <a href="http://unlicense.org">UNLICENSED</a>
 * </p>
 *
 * @author Joonas Vali
 */
public class SHA256ELI5 {
  // SHA256 sums two integers and takes modulo 2^32 from the result, this is a helper value for the function
  private static final BigInteger maxInt = new BigInteger("2").pow(32);

  //first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
  private static final String[] hash = {
      hexToBin32("6A09E667"),
      hexToBin32("BB67AE85"),
      hexToBin32("3C6EF372"),
      hexToBin32("A54FF53A"),
      hexToBin32("510E527F"),
      hexToBin32("9B05688C"),
      hexToBin32("1F83D9AB"),
      hexToBin32("5BE0CD19")
  };

  //Array of round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
  private static final String[] k_hex = {
      "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
      "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
      "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
      "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
      "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
      "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
      "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
      "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"
  };

  /**
   * @param bytes The input to process
   * @return The sha256 as bytes
   */
  public static byte[] digest(byte[] bytes) {
    // Preprocessing makes the length of bytes a multiple of 512 bits
    String preprocessedInput = preprocess(bytesToBinaryString(bytes));
    // Split the value to chunks of length 512.
    String chunks[] = split(preprocessedInput, 512);

    // The initial value of the returned hash is constant.
    String[] hash = copyArray(SHA256ELI5.hash);

    // Process the message in successive 512-bit chunks:
    for (String chunk : chunks) {
      // message schedule array
      String[] w = new String[64];

      String[] splitChunk = split(chunk, 32);
      // The chunk broken down to 32 bits fits exactly into first 16 slots of 64 slot array (512 / 32 = 16)
      for (int i = 0; i < splitChunk.length; i++) {
        w[i] = splitChunk[i];
      }

      // The rest, 48 slots, are filled using the following logic:
      for (int i = 16; i < 64; i++) {
        String s0 = xor32(rotateRight32(w[i - 15], 7), rotateRight32(w[i - 15], 18), shiftRight32(w[i - 15], 3));
        String s1 = xor32(rotateRight32(w[i - 2], 17), rotateRight32(w[i - 2], 19), shiftRight32(w[i - 2], 10));
        w[i] = sum32(w[i - 16], s0, w[i - 7], s1);
      }

      String a = hash[0];
      String b = hash[1];
      String c = hash[2];
      String d = hash[3];
      String e = hash[4];
      String f = hash[5];
      String g = hash[6];
      String h = hash[7];

      for (int i = 0; i < 64; i++) {
        //(e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        String s1 = xor32(rotateRight32(e, 6), rotateRight32(e, 11), rotateRight32(e, 25));
        //(e and f) xor ((not e) and g)
        String ch = xor32(and32(e, f), and32(not32(e), g));
        // h + S1 + ch + k[i] + w[i]
        String temp1 = sum32(h, s1, ch, hexToBin32(k_hex[i]), w[i]);
        // (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        String s0 = xor32(rotateRight32(a, 2), rotateRight32(a, 13), rotateRight32(a, 22));
        //(a and b) xor (a and c) xor (b and c)
        String maj = xor32(and32(a, b), and32(a, c), and32(b, c));
        //S0 + maj
        String temp2 = sum32(s0, maj);

        h = g;
        g = f;
        f = e;
        e = sum32(d, temp1);
        d = c;
        c = b;
        b = a;
        a = sum32(temp1, temp2);
      }

      hash[0] = sum32(hash[0], a);
      hash[1] = sum32(hash[1], b);
      hash[2] = sum32(hash[2], c);
      hash[3] = sum32(hash[3], d);
      hash[4] = sum32(hash[4], e);
      hash[5] = sum32(hash[5], f);
      hash[6] = sum32(hash[6], g);
      hash[7] = sum32(hash[7], h);
    }
    // digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
    String digest = hash[0] + hash[1] + hash[2] + hash[3] + hash[4] + hash[5] + hash[6] + hash[7];

    // Finally convert the resulting hash from binary string to byte array.
    // Often this is converted to Base 16 String when printed or stored, resulting in familiar alphanumeric form.
    return binaryStringToBytes(digest);
  }

  /**
   * Preprocessing extends the input to be multiple of 512 bits.
   * begin with the original message of length L bits
   * append a single '1' bit
   * append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
   * append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
   */
  private static String preprocess(String bin) {
    int length = bin.length();
    StringBuilder strb = new StringBuilder(bin);
    strb.append("1");
    for (int i = 0; i < 512; i++) {
      if ((strb.length() + 64) % 512 == 0) {
        break;
      }
      strb.append("0");
    }
    strb.append(normalizeTo64Bit(BigInteger.valueOf(length).toString(2)));
    bin = strb.toString();
    return bin;
  }

  /**
   * 32-bit function for shifting bits right in binary string
   */
  private static String not32(String bin) {
    return Integer.toBinaryString(~Integer.parseUnsignedInt(bin, 2));
  }

  /**
   * 32-bit function for shifting bits right in binary string
   */
  private static String shiftRight32(String bin, int steps) {
    return normalizeTo32Bit(Integer.toBinaryString(Integer.parseUnsignedInt(bin, 2) >>> steps));
  }

  /**
   * 32-bit function for rotating bits right in binary string
   */
  private static String rotateRight32(String bin, int steps) {
    return normalizeToNBit(Integer.toBinaryString(Integer.rotateRight(Integer.parseUnsignedInt(bin, 2), steps)), bin.length());
  }

  /**
   * 32-bit function for bitwise XOR function of binary strings
   */
  private static String xor32(String... bins) {
    int result = Integer.parseUnsignedInt(bins[0], 2);
    for (int i = 1; i < bins.length; i++) {
      result ^= Integer.parseUnsignedInt(bins[i], 2);
    }
    return normalizeTo32Bit(Integer.toBinaryString(result));
  }

  /**
   * 32-bit function for bitwise AND function of binary strings
   */
  private static String and32(String... bins) {
    int result = Integer.parseUnsignedInt(bins[0], 2);
    for (int i = 1; i < bins.length; i++) {
      result &= Integer.parseUnsignedInt(bins[i], 2);
    }
    return normalizeTo32Bit(Integer.toBinaryString(result));
  }

  /**
   * Converts String value hex to String Binary value.
   */
  private static String hexToBin32(String hex) {
    return normalizeTo32Bit(new BigInteger(hex, 16).toString(2));
  }

  /**
   * 32-bit function for summing integers which takes modulo 2^32 from the result
   */
  private static String sum32(String... bins) {
    BigInteger ans = BigInteger.ZERO;
    for (String nums : bins) {
      ans = ans.add(new BigInteger(nums, 2));
    }
    ans = ans.mod(maxInt);
    return normalizeTo32Bit(ans.toString(2));
  }

  /**
   * Splits String into equal parts of size 'chunkSize'.
   */
  private static String[] split(String str, int chunkSize) {
    return str.split("(?<=\\G.{" + chunkSize + "})");
  }

  /**
   * Adds enough zeros to the beginning of the binary string so that it would be of length n.
   *
   * @param bin String representation of a binary number.
   * @return 32-bit binary number in String representation
   */
  private static String normalizeToNBit(String bin, int n) {
    return IntStream.generate(() -> 0).limit(n - bin.length()).mapToObj(Integer::toString).collect(Collectors.joining()) + bin;
  }

  /**
   * @param bin String representation of a binary number.
   * @return 32-bit binary number in String representation
   */
  private static String normalizeTo32Bit(String bin) {
    return normalizeToNBit(bin, 32);
  }

  /**
   * @param bin String representation of a binary number.
   * @return 64-bit binary number in String representation
   */
  private static String normalizeTo64Bit(String bin) {
    return normalizeToNBit(bin, 64);
  }

  /**
   * Simple way to copy String array
   */
  private static String[] copyArray(String[] src) {
    String result[] = new String[src.length];
    System.arraycopy(src, 0, result, 0, result.length);
    return result;
  }

  /**
   * Convert binary string to byte array
   */
  private static byte[] binaryStringToBytes(String bin) {
    byte[] array = new BigInteger(bin, 2).toByteArray();
    // BigInteger likes to return leading 0 byte, we remove it if present
    if (array[0] == 0) {
      byte[] tmp = new byte[array.length - 1];
      System.arraycopy(array, 1, tmp, 0, tmp.length);
      array = tmp;
    }
    return array;
  }

  /**
   * Convert bytes to binary string, also keeps empty leading bytes if they exist
   *
   * @return Binary String that has multiple of 8 bits in it.
   */
  private static String bytesToBinaryString(byte[] bytes) {
    StringBuilder bin = new StringBuilder();
    for (byte b : bytes) {
      StringBuilder byteBuilder = new StringBuilder();
      byteBuilder.append(Integer.toBinaryString(b & 0xFF));
      while (byteBuilder.length() < 8) {
        byteBuilder.insert(0, "0");
      }
      bin.append(byteBuilder);
    }
    return bin.toString();
  }
}