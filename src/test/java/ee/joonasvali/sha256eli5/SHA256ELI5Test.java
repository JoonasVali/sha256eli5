package ee.joonasvali.sha256eli5;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SHA256ELI5Test {

  @Test
  public void testIntegersAgainstRealImplementation() throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    for (int i = 2; i < Integer.MAX_VALUE && i * 2 > 0; i *= 1.5d) {
      byte[] bytesToHash = intToByteArray(i);
      byte[] eli5bytes = SHA256ELI5.digest(bytesToHash);
      byte[] hash = digest.digest(bytesToHash);
      Assert.assertEquals(Arrays.toString(hash), Arrays.toString(eli5bytes));
    }
  }

  @Test
  public void testLeadingZeroIntegersAgainstRealImplementation() throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    for (int i = 1; i < Integer.MAX_VALUE && i * 2 > 0; i *= 2) {
      byte[] bytesToHash = BigInteger.valueOf(i).toByteArray(); // Creates sometimes leading zero bytes
      byte[] eli5bytes = SHA256ELI5.digest(bytesToHash);
      byte[] hash = digest.digest(bytesToHash);
      Assert.assertEquals(Arrays.toString(hash), Arrays.toString(eli5bytes));
    }
  }

  @Test
  public void testStringsAgainstRealImplementation() throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    StringBuilder strb = new StringBuilder();
    for (int i = 0; i < 100; i++) {
      strb.append("Hello world! ");
      byte[] bytesToHash = strb.toString().getBytes(StandardCharsets.UTF_8);
      byte[] eli5bytes = SHA256ELI5.digest(bytesToHash);
      byte[] hash = digest.digest(bytesToHash);
      Assert.assertEquals(Arrays.toString(hash), Arrays.toString(eli5bytes));
    }
  }

  @Test
  public void testZeroBytesAgainstRealImplementation() throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] bytesToHash = new byte[0];
    byte[] eli5bytes = SHA256ELI5.digest(bytesToHash);
    byte[] hash = digest.digest(bytesToHash);
    Assert.assertEquals(Arrays.toString(hash), Arrays.toString(eli5bytes));
  }

  private static byte[] intToByteArray(int value) {
    return new byte[] {
        (byte)(value >>> 24),
        (byte)(value >>> 16),
        (byte)(value >>> 8),
        (byte)value};
  }
}
