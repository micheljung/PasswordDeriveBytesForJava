/*
 * The MIT License (MIT)
 * Copyright (c) 2014, 2016 Changgun Lee <lazysense@gmail.com>
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.gilchris.encryption;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class PasswordDeriveBytes {

   private String hashNameValue;
   private byte[] saltValue;
   private int iterationsValue;

   private MessageDigest hash;
   private int state;
   private byte[] password;
   private byte[] initial;
   private byte[] output;
   private byte[] firstBaseOutput;
   private int position;
   private int hashNumber;
   private int skip;

   public PasswordDeriveBytes(String strPassword, byte[] rgbSalt) {
      prepare(strPassword, rgbSalt, "SHA-1", 100);
   }

   public PasswordDeriveBytes(String strPassword, byte[] rgbSalt, String strHashName, int iterations) {
      prepare(strPassword, rgbSalt, strHashName, iterations);
   }

   public PasswordDeriveBytes(byte[] password, byte[] salt) {
      prepare(password, salt, "SHA-1", 100);
   }


   public PasswordDeriveBytes(byte[] password, byte[] salt, String hashName, int iterations) {
      prepare(password, salt, hashName, iterations);
   }

   private void prepare(String strPassword, byte[] rgbSalt, String strHashName, int iterations) {
      Objects.requireNonNull(strPassword, "Password must not be null");

      byte[] pwd = strPassword.getBytes(StandardCharsets.US_ASCII);
      prepare(pwd, rgbSalt, strHashName, iterations);
   }

   private void prepare(byte[] password, byte[] rgbSalt, String strHashName, int iterations) {
      Objects.requireNonNull(password, "Password must not be null");

      this.password = password;

      state = 0;
      setSalt(rgbSalt);
      setHashName(strHashName);
      setIterationCount(iterations);

      initial = new byte[hash.getDigestLength()];
   }

   public byte[] getSalt() {
      if (saltValue == null) {
         return null;
      }
      return saltValue;
   }

   public void setSalt(byte[] salt) {
      if (state != 0) {
         throw new SecurityException("Can't change this property at this stage");
      }
      if (salt != null) {
         saltValue = salt;
      } else {
         saltValue = null;
      }
   }

   public String getHashName() {
      return hashNameValue;
   }

   public void setHashName(String hashName) {
      Objects.requireNonNull(hashName, "Hash name must not be null");
      if (state != 0) {
         throw new SecurityException("Can't change this property at this stage");
      }
      hashNameValue = hashName;

      try {
         hash = MessageDigest.getInstance(hashName);
      } catch (NoSuchAlgorithmException e) {
         e.printStackTrace();
      }
   }

   public int getIterationCount() {
      return iterationsValue;
   }

   public void setIterationCount(int iterationCount) {
      if (iterationCount < 1) {
         throw new IllegalArgumentException("Iteration count must be greater than 0");
      }
      if (state != 0) {
         throw new SecurityException("Can't change this property at this stage");
      }
      iterationsValue = iterationCount;
   }

   public byte[] getBytes(int cb) throws DigestException {
      if (cb < 1) {
         throw new IndexOutOfBoundsException("cb");
      }

      if (state == 0) {
         reset();
         state = 1;
      }

      byte[] result = new byte[cb];
      int cpos = 0;
      // the initial hash (in reset) + at least one iteration
      int iter = Math.max(1, iterationsValue - 1);

      // start with the PKCS5 key
      if (output == null) {
         // calculate the PKCS5 key
         output = initial;

         // generate new key material
         for (int i = 0; i < iter - 1; i++) {
            output = hash.digest(output);
         }
      }

      while (cpos < cb) {
         byte[] output2;
         if (hashNumber == 0) {
            // last iteration on output
            output2 = hash.digest(output);
         } else if (hashNumber < 1000) {
            byte[] n = Integer.toString(hashNumber).getBytes();
            output2 = new byte[output.length + n.length];
            System.arraycopy(n, 0, output2, 0, n.length);
            System.arraycopy(output, 0, output2, n.length, output.length);
            // don't update output
            output2 = hash.digest(output2);
         } else {
            throw new SecurityException("too long");
         }

         int rem = output2.length - position;
         int l = Math.min(cb - cpos, rem);
         System.arraycopy(output2, position, result, cpos, l);

         cpos += l;
         position += l;
         while (position >= output2.length) {
            position -= output2.length;
            hashNumber++;
         }
      }

      // saving first output length
      if (state == 1) {
         if (cb > 20) {
            skip = 40 - result.length;
         } else {
            skip = 20 - result.length;
         }
         firstBaseOutput = new byte[result.length];
         System.arraycopy(result, 0, firstBaseOutput, 0, result.length);
         state = 2;
      }
      // processing second output
      else if (skip > 0) {
         byte[] secondBaseOutput = new byte[(firstBaseOutput.length + result.length)];
         System.arraycopy(firstBaseOutput, 0, secondBaseOutput, 0, firstBaseOutput.length);
         System.arraycopy(result, 0, secondBaseOutput, firstBaseOutput.length, result.length);
         System.arraycopy(secondBaseOutput, skip, result, 0, skip);

         skip = 0;
      }

      return result;
   }

   public void reset() throws DigestException {
      state = 0;
      position = 0;
      hashNumber = 0;
      skip = 0;

      if (saltValue != null) {
         hash.update(password, 0, password.length);
         hash.update(saltValue, 0, saltValue.length);
         hash.digest(initial, 0, initial.length);
      } else {
         initial = hash.digest(password);
      }
   }
}
