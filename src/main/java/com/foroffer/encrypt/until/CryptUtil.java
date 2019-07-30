package com.foroffer.encrypt.until;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;

@Slf4j
public class CryptUtil {
    private static final String AES_ECB_PKCS5_PADDING = "AES/ECB/PKCS5Padding";
    private static final String DE_SEDE = "DESede";
    private static final String UTF_8 = "UTF-8";
    private static final String MD5_ENCODE_EXCEPTION_INFO = "MD5加密异常";

    public CryptUtil() {

    }

    /**
     * 转换字节数组为16进制字串 * * @param b * 字节数组 * @return 16进制字串
     */
    public static String byteArrayToHexString(byte[] b) {
        StringBuffer resultSb = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                hex = "0" + hex;
            }
            resultSb.append(hex);
        }
        return resultSb.toString();
    }

    /**
     * 将表示16进制值的字符串转换为byte数组， 和public static String byteArrayToHexString(byte[] * b) 互为可逆的转换过程 * * @param strIn * 需要转换的字符串 * @return 转换后的byte数组 * @throws Exception * 本方法不处理任何异常，所有异常全部抛出 * @author LiGuoQing
     */
    public static byte[] hexString2ByteArray(String strIn) throws Exception {
        byte[] arrB = strIn.getBytes();
        int iLen = arrB.length; // 两个字符表示一个字节，所以字节数组长度是字符串长度除以2
        byte[] arrOut = new byte[iLen / 2];
        for (int i = 0; i < iLen; i = i + 2) {
            String strTmp = new String(arrB, i, 2);
            arrOut[i / 2] = (byte) Integer.parseInt(strTmp, 16);
        }
        return arrOut;
    }

    /**
     * MD5 摘要计算(byte[]). * * @param src * byte[] * @throws Exception * @return byte[] 16 bit digest
     */
    public static byte[] md5Digest(byte[] src) throws Exception {
        return MessageDigest.getInstance("MD5").digest(src);// MD5 is 16 bit // message digest }
    }

    /**
     * MD5 摘要计算(String). * * @param src * String * @throws Exception * @return String
     */
    public static String md5Digest(String src) {
        try {
            return byteArrayToHexString(md5Digest(src.getBytes()));
        } catch (Exception e) {
            log.error(MD5_ENCODE_EXCEPTION_INFO, e);
        }
        return null;
    }

    /**
     * MD5 摘要计算(String UTF-8). * * @param src * String * @throws Exception * @return String
     */
    public static String md5DigestUTF8(String src) {
        try {
            return byteArrayToHexString(md5Digest(src.getBytes(UTF_8)));
        } catch (Exception e) {
            log.error(MD5_ENCODE_EXCEPTION_INFO, e);
        }
        return null;
    }

    /**
     * 对给定字符进行 URL 编码. * * @param src * String * @return String
     */
    public static String urlEncode(String src) {
        try {
            src = URLEncoder.encode(src, UTF_8);
            return src;
        } catch (Exception ex) {
            log.error("不支持的字符编码错误。", ex);
        }
        return src;
    }

    /**
     * 对给定字符进行 URL 解码 * * @param value * 解码前的字符串 * @return 解码后的字符串
     */
    public static String urlDecode(String
                                           value) {
        try {
            return URLDecoder.decode(value, UTF_8);
        } catch (Exception ex) {
            log.error("不支持的字符编码错误。", ex);
        }
        return value;
    }

    /*   */

    /**
     * 先3DES加密，再base64编码 * * @param key * 密钥 * @param str * 需要加密的字符串
     *//*
    public static String des3Base64Enc
    (SecretKey key, String str) throws Exception {
        if (key == null) {
            key = genDESKey();
        }
        byte[] enc = desEncrypt(key, str.getBytes());
        return base64Encode(enc);
    }*/
    public static SecretKey genDESKey() throws Exception {
        String keyStr = "$1#2@f3&4~6%7!a+*cd(e-h)";// 使用固定key
        byte key_byte[] = keyStr.getBytes();// 3DES 24 bytes key
        SecretKey k = null;
        k = new SecretKeySpec(key_byte, DE_SEDE);
        return k;
    }

    /**
     * 3DES加密(byte[]). * * @param key * SecretKey * @param src * byte[] * @throws Exception * @return byte[]
     */
    public static byte[] desEncrypt(SecretKey key, byte[] src) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(DE_SEDE);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(src);
    }

    /**
     * BASE64 编码(byte[]). * * @param src * byte[] inputed string * @return String returned string
     */
/*    public static String base64Encode(byte[] src) {
        Base64 encoder = new Base64();
        return encoder.encodeToString(src);
    }*/

    /**
     * 先base64解码,再3DES解密， * * @param key * 密钥 * @param str * 需要加密的字符串
     */
/*    public static String des3Base64Dec(SecretKey key, String str) throws Exception {
        if (key == null) {
            key = genDESKey();
        }
        byte[] decbase64 = base64DecodeToBytes(str);
        byte[] dec = desDecrypt(key, decbase64);
        return new String(dec, UTF_8);
    }*/

    /**
     * BASE64 解码(to byte[]). * * @param src * String inputed string * @return String returned string
     */
/*    public static byte[] base64DecodeToBytes(String src) {
        Base64 decoder = new Base64();
        return decoder.decode(src);
    }*/

    /**
     * 3DES 解密(byte[]). * * @param key * SecretKey * @param crypt * byte[] * @throws Exception * @return byte[]
     */
    public static byte[] desDecrypt(SecretKey key, byte[] crypt) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(DE_SEDE);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(crypt);
    }

    /**
     * 验证MD5
     */
    public static boolean validMd5(String data, String key, String sign) throws Exception {
        String b = md5Digest(data + key); // --log.info("数据密钥:" + b);
        return b.equals(sign);
    }

    /**
     * AES加密, 模式AES/ECB/PKCS5Padding
     */
    public static String aesEncrypt(String str, String key) throws Exception {
        checkKeyLen(key);
        Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5_PADDING);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return CryptUtil.byteArrayToHexString(cipher.doFinal(str.getBytes()));
    }

    /**
     * AES解密, 模式AES/ECB/PKCS5Padding
     */
    public static String aesDecrypt(String str, String key) throws Exception {
        checkKeyLen(key);
        Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5_PADDING);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encBytesBuf = CryptUtil.hexString2ByteArray(str);
        return new String(cipher.doFinal(encBytesBuf));
    }

    /**
     * check AES key
     */
    private static void checkKeyLen(String inKey) throws Exception {
        byte[] key = inKey.getBytes();
        if (key.length < 16 || (key.length % 16) != 0) {
            throw new Exception("Byte length of key must be (bytelen >= 16) and (bytelen mod 16 = 0)");
        }
    }

    /**
     * AES加密(String) * * @param src * @return
     */
/*    public static String encryptAES(String src, String aesKey) {
        try {
            return Base64.encodeBase64String(encryptAES(src.getBytes(), aesKey));
        } catch (Exception e) {
            log.error("AES加密异常", e);
        }
        return null;
    }*/

    /**
     * AES加密(byte) * * @param src * @return * @throws Exception
     */
    @SuppressWarnings("null")
    public static byte[] encryptAES(byte[] src, String aesKey) throws Exception {
        if (aesKey == null && aesKey.length() != 16) {// 判断Key是否为16位
            return null;
        }
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(aesKey.getBytes("GBK"));
        byte[] raw = md.digest();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return cipher.doFinal(src);
    }

    /**
     * base64编码签名 * * @param target * @param charset * @return
     */
/*    public static String md5DigestBase64(String target, String charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(target.getBytes(charset));
            return new String(Base64.encodeBase64(md.digest()));
        } catch (Exception e) {
            log.error(MD5_ENCODE_EXCEPTION_INFO, e);
        }
        return null;
    }*/

    /**
     * 验证SHA256
     */
/*    public static boolean validSHA256(String data, String key, String sign) throws Exception {
        String b = encryptSHA256(data + key); // --log.info("数据密钥:" + b);
        return Objects.equal(b, sign);
    }*/

    /**
     * SHA256加密 * @param data * @param charsetName * @return * @throws Exception
     */
    public static String encryptSHA256(String data, String charsetName) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(data.getBytes(charsetName));
        return byteArrayToHexString(messageDigest.digest());
    }

    /**
     * SHA256加密， 默认UTF-8编码 * @param data * @return * @throws Exception
     */
    public static String encryptSHA256(String data) throws Exception {
        return encryptSHA256(data, UTF_8);
    }

}
//	public static void main(String[] args) throws Exception { // String json="{\"orderId\":\"0001\",\"cuIdentity\":\"\",\"cuMobilePhone\":\"\",\"cuName\":\"\"}"; //	String json="{\"spdbName\":\"\",\"spdbLevel\":\"lv5\",\"spdbId\":\"110\"}";//小移人家 //	String encodStr=URLEncoder.encode(json, "utf-8"); // System.out.println("encodStr=="+encodStr); // // String aseStr=CryptUtil.aesEncrypt(encodStr, "qcSduJyX6oPsytX0"); // // System.out.println("aseStr=="+aseStr); // //	String md5Str=aseStr+"QyMCd5GH"; // // System.out.println("md5=="+md5Str); // //	String sign=CryptUtil.md5Digest(md5Str); // // System.out.println("sign=="+sign); //	String data="e0e57c98b197867afe1c45e24bb38eaa473cb33adaf248e3e7f9114f9690bd212019eb3ec03e5830fde7b20aa08ee3db33b6ba85e29a8ec621d4e31a928b3b421178c40d6a67d09a1b6c2b36351903820048b60ea0425a278f8157de40b51e0f0e2ae1c5b782a4b5a078bdda4522d7f657e0a4f8988c876c711fcc95b86cffac7380c2f34b0df1deccc138773f67c38d"; //	String sign="2a90a99b0cec3e53884e4d9b68f106dc"; // System.out.print(CryptUtil.aesDecrypt(data,"Spdbccc-testtess")); //	} }