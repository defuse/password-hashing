
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;



public class PasswordStorage {

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmac";
    private static final String HASH_ALGORITHM = "sha512";

    // These constants may be changed without breaking existing hashes.
    private static final int SALT_BYTE_SIZE = 18;
    private static final int HASH_BYTE_SIZE = 20;
    private static final int PBKDF2_ITERATIONS = 13000;

    private static class Hash {
        /**
         * 设置结果字符串的拼接顺序, 并去掉 ":" 分隔符 使字符串更难被解读
         * 你可以在项目已经发布运行之后的开发维护中修改除"HASH_SEQUENCE"和"HashItem.length" 以外的其他生成规则,
         * 代码依旧可以兼容验证过去生成的数据.
         * Set the sequence of the resulting string and remove the ":" to make it harder to interpret the string
         * You can modify the development rules other than "HASH_SEQUENCE" and "HashItem.length" after the project has been run.
         * The code can still be compatible with the data generated in the past
         * <p>
         * 注意: 不定长部分的长度字段必须要在 对应的不定长字段前
         * Note: the length field of an indefinite length must be before the corresponding indefinite length field
         * Right:
         * - ALGORITHM, ITERATIONS, HASH_SIZE, PBKDF2, SALT_SIZE, SALT
         * - SALT_SIZE, HASH_SIZE, PBKDF2,  SALT ,ALGORITHM ,ITERATIONS,
         * - ...
         * Wrong:
         * - ... PBKDF2,HASH_SIZE ...
         * - ... SALT , ... ,SALT_SIZE
         * <p>
         * ALGORITHM: 基础哈希算法 固定长度 6位，不足以 空格 填充
         *             Basic hash algorithm fixed length of 6, not enough to fill the space
         * ITERATIONS: 迭代重复次数 固定长度 6位，不足以 前导0 填充
         *             iterationCount fixed length of 6, not enough to fill the 0
         * HASH_SIZE: 计算hash后的字符串长度 固定长度3位，不足以 前导0 填充
         *            The length of hashed String fixed length of 3, not enough to fill the 0
         * PBKDF2: hash值转存的字符串 不定长
         *         A indefinite length hashed String 
         * SALT_SIZE:  随机盐值 转存字符串的长度 固定长度3位，不足以 前导0 填充
         *             The length of random salt String fixed length of 3, not enough to fill the 0
         * SALT: 随机盐值 的字符串 不定长
         *       A indefinite length random salt String 
         */
        private enum HashItem {
            ALGORITHM(6), ITERATIONS(6), HASH_SIZE(3), PBKDF2(0), SALT_SIZE(3), SALT(0);

            private int length;

            HashItem(int length) {
                this.length = length;
            }
        }

        // normal
        private static final HashItem[] HASH_SEQUENCE = {HashItem.ALGORITHM, HashItem.ITERATIONS, HashItem.HASH_SIZE, HashItem.PBKDF2, HashItem.SALT_SIZE, HashItem.SALT};
        // unordered
        // private static final HashItem[] HASH_SEQUENCE = {HashItem.SALT_SIZE, HashItem.ITERATIONS, HashItem.HASH_SIZE, HashItem.SALT, HashItem.ALGORITHM, HashItem.PBKDF2};
        // unordered + redundancy
        // private static final HashItem[] HASH_SEQUENCE = {HashItem.HASH_SIZE, HashItem.SALT_SIZE, HashItem.ITERATIONS, HashItem.PBKDF2, HashItem.SALT, HashItem.ALGORITHM, HashItem.PBKDF2};

        private String hashAlgorithm;
        private int pbkdf2Iterations;
        private byte[] hash;
        private String hashStr;
        private byte[] salt;
        private String saltStr;

        Hash() {
        }

        Hash(String correctHash) {
            StringBuilder builder = new StringBuilder(correctHash);
            int hashStrLength = -1;
            int saltStrLength = -1;
            for (HashItem hashItem : HASH_SEQUENCE) {
                int colLength = hashItem.length;
                switch (hashItem) {
                    case ALGORITHM:
                        hashAlgorithm = builder.substring(0, colLength).trim();
                        builder.delete(0, colLength);
                        break;
                    case ITERATIONS:
                        pbkdf2Iterations = Integer.parseInt(builder.substring(0, colLength));
                        builder.delete(0, colLength);
                        break;
                    case HASH_SIZE:
                        hashStrLength = Integer.parseInt(builder.substring(0, colLength));
                        builder.delete(0, colLength);
                        break;
                    case PBKDF2:
                        if (hashStrLength < 0) {
                            throw new IllegalArgumentException("Fields are missing from the password hash.length");
                        }
                        hashStr = builder.substring(0, hashStrLength);
                        hash = DatatypeConverter.parseBase64Binary(hashStr);
                        builder.delete(0, hashStrLength);
                        break;
                    case SALT_SIZE:
                        saltStrLength = Integer.parseInt(builder.substring(0, colLength));
                        builder.delete(0, colLength);
                        break;
                    case SALT:
                        if (saltStrLength < 0) {
                            throw new IllegalArgumentException("Base64 decoding of salt.length failed.");
                        }
                        saltStr = builder.substring(0, saltStrLength);
                        salt = DatatypeConverter.parseBase64Binary(saltStr);
                        builder.delete(0, saltStrLength);
                        break;
                }
            }
        }

        public String getHashAlgorithm() {
            return hashAlgorithm;
        }

        public void setHashAlgorithm(String hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
        }

        public void setPbkdf2Iterations(int pbkdf2Iterations) {
            this.pbkdf2Iterations = pbkdf2Iterations;
        }

        public byte[] getHash() {
            return hash;
        }

        public void setHash(byte[] hash) {
            this.hash = hash;
            this.hashStr = DatatypeConverter.printBase64Binary(hash);
        }

        public byte[] getSalt() {
            return salt;
        }

        public void setSalt(byte[] salt) {
            this.salt = salt;
            this.saltStr = DatatypeConverter.printBase64Binary(salt);
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();
            for (HashItem hashItem : HASH_SEQUENCE) {
                switch (hashItem) {
                    case ALGORITHM:
                        builder.append(String.format("%" + hashItem.length + "s", hashAlgorithm));
                        break;
                    case ITERATIONS:
                        builder.append(String.format("%0" + hashItem.length + "d", pbkdf2Iterations));
                        break;
                    case HASH_SIZE:
                        builder.append(String.format("%0" + hashItem.length + "d", hashStr.length()));
                        break;
                    case PBKDF2:
                        builder.append(hashStr);
                        break;
                    case SALT_SIZE:
                        builder.append(String.format("%0" + hashItem.length + "d", saltStr.length()));
                        break;
                    case SALT:
                        builder.append(saltStr);
                        break;
                }
            }
            return builder.toString();
        }
    }

    public static String createHash(String password) {
        return createHash(password.toCharArray());
    }

    public static String createHash(char[] password) {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);

        // Hash the password
        byte[] hash = pbkdf2(HASH_ALGORITHM, password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);

        Hash hashObj = new Hash();
        hashObj.setHashAlgorithm(HASH_ALGORITHM);
        hashObj.setPbkdf2Iterations(PBKDF2_ITERATIONS);
        hashObj.setHash(hash);
        hashObj.setSalt(salt);
        return hashObj.toString();
    }

    public static boolean verifyPassword(String password, String correctHash) {
        return verifyPassword(password.toCharArray(), correctHash);
    }

    public static boolean verifyPassword(char[] password, String correctHash) {
        // Decode the hash into its parameters
        Hash hash = new Hash(correctHash);

        // Compute the hash of the provided password, using the same salt,
        // iteration count, and hash length
        byte[] testHash = pbkdf2(hash.getHashAlgorithm(), password, hash.getSalt(), hash.pbkdf2Iterations, hash.getHash().length);
        // Compare the hashes in constant time. The password is correct if
        // both hashes match.
        return slowEquals(hash.getHash(), testHash);
    }

    private static boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static byte[] pbkdf2(String HashAlgorithm, char[] password, byte[] salt, int iterations, int bytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM + HashAlgorithm);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Hash algorithm not supported.", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid key spec.", e);
        }
    }
}
