import com.google.common.collect.Lists;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jcajce.provider.digest.RIPEMD160;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BasicCrypto {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        homework1();
        homework2();
        homework3();
        homework4();
    }

    /**
     * UTF16 으로 인코딩한 결과를 Base58 로 변환
     */
    private static void homework1() {
        System.out.println("\n1) ========================================================================================");
        String text = "\"UTF16란 무엇이고 베이스58이란 무엇인가?\"";
        System.out.println("Plain Text: " + text);

        String base58Text = Base58.encode(text.getBytes(StandardCharsets.UTF_16));
        System.out.println("Base58 Text: " + base58Text);
    }

    /**
     * apple, appel 두 단어를 UTF-8 로 표현한 바이트 배열을 가지고 SHA3(256 비트)와 RIPEMD160 해시값을 계산
     */
    private static void homework2() throws NoSuchAlgorithmException {
        System.out.println("\n2) ========================================================================================");
        String apple = "apple";
        String appel = "appel";

        System.out.println("SHA-256 apple: " + sha256(apple));
        System.out.println("RipeMD160 apple: " + ripemd160(apple));

        System.out.println("SHA-256 appel: " + sha256(appel));
        System.out.println("RipeMD160 appel: " + ripemd160(appel));
    }

    private static String sha256(String text) throws NoSuchAlgorithmException {
        MessageDigest md = SHA3.Digest256.getInstance("SHA-256");
        byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(digest);
    }

    private static String ripemd160(String text) throws NoSuchAlgorithmException {
        MessageDigest md = RIPEMD160.Digest.getInstance("RipeMD160");
        byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(digest);
    }

    private static void homework3() {
        System.out.println("\n3) ========================================================================================");
        System.out.println("늘의관전이습송에연더니하리다움은했여속오논");
        System.out.println("암호학은재미가있는것같지만머리도아파요");
    }

    private static void homework4() {
        System.out.println("\n4) ========================================================================================");

        String key = "플레이코인";
        String text = "오늘은이더리움연속전송에관하여논의했습니다";
        System.out.println("Key: " + key);
        System.out.println("Plain text: " + text);

        List<Integer> keys = getKeys(key);
        String encText = getEncText(keys, text);
        System.out.println("Encoded text: " + encText);
    }

    /**
     * 키를 정렬하여 텍스트를 읽어야할 순번 리스트를 생성한다.
     *
     * @param key
     * @return
     */
    private static List<Integer> getKeys(String key) {
        List<String> temps = Arrays.asList(key.split("|"));
        String sorted = temps.stream().sorted().collect(Collectors.joining());
        return Arrays.stream(sorted.split("|")).map(key::indexOf).collect(Collectors.toList());
    }

    /**
     * 잘라서 나열된 텍스트를 키의 순번대로 다시 재조합 한다.
     *
     * @param keys
     * @param text
     * @return
     */
    private static String getEncText(List<Integer> keys, String text) {
        int kLen = keys.size();
        List<String> texts = getTexts(kLen, text);

        StringBuilder full = new StringBuilder();
        for (int i = 0; i <= kLen; i++) {
            StringBuilder sub = new StringBuilder();
            for (String t : texts) {
                try {
                    sub.append(t, keys.get(i), keys.get(i) + 1);
                } catch (IndexOutOfBoundsException e) {
                    //ignore
                }
            }
            full.append(sub);
        }
        return full.toString();
    }

    /**
     * 키의 크기만큼 텍스트를 잘라서 나열한다.
     *
     * @param kLen
     * @param text
     * @return
     */
    private static List<String> getTexts(int kLen, String text) {
        int tLen = text.length();
        List<String> texts = Lists.newArrayList();
        for (int i = 0; i < tLen; i = i + kLen) {
            String t;
            try {
                t = text.substring(i, i + kLen);
            } catch (StringIndexOutOfBoundsException e) {
                t = text.substring(i);
            }
            texts.add(t);
        }
        return texts;
    }
}
