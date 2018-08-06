package com.yi.yizw.rsa;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * RSA加解密演示界面
 *
 * @author yizw
 */
public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    /**
     * 点击执行加密
     */
    private Button btnEncrypt;

    /**
     * 点击执行解密
     */
    private Button btnDecrypt;

    /**
     * 需加密的内容
     */
    private EditText etInput;

    /**
     * 加密后的内容
     */
    private TextView tvEncrypt;

    /**
     * 解密后的内容
     */
    private TextView tvDecrypt;

    /**
     * 密钥内容 base64 code
     */
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfRTdcPIH10g" +
            "T9f31rQuIInLwe7fl2dtEJ93gTmjE9c2H+kLVENWgECiJVQ5sonQNfwToMKdO0b3Olf4pg" +
            "BKeLThraz/L3nYJYlbqjHC3jTjUnZc0luumpXGsox62+PuSGBlfb8zJO6hix" +
            "4GV/vhyQVCpG9aYqgE7zyTRZYX9byQIDAQAB";

    private static final String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ9FN1w8gfXSBP1/fWtC4gicvB7t+XZ20Qn3eBOaMT1zYf6QtUQ1aAQKIlVDmyidA1/BOgwp07Rvc6V/imAEp4tOGtrP8vedgliVuqMcLeNONSdlzSW66alcayjHrb4+5IYGV9vzMk7qGLHgZX++HJBUKkb1piqATvPJNFlhf1vJAgMBAAECgYA736xhG0oL3EkN9yhx8zG/5RP/WJzoQOByq7pTPCr4m/Ch30qVerJAmoKvpPumN+h1zdEBk5PHiAJkm96sG/PTndEfkZrAJ2hwSBqptcABYk6ED70gRTQ1S53tyQXIOSjRBcugY/21qeswS3nMyq3xDEPKXpdyKPeaTyuK86AEkQJBAM1M7p1lfzEKjNw17SDMLnca/8pBcA0EEcyvtaQpRvaLn61eQQnnPdpvHamkRBcOvgCAkfwa1uboru0QdXii/gUCQQDGmkP+KJPX9JVCrbRt7wKyIemyNM+J6y1ZBZ2bVCf9jacCQaSkIWnIR1S9UM+1CFE30So2CA0CfCDmQy+y7A31AkB8cGFB7j+GTkrLP7SX6KtRboAU7E0q1oijdO24r3xf/Imw4Cy0AAIx4KAuL29GOp1YWJYkJXCVTfyZnRxXHxSxAkEAvO0zkSv4uI8rDmtAIPQllF8+eRBT/deDJBR7ga/k+wctwK/Bd4Fxp9xzeETP0l8/I+IOTagK+Dos8d8oGQUFoQJBAI4NwpfoMFaLJXGY9ok45wXrcqkJgM+SN6i8hQeujXESVHYatAIL/1DgLi+u46EFD69fw0w+c7o0HLlMsYPAzJw=";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
    }

    private void initView() {
        btnEncrypt = findViewById(R.id.btn_encrypt);
        btnDecrypt = findViewById(R.id.btn_decrypt);
        btnEncrypt.setOnClickListener(this);
        btnDecrypt.setOnClickListener(this);

        etInput = findViewById(R.id.et_input);
        tvEncrypt = findViewById(R.id.tv_encrypt);
        tvDecrypt = findViewById(R.id.tv_decrypt);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            // 加密
            case R.id.btn_encrypt:
                String source = etInput.getText().toString().trim();

                if (TextUtils.isEmpty(source)) {
                    Toast.makeText(this, getResources().getString(R.string.empty_text), Toast.LENGTH_SHORT).show();
                    return;
                }

                try {
                    // 从字符串中得到公钥
                    PublicKey publicKey = RsaUtil.loadPublicKey(PUBLIC_KEY);
                    // 加密
                    byte[] encryptByte = RsaUtil.encryptData(source.getBytes(), publicKey);

                    String afterEncrypt;
                    if (encryptByte != null) {
                        // 为了方便观察，把加密后的数据用base64加密转一下，要不然看起来是乱码,所以解密是也是要用Base64先转换
                        afterEncrypt = Base64Utils.encode(encryptByte);
                    } else {
                        afterEncrypt = getResources().getString(R.string.encrypt_fail);
                    }

                    tvEncrypt.setText(afterEncrypt);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            // 解密
            case R.id.btn_decrypt:
                String encryptContent = tvEncrypt.getText().toString().trim();

                if (TextUtils.isEmpty(encryptContent)) {
                    Toast.makeText(this, getResources().getString(R.string.empty_encrypt_content), Toast.LENGTH_SHORT).show();
                    return;
                }

                try {
                    // 从字符串中得到私钥
                    PrivateKey privateKey = RsaUtil.loadPrivateKey(PRIVATE_KEY);
                    // 因为RSA加密后的内容经Base64再加密转换了一下，所以先Base64解密回来再给RSA解密
                    byte[] decryptByte = RsaUtil.decryptData(Base64Utils.decode(encryptContent), privateKey);

                    String decryptStr;
                    if (decryptByte != null) {
                        decryptStr = new String(decryptByte);
                    } else {
                        decryptStr = getResources().getString(R.string.decrypt_fail);
                    }
                    tvDecrypt.setText(decryptStr);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                break;
        }
    }


}
