
package com.RNKeyPair;

import android.util.Base64;

import com.facebook.react.bridge.NoSuchKeyException;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.WritableNativeMap;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;


import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;


public class RNKeyPairModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  public RNKeyPairModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNKeyPair";
  }

  @ReactMethod
  public void generate(Callback callback)  {
    WritableNativeMap keys = new WritableNativeMap();

    try {

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      KeyPair keyPair = kpg.genKeyPair();
      byte[] publicKey = keyPair.getPublic().getEncoded();
      byte[] privateKey = keyPair.getPrivate().getEncoded();

      PemObject pemObject = new PemObject("PUBLIC KEY", publicKey);
      StringWriter stringWriter = new StringWriter();
      PemWriter pemWriter = new PemWriter(stringWriter);
      pemWriter.writeObject(pemObject);
      pemWriter.close();
      keys.putString("public", stringWriter.toString());

      PemObject pemObject2 = new PemObject("PRIVATE KEY", privateKey);
      StringWriter stringWriter2 = new StringWriter();
      PemWriter pemWriter2 = new PemWriter(stringWriter2);
      pemWriter2.writeObject(pemObject2);
      pemWriter2.close();
      keys.putString("private", stringWriter2.toString());
    }

    catch(NoSuchAlgorithmException e) {
    }
    catch(java.io.IOException e) {

    }
    callback.invoke(keys);
  }
}