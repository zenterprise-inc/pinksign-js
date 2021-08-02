import * as forge from "node-forge";
import {pki, util} from "node-forge";

class PinkSign {
  public pubkey: forge.pki.Certificate;

  constructor(pubkeyData: ArrayBuffer) {
    const pubAsn1 = forge.asn1.fromDer(new util.ByteStringBuffer(pubkeyData));
    this.pubkey = forge.pki.certificateFromAsn1(pubAsn1);
  }

  /**
   * 인증서 CN 값 가져오기
   */
  get cn(): string {
    return forge.util.decodeUtf8(this.pubkey.subject.getField('CN').value);
  }

  /**
   * 인증서 발급자 가져오기
   */
  get issuer(): string {
    return forge.util.decodeUtf8(this.pubkey.subject.getField('O').value);
  }

}

export default PinkSign;
