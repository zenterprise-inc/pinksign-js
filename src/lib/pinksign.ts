import * as forge from 'node-forge';
import { pki, util } from 'node-forge';

class PinkSign {
  public pubkey: pki.Certificate;

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

  /**
   * 유효기간 가져오기
   */
  get validDate(): { notBefore: Date; notAfter: Date } {
    return this.pubkey.validity;
  }

  /**
   * 시리얼번호 가져오기
   */
  get serialNum(): string {
    return this.pubkey.serialNumber;
  }
}

export default PinkSign;
