import base64
import binascii
from gmssl import sm2, func


def test_sm2():
    private_key = '3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8'
    public_key = '09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13'

    sm2_crypt = sm2.CryptSM2(
        public_key=public_key, private_key=private_key)
    data = b"111"
    enc_data = sm2_crypt.encrypt(data)
    #print("enc_data:%s" % enc_data)
    #print("enc_data_base64:%s" % base64.b64encode(bytes.fromhex(enc_data)))
    dec_data = sm2_crypt.decrypt(enc_data)
    print(b"dec_data:%s" % dec_data)
    assert data == dec_data

    print("-----------------test sign and verify---------------")
    #data from OSCCA spec. SM2

    #random_hex_str = func.random_hex(sm2_crypt.para_len)
    random_hex_str = '59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21'
    data = 'F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640'
    sign = sm2_crypt.sign(data, random_hex_str)
    print('sign:%s' % sign.upper())
    verify = sm2_crypt.verify(sign, data)
    print('verify:%s' % verify)
    assert verify

    
def test_sm2sm3():
     private_key = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
     public_key = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"\
                  "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
     random_hex_str = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"

     sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
     data = b"message digest"

     print("-----------------test SM2withSM3 sign and verify---------------")
     sign = sm2_crypt.sign_with_sm3(data, random_hex_str)
     print('sign: %s' % sign)
     verify = sm2_crypt.verify_with_sm3(sign, data)
     print('verify: %s' % verify)
     assert verify


if __name__ == '__main__':
    test_sm2()
    #test_sm2sm3()

