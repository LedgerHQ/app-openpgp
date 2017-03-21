# Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#


try:
    from ledgerblue.comm import getDongle
    from ledgerblue.commException import CommException
except :
    pass
import binascii

from smartcard.System import readers
import sys
import datetime
import pickle

# decode  level 0 of tlv|tlv|tlv
# return dico {t: v, t:v, ...}
#tlv: hexstring

def decode_tlv(tlv) :
    tags = {}
    while len(tlv)    :
        o  = 0
        l  = 0
        if (tlv[0] & 0x1F) == 0x1F:
            t = (tlv[0]<<8)|tlv[1]
            o = 2
        else:
            t = tlv[0]
            o = 1
        l = tlv[o]
        if l & 0x80 :
            if (l&0x7f) == 1:
                l = tlv[o+1]
                o += 2
            if (l&0x7f) == 2:
                l = (tlv[o+1]<<8)|tlv[o+2]
                o += 3
        else:
            o += 1
        v = tlv[o:o+l]
        tags[t] =  v
        tlv = tlv[o+l:]
    return tags

class GPGCard() :
    def __init__(self):
        self.reset()

    def reset(self):
        #token info
        self.AID                 = b''
        self.aid                 = b''
        self.ext_length          = b''
        self.ext_capabilities    = b''
        self.histo_bytes         = b''
        self.PW_status           = b''

        #user info
        self.login               = b''
        self.url                 = b''
        self.name                = b''
        self.sex                 = b''
        self.lang                = b''

        #keys info
        self.cardholder_cert     = b''
        self.sig_attribute       = b''
        self.dec_attribute       = b''
        self.aut_attribute       = b''
        self.sig_fingerprints    = b''
        self.dec_fingerprints    = b''
        self.aut_fingerprints    = b''
        self.sig_CA_fingerprints = b''
        self.dec_CA_fingerprints = b''
        self.aut_CA_fingerprints = b''
        self.sig_date            = b''
        self.dec_date            = b''
        self.aut_date            = b''
        self.cert_aut            = b''
        self.cert_dec            = b''
        self.cert_sig            = b''
        self.UIF_SIG             = b''
        self.UIF_DEC             = b''
        self.UIF_AUT             = b''
        self.digital_counter     = b''

        #private info
        self.private_01          = b''
        self.private_02          = b''
        self.private_03          = b''



    def connect(self, device):
        if device.startswith("ledger:"):
            self.token = getDongle(True)
            self.exchange = self._exchange_ledger
        elif device.startswith("pcsc:"):
            allreaders = readers()
            for r in allreaders:
                rname = str(r)
                print('try: %s : %s'%(rname,device[5:]))
                if rname.startswith(device[5:]):
                    r.createConnection()
                    self.token = r
                    self.connection = r.createConnection()
                    self.connection.connect()
                    self.exchange = self._exchange_pcsc
                else:
                    print("No")
        if not self.token:
            print("No token")


    ### APDU  interface ###
    def _exchange_ledger(self,cmd,sw=0x9000):
        resp = b''
        cond = True
        while cond:
            try:
                resp = resp + self.token.exchange(cmd,300)
                sw = 0x9000
                cond = False
            except CommException as e:
                if (e.data) :
                    resp = resp + e.data
                sw = e.sw
                if (sw&0xFF00) == 0x6100 :
                    cmd = binascii.unhexlify("00C00000%.02x"%(sw&0xFF))
                else:
                    cond = False
        return resp,sw

    def _exchange_pcsc(self,apdu,sw=0x9000):
        print("xch S cmd : %s"%(binascii.hexlify(apdu)))
        apdu = [x for x in apdu]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        while sw1==0x61:
            apdu = binascii.unhexlify(b"00c00000%.02x"%sw2)
            apdu = [x for x in apdu]
            resp2, sw1, sw2 = self.connection.transmit(apdu)
            resp = resp + resp2
        resp = bytes(resp)
        sw = (sw1<<8)|sw2
        print("xch S resp: %s %.04x"%(binascii.hexlify(resp),sw))
        return resp,sw

    def select(self):
        apdu = binascii.unhexlify(b"00A4040006D27600012401")
        return self.exchange(apdu)

    def activate(self):
        apdu = binascii.unhexlify(b"00440000")
        return self.exchange(apdu)

    def terminate(self):
        apdu = binascii.unhexlify(b"00E60000")
        return self.exchange(apdu)

    def get_data(self,tag):
        apdu = binascii.unhexlify(b"00CA%.04x00"%tag)
        return self.exchange(apdu)

    def put_data(self,tag,value):
        apdu = binascii.unhexlify(b"00DA%.04x%.02x"%(tag,len(value)))+value
        return self.exchange(apdu)

    def verify(self,id,value):
        apdu = binascii.unhexlify(b"002000%.02x%.02x"%(id,len(value)))+value
        return self.exchange(apdu)

    def change_reference_data(self,id,value,new_value):
        lc = len(value)+len(new_value)
        apdu = binascii.unhexlify(b"002400%.02x%.02x"%(id,lc))+value+new_value
        return self.exchange(apdu)

    def reset_retry_counter(self,RC,new_value):
        if len(RC)==0:
            p1 = 2
        else:
            p1 = 0
        lc = len(RC)+len(new_value)
        apdu = binascii.unhexlify(b"002C%02x81%.02x"%(p1,lc))+RC+new_value
        return self.exchange(apdu)

    def generate_asym_key_pair(self, mode, key):
        apdu = binascii.unhexlify(b"0047%02x0002%.04x"%(mode,key))
        return self.exchange(apdu)

    ### API  interfaces  ###
    def get_all(self):
        self.reset()

        self.AID,sw                      = self.get_data(0x4f)
        self.login ,sw                   = self.get_data(0x5e)
        self.url,sw                      = self.get_data(0x5f50)
        self.histo_bytes,sw              = self.get_data(0x5f52)

        cardholder,sw                    = self.get_data(0x65)
        tags                             = decode_tlv(cardholder)
        if 0x5b in tags:
            self.name                    = tags[0x5b]
        if 0x5f35 in tags:
            self.sex                     = tags[0x5f35]
        if 0x5f35 in tags:
            self.lang                    = tags[0x5f2d]

        application_data,sw              = self.get_data(0x6E)
        tags                             = decode_tlv(application_data)
        if 0x7f66 in tags:
            self.ext_length              = tags[0x7f66]
        if 0x73 in tags:
            dicretionary_data            = tags[0x73]
            tags                         = decode_tlv(dicretionary_data)
            if 0xc0 in tags:
                self.ext_capabilities    = tags[0xC0]

            if 0xc4 in tags:
                self.PW_status           = tags[0xC4]

            if 0xC1 in tags:
                self.sig_attribute       = tags[0xC1]
            if 0xC2 in tags:
                self.dec_attribute       = tags[0xC2]
            if 0xC3 in tags:
                self.aut_attribute       = tags[0xC3]
            if 0xC5 in tags:
                fingerprints             = tags[0xC5]
                self.sig_fingerprints    = fingerprints[0:20]
                self.dec_fingerprints    = fingerprints[20:40]
                self.aut_fingerprints    = fingerprints[40:60]
            if 0xC6 in tags:
                fingerprints             = tags[0xC6]
                self.sig_CA_fingerprints = fingerprints[0:20]
                self.dec_CA_fingerprints = fingerprints[20:40]
                self.aut_CA_fingerprints = fingerprints[40:60]
            if 0xcd in tags:
                dates                    = tags[0xCD]
                self.sig_date            = dates[0:4]
                self.dec_date            = dates[4:8]
                self.aut_date            = dates[8:12]
        
        self.cardholder_cert             = self.get_data(0x7f21)

        self.UIF_SIG,sw                  = self.get_data(0xD6)
        self.UIF_DEC,sw                  = self.get_data(0xD7)
        self.UIF_AUT,sw                  = self.get_data(0xD8)

        sec_template,sw                  = self.get_data(0x7A)
        tags                             = decode_tlv(sec_template)
        if 0x93 in tags:
            self.digital_counter         = tags[0x93]

        self.private_01,sw               = self.get_data(0x0101)
        self.private_02,sw               = self.get_data(0x0102)
        self.private_03,sw               = self.get_data(0x0103)
        self.private_04,sw               = self.get_data(0x0104)

    def set_all(self):
        self.put_data(0x4f,    self.AID[10:14])
        self.put_data(0x0101,  self.private_01)
        self.put_data(0x0102,  self.private_02)
        self.put_data(0x0103,  self.private_03)
        self.put_data(0x0104,  self.private_04)
        
        self.put_data(0x5b,   self.name)
        self.put_data(0x5e,   self.login)
        self.put_data(0x5f2d, self.lang)
        self.put_data(0x5f35, self.sex)
        self.put_data(0x5f50, self.url)
        
        self.put_data(0xc1,   self.sig_attribute)
        self.put_data(0xc2,   self.dec_attribute)
        self.put_data(0xc3,   self.aut_attribute)

        self.put_data(0xc4,   self.PW_status)

        self.put_data(0xc7,   self.sig_fingerprints)
        self.put_data(0xc8,   self.dec_fingerprints)
        self.put_data(0xc9,   self.aut_fingerprints)
        self.put_data(0xca,   self.sig_CA_fingerprints)
        self.put_data(0xcb,   self.dec_CA_fingerprints)
        self.put_data(0xcc,   self.aut_CA_fingerprints)
        self.put_data(0xce,   self.sig_date)
        self.put_data(0xcf,   self.dec_date)
        self.put_data(0xd0,   self.aut_date)
        #self.put_data(0x7f21, self.cardholder_cert)

        self.put_data(0xd6, self.UIF_SIG)
        self.put_data(0xd7, self.UIF_DEC)
        self.put_data(0xd8, self.UIF_AUT)

    def backup(self, file_name):
        f = open(file_name,mode='w+b')
        self.get_all();
        pickle.dump(
            (self.AID,
             self.private_01, self.private_02, self.private_03, self.private_04,
             self.name, self.login, self.sex, self.url,
             self.sig_attribute, self.dec_attribute, self.aut_attribute,
             self.PW_status,
             self.sig_fingerprints, self.dec_fingerprints, self.aut_fingerprints, 
             self.sig_CA_fingerprints, self.dec_CA_fingerprints, self.aut_CA_fingerprints, 
             self.sig_date, self.dec_date, self.aut_date, 
             self.cardholder_cert,
             self.UIF_SIG, self.UIF_DEC, self.UIF_AUT),
            f, 2)
        

    def restore(self, file_name, seed_key=False):
        f = open(file_name,mode='r+b')
        (self.AID,
         self.private_01, self.private_02, self.private_03, self.private_04,
         self.name, self.login, self.sex, self.url,
         self.sig_attribute, self.dec_attribute, self.aut_attribute,
         self.status,
         self.sig_fingerprints, self.dec_fingerprints, self.aut_fingerprints, 
         self.sig_CA_fingerprints, self.dec_CA_fingerprints, self.aut_CA_fingerprints, 
         self.sig_date, self.dec_date, self.aut_date, 
         self.cardholder_cert,
         self.UIF_SIG, self.UIF_DEC, self.UIF_AUT) = pickle.load(f)
        self.set_all()
        if seed_key :
            apdu = binascii.unhexlify(b"0047800102B600")
            self.exchange(apdu)
            apdu = binascii.unhexlify(b"0047800102B800")
            self.exchange(apdu)
            apdu = binascii.unhexlify(b"0047800102A400")
            self.exchange(apdu)




    def decode_AID(self):
        return  {
            'AID': ('AID'         , "%x"%int.from_bytes(self.AID,'big')),
            'RID': ('RID'          , "%x"%int.from_bytes(self.AID[0:5],'big')),
            'APP': ('application'  , "%.02x"%self.AID[5]),
            'VER': ('version'      , "%.02x.%.02x"%(self.AID[6], self.AID[7])),
            'MAN': ('manufacturer' , "%x"%int.from_bytes(self.AID[8:10],'big')),
            'SER': ('serial'       , "%x"%int.from_bytes(self.AID[10:14],'big'))
        }

    def decode_histo(self):
        return {
            'HIST': ('historical bytes', binascii.hexlify(self.histo_bytes))
        }

    def decode_extlength(self):
        if self.ext_length:
            return {
                'CMD': ('Max command length'  , "%d" %((self.ext_length[2]<<8)|self.ext_length[3])),
                'RESP':( 'Max response length' , "%d" %((self.ext_length[6]<<8)|self.ext_length[7]))
                }
        else:
            return {
                'CMD': ('Max command length'  , "unspecified"),
                'RESP':( 'Max response length' ,"unspecified"),
                }

    def decode_capabilities(self):
        d = {}
        b1 = self.ext_capabilities[0]
        if b1&0x80 :
            if   self.ext_capabilities[1] == 1:
                d['SM'] = ('Secure Messaging',  "yes: 128 bits")
            elif self.ext_capabilities[1] == 2:
                d['SM'] = ('Secure Messaging',  "yes: 256 bits")
            else:
                d['SM'] = ('Secure Messaging',  "yes: ?? bits")
        else:
            d['SM'] = ('Secure Messaging',  "no")

        if b1&0x40 :
            d['CHAL'] = ('GET CHALLENGE',  "yes")
        else:
            d['CHAL'] = ('GET CHALLENGE',  "no")

        if b1&0x20 :
            d['KEY'] = ('Key import',  "yes")
        else:
            d['KEY'] = ('Key import',  "no")

        if b1&0x10 :
            d['PWS'] = ('PW status changeable',  "yes")
        else:
            d['PWS'] = ('PW status changeable',  "no")

        if b1&0x08 :
            d['PDO'] = ('Private DOs',  "yes")
        else:
            d['PDO'] = ('Private DOs',  "no")

        if b1&0x04 :
            d['ATTR'] = ('Algo attributes changeable',  "yes")
        else:
            dd['ATTR'] = ('Algo attributes changeable',  "no")

        if b1&0x02 :
            d['PSO'] = ('PSO:DEC support AES',  "yes")
        else:
            d['PSO'] = ('PSO:DEC support AES',  "no")


        d['CHAL_MAX'] = ('Max GET_CHALLENGE length',
                  "%d"% ((self.ext_capabilities[2]<<8)|self.ext_capabilities[3]))
        d['CERT_MAX'] = ('Max Cert length',
                 "%d"% ((self.ext_capabilities[4]<<8)|self.ext_capabilities[5]))
        d['PDO_MAX'] = ('Max special DO length',
                  "%d"% ((self.ext_capabilities[6]<<8)|self.ext_capabilities[7]))
        if self.ext_capabilities[8] :
            d['PIN2'] = ('PIN 2 format supported', "yes")
        else:
            d['PIN2'] = ('PIN 2 format supported',"no")

        return d

    def decode_pws(self):
        d = {}
        if self.PW_status[0]==0:
            d['ONCE'] = ('PW1 valid for several CDS', 'yes')
        elif self.PW_status[0]==1:
            d['ONCE'] = ('PW1 valid for several CDS', 'no')
        else:
            d['ONCE'] = ('PW1 valid for several CDS', 'unknown (%d)'%self.PW_status[0])

        if self.PW_status[1] & 0x80:
            fmt = "Format-2"
        else:
            fmt = "UTF-8"
        pwlen = self.PW_status[1] & 0x7f
        d['PW1'] = ("PW1 format", "%s : %d bytes"%(fmt,pwlen))

        if self.PW_status[2] & 0x80:
            fmt = "Format-2"
        else:
            fmt = "UTF-8"
        pwlen = self.PW_status[2] & 0x7f
        d['RC'] = ("RC format", "%s : %d bytes"%(fmt,pwlen))

        if self.PW_status[3] & 0x80:
            fmt = "Format-2"
        else:
            fmt = "UTF-8"
        pwlen = self.PW_status[3] & 0x7f
        d['PW3'] = ("PW3 format", "%s : %d bytes"%(fmt,pwlen))

        d['CNT1'] = ('PW1 counter', "%x"%self.PW_status[4])
        d['CNTRC'] =('RC counter',  "%x"%self.PW_status[5])
        d['CNT3'] = ('PW3 counter', "%x"%self.PW_status[6])

        return d

    #USER Info
    # internals are always store as byres, get/set automatically convert from/to
    def set_name(self,name):
        """ Args:
              name (str) : utf8 string
        """
        self.name = name.encode('utf-8')
        self.put_data(  0x5b, self.name)

    def get_name(self):
        return self.name.decode('utf-8')

    def set_login(self,login):
        """ Args:
              login (str) : utf8 string
        """
        self.login = login.encode('utf-8')
        self.put_data(  0x5e, self.login)

    def get_login(self):
        return self.login.decode('utf-8')

    def set_url(self,url):
        """ Args:
              url (str) :  utf8 string
        """
        self.url = url.encode('utf-8')
        self.put_data(0x5f50, self.url)

    def get_url(self):
        return self.url.decode('utf-8')

    def set_sex(self,sex):
        """ Args:
              sex (str) : ascii string ('9', '1', '2')
        """
        self.sex = sex.encode('utf-8')
        self.put_data(0x5f35, self.sex)

    def get_sex(self):
        return self.sex.decode('utf-8')

    def set_lang(self,lang):
        """ Args:
              lang (str) :  utf8 string
        """
        self.lang = lang.encode('utf-8')
        self.put_data(0x5f2d, self.lang)

    def get_lang(self):
        return self.lang.decode('utf-8')


    #PINs
    def verify_pin(self,id,value):
        """ Args:
              id    (int) : 0x81, 0x82, ox83
              value (str) :  ascii string
        """
        value = value.encode('ascii')
        resp,sw = self.verify(id,value)
        return sw == 0x9000

    def change_pin(self, id, value,new_value):
        """ Args:
              id    (int) : 0x81,  ox83
              value (str) :  ascii string
        """
        value = value.encode('ascii')
        new_value = new_value.encode('ascii')
        resp,sw = self.change_reference_data(id,value,new_value)
        return sw == 0x9000

    def change_RC(self,new_value):
        """ Args:
              id    (int) : 0x81,  ox83
              value (str) :  ascii string
        """
        new_value = new_value.encode('ascii')
        resp,sw = self.put_data(0xd3,new_value)
        return sw == 0x9000

    def reset_PW1(self,RC,new_value):
        """ Args:
              id    (int) : 0x81,  ox83
              value (str) :  ascii string
        """
        new_value = new_value.encode('ascii')
        RC = RC.encode('ascii')
        resp,sw = self.reset_retry_counter(RC,new_value)
        return sw == 0x9000

    #keys
    def get_key_uif(self,key):
        """
          Returns: (int) 0,1,2,256(not supported)
        """
        uif = None
        if key=='sig':
            uif = self.UIF_SIG
        if key=='aut':
            uif = self.UIF_DEC
        if key=='dec':
            uif = self.UIF_AUT

        if uif:
            uif = int.from_bytes(uif,'big')
        else:
            uif = 256
        return uif

    def get_key_fingerprints(self, key):
        """
          Returns: (str) fingerprints hex string
        """
        fprints = None
        if key=='sig':
            fprints = self.sig_fingerprints
        if key=='aut':
            fprints = self.aut_fingerprints
        if key=='dec':
            fprints = self.dec_fingerprints
        if fprints:
            fprints = binascii.hexlify(fprints)
        else:
            fprint = '-'
        return fprints.decode('ascii')

    def get_key_CA_fingerprints(self, key):
        """
          Returns: (str) CA fingerprints hex string
        """
        fprints = None
        if key=='sig':
            fprints = self.sig_CA_fingerprints
        if key=='aut':
            fprints = self.aut_CA_fingerprints
        if key=='dec':
            fprints = self.dec_CA_fingerprints
        if fprints:
            fprints = binascii.hexlify(fprints)
        else:
            fprint = b'-'
        return fprints.decode('ascii')

    def get_key_date(self, key):
        """
          Returns: (str) date
        """
        fdate = None
        if key=='sig':
            fdate = self.sig_date
        if key=='aut':
            fdate = self.aut_date
        if key=='dec':
            fdate = self.dec_date
        if fdate:
            fdate =  datetime.datetime.fromtimestamp(int.from_bytes(fdate,'big')).isoformat(' ')
        else:
            fprint = b'-'.decode('ascii')
        return fdate


    def get_key_attribute(self, key):
        """
        for RSA:
           {'id':     (int)  0x01,
            'nsize':  (int)
            'esize'   (int)
            'format': (int)
            }

        for ECC:

           {'id':     (int) 0x18|0x19,
            'OID':    (bytes)
            }

        Args:
          key: (str) 'sig' | 'aut', 'dec'
        """

        attributes = None
        if key=='sig':
            attributes = self.sig_attribute
        if key=='dec':
            attributes = self.dec_attribute
        if key=='aut':
            attributes = self.aut_attribute
        if not attributes:
            return None
        if len(attributes) == 0:
            return None

        if attributes[0] == 0x01:
            return {
            'id':   1,
            'nsize': (attributes[1]<<8) | attributes[2],
            'esize': (attributes[3]<<8) | attributes[4],
            'format': attributes[5]
            }
        if attributes[0] == 18 or  attributes[0] == 19 :
            return {
            'id':  attributes[0] ,
            'oid': attributes[1:]
            }
        print ("NONE: %s"%binascii.hexlify(attributes))
        return None

    def set_template(self, template):
        """
        See get_template
        """
        pass


    def asymmetric_key(self, op, key) :
        """
        Args:
          op: (int) 0x80 generate, 0x81 read pub, 0x82 read pub&priv
          key: (str) 'sig' | 'aut', 'dec'

        Returns:
          for RSA:
             {'id': (int)  0x01,
              'n':  (bytes)
              'e'   (bytes)
              'd':  (bytes)
              }

          for ECC:

             {'id':     (int) 0x18|0x19,
              'OID':    (bytes)
              }

        """
        attributes = None
        if key=='sig':
            attributes = self.sig_attribute
            key = 0xb600
        if key=='dec':
            attributes = self.dec_attribute
            key = 0xb800
        if key=='aut':
            attributes = self.aut_attribute
            key = 0xa400
        if not attributes:
            return None
        if len(attributes) == 0:
            return None
        resp,sw = self.generate_asym_key_pair(op,key)
        if sw != 0x9000:
            return None
        resp,sw = self.generate_asym_key_pair(0x82,key)
        tags = decode_tlv(resp)
        tags = decode_tlv(tags[0x7f49])
        if attributes[0] == 0x01:
            return {
            'id':   1,
            'n': tags[0x81],
            'e': tags[0x82],
            'd': tags[0x98],
            }

    def dump():
        pass
