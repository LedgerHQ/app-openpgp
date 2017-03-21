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

from gpgcard import GPGCard

gpgcard = GPGCard()
gpgcard.connect("pcsc:Ledger")
gpgcard.get_all()


gpgcard.verify_pin(0x81, "123456")
gpgcard.verify_pin(0x83, "12345678")
gpgcard.restore("backup_card.pickle", True)
