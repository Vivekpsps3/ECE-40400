##Static Variables
MSG = message.txt
KEY = key.txt
ENC = encrypted.txt
DEC = decrypted.txt
PYFILE = AES.py

##Targets

encrypt:
	python3 $(PYFILE) -e $(MSG) $(KEY) $(ENC)

decrypt:
	python3 $(PYFILE) -d $(ENC) $(KEY) $(DEC)

test: encrypt decrypt

clean:
	rm -f $(ENC) $(DEC) *.zip

all: clean encrypt decrypt

#add HW02 <last name><first name>.zip with *.pdf, and DES.py
submit:
	zip -r HW04_Panchagnula_Raghava.zip HW04_Panchagnula_Raghava.pdf $(PYFILE)

.PHONY: encrypt decrypt test
