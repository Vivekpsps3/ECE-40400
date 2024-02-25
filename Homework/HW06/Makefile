##Static Variables
MSG = message.txt
KEY = p.txt q.txt
ENC = encrypted.txt
DEC = decrypted.txt

PYFILE = RSA.py
BREAK_FILE = break_RSA.py
BREAK_PYFILE = Break_RSA_test.py

##Targets
generate: 
	python3 $(PYFILE) -g $(KEY)

encrypt:
	python3 $(PYFILE) -e $(MSG) $(KEY) $(ENC)

decrypt:
	python3 $(PYFILE) -d $(ENC) $(KEY) $(DEC)

test: generate encrypt decrypt

clean:
	rm -f $(ENC) $(DEC) *.zip

all: clean encrypt decrypt

#add HW02 <last name><first name>.zip with *.pdf, and DES.py
submit:
	zip -r hw06_Panchagnula_Raghava.zip hw06_Panchagnula_Raghava.pdf $(PYFILE)

.PHONY: encrypt decrypt test
