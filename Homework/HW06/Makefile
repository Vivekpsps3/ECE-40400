##Static Variables
MSG = message.txt
KEY = p.txt q.txt
ENC = encrypted.txt
DEC = decrypted.txt

PYFILE = rsa.py
BREAK_FILE = breakRSA.py
BREAK_MESSAGE = enc1.txt enc2.txt enc3.txt n_1_2_3.txt
BREAK_OUTPUT = cracked.txt

##Targets
test: generate encrypt decrypt crack
	diff $(DEC) $(BREAK_OUTPUT)
	
generate: 
	python3 $(PYFILE) -g $(KEY)

encrypt:
	python3 $(PYFILE) -e $(MSG) $(KEY) $(ENC)
	python3 $(BREAK_FILE) -e $(MSG) $(BREAK_MESSAGE)

decrypt:
	python3 $(PYFILE) -d $(ENC) $(KEY) $(DEC)
	
crack:
	python3 $(BREAK_FILE) -c $(BREAK_MESSAGE) $(BREAK_OUTPUT)

submit:
	zip -r hw06_Panchagnula_Raghava.zip hw06_Panchagnula_Raghava.pdf $(PYFILE) $(BREAK_FILE)
.PHONY: encrypt decrypt test
