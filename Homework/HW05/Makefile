##Static Variables
MSG = message.txt
KEY = key.txt
ENC = encrypted.txt
DEC = decrypted.txt
IMG = image.ppm
img_enc = enc_image.ppm
PYFILE = AES.py

##Targets

encrypt:
	python3 $(PYFILE) -e $(MSG) $(KEY) $(ENC)

decrypt:
	python3 $(PYFILE) -d $(ENC) $(KEY) $(DEC)

image:
	python3 $(PYFILE) -i $(IMG) $(KEY) $(img_enc)

test: encrypt decrypt

clean:
	rm -f $(ENC) $(DEC) *.zip

all: clean encrypt decrypt

#add HW02 <last name><first name>.zip with *.pdf, and DES.py
submit:
	zip -r hw04_Panchagnula_Raghava.zip hw04_Panchagnula_Raghava.pdf $(PYFILE)

.PHONY: encrypt decrypt test
