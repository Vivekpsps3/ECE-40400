##Static Variables
MSG = message.txt
KEY = key.txt
ENC = encrypted.txt
DEC = decrypted.txt

##Targets
$(MSG):
	echo "This is a test message" > $(MSG)

encrypt:
	python3 DES.py -e $(MSG) $(KEY) $(ENC)

decrypt:
	python3 DES.py -d $(ENC) $(KEY) $(DEC)

test: encrypt decrypt
	diff $(MSG) $(DEC)

image:
	python3 DES.py -i image.ppm $(KEY) image_enc.ppm

clean:
	rm -f $(ENC) $(DEC) image_enc.ppm *.zip

all: clean encrypt decrypt image

#add HW02 <last name><first name>.zip with *.pdf, and DES.py
submit:
	zip -r HW02_Panchagnula_Raghava.zip HW02_Panchagnula_Raghava.pdf DES.py

.PHONY: encrypt decrypt test
