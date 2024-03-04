##Static Variables
MSG = input.txt
HASH = hashed.txt
TEST = test.txt

HW_NUM = 07

PYFILE = sha512.py

##Targets
test: hash
	diff $(HASH) $(TEST)

hash:
	python3 $(PYFILE) $(MSG) $(HASH)

submit:
	zip -r hw$(HW_NUM)_Panchagnula_Raghava.zip hw$(HW_NUM)_Panchagnula_Raghava.pdf $(PYFILE)
