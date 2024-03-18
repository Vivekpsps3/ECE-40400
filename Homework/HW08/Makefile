##Static Variables
HW_NUM = 08

TEST_PYFILE = TcpAttack_test.py
PYFILE = TcpAttack.py
PYTHON = /home/vivek/Files/.venv/bin/python3.10

##Targets
test: attack

attack:
	sudo $(PYTHON) $(PYFILE)

tcp:
	sudo tcpdump -vvv -nn -s 1500 -S -X -c 20 'dst moonshine.ecn.purdue.edu'

submit:
	zip -r hw$(HW_NUM)_Panchagnula_Raghava.zip hw$(HW_NUM)_Panchagnula_Raghava.pdf $(PYFILE)
