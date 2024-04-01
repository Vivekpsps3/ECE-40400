##Static Variables
HW_NUM = 09

TEST_BASH = firewall404.sh

##Targets
test: table

table:
	sudo bash ./$(TEST_BASH)

tcp:
	sudo tcpdump -vvv -nn -s 1500 -S -X -c 20 'dst moonshine.ecn.purdue.edu'

submit:
	zip -r hw$(HW_NUM)_Panchagnula_Raghava.zip hw$(HW_NUM)_Panchagnula_Raghava.pdf $(TEST_BASH)
