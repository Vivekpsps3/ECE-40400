import os

#!/usr/bin/env python3

# Test for Recipe 1
for i in range(1, 51):
    command = "procmail ./.procmailrc < Mail/junkMail_%d" % i
    os.system(command)
    if os.stat("/home/vivek/Mail/recipe_1").st_size > 0:
        print("Test", i, "Passed")
        os.system("> /home/vivek/Mail/recipe_1")
    else:
        print("Test", i, "failed")
        if os.stat("/home/vivek/Mail/recipe_2").st_size > 0:
            print("went to recipe 2")
            os.system("> /home/vivek/Mail/recipe_2")
            # write to Mail/recipe_2 that the test failed
            with open("Mail/recipe_2", "a") as f:
                f.write("Test %d failed" % i)
        if os.stat("/home/vivek/Mail/recipe_3").st_size > 0:
            print("went to recipe 3")
            os.system("> /home/vivek/Mail/recipe_3")
            # write to Mail/recipe_3 that the test failed
            with open("Mail/recipe_3", "a") as f:
                f.write("Test %d failed" % i)
        if os.stat("/home/vivek/Mail/recipe_4").st_size > 0:
            print("went to recipe 4")
            os.system("> /home/vivek/Mail/recipe_4")
            # write to Mail/recipe_4 that the test failed
            with open("Mail/recipe_4", "a") as f:
                f.write("Test %d failed" % i)
        exit()

print("Test 1-50 Passed - Recipe 1 is working")

# Test for Recipe 2
for i in range(51, 64):
    command = "procmail ./.procmailrc < Mail/junkMail_%d" % i
    os.system(command)
    if os.stat("/home/vivek/Mail/recipe_2").st_size > 0:
        print("Test", i, "Passed")
        os.system("> /home/vivek/Mail/recipe_2")

    else:
        print("Test", i, "failed")
        if os.stat("/home/vivek/Mail/recipe_3").st_size > 0:
            print("went to recipe 3")
            os.system("> /home/vivek/Mail/recipe_3")
            # write to Mail/recipe_3 that the test failed
            with open("Mail/recipe_3", "a") as f:
                f.write("Test %d failed" % i)
        if os.stat("/home/vivek/Mail/recipe_4").st_size > 0:
            print("went to recipe 4")
            os.system("> /home/vivek/Mail/recipe_4")
            # write to Mail/recipe_4 that the test failed
            with open("Mail/recipe_4", "a") as f:
                f.write("Test %d failed" % i)
        exit()

print("Test 51-63 Passed - Recipe 2 is working")

# Test for Recipe 3
for i in range(64, 67):
    command = "procmail ./.procmailrc < Mail/junkMail_%d" % i
    os.system(command)
    if os.stat("/home/vivek/Mail/recipe_3").st_size > 0:
        print("Test", i, "Passed")
        os.system("> /home/vivek/Mail/recipe_3")
        # write to Mail/recipe_3 that the test passed

    else:
        print("Test", i, "failed")
        if os.stat("/home/vivek/Mail/recipe_4").st_size > 0:
            print("went to recipe 4")
            os.system("> /home/vivek/Mail/recipe_4")
            # write to Mail/recipe_4 that the test failed
            with open("Mail/recipe_4", "a") as f:
                f.write("Test %d failed" % i)
        exit()

print("Test 64-66 Passed - Recipe 3 is working")

# Test for Recipe 4
for i in range(67, 75):
    command = "procmail ./.procmailrc < Mail/junkMail_%d" % i
    os.system(command)
    if os.stat("/home/vivek/Mail/recipe_4").st_size > 0:
        print("Test", i, "Passed")
        os.system("> /home/vivek/Mail/recipe_4")
    else:
        print("Test", i, "failed")
        # check if the recipie instead went to the default spam folder
        if os.stat("/home/vivek/Mail/spamFolder").st_size > 0:
            print("went to spam folder")
            os.system("> /home/vivek/Mail/spamFolder")
        exit()

print("Test 67-74 Passed - Recipe 4 is working")