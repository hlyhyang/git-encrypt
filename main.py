import admin as admin
import contributor as user
user_type = input("Share your code securly with others? Enter A. Request others' work? Enter U ")
if(user_type =="A" or user_type =='a'):
    admin.admin_func()
elif(user_type =="U" or user_type =='u'):
    user.user_func()
else:
    print("sorry please enter A or U only")