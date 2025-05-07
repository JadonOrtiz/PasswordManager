def managerPassword():
#Default Password is Password123
  managerPassword = "Password123"
  count = 0
#User will get locked out of password manager if wrong password is given 5 times
  while count < 5:
    attempt = input("Enter the password: ")
    if attempt == managerPassword:
      manager()
      break
    else:
      count += 1
      print("Wrong password")
  if count == 5:
    print("Locked Out")

def manager():
  print("Enter a Number \n 1. View Passwords \n 2. Enter new Password \n"
  " 3. Delete Password \n 4. Change Password \n 5. Change Manager Password")
  choice = int(input("Enter a number: "))
  if choice == 1:
    viewPasswords()
  elif choice == 2:
    newPassword()
  elif choice == 3:
    deletePassword()
  elif choice == 4:
    changePassword()
def viewPasswords():
  exit = 1
  while exit != 0:
    print("viewing passwords")
    exit = int(input("Enter 0 to exit: "))
def newPassword():
  pass
def deletePassword():
  pass
def changePassword():
  pass
def changeManagerPassword():
  pass
def main():
  managerPassword()
if __name__ == "__main__":
  main()