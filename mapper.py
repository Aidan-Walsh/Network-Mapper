import subprocess



# to be run from the pivot machine 
credentials_file = "credentials.txt"

# store usernames and passwords separately to be used
usernames = []
passwords = []
with open("credentials.txt", "r") as file_obj:
  content = file_obj.read()
  lines = content.split("\n")
  for line in lines:
    credential = line.split(":")
    usernames.append(credential[0])
    try:
      passwords.append(credential[1])
    except: 
      print("Error parsing credentials file")
      

# first within pivot, we need to enumerate first private network
# user should be sudo'd into pivot with "sudo su"

sudo_password = "your_sudo_password"  # Replace with your actual password (use with caution!)
command = ["ip", "a"]

try:
    result = subprocess.run(command, check=True, capture_output=True, text=True)   
    print(result)

except Exception as e:
    print(f"An error occurred: {e}")
      
      

      
  
    

    
  