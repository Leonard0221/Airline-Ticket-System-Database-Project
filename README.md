# Airline Ticket Reservation System
## Project Description

This project is mysql / flask project on airline ticket reservation system.\
This project runs perfectly on demo, meeting all the requirements of the projects details.

##Extra efforts in the projects (Bonus)

*Beside the requirements (Bonus):*
1. Add salt security to password: e.g., encrypted_password = gen_hash(password1, method='pbkdf2:sha256')
2. Fuzzy Query: One wants to search a specific flight, they could input the basic information one wants.
3. Relatively beautiful User-Interface: Adopting bootstrap.
4. Add Email Validation Check on customers: One customer needs to make sure his/her email is valid before signing up for an account.
5. Calendar Basics: In bar charts, I specifically make sure the differences between months (i.e. Number of days 28/31/30).

*Some problems that are beyond our capabilities:*
1. For existed passwords, because the security protocol has changed, persons need to reset passwords to make sure it works.
2. Email Validation: Currently it limits to some accounts with low email security. It differs from emails to emails, there is a great chance the email would bounce and end up with spam.

##Explanation of the project
Some notes: 
1. For the convenience of the new functions of the project, we decide to alter the original table:
* Set permission_type default value 'None' ;
* Set phone number length longer > 20;
* Need to change the password default length to 256;
2. It is very easy to run this project. Just click the main.py and run the module.

