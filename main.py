# Some note: I change the original table:
# Set permission_type default value 'None'
# Set phone number length longer > 20

from datetime import datetime
import base64
from flask import Flask, render_template, request, session, url_for, redirect, flash, abort
import pymysql.cursors
import matplotlib.pyplot as plt
from io import BytesIO
from werkzeug.security import generate_password_hash as gen_hash, check_password_hash as check_hash
import jwt
import numpy as np
from functools import wraps
import smtplib
import ssl
import random


EMAIL_ADDRESS = "420943364@qq.com"
EMAIL_PASSWORD = "ddfxlbhcvacpbjca"
context = ssl.create_default_context()
smtp = smtplib.SMTP_SSL("smtp.qq.com", 465, context=context)
smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)


def v_code():
    str = ""
    for i in range(6):
        ch = chr(random.randrange(ord('0'), ord('9') + 1))
        str += ch
    return str


def send_email(emailADD, email_Cap):
    subject = "hello, it's a python email"
    body = "Please confirm your password: " + str(email_Cap)
    msg = f"Subject: {subject}\n\n{body}"
    smtp.sendmail(EMAIL_ADDRESS, emailADD, msg)
# print(v_code()) # 224578
send_email("3167363942@qq.com", "234556")


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Spring2022'

conn = pymysql.connect(host='localhost',
                       user='root',
                       password='',
                       db='db_final_project', # Name the Database this name in Phpadmin
                       charset='utf8mb4',
                       cursorclass=pymysql.cursors.DictCursor)


@app.route('/')
def home():
    data=[]
    cur = conn.cursor()
    cur.execute("SELECT airline_name FROM airline")
    data1 = cur.fetchall()
    for i in data1:
        data.append(i['airline_name'])
    cur.close()
    session['action'] = 'none'
    return render_template('home.html', data=data)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.form['submit'] == 'login_as_booking_agent':
            return redirect('/booking_agent_login')
        elif request.form['submit'] == 'login_as_airline_staff':
            return redirect('/airline_staff_login')
        elif request.form['submit'] == 'login_as_customer':
            return redirect('/customer_login')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return render_template('home.html')


@app.route('/sign_up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        if request.form['submit'] == 'sign_up_customer':
            return redirect('/sign_up_customer')
        elif request.form['submit'] == 'sign_up_airline_staff':
            return redirect('/sign_up_airline_staff')
        elif request.form['submit'] == 'sign_up_booking_agent':
            return redirect('/sign_up_booking_agent')
    else:
        return render_template('sign_up.html')


@app.route('/welcome_page', methods=['POST', 'GET'])
def welcome():
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT airport_name FROM airport ORDER BY airport_name")
    airport_name = cur.fetchall()
    cur.execute("SELECT DISTINCT airport_city FROM airport ORDER BY airport_city")
    airport_city = cur.fetchall()

    if request.method == 'POST':
        values = []
        keys = []
        query = "SELECT * FROM flight WHERE"
        query_addtion = ""

        if request.form['From']:
            d_date = request.form['From']
            addtion = " AND departure_time LIKE '" + d_date + "%'"
            query_addtion += addtion

        if request.form['to']:
            a_time = request.form['to']
            addtion = " AND arrival_time LIKE '" + a_time + "%'"
            query_addtion += addtion

        if request.form['source_airport']:
            d_airport = request.form['source_airport']
            addtion = " AND departure_airport = '" + d_airport + "'"
            query_addtion += addtion

        if request.form['destination_airport']:
            a_airport = request.form['destination_airport']
            addtion = " AND arrival_airport = '" + a_airport + "'"
            query_addtion += addtion

        if request.form['source_city']:
            d_city = request.form['source_city']
            addtion = " AND departure_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + d_city + "')"
            query_addtion += addtion

        if request.form['destination_city']:
            a_city = request.form['destination_city']
            addtion = " AND arrival_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + a_city + "')"
            query_addtion += addtion

        if request.form['flight_num']:
            flight_num = request.form['flight_num']
            addtion = " AND flight_num = " + flight_num
            query_addtion += addtion

        if query_addtion == "":
            query = "SELECT * FROM flight WHERE status = 'Upcoming';"
        else:
            query = query + query_addtion[4:] + ";"
        print(query)
        cur.execute(query)
        flight_info = cur.fetchall()
        flight_info = tuple(flight_info)
        for j in flight_info[0].keys():
            keys.append(str(j))
        for i in range(len(flight_info)):
            sub_values = []
            for j in flight_info[i].values():
                sub_values.append(str(j))
            values.append(sub_values)
        keys = tuple(keys)
        values = tuple(values)
        print(keys)
        print(values)
        cur.close()
        # query = "SELECT flight.airline_name, flight.flight_num, flight.departure_airport, flight.departure_time, flight.arrival_airport, flight.arrival_time, flight.status, flight.price FROM flight, airport WHERE flight.departure_airport LIKE '%%%s%%' or flight.arrival_airport LIKE '%%%s%%'or (flight.departure_airport = airport.airport_name and airport.airport_city LIKE '%%%s%%') or (flight.arrival_airport = airport.airport_name and airport.airport_city LIKE '%%%s%%')" % (
        # searchText, searchText, searchText, searchText)
        # cursor.execute(query)
        return render_template("results.html", heading=keys, values=values)

    return render_template('welcome.html', airport_city=airport_city, airport_name=airport_name, title="Home Page")


@app.route('/customer_login', methods=['POST', 'GET'])
def customer_login():
    if request.method == 'POST':
        cur = conn.cursor()
        email = request.form['email']
        password = request.form['password']
        email = (email,)
        query = "SELECT * FROM customer c WHERE c.email = %s"
        cur.execute(query, email)
        customer_info = cur.fetchone()
        cur.close()
        if customer_info is not None:
            check_final = bool(str(customer_info['password']) == str(gen_hash(password, method='pbkdf2:sha256')))
            if check_final:
                session['action'] = 'customer'
                session['email'] = customer_info['email']
                session['name'] = customer_info['name']
                return redirect(url_for("customer"))
            else:
                flash('Wrong password, Try again! ')
        else:
            flash('Email address is not found, try again! ')

    return render_template("customer_login.html")


@app.route('/airline_staff_login', methods=['POST', 'GET'])
def airline_staff_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = conn.cursor()
        username = (username,)
        cur.execute("SELECT * FROM airline_staff WHERE airline_staff.username = %s", username)
        staff_list = cur.fetchone()
        if staff_list is not None:
            check_password = bool(str(staff_list['password']) == str(gen_hash(password, method='pbkdf2:sha256')))  # check if this correct
            #check_password = bool(str(staff_list['password']) == str(password))
            if check_password:
                cur.execute("SELECT * FROM permission WHERE username = %s", username)
                permission_list = cur.fetchone()
                cur.close()
                session['action'] = 'airline_staff'
                session['email'] = staff_list['username']
                session['name'] = staff_list['first_name']
                session['surname'] = staff_list['last_name']
                session['work_for'] = staff_list['airline_name']
                try:
                    session['permission'] = permission_list['permission_type']
                except:
                    session['permission'] = ''
                return redirect(url_for("airline_staff"))
            else:
                flash('Wrong password, try again! ')
        else:
            flash('Email address is not found, try again! ')
        cur.close()

    return render_template("airline_staff_login.html")


@app.route('/booking_agent_login', methods=['POST', 'GET'])
def booking_agent_login():
    if request.method == 'POST':
        work_for = []
        email = request.form['email']
        password = request.form.get('password')
        cur = conn.cursor()
        email_tuple = (email,)
        cur.execute("SELECT * FROM booking_agent ba WHERE ba.email = %s", email_tuple)
        self_info = cur.fetchone()
        cur.execute("SELECT airline_name FROM booking_agent_work_for b_work_for WHERE b_work_for.email = %s",
                    email_tuple)
        self_client = cur.fetchall()
        for row in self_client:
            work_for.append(row['airline_name'])
        if self_info:
            check_password = bool(str(self_info['password']) == str(gen_hash(password, method='pbkdf2:sha256')))
            # check_password = bool(str(self_info['password']) == str(password))

            if check_password:
                session['action'] = 'booking_agent'
                session['email'] = self_info['email']
                session['work_for'] = work_for
                session['booking_agent_id'] = self_info['booking_agent_id']
                return redirect(url_for("booking_agent"))
            else:
                flash('Wrong Password, try again!')
        else:
            flash('Email address is not found, try again! ')
        cur.close()

    return render_template("booking_agent_login.html")


@app.route('/sign_up_customer', methods=['POST', 'GET'])
def sign_up_customer():
    if request.method == 'POST':
        # a = str(v_code())
        a = '123456'
        email = request.form['email']
        name = request.form['name']
        if request.form['submit'] == "email_confirm":
            try:
                print("send email")
                send_email("123@nyu.edy", a)
            except:
                pass
        else:
            password1 = request.form['password1']
            password2 = request.form['password2']
            verification_code = request.form['emailVerify']
            building_number = request.form['building_number']
            street = request.form['street']
            city = request.form['city']
            state = request.form['state']
            phone_number = request.form['phone_number']
            print(verification_code)

            passport_number = request.form['passport_number']
            passport_expiration = request.form['passport_expiration']
            passport_country = request.form['passport_country']
            date_of_birth = request.form['birthdate']
            cur = conn.cursor()
            email_tuple = (email,)
            check_dup = cur.execute("SELECT * FROM customer WHERE customer.email = %s", email_tuple)
            if check_dup:
                flash("You have already registered.")
            elif password1 != password2:
                flash('Two passwords do not match.')
            elif verification_code != a:
                flash('Wrong Verification Code, try again.')
            elif type(int(phone_number)) != int:
                flash('Invalid phone number format.')
            else:
                encrypted_password = gen_hash(password1, method='pbkdf2:sha256')
                customer_info = (
                    email, name, encrypted_password, building_number, street, city, state, phone_number, passport_number,
                    passport_expiration, passport_country, date_of_birth)
                cur = conn.cursor()
                cur.execute("INSERT INTO customer VALUES (%s, %s, %ls, %s, %s, %s, %s, %s, %s, %s, %s, %s)", customer_info)
                flash('Account create successfully! ')
                session['email'] = email
                session['name'] = name
                session['action'] = 'customer'
                conn.commit()
                cur.close()
                return redirect('/login')

    return render_template("sign_up_customer.html")


@app.route('/sign_up_booking_agent', methods=['GET', 'POST'])
def sign_up_booking_agent():
    if request.method == 'POST':
        email = request.form['email'];
        booking_agent_id = request.form['booking_agent_id'];
        password1 = request.form['password1']
        password2 = request.form['password2'];
        cur = conn.cursor();
        email_tuple = (email,);
        check_dup = cur.execute("SELECT * FROM booking_agent WHERE booking_agent.email = %s", email_tuple);
        if check_dup:
            flash("You have already registered.");
        elif password1 != password2:
            flash('Two passwords do not match.');
        else:
            encrypted_password = gen_hash(password1, method='pbkdf2:sha256');
            ba_info = (email, encrypted_password, booking_agent_id);
            cur.execute("INSERT INTO booking_agent VALUES (%s, %s, %s)", ba_info);
            flash('Account created successfully!');
            session['email'] = email;
            session['booking_agent_id'] = booking_agent_id;
            session['action'] = 'booking_agent';
            session['work_for'] = ''
            conn.commit()
            cur.close()
            return redirect('/booking_agent');
    return render_template("sign_up_booking_agent.html")


@app.route('/sign_up_airline_staff', methods=['GET', 'POST'])
def sign_up_airline_staff():
    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        date_of_birth = request.form['date_of_birth']
        airline_name = request.form['airline_name']
        cur = conn.cursor()
        email_tuple = (username,)
        airline_name = (airline_name,)
        check_dup = cur.execute("SELECT * FROM airline_staff WHERE username = %s", email_tuple)
        check_dup1 = cur.execute("SELECT * FROM airline WHERE airline_name = %s", airline_name)
        if check_dup:
            flash("You have already registered.")
        elif check_dup1 is None:
            flash('Wrong airline name!')
        elif password1 != password2:
            flash('Two passwords do not match.')
        else:
            hash_password = gen_hash(str(password1), method='pbkdf2:sha256')
            staff_info = (username, hash_password, first_name, last_name, date_of_birth, airline_name)
            cur.execute("INSERT INTO airline_staff VALUES (%s, %s, %s, %s, %s, %s)", staff_info)
            flash('Account created successfully!')
            session['email'] = username
            session['action'] = 'airline_staff'
            session['name'] = first_name
            session['surname'] = last_name
            session['work_for'] = airline_name
            session['permission'] = "None"
            cur.execute("INSERT INTO permission(username) VALUES (%s)", username)
            conn.commit()
            cur.close()
            return redirect('/airline_staff')

    return render_template("sign_up_airline_staff.html")


# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kws):
#         if not 'Authorization' in request.headers:
#             abort(401)
#
#         user = None
#         data = request.headers['Authorization'].encode('ascii', 'ignore')
#         token = str.replace(str(data), 'Bearer ', '')
#         try:
#             user = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])['sub']
#         except:
#             abort(401)
#
#         return f(user, *args, **kws)
#
#     return decorated_function

# ------------------------------------------------------customer-------------------------------------------------------
@app.route('/customer', methods=['POST', 'GET'])
# @login_required
def customer():
    if request.method == 'POST':
        if request.form['submit'] == 'view_my_flight':
            heading = []
            values = []
            email = session['email']
            cur = conn.cursor()
            query = "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email ='" + email + "'));"
            cur.execute(query)
            flight_info = cur.fetchall()
            cur.close()
            flight_info = tuple(flight_info)

            for i in range(len(flight_info)):
                sub_values = []
                if i == 0:
                    for j in flight_info[0].keys():
                        heading.append(str(j))
                for j in flight_info[i].values():
                    sub_values.append(str(j))
                values.append(sub_values)
            heading = tuple(heading)
            values = tuple(values)
            return render_template("results.html", heading=heading, values=values)
        if request.form['submit'] == 'track_spending':
            return redirect('/track_spending')
        if request.form['submit'] == 'purchase_ticket':
            return redirect('/flight_search_specific')

    return render_template('customer.html')


@app.route('/flight_search_specific', methods=['GET', 'POST'])
def flight_search_specific():
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT airport_city FROM airport ORDER BY airport_city")
    airport_city = cur.fetchall()
    cur.execute("SELECT DISTINCT airport_name FROM airport ORDER BY airport_name")
    airport_name = cur.fetchall()

    if request.method == 'POST':
        if session['action'] == 'customer':
            keys = []
            values = []
            query = "SELECT * FROM flight WHERE"
            query_addtion = ""
            if request.form['From']:
                departure_time = request.form['From']
                addtion = " AND departure_time LIKE '" + departure_time + "%'"
                query_addtion += addtion
            if request.form['to']:
                arrival_time = request.form['to']
                addtion = " AND arrival_time LIKE " + arrival_time + "%"
                query_addtion += addtion
            if request.form['source_airport']:
                departure_airport = request.form['source_airport']
                addtion = " AND departure_airport = '" + departure_airport + "'"
                query_addtion += addtion
            if request.form['destination_airport']:
                arrival_airport = request.form['destination_airport']
                addtion = " AND arrival_airport = '" + arrival_airport + "'"
                query_addtion += addtion
            if request.form['source_city']:
                departure_city = request.form['source_city']
                addtion = " AND departure_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + departure_city + "')"
                query_addtion += addtion
            if request.form['destination_city']:
                a_city = request.form['destination_city']
                addtion = " AND arrival_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + a_city + "')"
                query_addtion += addtion
            if request.form['flight_num']:
                flight_num = request.form['flight_num']
                addtion = " AND flight_num = " + flight_num
                query_addtion += addtion
            if query_addtion == "":
                query = "SELECT * FROM flight WHERE status = 'Upcoming'; "
            else:
                query = query + query_addtion[4:] + ";"
            cur.execute(query)
            flight_info = cur.fetchall()
            flight_info = tuple(flight_info)

            for i in range(len(flight_info)):
                sub_values = []
                if i == 0:
                    for j in flight_info[0].keys():
                        keys.append(str(j))
                for j in flight_info[i].values():
                    sub_values.append(str(j))
                values.append(sub_values)
            keys = tuple(keys)
            values = tuple(values)
            session['heading'] = keys
            session['values'] = values
            cur.close()
            return redirect("/purchase_ticket")


        elif session['action'] == 'booking_agent':
            if session['work_for'] == []:
                keys = []
                values = []
                query = "SELECT * FROM flight WHERE "
                query_addtion = ""
                if request.form['From']:
                    departure_time = request.form['From']
                    addtion = " AND departure_time LIKE '" + departure_time + "%'"
                    query_addtion += addtion
                if request.form['to']:
                    arrival_time = request.form['to']
                    addtion = " AND arrival_time LIKE " + arrival_time + "%"
                    query_addtion += addtion
                if request.form['source_airport']:
                    departure_airport = request.form['source_airport']
                    addtion = " AND departure_airport = '" + departure_airport + "'"
                    query_addtion += addtion
                if request.form['destination_airport']:
                    arrival_airport = request.form['destination_airport']
                    addtion = " AND arrival_airport = '" + arrival_airport + "'"
                    query_addtion += addtion
                if request.form['source_city']:
                    departure_city = request.form['source_city']
                    addtion = " AND departure_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + departure_city + "')"
                    query_addtion += addtion
                if request.form['destination_city']:
                    a_city = request.form['destination_city']
                    addtion = " AND arrival_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + a_city + "')"
                    query_addtion += addtion
                if request.form['flight_num']:
                    flight_num = request.form['flight_num']
                    addtion = " AND flight_num = " + flight_num
                    query_addtion += addtion
                if query_addtion == "":
                    query = "SELECT * FROM flight WHERE "
                else:
                    query = query + query_addtion[4:] + ";"
                print(query)
                print(str(session['work_for']))
                cur.execute(query)
                flight_info = cur.fetchall()
                flight_info = tuple(flight_info)
                for i in range(len(flight_info)):
                    sub_values = []
                    if i == 0:
                        for j in flight_info[0].keys():
                            keys.append(str(j))
                    for j in flight_info[i].values():
                        sub_values.append(str(j))
                    values.append(sub_values)
                keys = tuple(keys)
                values = tuple(values)
                session['heading'] = keys
                session['values'] = values
                cur.close()
                return redirect('/purchase_ticket')
            else:
                keys = []
                values = []
                query = "SELECT * FROM flight WHERE airline_name IN (" + str(session['work_for'])[1:-1] + ") AND "
                query_addtion = ""
                if request.form['From']:
                    departure_time = request.form['From']
                    addtion = " AND departure_time LIKE '" + departure_time + "%'"
                    query_addtion += addtion
                if request.form['to']:
                    arrival_time = request.form['to']
                    addtion = " AND arrival_time LIKE " + arrival_time + "%"
                    query_addtion += addtion
                if request.form['source_airport']:
                    departure_airport = request.form['source_airport']
                    addtion = " AND departure_airport = '" + departure_airport + "'"
                    query_addtion += addtion
                if request.form['destination_airport']:
                    arrival_airport = request.form['destination_airport']
                    addtion = " AND arrival_airport = '" + arrival_airport + "'"
                    query_addtion += addtion
                if request.form['source_city']:
                    departure_city = request.form['source_city']
                    addtion = " AND departure_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + departure_city + "')"
                    query_addtion += addtion
                if request.form['destination_city']:
                    a_city = request.form['destination_city']
                    addtion = " AND arrival_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + a_city + "')"
                    query_addtion += addtion
                if request.form['flight_num']:
                    flight_num = request.form['flight_num']
                    addtion = " AND flight_num = " + flight_num
                    query_addtion += addtion
                if query_addtion == "":
                    query = "SELECT * FROM flight WHERE airline_name IN (" + str(session['work_for'])[1:] + ")"
                else:
                    query = query + query_addtion[4:] + ";"
                print(query)
                print(str(session['work_for']))
                cur.execute(query)
                flight_info = cur.fetchall()
                flight_info = tuple(flight_info)
                for i in range(len(flight_info)):
                    sub_values = []
                    if i == 0:
                        for j in flight_info[0].keys():
                            keys.append(str(j))
                    for j in flight_info[i].values():
                        sub_values.append(str(j))
                    values.append(sub_values)
                keys = tuple(keys)
                values = tuple(values)
                session['heading'] = keys
                session['values'] = values
                cur.close()
                return redirect('/purchase_ticket')
    return render_template('flight_search_specific.html', airport_city=airport_city, airport_name=airport_name)


@app.route("/purchase_ticket", methods=['GET', 'POST'])
def purchase_ticket():
    if request.method == 'POST':
        flight_num_list = []
        airline_name_list = []
        ticket_id_list = []
        final_ticket = []
        checked_value = request.form.getlist('checkbox')
        if len(checked_value) >= 1:
            for i in checked_value:
                first_index = i.index("'")
                second_index = i.index("'", first_index + 1)
                airline_name_list.append(i[first_index + 1:second_index])
                third_index = i.index("'", second_index + 1)
                fourth_index = i.index("'", third_index + 1)
                flight_num_list.append(i[third_index + 1:fourth_index])
                flight_num_spec = flight_num_list[0]
                airline_name_spec = airline_name_list[0]
                query_one = "SELECT count(flight_num) as count FROM ticket where flight_num = '" + flight_num_spec + "';"
                query_two = "select seats from airplane, flight where airplane.airplane_id = flight.airplane_id and flight.flight_num = '" + flight_num_spec + "';"
                cur = conn.cursor()
                cur.execute(query_one)
                ticket_num = cur.fetchone()
                cur = conn.cursor()
                cur.execute(query_two)
                seat_num = cur.fetchone()
                print(seat_num)
                print(ticket_num)
        else:
            return redirect('/purchase_ticket')


        if session['action'] == 'customer':
            if ticket_num['count'] == seat_num['seats']:
                flash("The tickets are sold out.")
                return redirect('/purchase_ticket')
            else:
                query = "SELECT count(ticket_id) as count FROM ticket;"
                print(query)
                cur = conn.cursor()
                cur.execute(query)
                ticket_id = cur.fetchone()
                print(ticket_id)
                print(ticket_id['count'])
                ticket_id = ticket_id['count'] + 1
                print(ticket_id)
                today = datetime.today().strftime('%Y-%m-%d')
                query3 = "INSERT INTO ticket (ticket_id, airline_name, flight_num) VALUES (" + str(
                    ticket_id) + ", '" + \
                         airline_name_list[0] + "', '" + flight_num_list[0] + "');"
                print(query3)
                cur = conn.cursor()
                cur.execute(query3)
                conn.commit()
                query2 = "INSERT INTO purchases (ticket_id, customer_email, purchase_date) VALUES (" + str(
                    ticket_id) + ", '" + \
                         session['email'] + "', '" + str(today) + "');"
                print(query2)
                cur = conn.cursor()
                cur.execute(query2)
                flash("purchase successfully!")
                conn.commit()
                cur.close()
                return redirect('/welcome_page')

        elif session['action'] == 'booking_agent':
            print(session)
            airline_array = []
            query_three = "SELECT distinct airline_name FROM booking_agent_work_for where email = '" + str(session['email']) + "';"
            cur = conn.cursor()
            cur.execute(query_three)
            airline = cur.fetchall()
            for i in airline:
                airline_array.append(i['airline_name'])

            print(airline_array)
            work_for = session['work_for'][0]
            if work_for not in airline_array:
                flash("You are not working for this airline.")
                return redirect('/purchase_ticket')

            if ticket_num['count'] == seat_num['seats']:
                flash("The tickets are sold out.")
                return redirect('/purchase_ticket')
            else:
                customer_email = request.form['customer_email']
                query = "SELECT count(ticket_id) as count FROM ticket;"
                print(query)
                cur = conn.cursor()
                cur.execute(query)
                ticket_id = cur.fetchone()
                print(ticket_id)
                print(ticket_id['count'])
                ticket_id = ticket_id['count'] + 1
                print(ticket_id)
                today = datetime.today().strftime('%Y-%m-%d')
                query3 = "INSERT INTO ticket (ticket_id, airline_name, flight_num) VALUES (" + str(
                    ticket_id) + ", '" + \
                         airline_name_list[0] + "', '" + flight_num_list[0] + "');"
                print(query3)
                cur = conn.cursor()
                cur.execute(query3)
                conn.commit()
                query2 = "INSERT INTO purchases (ticket_id, customer_email, booking_agent_id, purchase_date) VALUES (" + str(
                    ticket_id) + ", '" + \
                         customer_email + "', '" + str(session['booking_agent_id']) + "','" + str(today) + "');"
                print(query2)
                cur = conn.cursor()
                cur.execute(query2)
                conn.commit()
                cur.close()
                return redirect('/welcome_page')

    return render_template('purchase_ticket.html', heading=session['heading'], values=session['values'])


@app.route('/track_spending', methods=['POST', 'GET'])
def track_spending():
    month = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
             'November', 'December', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
             'September', 'October', 'November', 'December']
    payment_history = []
    corresponding_fight = []
    total = 0
    total_price = 0
    if request.method == 'POST':
        time = 'range'
        if request.form['From']:
            leaving_time = request.form['From']
        if request.form['to']:
            arriving_time = request.form['to']

        select_range_flight = "SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email = '" + \
                              session[
                                  'email'] + "' AND purchase_date >= '" + leaving_time + "' AND purchase_date <= '" + arriving_time + "');"
        cur = conn.cursor()
        cur.execute(select_range_flight)
        flights = cur.fetchall()
        for i in flights:
            i = str(i)
            key_left_appe = i.index(":", 0)
            right_comma = i.index("}", key_left_appe + 1)
            corresponding_fight.append(i[key_left_appe + 1:right_comma])
        for i in corresponding_fight:
            query_price = "SELECT price FROM flight WHERE flight_num= '" + str(i) + "';"
            cur = conn.cursor()
            cur.execute(query_price)
            spent = cur.fetchall()
            spent = str(spent)
            key_left_semi = spent.index("(")
            key_left_semi1 = spent.index("'", key_left_semi + 1)
            key_right_semi = spent.index("')", key_left_semi1 + 1)
            payment_history.append(spent[key_left_semi1 + 1:key_right_semi])
        for i in payment_history:
            total += int(i)
        start_month = int(leaving_time[5:7])
        end_month = int(arriving_time[5:7])
        print(start_month)
        print(end_month)
        x_label = [month[i - 1] for i in range(start_month, end_month + 1)]
        print(x_label)
        sell_record = []
        for i in range(start_month, end_month + 1):
            sell_record.append(0)
        for i in range(len(sell_record)):
            total = 0
            if i == 0:
                if start_month == end_month:
                    leaving_date2 = leaving_time[:5] + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + str(start_month) + arriving_time[7:]
                if start_month == 12 or start_month == 10:
                    leaving_date2 = leaving_time[:5] + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + str(start_month) + "-" + str(31)
                elif start_month == 11:
                    leaving_date2 = leaving_time[:5] + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + str(start_month) + "-" + str(30)
                elif start_month in [1, 3, 5, 7, 8]:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(31)
                elif start_month == 2:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(28)
                elif start_month in [4, 6, 9]:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + leaving_time[7:]
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(30)


            else:
                if start_month == 10 or start_month == 12:
                    leaving_date2 = leaving_time[:5] + str(start_month) + "-01"
                    arriving_date2 = leaving_time[:5] + str(start_month) + "-" + str(31)
                elif start_month == 2:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(28)
                elif start_month in [1, 3, 5, 7, 8]:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(31)
                elif start_month in [4, 6, 9]:
                    leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                    arriving_date2 = leaving_time[:5] + '0' + str(start_month) + "-" + str(30)
                elif start_month == 11:
                    leaving_date2 = leaving_time[:5] + str(start_month) + "-01"
                    arriving_date2 = leaving_time[:5] + str(start_month) + "-" + str(30)
                if start_month == end_month:
                    if start_month == 10 or start_month == 12:
                        leaving_date2 = leaving_time[:5] + str(start_month) + "-01"
                        arriving_date2 = leaving_time[:5] + str(start_month) + arriving_time[7:]
                    elif start_month == 2:
                        leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                        arriving_date2 = leaving_time[:5] + '0' + str(start_month) + arriving_time[7:]
                    elif start_month in [1, 3, 5, 7, 8]:
                        leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                        arriving_date2 = leaving_time[:5] + '0' + str(start_month) + arriving_time[7:]
                    elif start_month in [4, 6, 9]:
                        leaving_date2 = leaving_time[:5] + '0' + str(start_month) + "-01"
                        arriving_date2 = leaving_time[:5] + '0' + str(start_month) + arriving_time[7:]
                    elif start_month == 11:
                        leaving_date2 = leaving_time[:5] + str(start_month) + "-01"
                        arriving_date2 = leaving_time[:5] + str(start_month) + arriving_time[7:]
            select_rest = "SELECT price FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email = '" + str(
                session[
                    'email']) + "' AND purchase_date >= '" + leaving_date2 + "' AND purchase_date <= '" + arriving_date2 + "'));"
            print(select_rest)
            cur = conn.cursor()
            cur.execute(select_rest)
            counts = cur.fetchall()
            print(counts)
            for j in counts:
                total += j['price']
            sell_record[i] = total
            total_price += total
            start_month += 1
            if start_month > 12:
                start_month = 1
                leaving_date2 = str(int(leaving_time[:4]) + 1) + "-0" + str(start_month) + leaving_time[7:]

        plt.bar(x_label, sell_record)
        plt.title('Transaction Record : Monthly')
        plt.xlabel('Month')
        plt.ylabel('Sold')
        for a, b in zip(x_label, sell_record):
            plt.text(a, b, b, ha='center', va='bottom', fontsize=12)
        buffer = BytesIO()
        plt.savefig(buffer)
        plot_value = buffer.getvalue()
        imb = base64.b64encode(plot_value)
        ims = imb.decode()
        image = "data:image/png;base64," + ims
        plt.close()

        return render_template('track_spending.html', total_price=total_price, time=time, bar_chart=image)

    time = 'year'
    today = datetime.today().strftime('%Y-%m-%d')
    year = int(today[:4])
    prev_year = year - 1
    one_year_ago = str(prev_year) + today[4:]
    payment_history = []
    corresponding_fight = []
    total = 0
    select_range_flight = "SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email = '" + \
                          session['email'] + "' AND purchase_date >= '" + one_year_ago + "');"
    cur = conn.cursor()
    cur.execute(select_range_flight)
    flights = cur.fetchall()
    print(select_range_flight)
    print(flights)
    for i in flights:
        i = str(i)
        key_left_appe = i.index(":", 0)
        right_comma = i.index("}", key_left_appe + 1)
        corresponding_fight.append(i[key_left_appe + 1:right_comma])
    print(corresponding_fight)
    for i in corresponding_fight:
        query_price = "SELECT price FROM flight WHERE flight_num= " + str(i) + ";"
        cur = conn.cursor()
        cur.execute(query_price)
        spent = cur.fetchall()
        spent = str(spent)
        print(query_price)
        print(spent)
        key_left_semi = spent.index("(")
        key_left_semi1 = spent.index("'", key_left_semi + 1)
        key_right_semi = spent.index("')", key_left_semi1 + 1)
        payment_history.append(spent[key_left_semi1 + 1:key_right_semi])
    for i in payment_history:
        total += int(i)

    end_month = int(today[5:7])
    print(end_month)
    start_month = (end_month - 5) % 12
    print(start_month)
    if start_month == 0:
        start_month = 12
    if 7 < start_month < 10:
        half_year_ago = str(int(today[:4]) - 1) + "-0" + str(start_month) + today[7:]
    elif start_month <= 7:
        half_year_ago = today[:5] + "0" + str(start_month) + today[7:]
    else:
        half_year_ago = str(int(today[:4]) - 1) + '-' + str(start_month) + today[7:]

    if start_month < end_month:
        x_label = [month[i - 1] for i in range(start_month, end_month + 1)]
        print(x_label)
        sell_record = [0 for _ in range(start_month, end_month + 1)]
    else:
        x_label = [month[i - 1] for i in range(start_month + 1, 13)]
        x_label = x_label + [month[i - 1] for i in range(0, end_month + 1)]
        print(x_label)
        sell_record = [0 for _ in range(start_month + 1, 13)]
        sell_record = sell_record + [0 for _ in range(0, end_month + 1)]
        print(sell_record)

    for i in range(len(sell_record)):
        if 7 < start_month < 10:
            half_year_ago = str(int(today[:4]) - 1) + "-0" + str(start_month) + today[7:]
        elif start_month <= 7:
            half_year_ago = today[:5] + "0" + str(start_month) + today[7:]
        else:
            half_year_ago = str(int(today[:4]) - 1) + '-' + str(start_month) + today[7:]
        total = 0
        if i == 0:
            if start_month == 12 or start_month == 10:
                leaving_date2 = half_year_ago[:5] + str(start_month) + half_year_ago[7:]
                arriving_date2 = half_year_ago[:5] + str(start_month) + "-" + str(31)
            elif start_month == 11:
                leaving_date2 = half_year_ago[:5] + str(start_month) + half_year_ago[7:]
                arriving_date2 = half_year_ago[:5] + str(start_month) + "-" + str(30)
            elif start_month in [1, 3, 5, 7, 8]:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + half_year_ago[7:]
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(31)
            elif start_month == 2:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + half_year_ago[7:]
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(28)
            elif start_month in [4, 6, 9]:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + half_year_ago[7:]
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(30)

        else:
            if start_month == 10 or start_month == 12:
                leaving_date2 = half_year_ago[:5] + str(start_month) + "-01"
                arriving_date2 = half_year_ago[:5] + str(start_month) + "-" + str(31)
            elif start_month == 2:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-01"
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(28)
            elif start_month in [1, 3, 5, 7, 8]:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-01"
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(31)
            elif start_month in [4, 6, 9]:
                leaving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-01"
                arriving_date2 = half_year_ago[:5] + '0' + str(start_month) + "-" + str(30)
            elif start_month == 11:
                leaving_date2 = half_year_ago[:5] + str(start_month) + "-01"
                arriving_date2 = half_year_ago[:5] + str(start_month) + "-" + str(30)

        select_rest = "SELECT price FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email = '" + str(
            session[
                'email']) + "' AND purchase_date >= '" + leaving_date2 + "' AND purchase_date <= '" + arriving_date2 + "'));"

        cur = conn.cursor()
        cur.execute(select_rest)
        counts = cur.fetchall()
        print(select_rest)
        print(counts)
        for j in counts:
            total += j['price']
        sell_record[i] = total
        total_price += total
        start_month += 1
        if start_month > 12:
            start_month = 1
    plt.bar(x_label, sell_record)
    plt.title('Transaction Record: Monthly')
    plt.xlabel('Month')
    plt.ylabel('Sale')
    for a, b in zip(x_label, sell_record):
        plt.text(a, b, b, ha='center', va='bottom', fontsize=12)
    # plt.show()
    buffer = BytesIO()
    plt.savefig(buffer)
    plot_value = buffer.getvalue()
    imb = base64.b64encode(plot_value)
    ims = imb.decode()
    image = "data:image/png;base64," + ims
    plt.close()

    return render_template('track_spending.html', total_price=total_price, time=time, bar_chart=image)


@app.route("/booking_agent", methods=['POST', 'GET'])
def booking_agent():
    if request.method == 'POST':
        if request.form['submit'] == 'view_my_flight':
            keys = []
            values = []
            booking_agent_id = session['booking_agent_id']
            bk_tuple = (booking_agent_id,)
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id = %s))",
                bk_tuple)
            flight_info = cur.fetchall()
            cur.close()
            flight_info = tuple(flight_info)
            for i in range(len(flight_info)):
                sub_values = []
                for j in flight_info[0].keys():
                    keys.append(str(j))
                for j in flight_info[i].values():
                    sub_values.append(str(j))
                values.append(sub_values)
            keys = tuple(keys)
            values = tuple(values)
            return render_template("results.html", heading=keys, values=values)
        elif request.form['submit'] == 'purchase_ticket':
            return redirect('/flight_search_specific')
        elif request.form['submit'] == 'view_my_commission':
            return redirect('/view_my_commission')
        elif request.form['submit'] == 'view_top_customers':
            return redirect('/view_top_customers')
    return render_template("booking_agent.html")


@app.route('/view_my_commission', methods=['GET', 'POST'])
def view_my_commission():
    if request.method == 'POST':
        count = 0
        time = 'range'
        if request.form['From']:
            leaving_time = request.form['From']
        if request.form['to']:
            arriving_time = request.form['to']
        payment_history = []
        corresponding_flight = []
        total_price = 0
        query1 = "SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id = '" + str(
            session[
                'booking_agent_id']) + "' AND purchase_date >= '" + leaving_time + "' AND purchase_date <= '" + arriving_time + "');"
        cur = conn.cursor()
        cur.execute(query1)
        flights = cur.fetchall()
        print(flights)
        for i in flights:
            i = str(i)
            key_left_appe = i.index(":", 0)
            right_comma = i.index("}", key_left_appe + 1)
            corresponding_flight.append(i[key_left_appe + 1:right_comma])
        for i in corresponding_flight:
            query_price = "SELECT price FROM flight WHERE flight_num= '" + str(i) + "';"
            cur = conn.cursor()
            cur.execute(query_price)
            spent = cur.fetchall()
            spent = str(spent)
            key_left_semi = spent.index("(")
            key_left_semi1 = spent.index("'", key_left_semi + 1)
            key_right_semi = spent.index("')", key_left_semi1 + 1)
            payment_history.append(spent[key_left_semi1 + 1:key_right_semi])

        for j in payment_history:
            count += 1
            total_price += int(j) * 0.1
        try:
            average = total_price / count
        except:
            average = 0

        return render_template('track_spending.html', total_price=total_price, time=time, average=average, count=count)
    count = 0
    time = 'month'
    today = datetime.today().strftime('%Y-%m-%d')
    month = int(today[5:7])
    past_month = (month - 1)
    year = int(today[:4])
    prev_year = year - 1

    if month == 1:
        one_month_ago = str(prev_year) + '-12' + today[7:]
    elif past_month == 11 or past_month == 10:
        one_month_ago = today[:5] + str(past_month) + today[7:]
    else:
        one_month_ago = today[:5] + '0' + str(past_month) + today[7:]

    payment_history = []
    corresponding_flight = []
    total_price = 0
    query1 = "SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id = '" + str(
        session['booking_agent_id']) + "' AND purchase_date >= '" + one_month_ago + "');"
    cur = conn.cursor()
    cur.execute(query1)
    flights = cur.fetchall()
    for i in flights:
        i = str(i)
        key_left_appe = i.index(":", 0)
        right_comma = i.index("}", key_left_appe + 1)
        corresponding_flight.append(i[key_left_appe + 1:right_comma])
    for i in corresponding_flight:
        query2 = "SELECT price FROM flight WHERE flight_num= " + str(i)
        cur.execute(query2)
        spent = cur.fetchall()
        spent = str(spent)
        key_left_semi = spent.index("(")
        key_left_semi1 = spent.index("'", key_left_semi + 1)
        key_right_semi = spent.index("')", key_left_semi1 + 1)
        payment_history.append(spent[key_left_semi1 + 1:key_right_semi])
    for j in payment_history:
        total_price += int(j) * 0.1
        count += 1
    try:
        average = total_price / count
    except:
        average = 0
    return render_template('track_spending.html', total_price=total_price, time=time, count=count, average=average)


@app.route('/view_top_customers', methods=['GET', 'POST'])
def view_top_customers():
    email_list = []
    email_list_2 = []
    today = datetime.today().strftime('%Y-%m-%d')
    month = int(today[5:7])
    if month >= 6:
        today_minus_six = month - 6
        if today_minus_six <= 9:
            six_months_ago = today[:5] + "-0" + str(today_minus_six) + today[7:]
        else:
            six_months_ago = today[:5] + str(today_minus_six) + today[7:]
    else:
        today_minus_six = 12 + (month - 6)
        year = int(today[:4])
        last_year = year - 1
        if today_minus_six <= 9:
            six_months_ago = str(last_year) + "0" + str(today_minus_six) + today[7:]
        else:
            six_months_ago = str(last_year) + '-' + str(today_minus_six) + today[7:]
    select_five_most = "SELECT distinct customer_email, COUNT(customer_email) as count FROM purchases WHERE booking_agent_id = '" + str(
        session[
            'booking_agent_id']) + "' AND purchase_date >= '" + six_months_ago + "' group by customer_email ORDER BY count desc LIMIT 5 ;"
    print(select_five_most)
    cur = conn.cursor()
    cur.execute(select_five_most)
    most_customer = cur.fetchall()
    print(most_customer)
    for i in most_customer:
        email_list.append(i['customer_email'])
    corresponding_flight = []
    last_year = int(today[:4]) - 1
    one_year_ago_date = str(last_year) + '-' + today[5:]
    select_most_five_flights = "SELECT flight_num FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id = '" + str(
        session['booking_agent_id']) + "' AND purchase_date >= '" + one_year_ago_date + "');"
    print(select_most_five_flights)
    cur = conn.cursor()
    cur.execute(select_most_five_flights)
    flights = cur.fetchall()
    print(flights)
    for i in flights:
        i = str(i)
        key_left_appe = i.index(":", 0)
        right_comma = i.index("}", key_left_appe + 1)
        corresponding_flight.append(i[key_left_appe + 1:right_comma])
    print(corresponding_flight)
    corresponding_flight_num = []
    cur = conn.cursor()
    query2 = "SELECT flight_num FROM flight WHERE flight_num IN (" + str(corresponding_flight)[
                                                                     1:-1] + ") ORDER BY price LIMIT 5;"
    print(query2)
    cur.execute(query2)
    result2 = cur.fetchall()
    print(result2)
    for i in result2:
        corresponding_flight_num.append(i['flight_num'])
    select_email_query = "select email, sum(price) as price_sum from customer, purchases, ticket, flight where ticket.ticket_id in (select ticket_id from purchases where purchase_date >= '" + one_year_ago_date + "') and (customer.email = purchases.customer_email) and (ticket.ticket_id = purchases.ticket_id) and (flight.flight_num = ticket.flight_num) and purchases.booking_agent_id ='" + str(
        session['booking_agent_id']) + "' GROUP BY email ORDER BY price_sum DESC;"
    print(select_email_query)
    cur.execute(select_email_query)
    corresponding_info = cur.fetchall()
    print(corresponding_info)
    for i in corresponding_info:
        email_list_2.append(i['email'])
    sold1 = []
    x_axis = [email_list[i] for i in range(len(email_list))]
    for i in most_customer:
        sold1.append(i['count'])
    print(sold1)
    plt.bar(x_axis, sold1)
    plt.title('Top 5 based on number of tickets')
    plt.xlabel('Customer_name')
    plt.ylabel('Number of tickets sold')
    for a, b in zip(x_axis, sold1):
        plt.text(a, b, b, ha='center', va='bottom', fontsize=12)
    buffer = BytesIO()
    plt.savefig(buffer)
    plot_date = buffer.getvalue()
    imb = base64.b64encode(plot_date)
    ims = imb.decode()
    image_2 = "data:image/png;base64," + ims
    plt.close()

    sold = []
    x_axis = [email_list_2[i] for i in range(len(email_list_2))]
    for i in corresponding_info:
        sold.append(i['price_sum'])
    print(sold)
    plt.bar(x_axis, sold)
    plt.title('Top 5 based on commissions')
    plt.xlabel('Customer')
    plt.ylabel('Commissions')
    for a, b in zip(x_axis, sold):
        plt.text(a, b, b, ha='center', va='bottom', fontsize=7)
    buffer = BytesIO()
    plt.savefig(buffer)
    plot_date = buffer.getvalue()
    imb = base64.b64encode(plot_date)
    ims = imb.decode()
    image = "data:image/png;base64," + ims
    plt.close()
    return render_template('view_top_customers.html', heading=['Top 5 Customers based on Number of Tickets'],
                           email_list=email_list, heading2=['Top 5 Customers based on Commissions'],
                           email_list_2=email_list_2, bar_chart=image, bar_chart_2=image_2)


# ---------------------------------------------------------------------------------------------------------------------
@app.route("/airline_staff", methods=['GET', 'POST'])
# @login_required
def airline_staff():
    print(session)
    if request.method == 'POST':
        if request.form['submit'] == 'grant_new_permission':
            if session['permission'] != 'Admin':
                flash('Unauthorized user, please try again!')
                return redirect('/airline_staff')
            else:
                return redirect("/grant_new_permission")
        elif request.form['submit'] == 'add_booking_agent':
            if session['permission'] != 'Admin':
                flash('Unauthorized user, please try again!')
                return redirect('/airline_staff')
            else:
                return redirect("/add_booking_agent")
        elif request.form['submit'] == 'view_my_flight':
            return redirect("/view_staff_flight")
        elif request.form['submit'] == 'create_new_flight':
            return redirect("/create_new_flight")
        elif request.form['submit'] == 'top_booking_agent':
            return redirect("/top_booking_agent")
        elif request.form['submit'] == 'view_frequent_customer':
            return redirect("/view_frequent_customer")
        elif request.form['submit'] == 'view_flight_of_customers':
            return redirect("/view_flight_of_customers")
        elif request.form['submit'] == 'view_report':
            return redirect("/track_tickets_sold")
        elif request.form['submit'] == 'comparison':
            return redirect("/comparison")
        elif request.form['submit'] == 'view_top_destination':
            return redirect("/view_top_destination")
        elif request.form['submit'] == 'change_flight_status':
            return redirect("/change_flight_status")
        elif request.form['submit'] == 'add_airplane':
            return redirect("/add_airplane")
        elif request.form['submit'] == 'add_airport':
            return redirect("/add_airport")

    return render_template("airline_staff.html")


@app.route("/add_booking_agent", methods=['POST', 'GET'])
# @login_required
def add_booking_agent():
    info_1 =[]
    if request.method == 'POST':
        email = request.form['email']
        cur = conn.cursor()
        cur.execute("SELECT email FROM booking_agent")
        info = cur.fetchall()
        print(info)
        for i in info:
            info_1.append(i['email'])
        if email not in info_1:
            flash('This booking agent does not exist! Try again.')
            return render_template('add_booking_agent.html')
        cur.execute("SELECT * FROM booking_agent_work_for WHERE email= '" + str(email) + "' and airline_name =  '" + str(session['work_for']) + "';")
        check_existence = cur.fetchall()
        print(check_existence)
        if check_existence:
            flash('Booking agent already exists already! Try again.')
            return render_template('add_booking_agent.html')
        else:
            cur.execute(
                "INSERT INTO booking_agent_work_for VALUES('" + str(email) + "', '" + str(session['work_for']) + "')")
            conn.commit()
            cur.close()
            flash('Booking agent added')
            return redirect('/airline_staff')
    return render_template('add_booking_agent.html')


@app.route('/grant_new_permission', methods=['GET', 'POST'])
def grant_new_permission():
    if request.method == 'POST':
        staff_list = []
        cur = conn.cursor()
        airline = session['work_for']
        airline_tuple = (airline,)
        cur.execute("SELECT * FROM airline_staff WHERE airline_name = %s;", airline_tuple)
        info = cur.fetchall()
        for i in info:
            staff_list.append(i['username'])
        username = request.form['user_name']
        permission_type = request.form['permission_type']
        if username not in staff_list:
            flash('This is not in the list.')
            return redirect('/grant_new_permission')
        else:
            cur.execute("UPDATE permission SET permission_type = '"+permission_type+"' WHERE username = '"+username+"';")
            conn.commit()
            cur.close()
            flash('Update Successfully!')
            return redirect('/airline_staff')
    return render_template('grant_new_permission.html')


@app.route("/add_airport", methods=['GET', 'POST'])
def add_airport():
    if request.method == 'POST':
        airport_name = request.form['airport_name']
        airport_city = request.form['airport_city']
        if session["permission"] != "Admin":
            flash('Unauthorized user, please try again!')
            return redirect('/airline_staff')
        else:
            query = "INSERT INTO airport VALUES(%s,%s)"
            val = (str(airport_name), str(airport_city))
            cur = conn.cursor()
            cur.execute(query, val)
            conn.commit()
            flash('Update successfully!')
            return redirect("/airline_staff")
    return render_template('add_airport.html')


@app.route("/add_airplane", methods=['GET', 'POST'])
def add_airplane():
    if request.method == 'POST':
        airline_name = session['work_for']
        airplane_id = request.form['airplane_id']
        seats = request.form['seats']
        if session["permission"] != "Admin":
            flash('Unauthorized user, please try again!')
            return redirect('/airline_staff')
        query1 = "SELECT * FROM airplane WHERE airplane_id ='" + str(airplane_id) + "'"
        cur = conn.cursor()
        cur.execute(query1)
        check_list = cur.fetchall()
        if len(check_list) >= 1:
            flash('Airplane has already existed! ')
            return redirect("/add_airplane")
        else:
            heading = []
            values = []
            query2 = "INSERT INTO airplane VALUES(%s,%s,%s)"
            val = (airline_name, str(airplane_id), seats)
            cur.execute(query2, val)
            conn.commit()
            flash('Update successfully!')
            query3 = "SELECT * FROM airplane WHERE airline_name = '" + str(session['work_for']) + "'"
            cur.execute(query3)
            flight_result = cur.fetchall()
            flight_result = tuple(flight_result)
            for i in range(len(flight_result)):
                sub_values = []
                if i == 0:
                    for j in flight_result[i].keys():
                        heading.append(str(j))
                for j in flight_result[i].values():
                    sub_values.append(str(j))
                values.append(sub_values)
            heading = tuple(heading)
            values = tuple(values)
            session['heading'] = heading
            session['values'] = values
            return render_template('results.html', heading=session['heading'], values=session['values'])
    return render_template('add_airplane.html')


@app.route("/change_flight_status", methods=['GET', 'POST'])
def change_flight_status():
    if request.method == 'POST':
        flight_num = request.form['flight_num']
        airline_name = session['work_for']
        flight_status = request.form['flight_status']
        if session["permission"] != "Operator":
            flash('Unauthorized staff, please get the authorization!')
            return redirect('/airline_staff')
        else:
            cur = conn.cursor()
            select_flight_query = "SELECT * FROM flight WHERE flight_num = " + str(
                flight_num) + " AND airline_name = '" + airline_name + "'"
            cur.execute(select_flight_query)
            check_list = cur.fetchall()
            if len(check_list) == 0:
                flash('This flight does not exist!')
            else:
                update_query = "UPDATE flight SET status = '" + str(flight_status) + "' WHERE flight_num =" + str(
                    flight_num) + " AND airline_name = '" + airline_name + "'"
                cur.execute(update_query)
                conn.commit()
                flash('Update successfully! ')
                return redirect("/airline_staff")
    return render_template("change_flight_status.html")


@app.route('/view_top_destination', methods=['GET', 'POST'])
def view_top_destination():
    current_date = datetime.today().strftime('%Y-%m-%d')
    month = int(current_date[5:7])
    today_minus_three = month - 3
    three_months_ago = current_date[:5] + "0" + str(today_minus_three) + current_date[7:]
    one_year_ago = str(int(current_date[:4]) - 1) + "-0" + str(month) + current_date[7:]
    flight_store1 = []
    cities1 = []
    cur = conn.cursor()
    select_flight_num1 = "SELECT distinct flight_num FROM ticket natural join purchases where airline_name = '" + str(session[
                'work_for']) + "' and purchase_date >= '" + str(
        three_months_ago) + "' group by flight_num ORDER BY count(flight_num) desc LIMIT 3;"
    print(select_flight_num1)
    cur.execute(select_flight_num1)
    flight_num_list1 = cur.fetchall()
    print(flight_num_list1)
    for i in flight_num_list1:
        flight_store1.append(str(i['flight_num']))
    query = "SELECT distinct airport_city FROM airport WHERE airport_name IN (SELECT arrival_airport FROM flight WHERE flight_num IN (" + str(
        flight_store1)[1:-1] + ")); "
    print(query)
    cur.execute(query)
    city = cur.fetchall()
    for i in city:
        cities1.append(i['airport_city'])
    flight_store2 = []
    cities2 = []
    select_flight_num2 = "SELECT distinct flight_num FROM ticket natural join purchases where airline_name = '" + str(session[
                'work_for']) + "' and purchase_date >= '" + str(
        one_year_ago) + "' group by flight_num ORDER BY count(flight_num) desc LIMIT 3;"
    print(select_flight_num2)
    cur.execute(select_flight_num2)
    flight_num_list2 = cur.fetchall()
    print(flight_num_list2)
    for i in flight_num_list2:
        flight_store2.append(str(i['flight_num']))
    query = "SELECT distinct airport_city FROM airport WHERE airport_name IN (SELECT arrival_airport FROM flight WHERE flight_num IN (" + str(
        flight_store2)[1:-1] + ")); "
    print(query)
    cur.execute(query)
    city = cur.fetchall()
    print(city)
    cur.close()
    for i in city:
        cities2.append(i['airport_city'])
    return render_template("frequent_results.html", heading1=['TOP 3 DESTINATIONS SINCE 3 MONTHS AGO'], values1=cities1,
                           heading2=['TOP 3 DESTINATIONS SINCE 1 YEAR AGO'], values2=cities2)


@app.route("/view_staff_flight", methods=['GET', 'POST'])
def view_staff_flight():
    heading = []
    values = []
    today = datetime.today().strftime('%Y-%m-%d')
    current_month = int(today[5:7])
    current_year = int(today[:4])
    if current_month == 12:
        next_month = str(current_year + 1) + "-" + "01" + today[7:]
    elif current_month == 10 or current_month == 11 or current_month == 9:
        next_month = today[:5] + str(current_month + 1) + today[7:]
    else:
        next_month = today[:5] + "0" + str(current_month + 1) + today[7:]
    select_flight = "SELECT * FROM flight WHERE airline_name IN (SELECT airline_name FROM airline_staff WHERE username = '" + str(
        session['email']) + "') AND departure_time >= '" + str(today) + "' AND departure_time <= '" + str(
        next_month) + "';"
    cur = conn.cursor()
    cur.execute(select_flight)
    flight_list_result = cur.fetchall()
    cur.close()
    flight_list_result = tuple(flight_list_result)
    for i in range(len(flight_list_result)):
        sub_values = []
        if i == 0:
            for j in flight_list_result[i].keys():
                heading.append(str(j))
        for j in flight_list_result[i].values():
            sub_values.append(str(j))
        values.append(sub_values)
    heading = tuple(heading)
    values = tuple(values)
    session['heading'] = heading
    session['values'] = values
    return redirect("/staff_result")


@app.route("/staff_result", methods=['GET', 'POST'])
def staff_result():
    if request.method == 'POST':
        if request.form['submit'] == 'view_customers_of_flights':
            return redirect('/view_list_of_customers')
        if request.form['submit'] == 'set_range':
            return redirect('/view_airline_staff_flight')

    return render_template("staff_result.html", heading=session['heading'], values=session['values'])


@app.route('/view_list_of_customers', methods=['GET', 'POST'])
def view_list_of_customers():
    if request.method == 'POST':
        flight_num_list = []
        customer_email = []
        checked_list = request.form.getlist('checkbox')
        if len(checked_list) >= 1:
            for i in checked_list:
                flight_num_list.append(str(i))
            cur = conn.cursor()
            select_customer_email = "SELECT customer_email FROM purchases WHERE ticket_id IN (SELECT ticket_id FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and flight_num IN (" + str(
                flight_num_list)[1:-1] + "))"
            cur.execute(select_customer_email)
            customers_emails_final = cur.fetchall()
            for i in customers_emails_final:
                customer_email.append(i['customer_email'])
            return render_template('frequent_results.html', heading1=['Customers'], values1=customer_email)
        else:
            return redirect('/view_list_of_customers')
    flight_num = []
    select_customer_email = "SELECT * FROM flight WHERE airline_name = '" + str(session['work_for']) + "'"
    cur = conn.cursor()
    cur.execute(select_customer_email)
    flight = cur.fetchall()
    cur.close()
    for i in flight:
        flight_num.append(str(i['flight_num']))

    return render_template("view_list_of_customers.html", heading=['Flights_number'], values=flight_num)


@app.route('/view_airline_staff_flight', methods=['GET', 'POST'])
def view_airline_staff_flight():
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT airport_name FROM airport ORDER BY airport_name")
    airport_name = cur.fetchall()
    cur.execute("SELECT DISTINCT airport_city FROM airport ORDER BY airport_city")
    airport_city = cur.fetchall()

    if request.method == 'POST':
        values = []
        keys = []
        query = "SELECT * FROM flight WHERE"
        query_addtion = ""

        if request.form['From']:
            departure_date = request.form['From']
            addtion = " AND departure_time LIKE '" + departure_date + "%'"
            query_addtion += addtion

        if request.form['to']:
            arriving_time = request.form['to']
            addtion = " AND arrival_time LIKE '" + arriving_time + "%'"
            query_addtion += addtion

        if request.form['source_airport']:
            d_airport = request.form['source_airport']
            addtion = " AND departure_airport = '" + d_airport + "'"
            query_addtion += addtion

        if request.form['destination_airport']:
            arriving_airport = request.form['destination_airport']
            addtion = " AND arrival_airport = '" + arriving_airport + "'"
            query_addtion += addtion

        if request.form['source_city']:
            departure_city = request.form['source_city']
            addtion = " AND departure_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + departure_city + "')"
            query_addtion += addtion

        if request.form['destination_city']:
            arriving_city = request.form['destination_city']
            addtion = " AND arrival_airport IN (SELECT airport_name FROM airport WHERE airport_city= '" + arriving_city + "')"
            query_addtion += addtion

        if request.form['flight_num']:
            flight_num = request.form['flight_num']
            addtion = " AND flight_num = " + flight_num
            query_addtion += addtion

        if query_addtion == "":
            query = "SELECT * FROM flight WHERE status = 'Upcoming';"
        else:
            query = query + query_addtion[4:] + ";"
        print(query)
        cur.execute(query)
        flight_info = cur.fetchall()
        flight_info = tuple(flight_info)
        for i in range(len(flight_info)):
            sub_values = []
            if i == 0:
                for j in flight_info[i].keys():
                    keys.append(str(j))
            for j in flight_info[i].values():
                sub_values.append(str(j))
            values.append(sub_values)
        keys = tuple(keys)
        values = tuple(values)
        print(keys)
        print(values)
        cur.close()
        # query = "SELECT flight.airline_name, flight.flight_num, flight.departure_airport, flight.departure_time, flight.arrival_airport, flight.arrival_time, flight.status, flight.price FROM flight, airport WHERE flight.departure_airport LIKE '%%%s%%' or flight.arrival_airport LIKE '%%%s%%'or (flight.departure_airport = airport.airport_name and airport.airport_city LIKE '%%%s%%') or (flight.arrival_airport = airport.airport_name and airport.airport_city LIKE '%%%s%%')" % (
        # searchText, searchText, searchText, searchText)
        # cursor.execute(query)
        return render_template("results.html", heading=keys, values=values)

    return render_template("view_airline_staff_flight.html", airport_city=airport_city, airport_name=airport_name)


@app.route('/view_flight_of_customers', methods=['GET', 'POST'])
def view_flight_of_customers():
    if request.method == 'POST':
        flight_num_list = []
        customer_email = []
        check_list = request.form.getlist('checkbox')
        if len(check_list) >= 1:
            for i in check_list:
                customer_email.append(str(i))
            query = "SELECT * FROM flight WHERE flight_num IN ( SELECT flight_num FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (SELECT ticket_id FROM purchases WHERE customer_email IN (" + str(
                customer_email)[1:-1] + ")))"
            print(query)
            cur = conn.cursor()
            cur.execute(query)
            select_flight_list = cur.fetchall()
            for i in select_flight_list:
                flight_num_list.append(i['flight_num'])
            return render_template('frequent_results.html', heading1=['Flights_Number_List'], values1=flight_num_list)
        else:
            return redirect('/view_list_of_customers')
    customer_email = []
    query = "SELECT DISTINCT customer_email FROM purchases WHERE ticket_id IN (SELECT ticket_id FROM ticket WHERE airline_name = '" + str(
        session['work_for']) + "')"
    print(query)
    cur = conn.cursor()
    cur.execute(query)
    customer_list = cur.fetchall()
    cur.close()
    for i in customer_list:
        customer_email.append(str(i['customer_email']))

    return render_template("view_list_of_customers.html", heading=['Customers_List'], values=customer_email)


@app.route("/view_frequent_customer", methods=['GET', 'POST'])
def view_frequent_customer():
    top_customers = []
    customers_list = []
    ticket_list = []
    today = datetime.today().strftime('%Y-%m-%d')
    year = int(today[:4])
    prev_year = year - 1
    one_year_ago = str(prev_year) + today[4:]
    query1 = "SELECT * FROM ticket WHERE airline_name = '" + str(session['work_for']) + "'"
    cur = conn.cursor()
    cur.execute(query1)
    tickets = cur.fetchall()
    print(tickets)
    for i in tickets:
        ticket_list.append(str(i['ticket_id']))
    query2 = "SELECT * FROM purchases natural join ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (" + str(ticket_list)[
                                                              1:-1] + ") and purchase_date >= '" + one_year_ago + "';"
    cur.execute(query2)
    customers = cur.fetchall()
    print(query2)
    print(customers)
    for i in customers:
        customers_list.append(str(i['customer_email']))
    query3 = "SELECT customer_email, COUNT(customer_email) as count FROM purchases natural join ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and customer_email IN (" + str(
        customers_list)[1:-1] + ") group by customer_email ORDER BY count desc LIMIT 1;"
    print(query3)
    cur.execute(query3)
    running = cur.fetchall()
    print(running)
    top_customers.append(running[0]['customer_email'])
    return render_template('frequent_results.html', heading1=['The Most Frequent Customer Since Last Year: Only One'],
                           values1=top_customers)


@app.route("/create_new_flight", methods=['GET', 'POST'])
def create_new_flight():
    heading = []
    values = []
    today = datetime.today().strftime('%Y-%m-%d')
    month = int(today[5:7])
    year = int(today[:4])
    if month == 12:
        a_month_later = str(year + 1) + "-" + "01" + today[7:]
    elif month == 10 or month == 11 or month == 9:
        a_month_later = str(year + 1) + '-' + str(month) + today[7:]
    else:
        a_month_later = str(year + 1) + "-0" + str(month) + today[7:]
    select_flight = "SELECT * FROM flight WHERE airline_name IN (SELECT airline_name FROM airline_staff WHERE username = '" + str(
        session['email']) + "') AND departure_time >= '" + str(today) + "' AND departure_time <= '" + str(
        a_month_later) + "';"
    cur = conn.cursor()
    cur.execute(select_flight)
    flight_list = cur.fetchall()
    flight_list = tuple(flight_list)
    for i in range(len(flight_list)):
        sub_values = []
        if i == 0:
            for j in flight_list[i].keys():
                heading.append(str(j))
        for j in flight_list[i].values():
            sub_values.append(str(j))
        values.append(sub_values)
    heading = tuple(heading)
    values = tuple(values)
    session['heading'] = heading
    session['values'] = values
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT airport_city FROM airport ORDER BY airport_city")
    airport_city = cur.fetchall()
    cur.execute("SELECT DISTINCT airport_name FROM airport ORDER BY airport_name")
    airport_name = cur.fetchall()
    if request.method == 'POST':
        cur = conn.cursor()
        cur.execute("SELECT * FROM airplane WHERE airline_name = '" + str(session['work_for']) + "';")
        airplane_list = []
        for i in cur:
            airplane_list.append(str(i['airplane_id']))
        print(airplane_list)
        if session["permission"] != "Admin":
            flash('No authorization, be Admin First!')
            return redirect('/airline_staff')
        else:
            flight_num = request.form['flight_num']
            departure_airport = request.form['departure_airport']
            departure_time = request.form['From']
            departure_time = departure_time + ":00"
            arrival_airport = request.form['arrival_airport']
            arrival_time = request.form['To']
            arrival_time = arrival_time + ":00"
            airplane_id = request.form['airplane_id']
            price = request.form['price']
            status = request.form['status']
            if airplane_id not in airplane_list:
                flash('Not exist the entered airplane id')
            else:
                select_flight = "INSERT INTO flight VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                values = (
                session['work_for'], flight_num, departure_airport, departure_time, arrival_airport, arrival_time,
                price, status, airplane_id)
                cur.execute(select_flight, values)
                conn.commit()
                flash('Flight Created Successfully!')
                return redirect("/airline_staff")
        return redirect("/airline_staff")
    return render_template('create_new_flight.html', airport_city=airport_city, airport_name=airport_name,
                           heading=session['heading'], values=session['values'])


@app.route('/track_tickets_sold', methods=['GET', 'POST'])
def view_report():
    month = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
             'November', 'December', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
             'September', 'October', 'November', 'December']
    if request.method == 'POST':
        count_tickets = 0
        time = 'range'
        if request.form['From']:
            departure_time = request.form['From']
        if request.form['to']:
            arriving_time = request.form['to']
        track_count = "SELECT count(ticket_id) as count FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE airline_name = '" + str(
            session[
                'work_for']) + "' AND purchase_date >= '" + departure_time + "' AND purchase_date <= '" + arriving_time + "');"
        cur = conn.cursor()
        cur.execute(track_count)
        tickets = cur.fetchall()
        count_tickets += tickets[0]['count']
        start_month = int(departure_time[5:7])
        end_month = int(arriving_time[5:7])
        x_axis = [month[i - 1] for i in range(start_month, end_month + 1)]
        sold = [0] * (end_month - start_month + 1)
        for i in range(len(sold)):
            if i == 0:
                if start_month == 12 or start_month == 10 or start_month == 11:
                    departure_date = departure_time[:5] + str(start_month) + departure_time[7:]
                    arriving_date = arriving_time[:5] + str(start_month) + "-" + str(30)
                elif start_month <= 9:
                    departure_date = departure_time[:5] + '0' + str(start_month) + departure_time[7:]
                    arriving_date = arriving_time[:5] + '0' + str(start_month) + "-" + str(30)
            else:
                if start_month == 13:
                    departure_date = str(int(arriving_time[:4]) + 1) + "-01" + "-01"
                    arriving_date = str(int(arriving_time[:4]) + 1) + '-01' + "-" + str(30)
                    start_month = 0
                elif start_month == 10 or start_month == 11 or start_month == 12:
                    departure_date = departure_time[:5] + str(start_month) + "-01"
                    arriving_date = arriving_time[:5] + str(start_month) + "-" + str(30)
                elif start_month <= 9:
                    departure_date = departure_time[:5] + '0' + str(start_month) + "-01"
                    arriving_date = arriving_time[:5] + '0' + str(start_month) + "-" + str(30)

            if start_month == end_month:
                if start_month == 12 or start_month == 10 or start_month == 11:
                    departure_date = departure_time[:5] + str(start_month) + "-01"
                    arriving_date = arriving_time[:5] + str(start_month) + "-" + arriving_time[7:]
                elif start_month <= 9:
                    departure_date = departure_time[:5] + '0' + str(start_month) + "-01"
                    arriving_date = arriving_time[:5] + '0' + str(start_month) + arriving_time[7:]
            select_number_ticket_in_period = "SELECT count(ticket_id) as count FROM ticket WHERE ticket_id IN (SELECT ticket_id FROM purchases WHERE airline_name = '" + str(
                session[
                    'work_for']) + "' AND purchase_date >= '" + departure_date + "' AND purchase_date <= '" + arriving_date + "');"
            cur = conn.cursor()
            cur.execute(select_number_ticket_in_period)
            counts = cur.fetchall()
            cur.close()
            sold[i] = counts[0]['count']
            start_month += 1
        plt.bar(x_axis, sold)
        plt.title('Number of tickets sold in range')
        plt.xlabel('Month')
        plt.ylabel('Sale')
        for a, b in zip(x_axis, sold):
            plt.text(a, b, b, ha='center', va='bottom', fontsize=7)
        buffer = BytesIO()
        plt.savefig(buffer)
        plot = buffer.getvalue()
        imc = base64.b64encode(plot)
        imb = imc.decode()
        image = "data:image/png;base64," + imb
        plt.close()
        return render_template('track_tickets_sold.html', bar_chart=image, count_tickets=count_tickets, time=time)
    return render_template('track_tickets_sold.html')


@app.route('/comparison')
def comparison():
    today = datetime.today().strftime('%Y-%m-%d')
    month = int(today[5:7])
    prev_month = month - 1
    year = int(today[:4])
    last_yeas = year - 1
    if month == 1:
        one_month_ago = str(last_yeas) + '-12' + today[7:]
    elif prev_month == 11 or prev_month == 10:
        one_month_ago = today[:5] + str(prev_month) + today[7:]
    else:
        one_month_ago = today[:5] + '0' + str(prev_month) + today[7:]
    price_one = []
    price_twp = []
    total_price_num = 0
    total_two = 0
    sizes = [0 for i in range(2)]
    selet_res = "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id IS NULL AND purchase_date >= '" + str(
        one_month_ago) + "'));"
    cur = conn.cursor()
    cur.execute(selet_res)
    resid = cur.fetchall()
    for i in resid:
        price_one.append(i['price'])
    for i in price_one:
        total_price_num += i
    query2 = "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id AND purchase_date>= '" + str(
        one_month_ago) + "'));"
    cur.execute(query2)
    desid_2 = cur.fetchall()
    for i in desid_2:
        price_twp.append(i['price'])
    for i in price_twp:
        total_two += i
    total_all = total_price_num + total_two
    percentage_1 = total_price_num / total_all * 100
    percentage_2 = total_two / total_all * 100
    sizes[0] = percentage_1
    sizes[1] = percentage_2
    labels = ['Direct Sales', 'Indirect Sales']
    y = np.array(sizes)
    plt.title('Comparison of Revenue last month')
    plt.pie(y, labels=labels, startangle=90)
    buffer = BytesIO()
    plt.savefig(buffer)
    plot_date = buffer.getvalue()
    imb = base64.b64encode(plot_date)
    ims = imb.decode()
    image = "data:image/png;base64," + ims
    plt.close()

    today = datetime.today().strftime('%Y-%m-%d')
    year = int(today[:4])
    last_yeas = year - 1
    one_year_ago = str(last_yeas) + today[4:]
    price_one = []
    price_twp = []
    total_price_num = 0
    total_two = 0
    sizes = [0] * 2
    selet_res = "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id IS NULL AND purchase_date >= '" + str(
        one_year_ago) + "'));"
    cur = conn.cursor()
    cur.execute(selet_res)
    resid = cur.fetchall()
    for i in resid:
        price_one.append(i['price'])
    for i in price_one:
        total_price_num += i
    query2 = "SELECT * FROM flight WHERE flight_num IN (SELECT flight_num FROM ticket WHERE airline_name = '" + str(session[
                'work_for']) + "' and ticket_id IN (SELECT ticket_id FROM purchases WHERE booking_agent_id AND purchase_date>= '" + str(
        one_year_ago) + "'));"
    cur.execute(query2)
    desid_2 = cur.fetchall()
    for i in desid_2:
        price_twp.append(i['price'])
    for i in price_twp:
        total_two += i
    total_all = total_price_num + total_two
    percentage_1 = total_price_num / total_all * 100
    percentage_2 = total_two / total_all * 100
    sizes[0] = percentage_1
    sizes[1] = percentage_2
    labels = ['Direct Sales', 'Indirect Sales']
    y = np.array(sizes)
    plt.title('Comparison of Revenue last year')
    plt.pie(y, labels=labels, startangle=90)
    buffer = BytesIO()
    plt.savefig(buffer)
    plot_date = buffer.getvalue()
    imb = base64.b64encode(plot_date)
    ims = imb.decode()
    image1 = "data:image/png;base64," + ims
    plt.close()

    return render_template('comparison.html', pie_chart=image, pie_chart1=image1)


@app.route('/top_booking_agent', methods=['GET', 'POST'])
def top_booking_agent():
    today = datetime.today().strftime('%Y-%m-%d')
    month = int(today[5:7])
    prev_month = (month - 1)
    year = int(today[:4])
    prev_year = year - 1
    if month == 1:
        one_month_ago = str(prev_year) + '-12' + today[7:]
    elif prev_month == 11 or prev_month == 10:
        one_month_ago = today[:5] + str(prev_month) + today[7:]
    else:
        one_month_ago = today[:5] + '0' + str(prev_month) + today[7:]

    query = "SELECT distinct email FROM booking_agent natural join purchases where purchase_date >= '" + one_month_ago + "' group by email order by count(email) desc limit 5;"
    print(query)
    cur = conn.cursor()
    cur.execute(query)
    list = cur.fetchall()
    print(list)
    top_list = []
    top_year = []
    top_comission_list =[]
    for i in list:
        top_list.append(i['email'])

    today = datetime.today().strftime('%Y-%m-%d')
    year = int(today[:4])
    prev_year = year - 1
    one_year_ago = str(prev_year) + today[4:]
    select_past_emails = "SELECT distinct email FROM booking_agent natural join purchases where purchase_date >= '" + one_year_ago + "' group by email order by count(email) desc limit 5;"
    print(select_past_emails)
    cur = conn.cursor()
    cur.execute(select_past_emails)
    list1 = cur.fetchall()
    print(list1)
    for i in list1:
        top_year.append(i['email'])

    select_email = "select email, sum(price) as price_sum from booking_agent, purchases, ticket, flight where ticket.ticket_id in (select ticket_id from purchases where purchase_date >= '" + one_year_ago + "') and (booking_agent.booking_agent_id = purchases.booking_agent_id) and (ticket.ticket_id = purchases.ticket_id) and (flight.flight_num = ticket.flight_num) GROUP BY email ORDER BY price_sum DESC limit 5;"
    print(select_email)
    cur = conn.cursor()
    cur.execute(select_email)
    list2 = cur.fetchall()
    print(list2)
    for i in list2:
        top_comission_list.append(i['email'])

    return render_template('view_top_booking_agent.html',
                           heading1=['Top 5 Booking Agent on Number of Tickets last month'], list_1=top_list,
                           heading2=['Top 5 Booking Agent based on Number of tickets last year'], list_2=top_year,
                           heading3=['Top 5 Booking Agent based on Commission last year'], list_3=top_comission_list)


if __name__ == '__main__':
    app.run('127.0.0.1', 5000, debug=True)
