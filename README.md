# Airline Ticket Reservation System

## Project Description

The Airline Ticket Reservation System is a MySQL/Flask project that allows users to book airline tickets and manage their reservations. The system provides a user-friendly interface and meets all the requirements outlined in the project details.

## Database Design

The database consists of the following entities:

### 1. Airport
- Each airport consists of a unique name and a city.

### 2. Airline
- Each airline has a unique name and owns several airplanes.

### 3. Airplane
- An airplane belongs to an airline and has a unique identification number within that airline.
- The airplane also has the number of seats available.

### 4. Flight
- Each airline operates flights that have a unique flight number within that airline.
- Flights have departure and arrival airports, departure and arrival times, a price, and the identification number of the airplane assigned to the flight.

### 5. Ticket
- A ticket can be purchased by either a Customer or Booking Agent.
- The ticket includes the customer's email address, airline name, flight number, and booking_agent_ID.
- If a Booking Agent purchases the ticket, their booking_agent_ID will be used, and if a Customer purchases the ticket, the booking_agent_ID should be null.
- Each ticket has a unique ticket ID number in the system.

## User Types

### 1. Customer
- Customers have a name, unique email, password, address, phone number, passport number, passport expiration, passport country, and date of birth.
- Customers must log in to purchase a flight ticket.
- They can purchase tickets as long as there are available seats on the plane, paying the associated price for the flight.
- Customers can view their upcoming flights and previous flights taken for the airline they are logged in.

### 2. Booking Agent
- Booking Agents purchase tickets on behalf of customers and receive a 10% commission from the ticket price.
- They have a unique email, password, and booking_agent_ID to sign into the system.
- Booking Agents work for specific airlines and can only purchase tickets for those airlines.
- Once logged in, Booking Agents can view their commission for the past 30 days, average commission per ticket, and the total number of tickets booked.

### 3. Airline Staff
- Airline Staff have a unique username, password, first name, last name, date of birth, and the airline they work for.
- They work for one particular airline and may have "Admin" and/or "Operator" permissions.
- "Admin" permission allows them to add new airplanes and create new flights for the airline.
- "Operator" permission enables them to set in-progress flight statuses in the system.
- Airline Staff can view in-progress, upcoming, and previous flights for the airline they work for, as well as a list of passengers for the flights.
- They can see a list of all flights a particular Customer has taken only on that airline.
- Airline Staff can view the most frequent customer within the last year, the number of tickets sold each month, and the top 5 Booking Agents for the past month and year based on sales.
- Airline Staff can query for the number of flights that are delayed/on-time, etc.

## Extra Bonus Features

The Airline Ticket Reservation System incorporates the following features:

- User authentication and registration for Customers, Booking Agents, and Airline Staff.
- Booking flights based on seat availability and price.
- Fuzzy query for searching flights based on various criteria.
- Enhanced security with password salting for user passwords.
- Responsive and visually appealing user interface using Bootstrap.
- Email validation for customers during account registration.

